import json
import os
import re
import time

import paho.mqtt.client as mqtt
import redis
from django.conf import settings
from django.core.management.base import BaseCommand

from api.models import Email, EmailEvent


EVENT_TYPE_MAP = {
    "spam_classified": "email.spam_classified",
    "priority_assigned": "email.priority_assigned",
    "summary": "email.summary",
    "action_items": "email.action_items",
    "tone_analyzed": "email.tone_analyzed",
    "url_scanned": "email.url_scanned",
}


def _extract_int(s: str) -> int | None:
    """
    Accepts "1", "u1", "e42", "user-7", etc.
    Returns the first integer found (prefer trailing digits).
    """
    if s is None:
        return None
    s = str(s)
    m = re.search(r"(\d+)$", s)
    if not m:
        m = re.search(r"(\d+)", s)
    return int(m.group(1)) if m else None


def _parse_topic(topic: str):
    # Expected: <prefix>/<event>/<user_id>/<email_id>
    parts = [p for p in (topic or "").split("/") if p]
    if len(parts) < 4:
        return None

    prefix, event_name, user_part, email_part = parts[0], parts[1], parts[2], parts[3]
    user_id = _extract_int(user_part)
    email_id = _extract_int(email_part)

    if not user_id or not email_id:
        return None

    return {
        "prefix": prefix,
        "event_name": event_name,
        "user_id": user_id,
        "email_id": email_id,
    }


def _strip_code_fences(s: str) -> str:
    s = (s or "").strip()
    if not s.startswith("```"):
        return s

    lines = s.splitlines()
    # drop opening fence line: ``` or ```json
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    # drop closing fence
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _try_parse_json_from_text(text: str):
    """
    Tries hard to convert LLM-ish outputs into JSON:
    - strips ```json fences
    - tries raw json.loads
    - tries extracting the first {...} or [...]
    """
    raw = text
    s = _strip_code_fences(text)

    # 1) direct parse
    try:
        return json.loads(s)
    except Exception:
        pass

    # 2) extract first JSON object/array substring
    candidates = []
    obj_start = s.find("{")
    obj_end = s.rfind("}")
    if obj_start != -1 and obj_end != -1 and obj_end > obj_start:
        candidates.append(s[obj_start : obj_end + 1])

    arr_start = s.find("[")
    arr_end = s.rfind("]")
    if arr_start != -1 and arr_end != -1 and arr_end > arr_start:
        candidates.append(s[arr_start : arr_end + 1])

    for c in candidates:
        try:
            return json.loads(c)
        except Exception:
            continue

    return {"raw": raw}


def _decode_payload(msg_payload: bytes):
    # msg_payload may be bytes of JSON, or bytes of text that contains JSON
    try:
        s = msg_payload.decode("utf-8")
    except Exception:
        s = msg_payload.decode("utf-8", errors="ignore")

    # First try strict JSON (no fences)
    try:
        return json.loads(s)
    except Exception:
        return _try_parse_json_from_text(s)


class Command(BaseCommand):
    help = "Consume Solace topics and persist agent outputs into Postgres, then fan-out via Redis pubsub."

    def handle(self, *args, **options):
        print("bsjhfbwigygdvwgvdyktwf")
        host = os.getenv("SOLACE_HOST", "broker")
        port = int(os.getenv("SOLACE_MQTT_PORT", "1883"))
        username = os.getenv("SOLACE_USERNAME", "default")
        password = os.getenv("SOLACE_PASSWORD", "default")
        prefix = os.getenv("TOPIC_PREFIX", "email").strip("/")

        r = redis.Redis.from_url(settings.REDIS_URL)

        client_id = f"django-consumer-{int(time.time() * 1000)}"
        client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        client.username_pw_set(username, password)

        # keep consumer alive through broker restarts
        client.reconnect_delay_set(min_delay=1, max_delay=30)

        def on_connect(c, userdata, flags, rc, properties=None):
            self.stdout.write(self.style.SUCCESS(f"Connected to MQTT broker rc={rc}"))
            # Subscribe to all processed events
            for ev in ["spam_classified", "priority_assigned", "summary", "action_items", "tone_analyzed", "url_scanned"]:
                topic = f"{prefix}/{ev}/#"
                c.subscribe(topic, qos=0)
                print(f"[SUBSCRIBE] Subscribed to: {topic}")

        def on_disconnect(c, userdata, rc, properties=None):
            self.stdout.write(self.style.WARNING(f"Disconnected rc={rc} (will auto-reconnect)"))

        def on_message(c, userdata, msg):
            print(f"Received message on topic: {msg.topic}")
            meta = _parse_topic(msg.topic)
            if not meta:
                return

            payload = _decode_payload(msg.payload)

            # Persist to DB
            try:
                email = Email.objects.get(id=meta["email_id"], owner_id=meta["user_id"])
            except Email.DoesNotExist:
                print("Email not found:", meta)
                return

            ev = meta["event_name"]

            # Normalize payload if gateway published text
            # (payload might still be a string if someone published plain text)
            if isinstance(payload, str):
                payload = _try_parse_json_from_text(payload)

            if ev == "spam_classified":
                email.spam_label = payload.get("label") or payload.get("spam_label") or payload.get("spam")
                email.spam_reason = payload.get("reason") or payload.get("why") or payload.get("explanation")
            elif ev == "priority_assigned":
                email.priority = payload.get("priority")
                email.priority_reason = payload.get("reason") or payload.get("why") or payload.get("explanation")
            elif ev == "summary":
                email.summary = payload.get("summary") or payload.get("text") or payload.get("result")
            elif ev == "action_items":
                items = payload.get("action_items") or payload.get("items")
                # If items is a stringified JSON, parse it
                if isinstance(items, str):
                    try:
                        items = json.loads(_strip_code_fences(items))
                    except Exception:
                        pass
                email.action_items = items
            elif ev == "tone_analyzed":
                print(f"[TONE DEBUG] Raw payload: {payload}")
                print(f"[TONE DEBUG] Payload type: {type(payload)}")
                # Handle case where payload is {'raw': '```json...```'}
                if isinstance(payload, dict) and "raw" in payload:
                    raw_text = payload["raw"]
                    payload = _try_parse_json_from_text(raw_text)
                    print(f"[TONE DEBUG] Parsed from raw: {payload}")
                    # If still got raw back, try regex extraction for truncated JSON
                    if isinstance(payload, dict) and "raw" in payload:
                        import re
                        text = payload["raw"]
                        # Extract primary_emotion
                        match = re.search(r'"primary_emotion"\s*:\s*"([^"]+)"', text)
                        if match:
                            payload["primary_emotion"] = match.group(1)
                        # Extract confidence
                        match = re.search(r'"confidence"\s*:\s*"([^"]+)"', text)
                        if match:
                            payload["confidence"] = match.group(1)
                        # Extract explanation (may be truncated)
                        match = re.search(r'"explanation"\s*:\s*"([^"]*)', text)
                        if match:
                            payload["explanation"] = match.group(1).rstrip('\\')
                        print(f"[TONE DEBUG] Regex extracted: {payload}")
                email.tone_emotion = payload.get("primary_emotion") or payload.get("emotion")
                email.tone_confidence = payload.get("confidence")
                email.tone_explanation = payload.get("explanation") or payload.get("brief_explanation")
                print(f"[TONE DEBUG] Extracted: emotion={email.tone_emotion}, confidence={email.tone_confidence}")
            elif ev == "url_scanned":
                # Handle case where payload is {'raw': '```json...```'}
                if isinstance(payload, dict) and "raw" in payload:
                    raw_text = payload["raw"]
                    payload = _try_parse_json_from_text(raw_text)
                    # If still got raw back, try regex extraction for truncated JSON
                    if isinstance(payload, dict) and "raw" in payload:
                        import re
                        text = payload["raw"]
                        # Extract verdict
                        match = re.search(r'"verdict"\s*:\s*"([^"]+)"', text)
                        if match:
                            payload["verdict"] = match.group(1)
                        # Extract threat_level
                        match = re.search(r'"threat_level"\s*:\s*"([^"]+)"', text)
                        if match:
                            payload["threat_level"] = match.group(1)
                        # Extract counts
                        match = re.search(r'"malicious_count"\s*:\s*(\d+)', text)
                        if match:
                            payload["malicious_count"] = int(match.group(1))
                        match = re.search(r'"suspicious_count"\s*:\s*(\d+)', text)
                        if match:
                            payload["suspicious_count"] = int(match.group(1))
                email.url_scan_verdict = payload.get("verdict")
                email.url_scan_threat_level = payload.get("threat_level")
                email.url_scan_malicious_count = payload.get("malicious_count")
                email.url_scan_suspicious_count = payload.get("suspicious_count")
                email.url_scan_summary = payload.get("summary")
                email.url_scan_details = payload.get("details")

            email.save()

            event_type = EVENT_TYPE_MAP.get(ev, ev)
            EmailEvent.objects.create(
                email=email,
                event_type=event_type,
                payload=payload,
            )

            # Fan out via Redis for SSE
            out = {
                "event_type": event_type,
                "email_id": email.id,
                "user_id": email.owner_id,
                "payload": payload,
            }
            r.publish(f"events:{email.owner_id}", json.dumps(out, ensure_ascii=False))

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message

        client.connect(host, port, keepalive=30)
        client.loop_forever()
