import json
import os
import time
from dataclasses import dataclass

import paho.mqtt.client as mqtt


@dataclass
class SolaceMqttConfig:
    host: str
    port: int
    username: str
    password: str
    topic_prefix: str


def get_config() -> SolaceMqttConfig:
    return SolaceMqttConfig(
        host=os.getenv('SOLACE_HOST', 'localhost'),
        port=int(os.getenv('SOLACE_MQTT_PORT', '1883')),
        username=os.getenv('SOLACE_USERNAME', 'default'),
        password=os.getenv('SOLACE_PASSWORD', 'default'),
        topic_prefix=os.getenv('TOPIC_PREFIX', 'email').strip('/'),
    )


def topic(*parts: str) -> str:
    cfg = get_config()
    clean = [p.strip('/').strip() for p in parts if p and p.strip('/').strip()]
    return '/'.join([cfg.topic_prefix] + clean)


def publish_json(topic_name: str, payload: dict, qos: int = 0) -> None:
    cfg = get_config()
    client_id = f"django-pub-{int(time.time()*1000)}"
    client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
    client.username_pw_set(cfg.username, cfg.password)

    client.connect(cfg.host, cfg.port, keepalive=30)
    client.loop_start()

    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    info = client.publish(topic_name, payload=data, qos=qos, retain=False)
    info.wait_for_publish(timeout=5)

    client.loop_stop()
    client.disconnect()
