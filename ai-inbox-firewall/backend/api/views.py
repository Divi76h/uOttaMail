import json
import time
from typing import Iterable

import redis
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from .models import Email
from .serializers import RegisterSerializer, EmailSerializer, EmailCreateSerializer
from .solace_mqtt import publish_json, topic

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response({'id': user.id, 'username': user.username}, status=status.HTTP_201_CREATED)


@api_view(['GET', 'POST'])
def emails(request):
    if request.method == 'GET':
        qs = Email.objects.filter(owner=request.user).order_by('-created_at')
        return Response(EmailSerializer(qs, many=True).data)

    # POST: create a new internal email and ingest it as an event
    ser = EmailCreateSerializer(data=request.data)
    ser.is_valid(raise_exception=True)

    recipient_username = ser.validated_data['recipient_username']
    try:
        recipient = User.objects.get(username=recipient_username)
    except User.DoesNotExist:
        return Response({'detail': 'Recipient not found'}, status=status.HTTP_404_NOT_FOUND)

    email = Email.objects.create(
        owner=recipient,
        sender=request.user,
        subject=ser.validated_data['subject'],
        body=ser.validated_data['body'],
    )

    payload = {
        'id': email.id,
        'user_id': recipient.id,
        'sender_username': request.user.username,
        'subject': email.subject,
        'body': email.body,
        'created_at': email.created_at.isoformat(),
    }

    publish_json(topic('new', str(recipient.id), str(email.id)), payload, qos=0)

    return Response(EmailSerializer(email).data, status=status.HTTP_201_CREATED)


@api_view(['GET', 'PATCH'])
def email_detail(request, email_id: int):
    try:
        email = Email.objects.get(id=email_id, owner=request.user)
    except Email.DoesNotExist:
        return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PATCH':
        is_read = request.data.get('is_read')
        if isinstance(is_read, bool):
            email.is_read = is_read
            email.save(update_fields=['is_read'])
        return Response(EmailSerializer(email).data)

    return Response(EmailSerializer(email).data)


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def event_stream(request):
    # Simple SSE stream driven by Redis pubsub.
    # Frontend connects with Authorization header and keeps the connection open.
    token = request.GET.get('token')
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ', 1)[1]
    if not token:
        return JsonResponse({'detail': 'Missing token'}, status=401)

    # Let DRF/JWT auth validate the token by doing a cheap internal call.
    # Since this is plain Django view, we manually decode by importing SimpleJWT.
    from rest_framework_simplejwt.authentication import JWTAuthentication

    jwt_auth = JWTAuthentication()
    try:
        validated = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated)
    except Exception:
        return JsonResponse({'detail': 'Invalid token'}, status=401)

    r = redis.Redis.from_url(settings.REDIS_URL)
    channel = f"events:{user.id}"
    pubsub = r.pubsub()
    pubsub.subscribe(channel)

    def gen() -> Iterable[bytes]:
        # Initial ping
        yield _sse_format('connected', {'user_id': user.id}).encode('utf-8')
        last_ping = time.time()
        try:
            for msg in pubsub.listen():
                if msg['type'] != 'message':
                    continue
                try:
                    payload = json.loads(msg['data'].decode('utf-8'))
                except Exception:
                    payload = {'raw': msg['data'].decode('utf-8', errors='ignore')}

                yield _sse_format(payload.get('event_type', 'update'), payload).encode('utf-8')

                # Keep-alive comment every ~20s
                if time.time() - last_ping > 20:
                    yield b": ping\n\n"
                    last_ping = time.time()
        finally:
            pubsub.close()

    resp = StreamingHttpResponse(gen(), content_type='text/event-stream')
    resp['Cache-Control'] = 'no-cache'
    resp['X-Accel-Buffering'] = 'no'
    return resp
