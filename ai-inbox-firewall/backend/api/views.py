import json
import time
import uuid
from typing import Iterable

import redis
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
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


@api_view(['GET'])
def action_items(request):
    """Get all action items across all emails for the current user."""
    emails_qs = Email.objects.filter(owner=request.user).exclude(action_items__isnull=True)
    
    all_items = []
    for email in emails_qs:
        items = email.action_items
        if not isinstance(items, list):
            continue
        for idx, item in enumerate(items):
            if isinstance(item, dict):
                all_items.append({
                    'email_id': email.id,
                    'email_subject': email.subject,
                    'sender_username': email.sender.username if email.sender else None,
                    'index': idx,
                    'text': item.get('text', ''),
                    'due': item.get('due'),
                    'assignee': item.get('assignee'),
                    'done': item.get('done', False),
                })
    
    return Response(all_items)


@api_view(['PATCH'])
def action_item_toggle(request, email_id: int, item_index: int):
    """Toggle the done status of an action item."""
    try:
        email = Email.objects.get(id=email_id, owner=request.user)
    except Email.DoesNotExist:
        return Response({'detail': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
    
    items = email.action_items
    if not isinstance(items, list) or item_index >= len(items):
        return Response({'detail': 'Action item not found'}, status=status.HTTP_404_NOT_FOUND)
    
    item = items[item_index]
    if isinstance(item, dict):
        item['done'] = not item.get('done', False)
        email.action_items = items
        email.save(update_fields=['action_items'])
    
    return Response({'done': item.get('done', False), 'email_id': email_id, 'index': item_index})


@api_view(['GET'])
def search_emails(request):
    """Search emails by text query (subject, body, sender, summary, action items).
    Also searches for individual words > 3 characters."""
    query = request.GET.get('q', '').strip()
    
    if not query:
        return Response([])
    
    # Build list of search terms: full query + individual words > 3 chars
    search_terms = [query]
    words = query.split()
    for word in words:
        word = word.strip()
        if len(word) > 3 and word not in search_terms:
            search_terms.append(word)
    
    # Build filter using Q objects for OR matching across multiple fields and terms
    combined_q = Q()
    for term in search_terms:
        combined_q |= (
            Q(subject__icontains=term) |
            Q(body__icontains=term) |
            Q(sender__username__icontains=term) |
            Q(summary__icontains=term) |
            Q(spam_reason__icontains=term) |
            Q(priority_reason__icontains=term) |
            Q(tone_explanation__icontains=term)
        )
    
    emails_qs = Email.objects.filter(owner=request.user).filter(combined_q).distinct().order_by('-created_at')[:50]
    
    return Response(EmailSerializer(emails_qs, many=True).data)


@api_view(['POST'])
def chat_query(request):
    """
    Send a natural language query to the EmailQueryAgent via Solace.
    Publishes to email/chat/{user_id}/{request_id} topic.
    Response comes back via SSE on email.chat_response event.
    """
    query = request.data.get('query', '').strip()
    
    if not query:
        return Response({'detail': 'Query is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Gather email context for the AI agent
    emails_qs = Email.objects.filter(owner=request.user).order_by('-created_at')[:20]
    emails_context = []
    for e in emails_qs:
        emails_context.append({
            'id': e.id,
            'subject': e.subject,
            'body': e.body[:500],  # Truncate body for context
            'sender': e.sender.username if e.sender else None,
            'spam_label': e.spam_label,
            'priority': e.priority,
            'summary': e.summary,
            'tone_emotion': e.tone_emotion,
            'action_items': e.action_items,
            'created_at': e.created_at.isoformat(),
        })
    
    # Generate a unique request ID
    request_id = str(uuid.uuid4())
    
    # Prepare payload for SAM agent
    payload = {
        'query': query,
        'emails': emails_context,
    }
    
    # Publish to chat topic - SAM gateway will route to EmailQueryAgent
    chat_topic = topic('chat', str(request.user.id), request_id)
    publish_json(chat_topic, payload, qos=0)
    
    print(f"[CHAT] Published query to {chat_topic}: {query[:50]}...")
    
    # Return immediately - response will come via SSE
    return Response({
        'status': 'processing',
        'request_id': request_id,
        'message': 'Query sent to AI assistant. Response will appear shortly.',
    })


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
