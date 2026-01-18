from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Email

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['id', 'username', 'password']

    def create(self, validated_data):
        user = User(username=validated_data['username'])
        user.set_password(validated_data['password'])
        user.save()
        return user


class EmailSerializer(serializers.ModelSerializer):
    sender_username = serializers.SerializerMethodField()

    class Meta:
        model = Email
        fields = [
            'id',
            'sender_username',
            'subject',
            'body',
            'created_at',
            'is_read',
            'spam_label',
            'spam_reason',
            'priority',
            'priority_reason',
            'summary',
            'action_items',
            'tone_emotion',
            'tone_confidence',
            'tone_explanation',
            'url_scan_verdict',
            'url_scan_threat_level',
            'url_scan_malicious_count',
            'url_scan_suspicious_count',
            'url_scan_summary',
            'url_scan_details',
        ]

    def get_sender_username(self, obj: Email):
        return obj.sender.username if obj.sender else None


class EmailCreateSerializer(serializers.Serializer):
    # Internal email system: choose recipient username
    recipient_username = serializers.CharField(max_length=150)
    subject = serializers.CharField(max_length=255)
    body = serializers.CharField()
