from django.conf import settings
from django.db import models


class Email(models.Model):
    PRIORITY_CHOICES = [
        ('urgent', 'Urgent'),
        ('normal', 'Normal'),
        ('low', 'Low'),
    ]

    SPAM_CHOICES = [
        ('spam', 'Spam'),
        ('newsletter', 'Newsletter'),
        ('legitimate', 'Legitimate'),
    ]

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='inbox_emails')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='sent_emails')

    subject = models.CharField(max_length=255)
    body = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    # Agent outputs
    spam_label = models.CharField(max_length=32, choices=SPAM_CHOICES, null=True, blank=True)
    spam_reason = models.TextField(null=True, blank=True)

    priority = models.CharField(max_length=16, choices=PRIORITY_CHOICES, null=True, blank=True)
    priority_reason = models.TextField(null=True, blank=True)

    summary = models.TextField(null=True, blank=True)
    action_items = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.id} | {self.subject}"


class EmailEvent(models.Model):
    EVENT_TYPES = [
        ('email.new', 'New Email'),
        ('email.spam_classified', 'Spam Classified'),
        ('email.priority_assigned', 'Priority Assigned'),
        ('email.summary', 'Summary'),
        ('email.action_items', 'Action Items'),
    ]

    email = models.ForeignKey(Email, on_delete=models.CASCADE, related_name='events')
    event_type = models.CharField(max_length=64, choices=EVENT_TYPES)
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.event_type} for email {self.email_id}"
