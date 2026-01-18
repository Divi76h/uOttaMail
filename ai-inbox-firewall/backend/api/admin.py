from django.contrib import admin

from .models import Email, EmailEvent


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'sender', 'subject', 'created_at', 'is_read', 'spam_label', 'priority')
    list_filter = ('is_read', 'spam_label', 'priority')
    search_fields = ('subject', 'body')


@admin.register(EmailEvent)
class EmailEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'event_type', 'created_at')
    list_filter = ('event_type',)
    search_fields = ('email__subject',)
