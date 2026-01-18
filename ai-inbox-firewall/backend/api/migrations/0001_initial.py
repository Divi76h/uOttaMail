# Generated manually for the starter template

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Email',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject', models.CharField(max_length=255)),
                ('body', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('spam_label', models.CharField(blank=True, choices=[('spam', 'Spam'), ('newsletter', 'Newsletter'), ('legitimate', 'Legitimate')], max_length=32, null=True)),
                ('spam_reason', models.TextField(blank=True, null=True)),
                ('priority', models.CharField(blank=True, choices=[('urgent', 'Urgent'), ('normal', 'Normal'), ('low', 'Low')], max_length=16, null=True)),
                ('priority_reason', models.TextField(blank=True, null=True)),
                ('summary', models.TextField(blank=True, null=True)),
                ('action_items', models.JSONField(blank=True, null=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='inbox_emails', to=settings.AUTH_USER_MODEL)),
                ('sender', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sent_emails', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='EmailEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(choices=[('email.new', 'New Email'), ('email.spam_classified', 'Spam Classified'), ('email.priority_assigned', 'Priority Assigned'), ('email.summary', 'Summary'), ('email.action_items', 'Action Items')], max_length=64)),
                ('payload', models.JSONField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='events', to='api.email')),
            ],
        ),
    ]
