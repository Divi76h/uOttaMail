# Generated migration for URL scan fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_add_tone_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='email',
            name='url_scan_verdict',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name='email',
            name='url_scan_threat_level',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name='email',
            name='url_scan_malicious_count',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='email',
            name='url_scan_suspicious_count',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='email',
            name='url_scan_summary',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='email',
            name='url_scan_details',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='emailevent',
            name='event_type',
            field=models.CharField(choices=[('email.new', 'New Email'), ('email.spam_classified', 'Spam Classified'), ('email.priority_assigned', 'Priority Assigned'), ('email.summary', 'Summary'), ('email.action_items', 'Action Items'), ('email.tone_analyzed', 'Tone Analyzed'), ('email.url_scanned', 'URL Scanned')], max_length=64),
        ),
    ]
