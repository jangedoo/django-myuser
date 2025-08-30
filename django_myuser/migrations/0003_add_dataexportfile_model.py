# Generated manually for DataExportFile model

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_myuser', '0002_auditlog'),
    ]

    operations = [
        migrations.CreateModel(
            name='DataExportFile',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('file_path', models.CharField(help_text='Path to the exported file relative to MEDIA_ROOT', max_length=500)),
                ('file_size', models.PositiveBigIntegerField(help_text='File size in bytes')),
                ('download_token', models.CharField(help_text='Secure token for file download', max_length=64, unique=True)),
                ('expires_at', models.DateTimeField(help_text='When the file expires and should be deleted')),
                ('download_count', models.PositiveIntegerField(default=0, help_text='Number of times file has been downloaded')),
                ('data_request', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='export_file', to='django_myuser.datarequest')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['download_token'], name='django_myus_downloa_79ae9e_idx'),
                    models.Index(fields=['expires_at'], name='django_myus_expires_c85b90_idx')
                ],
            },
        ),
    ]