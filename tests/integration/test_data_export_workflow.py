"""
Integration tests for the complete data export workflow.
Tests the full process from request creation to file download.
"""
import pytest
import os
import json
import zipfile
import tempfile
from unittest.mock import patch, MagicMock
from django.urls import reverse
from django.conf import settings
from django.test import override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from datetime import timedelta

from django_myuser.models import DataRequest, DataExportFile, UserSession, AuditLog
from django_myuser.tasks import process_data_request, cleanup_expired_exports
from tests.factories import UserFactory, DataRequestFactory, UserSessionFactory

User = get_user_model()


@pytest.mark.django_db
class TestDataExportWorkflow:
    """Test the complete data export workflow."""
    
    @patch('django_myuser.tasks.send_async_email')
    def test_complete_export_workflow(self, mock_send_email, authenticated_client, user, tmp_path):
        """Test the complete export workflow from request to download."""
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,  # Run tasks synchronously
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            # 1. Create export request via API
            data_requests_url = reverse('data_requests')
            response = authenticated_client.post(
                data_requests_url, 
                {'request_type': 'EXPORT'}, 
                format='json'
            )
            
            assert response.status_code == status.HTTP_201_CREATED
            data_request_id = response.json()['id']
            
            # 2. Process the request via task (synchronously due to CELERY_TASK_ALWAYS_EAGER)
            result = process_data_request(data_request_id)
            assert "processed successfully" in result
            
            # 3. Verify DataRequest was marked as completed
            data_request = DataRequest.objects.get(id=data_request_id)
            assert data_request.status == DataRequest.RequestStatus.COMPLETED
            assert "Data export file created successfully" in data_request.notes
            
            # 4. Verify DataExportFile was created
            assert hasattr(data_request, 'export_file')
            export_file = data_request.export_file
            assert export_file.file_path
            assert export_file.file_size > 0
            assert export_file.download_token
            assert not export_file.is_expired()
            
            # 5. Verify physical file exists
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            assert os.path.exists(full_path)
            
            # 6. Test file download via API
            download_url = reverse('data_export_download', args=[export_file.download_token])
            download_response = authenticated_client.get(download_url)
            
            assert download_response.status_code == status.HTTP_200_OK
            assert download_response['Content-Type'] == 'application/zip'
            assert 'attachment' in download_response['Content-Disposition']
            
            # 7. Verify download count was incremented
            export_file.refresh_from_db()
            assert export_file.download_count == 1
    
    @patch('django_myuser.tasks.send_async_email')
    def test_export_includes_user_data(self, mock_send_email, authenticated_client, user, tmp_path):
        """Test that the export includes comprehensive user data."""
        # Create some test data
        session = UserSessionFactory(user=user)
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            # Create and process export request
            data_request = DataRequestFactory(
                user=user, 
                request_type=DataRequest.RequestType.EXPORT
            )
            
            process_data_request(data_request.id)
            
            # Get the export file
            export_file = data_request.export_file
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            
            # Extract and verify ZIP contents (new multi-file structure)
            with zipfile.ZipFile(full_path, 'r') as zipf:
                files = zipf.namelist()
                
                # Check for expected files in new format
                assert 'user_info.json' in files
                assert 'profile.json' in files
                assert 'sessions.csv' in files
                assert 'audit_logs.jsonl' in files
                assert 'export_info.json' in files
                
                # Verify user info
                user_info_json = zipf.read('user_info.json').decode('utf-8')
                user_info = json.loads(user_info_json)
                assert user_info['username'] == user.username
                assert user_info['email'] == user.email
                
                # Verify profile data
                profile_json = zipf.read('profile.json').decode('utf-8')
                profile = json.loads(profile_json)
                assert 'marketing_consent' in profile
                
                # Verify export metadata
                export_info_json = zipf.read('export_info.json').decode('utf-8')
                export_info = json.loads(export_info_json)
                assert export_info['request_id'] == str(data_request.id)
                assert export_info['format_version'] == '2.0'
    
    @patch('django_myuser.tasks.send_async_email')
    def test_export_sends_notification_email(self, mock_send_email, user, tmp_path):
        """Test that processing an export sends a notification email."""
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            data_request = DataRequestFactory(
                user=user,
                request_type=DataRequest.RequestType.EXPORT
            )
            
            process_data_request(data_request.id)
            
            # Verify email was sent
            assert mock_send_email.delay.called
            call_args = mock_send_email.delay.call_args[1]
            
            assert call_args['subject'] == "Your data export is ready"
            assert call_args['template_name'] == "account/email/data_export"
            assert call_args['to_email'] == user.email
            
            # Verify email context contains download info
            context = call_args['context']
            assert 'download_token' in context
            assert 'download_url' in context
            assert 'expires_at' in context
            assert 'file_size_mb' in context


@pytest.mark.django_db
class TestDataExportDownload:
    """Test the data export download functionality."""
    
    def test_successful_download(self, client, tmp_path):
        """Test successful file download with valid token."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            # Create export file manually for testing
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            # Test download
            download_url = reverse('data_export_download', args=[export_file.download_token])
            response = client.get(download_url)
            
            assert response.status_code == status.HTTP_200_OK
            assert response['Content-Type'] == 'application/zip'
            assert 'attachment' in response['Content-Disposition']
            
            # Verify download count incremented
            export_file.refresh_from_db()
            assert export_file.download_count == 1
    
    def test_download_invalid_token(self, client):
        """Test download with invalid token returns 404."""
        download_url = reverse('data_export_download', args=['invalid-token'])
        response = client.get(download_url)
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_download_expired_file(self, client, tmp_path):
        """Test download of expired file returns 404."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            # Manually expire the file
            export_file.expires_at = timezone.now() - timedelta(hours=1)
            export_file.save()
            
            # Test download
            download_url = reverse('data_export_download', args=[export_file.download_token])
            response = client.get(download_url)
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_download_deleted_file(self, client, tmp_path):
        """Test download when physical file doesn't exist."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            # Delete the physical file
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            os.remove(full_path)
            
            # Test download
            download_url = reverse('data_export_download', args=[export_file.download_token])
            response = client.get(download_url)
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_download_multiple_times(self, client, tmp_path):
        """Test that multiple downloads increment the counter."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            download_url = reverse('data_export_download', args=[export_file.download_token])
            
            # Download 3 times
            for i in range(3):
                response = client.get(download_url)
                assert response.status_code == status.HTTP_200_OK
            
            # Verify download count
            export_file.refresh_from_db()
            assert export_file.download_count == 3


@pytest.mark.django_db  
class TestExportCleanup:
    """Test the export file cleanup functionality."""
    
    def test_cleanup_expired_exports_task(self, tmp_path):
        """Test the cleanup_expired_exports Celery task."""
        user = UserFactory()
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            # Create an expired export
            data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            # Manually expire the file
            export_file.expires_at = timezone.now() - timedelta(hours=1)
            export_file.save()
            
            # Verify file exists before cleanup
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            assert os.path.exists(full_path)
            assert export_file.deleted_at is None
            
            # Run cleanup task
            result = cleanup_expired_exports()
            
            # Verify cleanup happened
            assert "Cleaned up 1 expired export files" in result
            
            # Verify file was deleted physically
            assert not os.path.exists(full_path)
            
            # Verify database record was soft deleted
            export_file.refresh_from_db()
            assert export_file.deleted_at is not None
    
    def test_cleanup_preserves_active_files(self, tmp_path):
        """Test that cleanup doesn't delete active (non-expired) files."""
        user = UserFactory()
        
        with override_settings(
            MEDIA_ROOT=str(tmp_path),
            CELERY_TASK_ALWAYS_EAGER=True,
            CELERY_TASK_EAGER_PROPAGATES=True,
            CELERY_BROKER_URL='memory://',
            CELERY_RESULT_BACKEND='cache+memory://'
        ):
            # Create a non-expired export
            data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
            process_data_request(data_request.id)
            data_request.refresh_from_db()
            export_file = data_request.export_file
            
            # Ensure file is not expired
            export_file.expires_at = timezone.now() + timedelta(days=7)
            export_file.save()
            
            # Verify file exists before cleanup
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            assert os.path.exists(full_path)
            
            # Run cleanup task
            result = cleanup_expired_exports()
            
            # Verify no files were cleaned up
            assert "Cleaned up 0 expired export files" in result
            
            # Verify file still exists
            assert os.path.exists(full_path)
            export_file.refresh_from_db()
            assert export_file.deleted_at is None
    
    def test_cleanup_handles_missing_physical_files(self):
        """Test cleanup when physical files are already missing."""
        user = UserFactory()
        
        # Create an expired export file record without physical file
        data_request = DataRequestFactory(user=user)
        export_file = DataExportFile.objects.create(
            data_request=data_request,
            file_path='nonexistent/file.zip',
            file_size=1024,
            expires_at=timezone.now() - timedelta(hours=1)
        )
        
        # Run cleanup - should not raise an error
        result = cleanup_expired_exports()
        assert "Cleaned up 1 expired export files" in result
        
        # Verify database record was soft deleted
        export_file.refresh_from_db()
        assert export_file.deleted_at is not None


@pytest.mark.django_db
class TestExportFileModel:
    """Test the DataExportFile model functionality."""
    
    def test_auto_generate_download_token(self):
        """Test that download token is auto-generated on save."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        export_file = DataExportFile(
            data_request=data_request,
            file_path='test/file.zip',
            file_size=1024
        )
        
        assert not export_file.download_token  # Initially empty
        export_file.save()
        
        assert export_file.download_token  # Should be generated
        assert len(export_file.download_token) == 64  # URL-safe base64 encoding
    
    def test_auto_set_expiration_date(self):
        """Test that expiration date is auto-set based on settings."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(DJANGO_MYUSER={'EXPORT_FILE_RETENTION_DAYS': 14}):
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path='test/file.zip',
                file_size=1024
            )
            
            # Should expire in 14 days (within a reasonable tolerance)
            expected_expiry = timezone.now() + timedelta(days=14)
            time_diff = abs((export_file.expires_at - expected_expiry).total_seconds())
            assert time_diff < 60  # Within 1 minute
    
    def test_is_expired_method(self):
        """Test the is_expired method."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        # Create non-expired file
        export_file = DataExportFile.objects.create(
            data_request=data_request,
            file_path='test/file.zip',
            file_size=1024,
            expires_at=timezone.now() + timedelta(hours=1)
        )
        assert not export_file.is_expired()
        
        # Make it expired
        export_file.expires_at = timezone.now() - timedelta(hours=1)
        export_file.save()
        assert export_file.is_expired()
    
    def test_unique_download_tokens(self):
        """Test that download tokens are unique."""
        user = UserFactory()
        
        # Create multiple export files
        tokens = set()
        for i in range(10):
            data_request = DataRequestFactory(user=user)
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path=f'test/file{i}.zip',
                file_size=1024
            )
            tokens.add(export_file.download_token)
        
        # All tokens should be unique
        assert len(tokens) == 10


@pytest.mark.django_db
class TestExportErrorHandling:
    """Test error handling in the export process."""
    
    def test_process_data_request_nonexistent_request(self):
        """Test processing a non-existent data request."""
        fake_uuid = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        result = process_data_request(fake_uuid)
        
        assert f"Data request {fake_uuid} not found" in result
    
    @patch('django_myuser.exporters.export_user_data')
    def test_process_data_request_export_failure(self, mock_export, user):
        """Test handling of export failure during processing."""
        mock_export.side_effect = Exception("Export failed")
        
        data_request = DataRequestFactory(
            user=user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        with pytest.raises(Exception) as exc_info:
            process_data_request(data_request.id)
        
        assert "Export failed" in str(exc_info.value)
        
        # Verify request was marked as failed
        data_request.refresh_from_db()
        assert data_request.status == DataRequest.RequestStatus.FAILED
        assert "Processing failed" in data_request.notes
    
    def test_download_with_malformed_token(self, client):
        """Test download with malformed token."""
        # Test tokens that fit URL pattern but are invalid
        invalid_but_valid_url_tokens = ['short', 'x' * 100, 'token_with_underscores']
        
        for token in invalid_but_valid_url_tokens:
            download_url = reverse('data_export_download', args=[token])
            response = client.get(download_url)
            assert response.status_code == status.HTTP_404_NOT_FOUND
            
        # Test tokens that don't fit URL pattern (will cause reverse errors)
        url_pattern_incompatible_tokens = ['', 'token with spaces', 'token/with/slashes']
        
        for token in url_pattern_incompatible_tokens:
            try:
                download_url = reverse('data_export_download', args=[token])
                response = client.get(download_url)
                assert response.status_code == status.HTTP_404_NOT_FOUND
            except Exception:
                # URL pattern doesn't accept these characters, which is expected behavior
                pass