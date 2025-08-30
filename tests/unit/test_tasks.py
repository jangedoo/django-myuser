"""
Unit tests for Celery tasks related to data export.
"""
import pytest
import os
from unittest.mock import patch, MagicMock
from django.conf import settings
from django.test import override_settings
from django.utils import timezone
from datetime import timedelta

from django_myuser.models import DataRequest, DataExportFile
from django_myuser.tasks import process_data_request, cleanup_expired_exports
from tests.factories import UserFactory, DataRequestFactory


@pytest.mark.django_db
class TestProcessDataRequestTask:
    """Test the process_data_request Celery task."""
    
    def test_process_export_request_success(self, tmp_path):
        """Test successful processing of an export request."""
        user = UserFactory()
        data_request = DataRequestFactory(
            user=user,
            request_type=DataRequest.RequestType.EXPORT,
            status=DataRequest.RequestStatus.PENDING
        )
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            with patch('django_myuser.tasks.send_async_email') as mock_email:
                result = process_data_request(data_request.id)
                
                assert "processed successfully" in result
                
                # Verify data request was updated
                data_request.refresh_from_db()
                assert data_request.status == DataRequest.RequestStatus.COMPLETED
                assert "Data export file created successfully" in data_request.notes
                
                # Verify export file was created
                assert hasattr(data_request, 'export_file')
                export_file = data_request.export_file
                assert export_file.file_path
                assert export_file.file_size > 0
                assert export_file.download_token
                
                # Verify physical file exists
                full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
                assert os.path.exists(full_path)
                
                # Verify email notification was sent
                assert mock_email.delay.called
    
    def test_process_delete_request_success(self):
        """Test processing of a delete request."""
        user = UserFactory()
        data_request = DataRequestFactory(
            user=user,
            request_type=DataRequest.RequestType.DELETE,
            status=DataRequest.RequestStatus.PENDING
        )
        
        with patch('django_myuser.tasks.send_async_email') as mock_email:
            result = process_data_request(data_request.id)
            
            assert "processed successfully" in result
            
            # Verify data request was updated
            data_request.refresh_from_db()
            assert data_request.status == DataRequest.RequestStatus.COMPLETED
            assert "Account deletion request processed" in data_request.notes
            
            # Verify email notification was sent
            assert mock_email.delay.called
    
    def test_process_nonexistent_request(self):
        """Test processing a non-existent request."""
        fake_uuid = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        result = process_data_request(fake_uuid)
        
        assert f"Data request {fake_uuid} not found" in result
    
    @patch('django_myuser.exporters.export_user_data')
    def test_process_request_export_failure(self, mock_export):
        """Test handling of export failure."""
        user = UserFactory()
        data_request = DataRequestFactory(
            user=user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        mock_export.side_effect = Exception("Export failed")
        
        with pytest.raises(Exception) as exc_info:
            process_data_request(data_request.id)
        
        assert "Export failed" in str(exc_info.value)
        
        # Verify request was marked as failed
        data_request.refresh_from_db()
        assert data_request.status == DataRequest.RequestStatus.FAILED
        assert "Processing failed: Export failed" in data_request.notes


@pytest.mark.django_db
class TestCleanupExpiredExportsTask:
    """Test the cleanup_expired_exports Celery task."""
    
    def test_cleanup_expired_files(self, tmp_path):
        """Test cleaning up expired export files."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            # Create an export file and make it expired
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path='test_exports/expired_file.zip',
                file_size=1024,
                expires_at=timezone.now() - timedelta(hours=1)
            )
            
            # Create physical file
            os.makedirs(os.path.dirname(os.path.join(settings.MEDIA_ROOT, export_file.file_path)), exist_ok=True)
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            with open(full_path, 'w') as f:
                f.write('test content')
            
            assert os.path.exists(full_path)
            assert export_file.deleted_at is None
            
            # Run cleanup
            result = cleanup_expired_exports()
            
            assert "Cleaned up 1 expired export files" in result
            
            # Verify file was deleted
            assert not os.path.exists(full_path)
            
            # Verify database record was soft deleted
            export_file.refresh_from_db()
            assert export_file.deleted_at is not None
    
    def test_cleanup_preserves_active_files(self, tmp_path):
        """Test that active files are not cleaned up."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            # Create a non-expired export file
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path='test_exports/active_file.zip',
                file_size=1024,
                expires_at=timezone.now() + timedelta(days=7)
            )
            
            # Create physical file
            os.makedirs(os.path.dirname(os.path.join(settings.MEDIA_ROOT, export_file.file_path)), exist_ok=True)
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            with open(full_path, 'w') as f:
                f.write('test content')
            
            # Run cleanup
            result = cleanup_expired_exports()
            
            assert "Cleaned up 0 expired export files" in result
            
            # Verify file still exists
            assert os.path.exists(full_path)
            
            # Verify database record is not deleted
            export_file.refresh_from_db()
            assert export_file.deleted_at is None
    
    def test_cleanup_handles_missing_files(self):
        """Test cleanup when physical files are missing."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        # Create expired export file record without physical file
        export_file = DataExportFile.objects.create(
            data_request=data_request,
            file_path='nonexistent/file.zip',
            file_size=1024,
            expires_at=timezone.now() - timedelta(hours=1)
        )
        
        # Run cleanup - should handle missing file gracefully
        result = cleanup_expired_exports()
        
        assert "Cleaned up 1 expired export files" in result
        
        # Verify database record was soft deleted
        export_file.refresh_from_db()
        assert export_file.deleted_at is not None
    
    def test_cleanup_error_handling(self, tmp_path):
        """Test cleanup error handling."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            # Create expired export file
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path='test_exports/error_file.zip',
                file_size=1024,
                expires_at=timezone.now() - timedelta(hours=1)
            )
            
            # Create physical file to test file deletion error
            os.makedirs(os.path.dirname(os.path.join(settings.MEDIA_ROOT, export_file.file_path)), exist_ok=True)
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            with open(full_path, 'w') as f:
                f.write('test content')
            
            # Mock os.remove to raise an exception
            with patch('os.remove') as mock_remove:
                mock_remove.side_effect = OSError("Permission denied")
                
                result = cleanup_expired_exports()
                
                # Should report error but continue
                assert "with 1 errors" in result
                
                # Database record should still be there since cleanup failed
                export_file.refresh_from_db()
                assert export_file.deleted_at is None