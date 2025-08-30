"""
Unit tests for data exporter functionality.
Tests the exporter classes and their integration.
"""
import pytest
import os
import json
import zipfile
import tempfile
from unittest.mock import patch, MagicMock
from django.conf import settings
from django.test import override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from django_myuser.models import DataRequest, DataExportFile
from django_myuser.exporters import (
    UserDataExporter, 
    DefaultUserDataExporter, 
    get_exporter_class,
    export_user_data
)
from tests.factories import UserFactory, DataRequestFactory

User = get_user_model()


@pytest.mark.django_db
class TestUserDataExporter:
    """Test the abstract UserDataExporter base class."""
    
    def test_cannot_instantiate_abstract_class(self):
        """Test that UserDataExporter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            UserDataExporter()
    
    def test_export_directory_creates_directory(self, tmp_path):
        """Test that export_directory property creates the directory if it doesn't exist."""
        # Create a concrete implementation for testing
        class TestExporter(UserDataExporter):
            def generate_data(self, data_request, user):
                return "test_file.zip"
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            exporter = TestExporter()
            export_dir = exporter.export_directory
            
            assert os.path.exists(export_dir)
            assert export_dir.name == 'data_exports'
    
    def test_export_builder_creates_archive(self, tmp_path):
        """Test that ExportBuilder creates a proper archive with multiple files."""
        class TestExporter(UserDataExporter):
            def generate_data(self, data_request, user):
                with self.create_export_builder(user) as builder:
                    # Add test data
                    builder.add_json_file('user_info.json', {'username': user.username})
                    builder.add_raw_file('test.txt', 'test content')
                    return builder.create_archive('test_export')
        
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            exporter = TestExporter()
            zip_path = exporter.generate_data(data_request, user)
            
            # Check file was created
            full_path = os.path.join(settings.MEDIA_ROOT, zip_path)
            assert os.path.exists(full_path)
            
            # Check ZIP contents
            with zipfile.ZipFile(full_path, 'r') as zipf:
                files = zipf.namelist()
                assert 'user_info.json' in files
                assert 'test.txt' in files
                
                # Check JSON data
                user_data_json = zipf.read('user_info.json').decode('utf-8')
                loaded_data = json.loads(user_data_json)
                assert loaded_data['username'] == user.username
                
                # Check text file
                text_content = zipf.read('test.txt').decode('utf-8')
                assert text_content == 'test content'


@pytest.mark.django_db
class TestDefaultUserDataExporter:
    """Test the DefaultUserDataExporter implementation."""
    
    def test_generate_data_creates_zip_file(self, tmp_path):
        """Test that generate_data creates a proper ZIP file with new format."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user, request_type=DataRequest.RequestType.EXPORT)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            exporter = DefaultUserDataExporter()
            zip_path = exporter.generate_data(data_request, user)
            
            # Check file exists
            full_path = os.path.join(settings.MEDIA_ROOT, zip_path)
            assert os.path.exists(full_path)
            
            # Check ZIP contents with new file structure
            with zipfile.ZipFile(full_path, 'r') as zipf:
                files = zipf.namelist()
                
                # Should contain multiple files in new format
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
                
                # Verify export info
                export_info_json = zipf.read('export_info.json').decode('utf-8')
                export_info = json.loads(export_info_json)
                assert export_info['request_id'] == str(data_request.id)
                assert export_info['format_version'] == '2.0'
    


@pytest.mark.django_db
class TestExporterIntegration:
    """Test exporter integration functions."""
    
    def test_get_exporter_class_default(self):
        """Test getting the default exporter class."""
        exporter_class = get_exporter_class()
        assert exporter_class == DefaultUserDataExporter
    
    @override_settings(DJANGO_MYUSER={'DATA_EXPORTER_CLASS': 'django_myuser.exporters.DefaultUserDataExporter'})
    def test_get_exporter_class_configured(self):
        """Test getting a configured exporter class."""
        exporter_class = get_exporter_class()
        assert exporter_class == DefaultUserDataExporter
    
    @override_settings(DJANGO_MYUSER={'DATA_EXPORTER_CLASS': 'nonexistent.module.Class'})
    def test_get_exporter_class_invalid_import(self):
        """Test handling of invalid exporter class configuration."""
        with pytest.raises(ImportError) as exc_info:
            get_exporter_class()
        
        assert "Could not import data exporter class" in str(exc_info.value)
    
    def test_export_user_data_function(self, tmp_path):
        """Test the export_user_data utility function."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            zip_path = export_user_data(data_request, user)
            
            assert isinstance(zip_path, str)
            assert zip_path.endswith('.zip')
            
            # Check file exists
            full_path = os.path.join(settings.MEDIA_ROOT, zip_path)
            assert os.path.exists(full_path)


@pytest.mark.django_db
class TestCustomExporter:
    """Test custom exporter implementation."""
    
    def test_custom_exporter_can_extend_base_data(self, tmp_path):
        """Test that a custom exporter can extend the base user data using ExportBuilder."""
        
        class CustomExporter(UserDataExporter):
            def generate_data(self, data_request, user):
                with self.create_export_builder(user) as builder:
                    # Add user info
                    builder.add_json_file('user_info.json', {'username': user.username})
                    
                    # Add custom data
                    builder.add_json_file('custom_data.json', {
                        'custom_field': 'custom_value',
                        'computed_data': f"User {user.username} export"
                    })
                    
                    return builder.create_archive('custom_export')
        
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            exporter = CustomExporter()
            zip_path = exporter.generate_data(data_request, user)
            
            # Verify custom data was added
            full_path = os.path.join(settings.MEDIA_ROOT, zip_path)
            with zipfile.ZipFile(full_path, 'r') as zipf:
                files = zipf.namelist()
                assert 'user_info.json' in files
                assert 'custom_data.json' in files
                
                # Check user info
                user_info_json = zipf.read('user_info.json').decode('utf-8')
                user_info = json.loads(user_info_json)
                assert user_info['username'] == user.username
                
                # Check custom data
                custom_data_json = zipf.read('custom_data.json').decode('utf-8')
                custom_data = json.loads(custom_data_json)
                assert custom_data['custom_field'] == 'custom_value'
                assert custom_data['computed_data'] == f"User {user.username} export"
    
    @override_settings(DJANGO_MYUSER={'DATA_EXPORTER_CLASS': 'tests.unit.test_exporters.TestCustomExporter'})
    def test_custom_exporter_via_settings(self, tmp_path):
        """Test using a custom exporter via Django settings."""
        
        # Define a simple custom exporter
        def custom_generate_data(self, data_request, user):
            with self.create_export_builder(user) as builder:
                builder.add_json_file('user_info.json', {'test': 'data', 'custom': True})
                return builder.create_archive('settings_export')
        
        # Create the exporter class
        globals()['TestCustomExporter'] = type('TestCustomExporter', (UserDataExporter,), {
            'generate_data': custom_generate_data
        })
        
        try:
            user = UserFactory()
            data_request = DataRequestFactory(user=user)
            
            with override_settings(MEDIA_ROOT=str(tmp_path)):
                zip_path = export_user_data(data_request, user)
                
                # Verify custom exporter was used
                full_path = os.path.join(settings.MEDIA_ROOT, zip_path)
                with zipfile.ZipFile(full_path, 'r') as zipf:
                    user_data_json = zipf.read('user_info.json').decode('utf-8')
                    loaded_data = json.loads(user_data_json)
                    
                    assert loaded_data['custom'] is True
                    assert loaded_data['test'] == 'data'
        finally:
            # Clean up the global namespace
            if 'TestCustomExporter' in globals():
                del globals()['TestCustomExporter']


@pytest.mark.django_db
class TestExporterConfiguration:
    """Test exporter configuration options."""
    
    @override_settings(DJANGO_MYUSER={
        'EXPORT_FILE_PATH': 'custom_exports',
        'EXPORT_FILE_RETENTION_DAYS': 14
    })
    def test_custom_export_path_and_retention(self, tmp_path):
        """Test custom export path and retention settings."""
        user = UserFactory()
        data_request = DataRequestFactory(user=user)
        
        with override_settings(MEDIA_ROOT=str(tmp_path)):
            exporter = DefaultUserDataExporter()
            zip_path = exporter.generate_data(data_request, user)
            
            # Check path uses custom directory
            assert zip_path.startswith('custom_exports/')
            
            # Check directory was created
            custom_dir = os.path.join(settings.MEDIA_ROOT, 'custom_exports')
            assert os.path.exists(custom_dir)
    
    def test_default_configuration_values(self, tmp_path):
        """Test that default configuration values are used when not specified."""
        user = UserFactory()
        
        with override_settings(MEDIA_ROOT=str(tmp_path), DJANGO_MYUSER={}):
            exporter = DefaultUserDataExporter()
            export_dir = exporter.export_directory
            
            # Should use default path
            assert export_dir.name == 'data_exports'