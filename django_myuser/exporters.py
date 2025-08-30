import json
import csv
import zipfile
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from functools import cached_property
from typing import Dict, Any, List, Iterable, Optional, Callable, Union, Generator, Tuple, TYPE_CHECKING
from datetime import datetime, date

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model

if TYPE_CHECKING:
    from .models import DataRequest

User = get_user_model()


class ExportSerializer:
    """Utilities for serializing complex data types in exports."""
    
    @staticmethod
    def datetime_handler(obj: Any) -> str:
        """Handle datetime and date objects for JSON serialization."""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    @staticmethod
    def safe_json_handler(obj: Any) -> Any:
        """Safe JSON handler that converts most objects to strings."""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return str(obj)


class ExportBuilder:
    """
    Builder class for creating data export archives with support for large datasets.
    
    Provides a context manager interface for efficient file handling and supports
    multiple file formats (JSON, CSV, JSONL, raw files).
    """
    
    def __init__(self, user: 'User', export_dir: Path):
        self.user = user
        self.export_dir = export_dir
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.files: List[Tuple[str, Path]] = []
    
    def __enter__(self) -> 'ExportBuilder':
        """Create temporary directory for building the export."""
        self.temp_dir = tempfile.TemporaryDirectory()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up temporary directory."""
        if self.temp_dir:
            self.temp_dir.cleanup()
    
    @property
    def temp_path(self) -> Path:
        """Get the temporary directory path."""
        if not self.temp_dir:
            raise RuntimeError("ExportBuilder must be used as a context manager")
        return Path(self.temp_dir.name)
    
    def add_json_file(
        self, 
        filename: str, 
        data: Any, 
        serializer: Optional[Callable[[Any], Any]] = None,
        indent: int = 2
    ) -> None:
        """
        Add JSON data to the export.
        
        Args:
            filename: Name of the file in the archive
            data: Data to serialize as JSON
            serializer: Custom serialization function for complex objects
            indent: JSON indentation level
        """
        file_path = self.temp_path / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(
                data, 
                f, 
                indent=indent, 
                default=serializer or ExportSerializer.safe_json_handler,
                ensure_ascii=False
            )
        
        self.files.append((filename, file_path))
    
    def add_csv_file(
        self, 
        filename: str, 
        rows: Iterable[Dict[str, Any]], 
        headers: Optional[List[str]] = None
    ) -> None:
        """
        Add CSV data to the export.
        
        Args:
            filename: Name of the CSV file
            rows: Iterable of dictionaries (supports generators for large datasets)
            headers: Optional list of column headers
        """
        file_path = self.temp_path / filename
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = None
            
            for row in rows:
                if writer is None:
                    # Initialize writer with headers from first row
                    fieldnames = headers or list(row.keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                
                # Convert complex objects to strings
                safe_row = {
                    k: v.isoformat() if isinstance(v, (datetime, date)) else str(v) if v is not None else ''
                    for k, v in row.items()
                }
                writer.writerow(safe_row)
        
        self.files.append((filename, file_path))
    
    def add_jsonl_file(
        self, 
        filename: str, 
        items: Iterable[Any], 
        serializer: Optional[Callable[[Any], Any]] = None
    ) -> None:
        """
        Add JSON Lines file for streaming large datasets.
        
        Args:
            filename: Name of the JSONL file
            items: Iterable of items to serialize (supports generators)
            serializer: Custom serialization function
        """
        file_path = self.temp_path / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in items:
                json.dump(
                    item, 
                    f, 
                    default=serializer or ExportSerializer.safe_json_handler,
                    ensure_ascii=False
                )
                f.write('\n')
        
        self.files.append((filename, file_path))
    
    def add_raw_file(self, filename: str, content: Union[str, bytes]) -> None:
        """
        Add raw text or binary file to the export.
        
        Args:
            filename: Name of the file
            content: File content as string or bytes
        """
        file_path = self.temp_path / filename
        
        mode = 'wb' if isinstance(content, bytes) else 'w'
        encoding = None if isinstance(content, bytes) else 'utf-8'
        
        with open(file_path, mode, encoding=encoding) as f:
            f.write(content)
        
        self.files.append((filename, file_path))
    
    def create_archive(self, filename_prefix: str = 'export') -> str:
        """
        Create final ZIP archive and return relative path.
        
        Args:
            filename_prefix: Prefix for the archive filename
            
        Returns:
            str: Path to the ZIP file (relative to MEDIA_ROOT)
        """
        if not self.files:
            raise ValueError("No files added to export")
        
        # Create unique filename
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        zip_filename = f"{filename_prefix}_{self.user.id}_{timestamp}.zip"
        zip_path = self.export_dir / zip_filename
        
        # Create ZIP archive
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for archive_name, file_path in self.files:
                zipf.write(file_path, archive_name)
        
        # Return relative path
        config = getattr(settings, 'DJANGO_MYUSER', {})
        export_path = config.get('EXPORT_FILE_PATH', 'data_exports')
        return f"{export_path.rstrip('/')}/{zip_filename}"


class UserDataExporter(ABC):
    """
    Abstract base class for user data exporters.
    
    Subclass this to create custom data exporters for your application.
    Provides efficient utilities for handling large datasets and multiple file formats.
    """
    
    @cached_property
    def export_directory(self) -> Path:
        """Get the export directory path (computed once and cached)."""
        config = getattr(settings, 'DJANGO_MYUSER', {})
        export_path = config.get('EXPORT_FILE_PATH', 'data_exports')
        full_path = Path(settings.MEDIA_ROOT) / export_path
        full_path.mkdir(parents=True, exist_ok=True)
        return full_path
    
    @abstractmethod
    def generate_data(self, data_request: 'DataRequest', user: 'User') -> str:
        """
        Generate user data export file.
        
        Args:
            data_request: DataRequest instance
            user: User instance
            
        Returns:
            str: Path to the generated file (relative to MEDIA_ROOT)
        """
        pass
    
    def create_export_builder(self, user: 'User') -> ExportBuilder:
        """Create an export builder for the given user."""
        return ExportBuilder(user, self.export_directory)


class DefaultUserDataExporter(UserDataExporter):
    """
    Default implementation of UserDataExporter with efficient data handling.
    
    Exports django-myuser data using multiple file formats:
    - User and profile info as JSON
    - Sessions as CSV for efficiency
    - Audit logs as JSONL for large datasets
    """
    
    def generate_data(self, data_request: 'DataRequest', user: 'User') -> str:
        """
        Generate default user data export using chunked processing.
        
        Args:
            data_request: DataRequest instance
            user: User instance
            
        Returns:
            str: Path to the generated ZIP file
        """
        with self.create_export_builder(user) as builder:
            # Add user info as JSON
            builder.add_json_file('user_info.json', self.get_user_info(user))
            
            # Add profile data
            builder.add_json_file('profile.json', self.get_profile_data(user))
            
            # Stream sessions to CSV for efficiency
            builder.add_csv_file('sessions.csv', self.iter_sessions(user))
            
            # Stream audit logs to JSONL for large datasets
            builder.add_jsonl_file('audit_logs.jsonl', self.iter_audit_logs(user))
            
            # Add export metadata
            builder.add_json_file('export_info.json', {
                'request_id': str(data_request.id),
                'request_date': data_request.created_at.isoformat(),
                'export_date': timezone.now().isoformat(),
                'format_version': '2.0'
            })
            
            return builder.create_archive('user_export')
    
    def get_user_info(self, user: 'User') -> Dict[str, Any]:
        """Get basic user information."""
        return {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': user.date_joined,
            'last_login': user.last_login,
        }
    
    def get_profile_data(self, user: 'User') -> Dict[str, Any]:
        """Get user profile information."""
        if not hasattr(user, 'profile'):
            return {}
            
        profile = user.profile
        return {
            'marketing_consent': profile.marketing_consent,
            'marketing_consent_updated_at': profile.marketing_consent_updated_at,
        }
    
    def iter_sessions(self, user: 'User') -> Generator[Dict[str, Any], None, None]:
        """Generate session data in chunks to handle large datasets efficiently."""
        from .models import UserSession
        
        # Use iterator() for memory efficiency with large datasets
        sessions = user.usersession_set.all()
        for session in sessions.iterator(chunk_size=100):
            yield {
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'last_activity': session.last_activity,
                'created_at': session.created_at,
            }
    
    def iter_audit_logs(self, user: 'User') -> Generator[Dict[str, Any], None, None]:
        """Generate audit log data in chunks to handle large datasets efficiently."""
        from .models import AuditLog
        
        # Use iterator() for memory efficiency - don't limit to 100 anymore
        logs = user.auditlog_set.all()
        for log in logs.iterator(chunk_size=500):
            yield {
                'event_type': log.event_type,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'description': log.description,
                'created_at': log.created_at,
                'extra_data': log.extra_data,
            }


def get_exporter_class():
    """
    Get the configured exporter class.
    
    Returns:
        class: UserDataExporter subclass
    """
    config = getattr(settings, 'DJANGO_MYUSER', {})
    exporter_path = config.get('DATA_EXPORTER_CLASS', 'django_myuser.exporters.DefaultUserDataExporter')
    
    try:
        from django.utils.module_loading import import_string
        return import_string(exporter_path)
    except (ImportError, AttributeError) as e:
        raise ImportError(
            f"Could not import data exporter class '{exporter_path}'. "
            f"Make sure the class exists and is properly configured in DJANGO_MYUSER settings. "
            f"Error: {e}"
        )


def export_user_data(data_request: 'DataRequest', user: 'User') -> str:
    """
    Export user data using the configured exporter.
    
    Args:
        data_request: DataRequest instance
        user: User instance
        
    Returns:
        str: Path to the exported file
    """
    exporter_class = get_exporter_class()
    exporter = exporter_class()
    return exporter.generate_data(data_request, user)