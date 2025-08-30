"""
Unit tests for Django MyUser models.
Tests model behavior, validation, and business logic in isolation.
"""
import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

from django_myuser.models import Profile, UserSession, DataRequest, AuditLog
from tests.factories import UserFactory, ProfileFactory, UserSessionFactory, DataRequestFactory

User = get_user_model()


@pytest.mark.django_db
class TestProfileModel:
    """Test Profile model functionality."""
    
    def test_profile_creation(self):
        """Test profile creation with default values."""
        user = UserFactory()
        
        # Check if profile already exists (created by signal)
        if hasattr(user, 'profile'):
            profile = user.profile
        else:
            profile = Profile.objects.create(user=user)
        
        assert profile.user == user
        assert profile.marketing_consent is False  # Default value
        assert profile.marketing_consent_updated_at is None
    
    def test_profile_str_representation(self):
        """Test profile string representation."""
        user = UserFactory()
        
        # Check if profile already exists (created by signal)
        if hasattr(user, 'profile'):
            profile = user.profile
        else:
            profile = Profile.objects.create(user=user)
            
        expected_str = user.username
        
        assert str(profile) == expected_str
    
    def test_profile_unique_constraint(self):
        """Test that each user can have only one profile."""
        user = UserFactory()
        
        # If profile doesn't exist, create first one
        if not hasattr(user, 'profile'):
            Profile.objects.create(user=user)
        
        # Creating second profile for same user should raise error
        with pytest.raises(Exception):
            Profile.objects.create(user=user)
    
    def test_marketing_consent_timestamp_update(self):
        """Test marketing consent timestamp behavior."""
        user = UserFactory()
        
        # Check if profile already exists for this user (created by signal)
        if hasattr(user, 'profile'):
            profile = user.profile
            profile.marketing_consent = False
            profile.marketing_consent_updated_at = None
            profile.save()
        else:
            profile = ProfileFactory(user=user, marketing_consent=False)
        
        # Initially no timestamp
        assert profile.marketing_consent_updated_at is None
        
        # Changing consent should set timestamp
        profile.marketing_consent = True
        profile.save()
        
        assert profile.marketing_consent_updated_at is not None
        first_timestamp = profile.marketing_consent_updated_at
        
        # Changing again should update timestamp
        profile.marketing_consent = False
        profile.save()
        
        assert profile.marketing_consent_updated_at > first_timestamp


@pytest.mark.django_db
class TestUserSessionModel:
    """Test UserSession model functionality."""
    
    def test_user_session_creation(self):
        """Test user session creation."""
        user = UserFactory()
        session = UserSession.objects.create(
            user=user,
            ip_address='192.168.1.1',
            user_agent='TestBrowser/1.0',
            refresh_token='test-token-123'
        )
        
        assert session.user == user
        assert session.ip_address == '192.168.1.1'
        assert session.user_agent == 'TestBrowser/1.0'
        assert session.refresh_token == 'test-token-123'
        assert session.created_at is not None
        assert session.last_activity is not None
    
    def test_user_session_str_representation(self):
        """Test user session string representation."""
        user = UserFactory()
        session = UserSessionFactory(user=user)
        expected_str = f"{user.username} - {session.ip_address}"
        
        assert str(session) == expected_str


@pytest.mark.django_db
class TestDataRequestModel:
    """Test DataRequest model functionality."""
    
    def test_data_request_creation(self):
        """Test data request creation with default values."""
        user = UserFactory()
        data_request = DataRequest.objects.create(
            user=user,
            request_type='EXPORT'
        )
        
        assert data_request.user == user
        assert data_request.request_type == 'EXPORT'
        assert data_request.status == 'PENDING'  # Default value
        assert data_request.created_at is not None
        # DataRequest doesn't have completed_at field (it's a BaseModel with created_at/updated_at)
        assert hasattr(data_request, 'created_at')
        assert hasattr(data_request, 'updated_at')


@pytest.mark.django_db
class TestAuditLogModel:
    """Test AuditLog model functionality."""
    
    def test_audit_log_creation(self):
        """Test audit log creation."""
        user = UserFactory()
        audit_log = AuditLog.objects.create(
            user=user,
            event_type=AuditLog.EventType.LOGIN,
            ip_address='192.168.1.1',
            user_agent='TestBrowser/1.0',
            description='User logged in successfully'
        )
        
        assert audit_log.user == user
        assert audit_log.event_type == AuditLog.EventType.LOGIN
        assert audit_log.ip_address == '192.168.1.1'
        assert audit_log.user_agent == 'TestBrowser/1.0'
        assert audit_log.description == 'User logged in successfully'
        assert audit_log.created_at is not None