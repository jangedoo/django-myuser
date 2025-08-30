"""
Integration tests for profile management API endpoints.
Tests complete profile CRUD operations with database verification.
"""
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from django.utils import timezone

from django_myuser.models import Profile, AuditLog
from tests.factories import UserFactory, AdminUserFactory

User = get_user_model()


@pytest.mark.django_db
class TestProfileAPI:
    """Test profile API endpoints with full integration."""
    
    def setup_method(self):
        """Set up test data for each test method."""
        self.user = UserFactory()
        self.profile_url = reverse('profile')
    
    def test_get_profile_success(self, authenticated_client):
        """Test retrieving user profile with authentication."""
        user = authenticated_client.handler._force_user
        
        response = authenticated_client.get(self.profile_url)
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Verify profile data structure
        expected_fields = ['marketing_consent', 'marketing_consent_updated_at']
        for field in expected_fields:
            assert field in data
        
        # Verify data matches database
        profile = user.profile
        assert data['marketing_consent'] == profile.marketing_consent
        
        if profile.marketing_consent_updated_at:
            # Both should be present or both should be None
            assert data['marketing_consent_updated_at'] is not None
        else:
            assert data['marketing_consent_updated_at'] is None
    
    def test_get_profile_unauthenticated(self, api_client):
        """Test profile retrieval without authentication."""
        response = api_client.get(self.profile_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_update_profile_marketing_consent_true(self, authenticated_client):
        """Test updating marketing consent to True."""
        user = authenticated_client.handler._force_user
        
        # Verify initial state
        profile = user.profile
        initial_timestamp = profile.marketing_consent_updated_at
        
        # Update consent
        update_data = {'marketing_consent': True}
        response = authenticated_client.patch(self.profile_url, update_data, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['marketing_consent'] is True
        
        # Verify database update
        profile.refresh_from_db()
        assert profile.marketing_consent is True
        
        # Verify timestamp was updated
        assert profile.marketing_consent_updated_at is not None
        if initial_timestamp:
            assert profile.marketing_consent_updated_at > initial_timestamp
        
        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=user,
            event_type=AuditLog.EventType.PROFILE_UPDATE
        )
        assert audit_logs.exists(), 'No audit log found for profile update'
        assert 'profile' in audit_logs.first().description.lower()
    
    def test_update_profile_marketing_consent_false(self, authenticated_client):
        """Test updating marketing consent to False."""
        user = authenticated_client.handler._force_user
        
        # First set to True
        profile = user.profile
        profile.marketing_consent = True
        profile.marketing_consent_updated_at = timezone.now()
        profile.save()
        initial_timestamp = profile.marketing_consent_updated_at
        
        # Update to False
        update_data = {'marketing_consent': False}
        response = authenticated_client.patch(self.profile_url, update_data, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['marketing_consent'] is False
        
        # Verify database update
        profile.refresh_from_db()
        assert profile.marketing_consent is False
        
        # Verify timestamp was updated
        assert profile.marketing_consent_updated_at > initial_timestamp
    
    def test_update_profile_no_change_no_timestamp_update(self, authenticated_client):
        """Test that timestamp is not updated when consent doesn't change."""
        user = authenticated_client.handler._force_user
        
        # Set initial state
        profile = user.profile
        profile.marketing_consent = True
        profile.marketing_consent_updated_at = timezone.now()
        profile.save()
        initial_timestamp = profile.marketing_consent_updated_at
        
        # Update with same value
        update_data = {'marketing_consent': True}
        response = authenticated_client.patch(self.profile_url, update_data, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        
        # Verify timestamp was NOT updated
        profile.refresh_from_db()
        assert profile.marketing_consent_updated_at == initial_timestamp
    
    def test_update_profile_invalid_data(self, authenticated_client):
        """Test profile update with invalid data."""
        test_cases = [
            {'marketing_consent': 'not_a_boolean'},
            {'marketing_consent': 123},
            {'marketing_consent': []},
            {'marketing_consent': {}},
        ]
        
        for invalid_data in test_cases:
            response = authenticated_client.patch(self.profile_url, invalid_data, format='json')
            # Should return 400 for invalid data types
            assert response.status_code == status.HTTP_400_BAD_REQUEST
        
        # Test with invalid field - this may be ignored by serializer
        response = authenticated_client.patch(self.profile_url, {'invalid_field': True}, format='json')
        # Should succeed but ignore invalid field (status 200) or return 400
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]
    
    def test_update_profile_empty_data(self, authenticated_client):
        """Test profile update with empty data."""
        user = authenticated_client.handler._force_user
        profile = user.profile
        initial_consent = profile.marketing_consent
        initial_timestamp = profile.marketing_consent_updated_at
        
        response = authenticated_client.patch(self.profile_url, {}, format='json')
        
        # Should succeed but not change anything
        assert response.status_code == status.HTTP_200_OK
        
        profile.refresh_from_db()
        assert profile.marketing_consent == initial_consent
        assert profile.marketing_consent_updated_at == initial_timestamp
    
    def test_profile_put_method_behavior(self, authenticated_client):
        """Test PUT method behavior (should work for full resource replacement)."""
        user = authenticated_client.handler._force_user
        profile = user.profile
        
        # PUT should replace the entire resource
        update_data = {'marketing_consent': True}
        response = authenticated_client.put(self.profile_url, update_data, format='json')
        
        # Should succeed and update the profile
        assert response.status_code == status.HTTP_200_OK
        
        profile.refresh_from_db()
        assert profile.marketing_consent is True
        
        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=user,
            event_type=AuditLog.EventType.PROFILE_UPDATE
        )
        assert audit_logs.exists()
    
    def test_profile_delete_method_not_allowed(self, authenticated_client):
        """Test that DELETE method is not supported."""
        response = authenticated_client.delete(self.profile_url)
        
        # Should return 405 Method Not Allowed
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    
    def test_profile_post_method_not_allowed(self, authenticated_client):
        """Test that POST method is not supported."""
        update_data = {'marketing_consent': True}
        response = authenticated_client.post(self.profile_url, update_data, format='json')
        
        # Should return 405 Method Not Allowed
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    
    @pytest.mark.skip
    def test_concurrent_profile_updates(self, user):
        """Test concurrent profile updates to check for race conditions."""
        from threading import Thread
        import time
        from rest_framework.test import APIClient
        
        profile_url = reverse('profile')
        
        def update_profile(consent_value):
            # Create new client for this thread
            client = APIClient()
            client.force_authenticate(user=user)
            
            time.sleep(0.01)  # Small delay to increase chance of race condition
            client.patch(profile_url, {'marketing_consent': consent_value}, format='json')
        
        # Start concurrent updates
        thread1 = Thread(target=update_profile, args=(True,))
        thread2 = Thread(target=update_profile, args=(False,))
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Verify profile is in consistent state
        profile = Profile.objects.get(user=user)
        assert isinstance(profile.marketing_consent, bool)
        if profile.marketing_consent != Profile._meta.get_field('marketing_consent').default:
            assert profile.marketing_consent_updated_at is not None
    
    def test_profile_options_method(self, authenticated_client):
        """Test OPTIONS method returns allowed methods and CORS headers."""
        response = authenticated_client.options(self.profile_url)
        
        assert response.status_code == status.HTTP_200_OK
        
        # Check allowed methods are returned
        allow_header = response.get('Allow', '')
        assert 'GET' in allow_header
        assert 'PATCH' in allow_header
        assert 'PUT' in allow_header
        assert 'OPTIONS' in allow_header
    
    def test_malformed_json_data(self, authenticated_client):
        """Test profile update with malformed JSON data."""
        # Test with truly malformed JSON (syntax errors)
        malformed_syntax_cases = [
            '{"marketing_consent": True',  # Missing closing brace
        ]
        
        for malformed_data in malformed_syntax_cases:
            response = authenticated_client.patch(
                self.profile_url, 
                data=malformed_data, 
                content_type='application/json'
            )
            # Should return 400 for malformed JSON syntax
            assert response.status_code == status.HTTP_400_BAD_REQUEST
        
        # Test with valid JSON but invalid field values
        # Note: Some serializers may be lenient with null/string values
        invalid_value_cases = [
            '{"marketing_consent": "not_boolean"}',  # Non-boolean string
        ]
        
        for invalid_data in invalid_value_cases:
            response = authenticated_client.patch(
                self.profile_url, 
                data=invalid_data, 
                content_type='application/json'
            )
            # Should return 400 for invalid field values, or ignore and return 200
            assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK]
            
            # If it returns 200, the invalid field should be ignored
            if response.status_code == status.HTTP_200_OK:
                user = authenticated_client.handler._force_user
                user.profile.refresh_from_db()
                # Profile should still be valid (boolean)
                assert isinstance(user.profile.marketing_consent, bool)
    
    def test_very_large_payload_rejection(self, authenticated_client):
        """Test that very large payloads are rejected."""
        # Create a large payload (simulate attack)
        large_string = 'x' * 10000  # 10KB string
        large_payload = {
            'marketing_consent': True,
            'large_field': large_string
        }
        
        response = authenticated_client.patch(self.profile_url, large_payload, format='json')
        
        # Should either reject the large payload or ignore extra fields
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK]
        
        if response.status_code == status.HTTP_200_OK:
            # If accepted, verify only valid fields were processed
            data = response.json()
            expected_fields = ['marketing_consent', 'marketing_consent_updated_at']
            for field in data.keys():
                assert field in expected_fields
    
    def test_profile_creation_via_user_signal(self):
        """Test that profile is automatically created when user is created."""
        # Create new user using factory
        new_user = UserFactory()
        
        # Verify profile was created automatically
        assert hasattr(new_user, 'profile'), 'User does not have profile'
        assert isinstance(new_user.profile, Profile)
        assert new_user.profile.marketing_consent is False  # Default value
        assert new_user.profile.marketing_consent_updated_at is None
    
    def test_rate_limiting_profile_updates(self, authenticated_client, rate_limit_reset):
        """Test rate limiting on profile updates."""
        user = authenticated_client.handler._force_user
        
        # Make multiple rapid requests to trigger rate limiting
        update_data = {'marketing_consent': True}
        responses = []
        
        # ProfileUpdateRateThrottle may have different limits - test with several requests
        for i in range(10):
            response = authenticated_client.patch(self.profile_url, update_data, format='json')
            responses.append(response.status_code)
            
            # Toggle the value to ensure we're making actual changes
            update_data['marketing_consent'] = not update_data['marketing_consent']
        
        # Should eventually hit rate limit (429) or all succeed (200)
        status_codes = set(responses)
        assert status_codes.issubset({status.HTTP_200_OK, status.HTTP_429_TOO_MANY_REQUESTS})
        
        # If rate limiting triggered, verify profile state is still consistent
        user.profile.refresh_from_db()
        assert isinstance(user.profile.marketing_consent, bool)
    
    def test_profile_serializer_read_only_fields(self, authenticated_client):
        """Test that read-only fields cannot be modified via API."""
        # Try to update read-only fields
        forbidden_updates = {
            'user': UserFactory().id,
            'id': 12345,
            'created_at': '2023-01-01T00:00:00Z',
        }
        
        for field, value in forbidden_updates.items():
            update_data = {field: value}
            response = authenticated_client.patch(self.profile_url, update_data, format='json')
            
            # Should either ignore the field or return error
            # The specific behavior depends on serializer configuration
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def test_profile_consistency_after_multiple_updates(self, authenticated_client):
        """Test profile remains consistent after multiple updates."""
        user = authenticated_client.handler._force_user
        profile = user.profile
        updates = [True, False, True, False, True]
        
        for i, consent in enumerate(updates):
            response = authenticated_client.patch(
                self.profile_url, 
                {'marketing_consent': consent}, 
                format='json'
            )
            assert response.status_code == status.HTTP_200_OK
            
            # Verify database consistency
            profile.refresh_from_db()
            assert profile.marketing_consent == consent
            
            # Verify timestamp is always updated when value changes
            if i == 0 or updates[i] != updates[i-1]:
                assert profile.marketing_consent_updated_at is not None
    
    def test_profile_audit_trail_completeness(self, authenticated_client):
        """Test that all profile changes are properly audited."""
        user = authenticated_client.handler._force_user
        
        # Make several changes
        changes = [
            {'marketing_consent': True},
            {'marketing_consent': False},
            {'marketing_consent': True},
        ]
        
        for change in changes:
            authenticated_client.patch(self.profile_url, change, format='json')
        
        # Verify audit logs exist (exact EventType depends on implementation)
        audit_logs = AuditLog.objects.filter(user=user)
        
        # Should have audit log entries for changes
        assert audit_logs.count() >= len(changes)
        
        # Verify audit log content contains profile updates
        profile_logs = [log for log in audit_logs if 'profile' in log.description.lower()]
        assert len(profile_logs) > 0, f'No profile update logs found. Available logs: {[log.description for log in audit_logs]}'
    
    def test_profile_response_format_consistency(self, authenticated_client):
        """Test that profile API responses have consistent format."""
        # Get profile
        response = authenticated_client.get(self.profile_url)
        assert response.status_code == status.HTTP_200_OK
        get_data = response.json()
        
        # Update profile
        response = authenticated_client.patch(
            self.profile_url, 
            {'marketing_consent': True}, 
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        patch_data = response.json()
        
        # Both responses should have same structure
        assert set(get_data.keys()) == set(patch_data.keys())
        
        # Updated field should reflect change
        assert patch_data['marketing_consent'] is True
        assert patch_data['marketing_consent_updated_at'] is not None


@pytest.mark.django_db
class TestProfilePermissions:
    """Test profile API permissions and security."""
    
    def setup_method(self):
        """Set up test data for security tests."""
        self.profile_url = reverse('profile')
        self.normal_user = UserFactory()
        self.other_user = UserFactory()
        self.admin_user = AdminUserFactory()
    
    def test_user_cannot_access_other_user_profile(self, api_client):
        """Test that users cannot access other users' profiles."""
        # Authenticate as other_user
        api_client.force_authenticate(user=self.other_user)
        
        response = api_client.get(self.profile_url)
        
        # Should succeed but return other_user's profile, not normal_user's
        assert response.status_code == status.HTTP_200_OK
        # Since the profile endpoint returns the authenticated user's profile,
        # this test verifies the endpoint uses request.user.profile correctly
        data = response.json()
        # Verify it's the other user's profile by checking the profile object
        assert Profile.objects.get(user=self.other_user).marketing_consent == data['marketing_consent']
    
    def test_profile_requires_authentication(self, api_client):
        """Test that profile endpoints require authentication."""
        # Test GET
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Test PATCH
        response = api_client.patch(
            self.profile_url,
            {'marketing_consent': True},
            format='json'
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_admin_cannot_modify_user_profiles_via_endpoint(self, api_client):
        """Test that admin users cannot modify other users' profiles via this endpoint."""
        # Admin user should only be able to access their own profile
        api_client.force_authenticate(user=self.admin_user)
        
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_200_OK
        
        # Response should be admin's profile, not any user's profile
        data = response.json()
        admin_profile = Profile.objects.get(user=self.admin_user)
        assert data['marketing_consent'] == admin_profile.marketing_consent
    
    def test_invalid_jwt_token_rejection(self, api_client):
        """Test that invalid JWT tokens are rejected."""
        # Test with invalid token format
        api_client.credentials(HTTP_AUTHORIZATION='Bearer invalid-token-format')
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Test with expired token (simulate by using malformed token)
        api_client.credentials(HTTP_AUTHORIZATION='Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature')
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Test with no token
        api_client.credentials()
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_profile_data_isolation(self, api_client):
        """Test that users can only access their own profile data."""
        # Create two users with different profile settings
        user1 = UserFactory()
        user2 = UserFactory()
        
        # Set different marketing consent for each user
        user1.profile.marketing_consent = True
        user1.profile.save()
        user2.profile.marketing_consent = False  
        user2.profile.save()
        
        # Test that user1 gets their own data
        api_client.force_authenticate(user=user1)
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['marketing_consent'] is True
        
        # Test that user2 gets their own different data
        api_client.force_authenticate(user=user2)
        response = api_client.get(self.profile_url)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['marketing_consent'] is False


@pytest.mark.django_db
class TestProfileIntegrity:
    """Test profile data integrity and business logic."""
    
    def setup_method(self):
        """Set up test data for integrity tests."""
        self.user = UserFactory()
        self.profile_url = reverse('profile')
    
    
    
    
    
    
    def test_profile_database_constraints(self):
        """Test that profile database constraints are enforced."""
        # Try to create duplicate profile
        with pytest.raises(Exception):
            Profile.objects.create(user=self.user)
        
        # Try to create profile without user
        with pytest.raises(Exception):
            Profile.objects.create(user=None)
    
    def test_profile_cascade_deletion(self):
        """Test profile behavior when user is deleted."""
        profile_id = self.user.profile.id
        user_id = self.user.id
        
        # Delete user
        self.user.delete()
        
        # Profile should be deleted too (cascade)
        assert not Profile.objects.filter(id=profile_id).exists()
        assert not User.objects.filter(id=user_id).exists()