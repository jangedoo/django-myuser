"""
Integration tests for authentication API endpoints.
Tests the complete JWT authentication flow with real database operations.
"""
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from django_myuser.models import UserSession, AuditLog
from tests.factories import UserFactory

User = get_user_model()


@pytest.mark.django_db
@pytest.mark.usefixtures('rate_limit_reset')
class TestAuthenticationAPI:
    """Test JWT authentication API endpoints with full integration."""
    
    def setup_method(self):
        """Set up test data for each test method."""
        self.user = UserFactory()
        self.user.set_password('TestPassword123!')
        self.user.save()
        
        self.valid_credentials = {
            'username': self.user.username,
            'password': 'TestPassword123!'
        }
        self.invalid_credentials = {
            'username': self.user.username,
            'password': 'wrongpassword'
        }
    
    def test_token_obtain_success(self, api_client):
        """Test successful token obtain with valid credentials."""
        url = reverse('token_obtain_pair')
        
        response = api_client.post(url, self.valid_credentials, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'access' in data
        assert 'refresh' in data
        
        # Verify tokens are valid
        access_token = data['access']
        refresh_token = data['refresh']
        
        # Test access token works
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        profile_response = api_client.get(reverse('profile'))
        assert profile_response.status_code == status.HTTP_200_OK
        
        # Verify user session was created
        user_sessions = UserSession.objects.filter(user=self.user)
        assert user_sessions.exists(), 'No session found for user after login'
        
        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(
            user=self.user, 
            event_type=AuditLog.EventType.LOGIN
        )
        assert audit_logs.exists(), 'No audit log found for successful login'
    
    def test_token_obtain_invalid_credentials(self, api_client):
        """Test token obtain with invalid credentials."""
        url = reverse('token_obtain_pair')
        
        response = api_client.post(url, self.invalid_credentials, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Verify no session was created
        user_sessions = UserSession.objects.filter(user=self.user)
        assert not user_sessions.exists(), 'Session should not be created for failed login'
        
        # Verify failed login was logged (user=None for failed attempts)
        audit_logs = AuditLog.objects.filter(
            user__isnull=True,
            event_type=AuditLog.EventType.LOGIN_FAILED
        )
        assert audit_logs.exists(), 'No audit log found for failed login'
    
    def test_token_obtain_missing_fields(self, api_client):
        """Test token obtain with missing required fields."""
        url = reverse('token_obtain_pair')
        
        test_cases = [
            {},  # Empty data
            {'username': 'testuser'},  # Missing password
            {'password': 'TestPassword123!'},  # Missing username
        ]
        
        for credentials in test_cases:
            response = api_client.post(url, credentials, format='json')
            assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_token_refresh_success(self, api_client):
        """Test successful token refresh with valid refresh token."""
        # First obtain tokens
        url = reverse('token_obtain_pair')
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        refresh_token = tokens['refresh']
        
        # Now refresh the token
        refresh_url = reverse('token_refresh')
        response = api_client.post(refresh_url, {'refresh': refresh_token}, format='json')
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'access' in data
        
        # Verify new access token works
        new_access_token = data['access']
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        profile_response = api_client.get(reverse('profile'))
        assert profile_response.status_code == status.HTTP_200_OK
    
    def test_token_refresh_invalid_token(self, api_client):
        """Test token refresh with invalid refresh token."""
        refresh_url = reverse('token_refresh')
        
        test_cases = [
            {'refresh': 'invalid_token'},
            {'refresh': ''},
            {},  # No refresh token
        ]
        
        for data in test_cases:
            response = api_client.post(refresh_url, data, format='json')
            assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
    
    def test_token_verify_success(self, api_client):
        """Test successful token verification."""
        # Obtain access token
        url = reverse('token_obtain_pair')
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        access_token = tokens['access']
        
        # Verify token
        verify_url = reverse('token_verify')
        response = api_client.post(verify_url, {'token': access_token}, format='json')
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_token_verify_invalid_token(self, api_client):
        """Test token verification with invalid token."""
        verify_url = reverse('token_verify')
        
        test_cases = [
            {'token': 'invalid_token'},
            {'token': ''},
            {},  # No token
        ]
        
        for data in test_cases:
            response = api_client.post(verify_url, data, format='json')
            assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
    
    def test_logout_success(self, api_client):
        """Test successful logout with token blacklisting."""
        # First login
        url = reverse('token_obtain_pair')
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        refresh_token = tokens['refresh']
        access_token = tokens['access']
        
        # Authenticate for logout
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Logout
        logout_url = reverse('logout')
        response = api_client.post(logout_url, {'refresh': refresh_token}, format='json')
        
        # Verify logout response
        assert response.status_code == status.HTTP_205_RESET_CONTENT
        
        # Verify token is blacklisted - try to use the refresh token again
        from rest_framework_simplejwt.exceptions import TokenError
        try:
            # This should raise TokenError if token is blacklisted
            RefreshToken(refresh_token)
            # If we reach here, check if it's blacklisted in the database
            refresh_obj = RefreshToken(refresh_token)
            assert BlacklistedToken.objects.filter(token__token=refresh_obj.token).exists(), \
                'Refresh token should be blacklisted after logout'
        except TokenError:
            # Expected behavior - token is invalid/blacklisted
            pass
        
        # Verify session was removed
        user_sessions = UserSession.objects.filter(user=self.user, refresh_token=refresh_token)
        assert not user_sessions.exists(), 'Session should be removed after logout'
        
        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            event_type=AuditLog.EventType.LOGOUT
        )
        assert audit_logs.exists(), 'No audit log found for logout'
    
    def test_logout_invalid_refresh_token(self, api_client):
        """Test logout with invalid refresh token."""
        # Create authenticated user
        api_client.force_authenticate(user=self.user)
        
        logout_url = reverse('logout')
        response = api_client.post(logout_url, {'refresh': 'invalid_token'}, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_logout_unauthenticated(self, api_client):
        """Test logout without authentication."""
        logout_url = reverse('logout')
        response = api_client.post(logout_url, {'refresh': 'some_token'}, format='json')
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_protected_endpoint_without_authentication(self, api_client):
        """Test accessing protected endpoint without authentication."""
        profile_url = reverse('profile')
        response = api_client.get(profile_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_protected_endpoint_with_invalid_token(self, api_client):
        """Test accessing protected endpoint with invalid token."""
        profile_url = reverse('profile')
        api_client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = api_client.get(profile_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_multiple_concurrent_logins(self, api_client):
        """Test multiple concurrent login sessions."""
        url = reverse('token_obtain_pair')
        
        # Login multiple times
        sessions = []
        for i in range(3):
            response = api_client.post(url, self.valid_credentials, format='json')
            assert response.status_code == status.HTTP_200_OK
            tokens = response.json()
            sessions.append(tokens)
        
        # Verify all sessions are valid
        for tokens in sessions:
            api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
            profile_response = api_client.get(reverse('profile'))
            assert profile_response.status_code == status.HTTP_200_OK
        
        # Verify multiple sessions exist in database
        user_sessions = UserSession.objects.filter(user=self.user)
        assert user_sessions.count() >= 3, f'Expected at least 3 sessions, found {user_sessions.count()}'
    
    def test_token_refresh_rotation(self, api_client):
        """Test refresh token rotation if enabled."""
        # First obtain tokens
        url = reverse('token_obtain_pair')
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        original_refresh = tokens['refresh']
        
        # Refresh the token
        refresh_url = reverse('token_refresh')
        response = api_client.post(refresh_url, {'refresh': original_refresh}, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        new_data = response.json()
        
        # If rotation is enabled, we should get a new refresh token
        if 'refresh' in new_data:
            new_refresh = new_data['refresh']
            assert original_refresh != new_refresh
            
            # Original refresh token should be invalid now
            response = api_client.post(refresh_url, {'refresh': original_refresh}, format='json')
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_session_metadata_recording(self, api_client):
        """Test that session metadata is properly recorded."""
        url = reverse('token_obtain_pair')
        
        # Set custom headers to test metadata recording
        headers = {
            'HTTP_USER_AGENT': 'TestBrowser/1.0',
            'HTTP_X_FORWARDED_FOR': '192.168.1.1',
        }
        
        response = api_client.post(
            url, 
            self.valid_credentials, 
            format='json',
            **headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify session metadata
        session = UserSession.objects.filter(user=self.user).first()
        assert session is not None, 'No session found after login'
        assert session.user_agent == 'TestBrowser/1.0', f'Expected TestBrowser/1.0, got {session.user_agent}'
        # IP might be processed differently based on proxy settings
        assert session.ip_address is not None, 'Session IP address should be recorded'
    
    @pytest.mark.usefixtures()  # Don't use rate_limit_reset for this test
    def test_authentication_rate_limiting(self):
        """Test that authentication endpoints are properly rate limited."""
        from rest_framework.test import APIClient
        
        # Use fresh API client that doesn't clear rate limits
        client = APIClient()
        url = reverse('token_obtain_pair')
        
        # Make multiple failed attempts - should hit rate limit (configured as 5/minute)
        responses = []
        for i in range(7):  # More than the 5/minute limit
            response = client.post(url, self.invalid_credentials, format='json')
            responses.append(response.status_code)
            
        # Should have some 401s (failed auth) and at least one 429 (rate limited)
        status_codes = set(responses)
        
        # Verify we got some authentication failures
        assert status.HTTP_401_UNAUTHORIZED in status_codes, \
            f"Expected 401 responses for invalid credentials, got: {responses}"
        
        # Verify rate limiting kicked in
        assert status.HTTP_429_TOO_MANY_REQUESTS in status_codes, \
            f"Expected 429 (rate limited) after {len(responses)} requests, got: {responses}"
        
        # Verify rate limiting happened after some attempts (not immediately)
        first_rate_limit_index = next(i for i, code in enumerate(responses) 
                                     if code == status.HTTP_429_TOO_MANY_REQUESTS)
        assert first_rate_limit_index > 0, \
            "Rate limiting should not happen on first request"
    
    def test_audit_log_completeness(self, api_client):
        """Test that all authentication events are properly logged."""
        url = reverse('token_obtain_pair')
        
        # Successful login
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        
        # Failed login  
        api_client.post(url, self.invalid_credentials, format='json')
        
        # Logout
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        logout_url = reverse('logout')
        api_client.post(logout_url, {'refresh': tokens['refresh']}, format='json')
        
        # Verify all events were logged
        audit_logs = AuditLog.objects.filter(user=self.user)
        event_types = list(audit_logs.values_list('event_type', flat=True))
        
        expected_events = [
            AuditLog.EventType.LOGIN,
            AuditLog.EventType.LOGOUT
        ]
        
        for expected_event in expected_events:
            assert expected_event in event_types, f'Expected {expected_event} not found in audit logs'
        
        # Check for failed login audit log (user=None for failed attempts)
        failed_login_logs = AuditLog.objects.filter(
            event_type=AuditLog.EventType.LOGIN_FAILED,
            user__isnull=True
        )
        assert failed_login_logs.exists(), 'No failed login audit log found'
    
    def test_database_integrity_during_auth_flow(self, api_client):
        """Test that database remains consistent during authentication flow."""
        initial_user_count = User.objects.count()
        initial_session_count = UserSession.objects.count()
        initial_audit_count = AuditLog.objects.count()
        
        # Complete authentication flow
        url = reverse('token_obtain_pair')
        response = api_client.post(url, self.valid_credentials, format='json')
        tokens = response.json()
        
        # Logout
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        logout_url = reverse('logout')
        api_client.post(logout_url, {'refresh': tokens['refresh']}, format='json')
        
        # Verify database state
        assert User.objects.count() == initial_user_count, 'User count should remain the same'
        # Session should be cleaned up after logout
        assert UserSession.objects.count() == initial_session_count, 'Session should be cleaned up after logout'
        # Audit logs should be added
        assert AuditLog.objects.count() > initial_audit_count, 'Audit logs should be created for auth events'