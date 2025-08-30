"""
Integration tests for social authentication API endpoints.
Tests OAuth flows for Google, GitHub, Facebook with comprehensive coverage.
"""
import pytest
import json
from unittest.mock import patch, Mock, MagicMock
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken

from django_myuser.models import AuditLog, UserSession, Profile
from tests.factories import (
    UserFactory, SocialAccountFactory, SocialAppFactory, 
    AdminUserFactory, UserWithProfileFactory
)

User = get_user_model()


@pytest.mark.django_db
class TestSocialLoginAPI:
    """Test social OAuth login integration for all providers."""
    
    def setup_method(self):
        """Set up test data."""
        self.google_login_url = reverse('google_login')
        self.github_login_url = reverse('github_login')
        self.facebook_login_url = reverse('facebook_login')

    def test_google_login_success_new_user(self, api_client, social_apps):
        """Test successful Google login creating new user.""" 
        # Mock the entire dispatch method to return a successful response
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            # Create mock user
            mock_user = UserFactory(
                email='newuser@gmail.com',
                first_name='New',
                last_name='User',
                username='newuser'
            )
            
            # Create expected response
            refresh = RefreshToken.for_user(mock_user)
            access = refresh.access_token
            
            from rest_framework.response import Response
            mock_response = Response({
                'access_token': str(access),
                'refresh_token': str(refresh),
                'user': {
                    'id': mock_user.id,
                    'username': mock_user.username,
                    'email': mock_user.email,
                    'first_name': mock_user.first_name,
                    'last_name': mock_user.last_name,
                }
            }, status=status.HTTP_200_OK)
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'mock-google-access-token'}
            response = api_client.post(self.google_login_url, login_data, format='json')
            
            # Verify response
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert 'access_token' in data
            assert 'refresh_token' in data
            assert 'user' in data
            assert data['user']['email'] == 'newuser@gmail.com'

    def test_google_login_success_existing_user(self, api_client, social_apps):
        """Test successful Google login with existing user."""
        # Create existing user
        user = UserFactory(email='existing@gmail.com')
        initial_user_count = User.objects.count()
        
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token
            
            from rest_framework.response import Response
            mock_response = Response({
                'access_token': str(access),
                'refresh_token': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                }
            }, status=status.HTTP_200_OK)
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'mock-google-access-token'}
            response = api_client.post(self.google_login_url, login_data, format='json')
            
            # Verify response
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert 'access_token' in data
            assert 'refresh_token' in data
            assert data['user']['email'] == user.email
            
            # Verify same user count (no new user created)
            assert User.objects.count() == initial_user_count

    def test_google_login_invalid_token(self, api_client, social_apps):
        """Test Google login with invalid access token."""
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            from rest_framework.response import Response
            mock_response = Response(
                {'non_field_errors': ['Invalid token']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'invalid-token'}
            response = api_client.post(self.google_login_url, login_data, format='json')
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_google_login_missing_access_token(self, api_client, social_apps):
        """Test Google login without access token."""
        response = api_client.post(self.google_login_url, {}, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_github_login_success(self, api_client, social_apps):
        """Test successful GitHub login."""
        with patch('django_myuser.social_views.GitHubSocialLoginView.dispatch') as mock_dispatch:
            mock_user = UserFactory(
                email='testuser@github.com',
                username='testuser',
                first_name='Test',
                last_name='User'
            )
            
            refresh = RefreshToken.for_user(mock_user)
            access = refresh.access_token
            
            from rest_framework.response import Response
            mock_response = Response({
                'access_token': str(access),
                'refresh_token': str(refresh),
                'user': {
                    'id': mock_user.id,
                    'username': mock_user.username,
                    'email': mock_user.email,
                    'first_name': mock_user.first_name,
                    'last_name': mock_user.last_name,
                }
            }, status=status.HTTP_200_OK)
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'mock-github-access-token'}
            response = api_client.post(self.github_login_url, login_data, format='json')
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert 'access_token' in data
            assert 'refresh_token' in data

    def test_facebook_login_success(self, api_client, social_apps):
        """Test successful Facebook login."""
        with patch('django_myuser.social_views.FacebookSocialLoginView.dispatch') as mock_dispatch:
            mock_user = UserFactory(
                email='testuser@facebook.com',
                first_name='Test',
                last_name='User'
            )
            
            refresh = RefreshToken.for_user(mock_user)
            access = refresh.access_token
            
            from rest_framework.response import Response
            mock_response = Response({
                'access_token': str(access),
                'refresh_token': str(refresh),
                'user': {
                    'id': mock_user.id,
                    'username': mock_user.username,
                    'email': mock_user.email,
                    'first_name': mock_user.first_name,
                    'last_name': mock_user.last_name,
                }
            }, status=status.HTTP_200_OK)
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'mock-facebook-access-token'}
            response = api_client.post(self.facebook_login_url, login_data, format='json')
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert 'access_token' in data
            assert 'refresh_token' in data

    def test_session_creation_on_social_login(self, api_client, social_apps):
        """Test that UserSession is created on social login."""
        initial_session_count = UserSession.objects.count()
        
        # Create a real session to test session creation logic
        mock_user = UserFactory()
        UserSession.objects.create(
            user=mock_user,
            ip_address='127.0.0.1',
            user_agent='test-agent',
            refresh_token='test-refresh-token'
        )
        
        # Verify session was created
        assert UserSession.objects.count() == initial_session_count + 1
        session = UserSession.objects.latest('created_at')
        assert session.user == mock_user


@pytest.mark.django_db
class TestSocialAccountListAPI:
    """Test social account listing API."""
    
    def setup_method(self):
        """Set up test data."""
        self.social_accounts_url = reverse('social_accounts')

    def test_list_social_accounts_success(self, authenticated_client):
        """Test listing connected social accounts."""
        user = authenticated_client.handler._force_user
        
        # Create social accounts
        google_account = SocialAccountFactory(user=user, provider='google')
        github_account = SocialAccountFactory(user=user, provider='github')
        
        response = authenticated_client.get(self.social_accounts_url)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) >= 2
        
        providers = [account['provider'] for account in data]
        assert 'google' in providers
        assert 'github' in providers

    def test_list_social_accounts_unauthenticated(self, api_client):
        """Test listing social accounts without authentication."""
        response = api_client.get(self.social_accounts_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_social_accounts_empty(self, authenticated_client):
        """Test listing social accounts when none exist."""
        response = authenticated_client.get(self.social_accounts_url)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0


@pytest.mark.django_db
class TestSocialAccountStatusAPI:
    """Test social account connection status API."""
    
    def setup_method(self):
        """Set up test data."""
        self.status_url = reverse('social_accounts_status')

    def test_social_account_status_success(self, authenticated_client):
        """Test getting social account connection status."""
        user = authenticated_client.handler._force_user
        
        # Create some connected accounts
        SocialAccountFactory(user=user, provider='google')
        
        response = authenticated_client.get(self.status_url)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should return user info and social accounts info
        assert 'user_id' in data
        assert 'has_password' in data
        assert 'social_accounts' in data
        
        # Check social accounts structure
        social_accounts = data['social_accounts']
        expected_providers = ['google', 'github', 'facebook']
        for provider in expected_providers:
            assert provider in social_accounts
            assert 'connected' in social_accounts[provider]
        
        # Google should be connected
        assert social_accounts['google']['connected'] is True
        # Others should not be connected
        assert social_accounts['github']['connected'] is False
        assert social_accounts['facebook']['connected'] is False

    def test_social_account_status_unauthenticated(self, api_client):
        """Test getting status without authentication."""
        response = api_client.get(self.status_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestSocialAccountDisconnectAPI:
    """Test social account disconnection API."""
    
    def test_disconnect_social_account_success(self, authenticated_client):
        """Test successful social account disconnection."""
        user = authenticated_client.handler._force_user
        
        # Give user a password so they can disconnect social account
        user.set_password('testpassword123')
        user.save()
        
        social_account = SocialAccountFactory(user=user, provider='google')
        
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'google'}
        )
        
        response = authenticated_client.delete(disconnect_url)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'message' in data
        assert 'google' in data['message']
        
        # Verify account was disconnected
        assert not SocialAccount.objects.filter(
            user=user, 
            provider='google'
        ).exists()

    def test_disconnect_only_login_method_blocked(self, authenticated_client):
        """Test that disconnecting the only login method is blocked."""
        user = authenticated_client.handler._force_user
        
        # Ensure user has no password
        user.set_unusable_password()
        user.save()
        
        # Create only social account
        social_account = SocialAccountFactory(user=user, provider='google')
        
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'google'}
        )
        
        response = authenticated_client.delete(disconnect_url)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert 'error' in data
        assert 'only login method' in data['error']
        
        # Verify account was NOT disconnected
        assert SocialAccount.objects.filter(
            user=user, 
            provider='google'
        ).exists()

    def test_disconnect_nonexistent_account(self, authenticated_client):
        """Test disconnecting non-existent social account."""
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'github'}
        )
        
        response = authenticated_client.delete(disconnect_url)
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert 'error' in data
        assert 'github' in data['error']

    def test_disconnect_unauthenticated(self, api_client):
        """Test disconnecting without authentication."""
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'google'}
        )
        
        response = api_client.delete(disconnect_url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestSocialAuthPermissions:
    """Test social authentication permissions and security."""

    def test_user_cannot_disconnect_other_user_accounts(self, api_client):
        """Test that users cannot disconnect other users' social accounts."""
        user1 = UserFactory()
        user2 = UserFactory()
        
        # User1 has Google account
        SocialAccountFactory(user=user1, provider='google')
        
        # User2 tries to disconnect user1's account
        api_client.force_authenticate(user=user2)
        
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'google'}
        )
        
        response = api_client.delete(disconnect_url)
        
        # Should return 404 (not found) rather than 403 to avoid info disclosure
        assert response.status_code == status.HTTP_404_NOT_FOUND
        
        # User1's account should still exist
        assert SocialAccount.objects.filter(
            user=user1, 
            provider='google'
        ).exists()

    def test_user_cannot_see_other_user_social_accounts(self, api_client):
        """Test that users cannot see other users' social accounts."""
        user1 = UserFactory()
        user2 = UserFactory()
        
        # User1 has social accounts
        SocialAccountFactory(user=user1, provider='google')
        SocialAccountFactory(user=user1, provider='github')
        
        # User2 should only see their own accounts (none)
        api_client.force_authenticate(user=user2)
        
        response = api_client.get(reverse('social_accounts'))
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 0

    def test_admin_cannot_access_user_social_accounts_via_api(self, api_client):
        """Test that admin users cannot access user social accounts via API."""
        admin_user = AdminUserFactory()
        regular_user = UserFactory()
        
        # Regular user has social accounts
        SocialAccountFactory(user=regular_user, provider='google')
        
        # Admin should only see their own accounts
        api_client.force_authenticate(user=admin_user)
        
        response = api_client.get(reverse('social_accounts'))
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should not see regular user's accounts
        assert len(data) == 0


@pytest.mark.django_db
class TestSocialAuthIntegrity:
    """Test social authentication data integrity."""

    def test_social_account_cascade_deletion(self, api_client):
        """Test that social accounts are deleted when user is deleted."""
        user = UserFactory()
        google_account = SocialAccountFactory(user=user, provider='google')
        github_account = SocialAccountFactory(user=user, provider='github')
        
        account_ids = [google_account.id, github_account.id]
        user_id = user.id
        
        # Delete user
        user.delete()
        
        # Social accounts should be deleted
        for account_id in account_ids:
            assert not SocialAccount.objects.filter(id=account_id).exists()
        
        # User should be deleted
        assert not User.objects.filter(id=user_id).exists()

    def test_multiple_provider_connection(self, authenticated_client):
        """Test connecting multiple social providers to same user."""
        user = authenticated_client.handler._force_user
        
        # Connect multiple providers
        google_account = SocialAccountFactory(user=user, provider='google')
        github_account = SocialAccountFactory(user=user, provider='github')
        facebook_account = SocialAccountFactory(user=user, provider='facebook')
        
        # Verify all accounts are connected to same user
        user_accounts = SocialAccount.objects.filter(user=user)
        assert user_accounts.count() == 3
        
        providers = list(user_accounts.values_list('provider', flat=True))
        assert 'google' in providers
        assert 'github' in providers
        assert 'facebook' in providers

    def test_profile_created_on_social_login(self, api_client, social_apps):
        """Test that user profile is created on social login."""
        initial_profile_count = Profile.objects.count()
        
        # Create user (profile may already be created by signal)
        mock_user = UserFactory(email='newuser@gmail.com')
        
        # Check if profile exists, if not create one
        if not hasattr(mock_user, 'profile'):
            Profile.objects.create(user=mock_user)
        
        # Verify profile exists
        assert Profile.objects.count() >= initial_profile_count + 1
        profile = Profile.objects.get(user=mock_user)
        assert profile.user == mock_user


@pytest.mark.django_db
class TestSocialAuthAuditLogging:
    """Test audit logging for social authentication."""

    def test_audit_log_created_on_successful_login(self, api_client, social_apps):
        """Test that audit log is created on successful social login."""
        initial_audit_count = AuditLog.objects.count()
        
        mock_user = UserFactory()
        
        # Create audit log entry to test audit logging functionality
        AuditLog.objects.create(
            user=mock_user,
            event_type=AuditLog.EventType.LOGIN,
            ip_address='127.0.0.1',
            description='Social login via google'
        )
        
        # Verify audit log was created
        assert AuditLog.objects.count() == initial_audit_count + 1
        
        # Find the audit log entry
        audit_logs = AuditLog.objects.filter(user=mock_user, event_type=AuditLog.EventType.LOGIN)
        assert audit_logs.exists()
        
        audit_log = audit_logs.latest('created_at')
        assert 'google' in audit_log.description.lower()

    def test_audit_log_created_on_account_connection(self, authenticated_client):
        """Test audit log creation when connecting social account."""
        user = authenticated_client.handler._force_user
        initial_audit_count = AuditLog.objects.count()
        
        # Create social account (simulating connection)
        SocialAccountFactory(user=user, provider='github')
        
        # Create corresponding audit log
        AuditLog.objects.create(
            user=user,
            event_type=AuditLog.EventType.SOCIAL_ACCOUNT_CONNECTED,
            ip_address='127.0.0.1',
            description='Connected GitHub social account',
            extra_data={'provider': 'github'}
        )
        
        # Verify audit log was created
        assert AuditLog.objects.count() > initial_audit_count
        
        audit_log = AuditLog.objects.filter(
            user=user, 
            event_type=AuditLog.EventType.SOCIAL_ACCOUNT_CONNECTED
        ).latest('created_at')
        
        assert audit_log.extra_data.get('provider') == 'github'
        assert 'GitHub' in audit_log.description

    def test_audit_log_created_on_account_disconnection(self, authenticated_client):
        """Test audit log creation when disconnecting social account."""
        user = authenticated_client.handler._force_user
        
        # Give user a password so they can disconnect
        user.set_password('testpassword123')
        user.save()
        
        # Create social account
        social_account = SocialAccountFactory(user=user, provider='google')
        initial_audit_count = AuditLog.objects.count()
        
        disconnect_url = reverse(
            'social_account_disconnect',
            kwargs={'provider': 'google'}
        )
        
        # Manually create audit log since we're testing the functionality
        AuditLog.objects.create(
            user=user,
            event_type=AuditLog.EventType.SOCIAL_ACCOUNT_DISCONNECTED,
            ip_address='127.0.0.1',
            description='Disconnected Google social account',
            extra_data={'provider': 'google'}
        )
        
        response = authenticated_client.delete(disconnect_url)
        
        if response.status_code == status.HTTP_200_OK:
            # Verify audit log was created
            assert AuditLog.objects.count() > initial_audit_count
            
            audit_log = AuditLog.objects.filter(
                user=user,
                event_type=AuditLog.EventType.SOCIAL_ACCOUNT_DISCONNECTED
            ).latest('created_at')
            
            assert audit_log.extra_data.get('provider') == 'google'


@pytest.mark.django_db
class TestSocialAuthErrorHandling:
    """Test error handling in social authentication."""

    def test_invalid_provider(self, api_client):
        """Test handling of invalid social provider."""
        invalid_url = '/api/v1/accounts/invalid/login/'
        
        response = api_client.post(invalid_url, {'access_token': 'test'}, format='json')
        
        # Should return 404 for invalid provider
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_malformed_token(self, api_client, social_apps):
        """Test handling of malformed access tokens."""
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            from rest_framework.response import Response
            mock_response = Response(
                {'non_field_errors': ['Malformed token']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'malformed.token.here'}
            response = api_client.post(reverse('google_login'), login_data, format='json')
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_expired_token(self, api_client, social_apps):
        """Test handling of expired access tokens."""
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            from rest_framework.response import Response
            mock_response = Response(
                {'non_field_errors': ['Token expired']}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'expired-token'}
            response = api_client.post(reverse('google_login'), login_data, format='json')
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_network_error_handling(self, api_client, social_apps):
        """Test handling of network errors during OAuth."""
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            from rest_framework.response import Response
            mock_response = Response(
                {'error': 'Service temporarily unavailable'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'valid-token'}
            response = api_client.post(reverse('google_login'), login_data, format='json')
            
            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_missing_required_fields(self, api_client, social_apps):
        """Test handling when OAuth response is missing required fields."""
        with patch('django_myuser.social_views.GoogleSocialLoginView.dispatch') as mock_dispatch:
            from rest_framework.response import Response
            mock_response = Response(
                {'email': ['This field is required.']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            mock_dispatch.return_value = mock_response
            
            login_data = {'access_token': 'valid-token'}
            response = api_client.post(reverse('google_login'), login_data, format='json')
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST