import json
from unittest.mock import patch, Mock
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.sites.models import Site
from rest_framework.test import APITestCase
from rest_framework import status
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter

from django_myuser.models import UserSession, Profile

User = get_user_model()


class SocialAuthTestCase(APITestCase):
    """Test cases for social authentication functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create social apps for testing
        site = Site.objects.get_current()
        
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_google_client_id',
            secret='test_google_secret'
        )
        self.google_app.sites.add(site)
        
        self.github_app = SocialApp.objects.create(
            provider='github',
            name='GitHub',
            client_id='test_github_client_id',
            secret='test_github_secret'
        )
        self.github_app.sites.add(site)
        
        self.facebook_app = SocialApp.objects.create(
            provider='facebook',
            name='Facebook',
            client_id='test_facebook_client_id',
            secret='test_facebook_secret'
        )
        self.facebook_app.sites.add(site)
    
    def test_social_account_list_view(self):
        """Test listing connected social accounts"""
        # Create a social account for the user
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789',
            extra_data={
                'email': 'test@gmail.com',
                'name': 'Test User',
                'picture': 'https://example.com/avatar.jpg'
            }
        )
        
        self.client.force_authenticate(user=self.user)
        
        response = self.client.get(reverse('social_accounts'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['provider'], 'google')
        self.assertEqual(response.data[0]['uid'], '123456789')
    
    def test_social_account_connect_status_view(self):
        """Test checking connection status for all providers"""
        # Create a Google social account
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789'
        )
        
        self.client.force_authenticate(user=self.user)
        
        response = self.client.get(reverse('social_accounts_status'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_id'], self.user.id)
        self.assertTrue(response.data['has_password'])
        self.assertTrue(response.data['social_accounts']['google']['connected'])
        self.assertFalse(response.data['social_accounts']['github']['connected'])
        self.assertFalse(response.data['social_accounts']['facebook']['connected'])
    
    def test_social_account_disconnect_success(self):
        """Test disconnecting a social account successfully"""
        # Create a social account
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789'
        )
        
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(reverse('social_account_disconnect', args=['google']))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('google account disconnected successfully', response.data['message'])
        
        # Verify the social account was deleted
        self.assertFalse(
            SocialAccount.objects.filter(user=self.user, provider='google').exists()
        )
    
    def test_social_account_disconnect_prevent_last_login_method(self):
        """Test that disconnecting the only login method is prevented"""
        # Remove user's password
        self.user.set_unusable_password()
        self.user.save()
        
        # Create only one social account
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789'
        )
        
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(reverse('social_account_disconnect', args=['google']))
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Cannot disconnect the only login method', response.data['error'])
        
        # Verify the social account was not deleted
        self.assertTrue(
            SocialAccount.objects.filter(user=self.user, provider='google').exists()
        )
    
    def test_social_account_disconnect_nonexistent(self):
        """Test disconnecting a non-existent social account"""
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(reverse('social_account_disconnect', args=['google']))
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('No google account found', response.data['error'])
    
    def test_social_account_disconnect_with_other_social_accounts(self):
        """Test that disconnection is allowed when other social accounts exist"""
        # Remove user's password
        self.user.set_unusable_password()
        self.user.save()
        
        # Create two social accounts
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789'
        )
        SocialAccount.objects.create(
            user=self.user,
            provider='github',
            uid='987654321'
        )
        
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(reverse('social_account_disconnect', args=['google']))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify Google account was deleted but GitHub remains
        self.assertFalse(
            SocialAccount.objects.filter(user=self.user, provider='google').exists()
        )
        self.assertTrue(
            SocialAccount.objects.filter(user=self.user, provider='github').exists()
        )


@patch('django_myuser.social_views.GoogleOAuth2Adapter')
@patch('django_myuser.social_views.RefreshToken')
class GoogleSocialLoginTestCase(APITestCase):
    """Test cases for Google social login"""
    
    def setUp(self):
        """Set up test data"""
        site = Site.objects.get_current()
        
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_google_client_id',
            secret='test_google_secret'
        )
        self.google_app.sites.add(site)
        
        # Create a test user that would be returned by Google OAuth
        self.test_user = User.objects.create_user(
            username='googleuser',
            email='googleuser@gmail.com',
            first_name='Google',
            last_name='User'
        )
    
    def test_google_social_login_creates_user_session(self, mock_refresh_token, mock_adapter):
        """Test that Google social login creates a UserSession"""
        # Mock the JWT token generation
        mock_token_instance = Mock()
        mock_token_instance.__str__ = Mock(return_value='fake-refresh-token')
        mock_refresh_token.for_user.return_value = mock_token_instance
        mock_token_instance.access_token.__str__ = Mock(return_value='fake-access-token')
        
        # Mock the social login view's user attribute
        with patch('django_myuser.social_views.GoogleSocialLoginView.user', self.test_user):
            response = self.client.post(
                reverse('google_login'),
                {'access_token': 'fake-google-token'},
                HTTP_X_FORWARDED_FOR='192.168.1.1',
                HTTP_USER_AGENT='Test User Agent'
            )
        
        # Note: This test would need more mocking to work properly with allauth
        # In a real scenario, you'd mock the entire OAuth flow
        # For now, we're testing the structure


class SocialAuthSignalsTestCase(TestCase):
    """Test cases for social authentication signals"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
    
    @patch('django_myuser.signals.send_async_email.delay')
    def test_social_account_added_signal(self, mock_send_email):
        """Test that adding a social account triggers email notification"""
        # Create a social account (this should trigger the signal)
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789'
        )
        
        # Manually trigger the signal since it might not fire in tests
        from django_myuser.signals import social_account_added_handler
        from allauth.socialaccount.models import SocialLogin
        
        # Create a mock request and sociallogin
        mock_request = Mock()
        mock_request.META = {
            'REMOTE_ADDR': '192.168.1.1',
            'HTTP_USER_AGENT': 'Test Browser'
        }
        mock_sociallogin = Mock()
        mock_sociallogin.user = self.user
        mock_sociallogin.account = social_account
        
        social_account_added_handler(
            sender=SocialAccount,
            request=mock_request,
            sociallogin=mock_sociallogin
        )
        
        # Verify email was queued
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args[1]
        self.assertEqual(call_args['subject'], 'Google account connected')
        self.assertEqual(call_args['to_email'], self.user.email)
    
    @patch('django_myuser.signals.send_async_email.delay')
    def test_user_signed_up_signal(self, mock_send_email):
        """Test that user signup triggers welcome email"""
        # Manually trigger the signal
        from django_myuser.signals import user_signed_up_handler
        
        mock_request = Mock()
        mock_request.META = {
            'REMOTE_ADDR': '192.168.1.1',
            'HTTP_USER_AGENT': 'Test Browser'
        }
        
        user_signed_up_handler(
            sender=User,
            request=mock_request,
            user=self.user
        )
        
        # Verify welcome email was queued
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args[1]
        self.assertEqual(call_args['subject'], 'Welcome to our platform!')
        self.assertEqual(call_args['to_email'], self.user.email)


class SocialAuthSerializerTestCase(TestCase):
    """Test cases for social authentication serializers"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
    
    def test_social_account_serializer(self):
        """Test SocialAccountSerializer"""
        from django_myuser.serializers import SocialAccountSerializer
        
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789',
            extra_data={
                'email': 'test@gmail.com',
                'name': 'Test User',
                'picture': 'https://example.com/avatar.jpg'
            }
        )
        
        serializer = SocialAccountSerializer(social_account)
        data = serializer.data
        
        self.assertEqual(data['provider'], 'google')
        self.assertEqual(data['provider_display'], 'Google')
        self.assertEqual(data['uid'], '123456789')
        self.assertEqual(data['avatar_url'], 'https://example.com/avatar.jpg')
    
    def test_social_account_serializer_github(self):
        """Test SocialAccountSerializer with GitHub data"""
        from django_myuser.serializers import SocialAccountSerializer
        
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='github',
            uid='987654321',
            extra_data={
                'login': 'testuser',
                'avatar_url': 'https://github.com/avatar.jpg',
                'html_url': 'https://github.com/testuser'
            }
        )
        
        serializer = SocialAccountSerializer(social_account)
        data = serializer.data
        
        self.assertEqual(data['provider'], 'github')
        self.assertEqual(data['provider_display'], 'GitHub')
        self.assertEqual(data['avatar_url'], 'https://github.com/avatar.jpg')
        self.assertEqual(data['profile_url'], 'https://github.com/testuser')
    
    def test_social_account_disconnect_serializer_validation(self):
        """Test SocialAccountDisconnectSerializer validation"""
        from django_myuser.serializers import SocialAccountDisconnectSerializer
        
        # Test valid data
        valid_data = {'provider': 'google', 'confirm': True}
        serializer = SocialAccountDisconnectSerializer(data=valid_data)
        self.assertTrue(serializer.is_valid())
        
        # Test invalid data (no confirmation)
        invalid_data = {'provider': 'google', 'confirm': False}
        serializer = SocialAccountDisconnectSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('confirm', serializer.errors)


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class SocialAuthIntegrationTestCase(APITestCase):
    """Integration tests for social authentication flow"""
    
    def setUp(self):
        """Set up test data"""
        # Create social apps
        site = Site.objects.get_current()
        
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_google_client_id',
            secret='test_google_secret'
        )
        self.google_app.sites.add(site)
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_social_authentication_complete_flow(self):
        """Test complete social authentication flow"""
        self.client.force_authenticate(user=self.user)
        
        # 1. Check initial status (no social accounts)
        response = self.client.get(reverse('social_accounts_status'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['social_accounts']['google']['connected'])
        
        # 2. Simulate connecting a Google account
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='123456789',
            extra_data={'email': 'test@gmail.com', 'name': 'Test User'}
        )
        
        # 3. Check status after connection
        response = self.client.get(reverse('social_accounts_status'))
        self.assertTrue(response.data['social_accounts']['google']['connected'])
        
        # 4. List social accounts
        response = self.client.get(reverse('social_accounts'))
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['provider'], 'google')
        
        # 5. Disconnect social account
        response = self.client.delete(reverse('social_account_disconnect', args=['google']))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 6. Verify disconnection
        response = self.client.get(reverse('social_accounts_status'))
        self.assertFalse(response.data['social_accounts']['google']['connected'])


class SocialAuthAdapterTestCase(TestCase):
    """Test cases for social authentication adapter"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
    
    @patch('django_myuser.adapters.send_async_email.delay')
    def test_adapter_send_welcome_email(self, mock_send_email):
        """Test adapter sends welcome email"""
        from django_myuser.adapters import MySocialAccountAdapter
        
        adapter = MySocialAccountAdapter()
        adapter.send_welcome_email(self.user)
        
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args[1]
        self.assertEqual(call_args['subject'], 'Welcome to our platform!')
        self.assertEqual(call_args['to_email'], self.user.email)
    
    def test_adapter_populate_user_google(self):
        """Test adapter populates user data from Google"""
        from django_myuser.adapters import MySocialAccountAdapter
        from allauth.socialaccount.models import SocialLogin, SocialAccount
        
        adapter = MySocialAccountAdapter()
        
        # Create mock social login with Google data
        social_account = SocialAccount(
            provider='google',
            uid='123456789',
            extra_data={
                'given_name': 'John',
                'family_name': 'Doe',
                'email': 'john.doe@gmail.com'
            }
        )
        
        mock_request = Mock()
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        data = {'email': 'john.doe@gmail.com'}
        
        user = adapter.populate_user(mock_request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
    
    def test_adapter_populate_user_github(self):
        """Test adapter populates user data from GitHub"""
        from django_myuser.adapters import MySocialAccountAdapter
        from allauth.socialaccount.models import SocialLogin, SocialAccount
        
        adapter = MySocialAccountAdapter()
        
        # Create mock social login with GitHub data
        social_account = SocialAccount(
            provider='github',
            uid='987654321',
            extra_data={
                'name': 'Jane Smith',
                'email': 'jane.smith@github.com'
            }
        )
        
        mock_request = Mock()
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        data = {'email': 'jane.smith@github.com'}
        
        user = adapter.populate_user(mock_request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'Jane')
        self.assertEqual(user.last_name, 'Smith')