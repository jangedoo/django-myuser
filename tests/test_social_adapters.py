from unittest.mock import Mock, patch
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialApp
from allauth.account.models import EmailAddress

from django_myuser.adapters import MySocialAccountAdapter, MyAccountAdapter
from django_myuser.models import UserSession

User = get_user_model()


class MySocialAccountAdapterTestCase(TestCase):
    """Test cases for MySocialAccountAdapter"""
    
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        self.adapter = MySocialAccountAdapter()
        
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        
        # Create a social app
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_client_id',
            secret='test_secret'
        )
        
        # Create a site and associate the social app
        site = Site.objects.get_current()
        self.google_app.sites.add(site)
    
    def test_pre_social_login_existing_user(self):
        """Test pre_social_login connects to existing user with same email"""
        # Create a mock social login
        social_account = SocialAccount(
            provider='google',
            uid='123456789',
            extra_data={'email': 'test@example.com'}
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        mock_sociallogin.connect = Mock()
        
        request = self.factory.get('/')
        
        # Call pre_social_login
        self.adapter.pre_social_login(request, mock_sociallogin)
        
        # Verify that connect was called with the existing user
        mock_sociallogin.connect.assert_called_once_with(request, self.user)
    
    def test_pre_social_login_no_existing_user(self):
        """Test pre_social_login when no existing user with email"""
        # Create a mock social login with email that doesn't exist
        social_account = SocialAccount(
            provider='google',
            uid='123456789',
            extra_data={'email': 'newuser@example.com'}
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        mock_sociallogin.connect = Mock()
        
        request = self.factory.get('/')
        
        # Call pre_social_login
        self.adapter.pre_social_login(request, mock_sociallogin)
        
        # Verify that connect was not called
        mock_sociallogin.connect.assert_not_called()
    
    @patch('django_myuser.adapters.RefreshToken')
    @patch('django_myuser.adapters.MySocialAccountAdapter.send_welcome_email')
    def test_save_user_generates_jwt_tokens(self, mock_send_email, mock_refresh_token):
        """Test that save_user generates JWT tokens and creates session"""
        # Mock JWT token generation
        mock_token_instance = Mock()
        mock_token_instance.__str__ = Mock(return_value='fake-refresh-token')
        mock_refresh_token.for_user.return_value = mock_token_instance
        mock_token_instance.access_token.__str__ = Mock(return_value='fake-access-token')
        
        # Create a new user for this test
        new_user = User.objects.create_user(
            username='newuser',
            email='newuser@example.com'
        )
        
        # Create mock social login
        mock_sociallogin = Mock()
        mock_sociallogin.user = new_user
        
        # Create request with session
        request = self.factory.post('/')
        request.session = {}
        request.META = {
            'HTTP_X_FORWARDED_FOR': '192.168.1.1',
            'HTTP_USER_AGENT': 'Test User Agent'
        }
        
        # Call save_user with mocked parent class method
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.save_user', return_value=new_user) as mock_super_save:
            result_user = self.adapter.save_user(request, mock_sociallogin)
        
        # Verify JWT tokens were generated
        mock_refresh_token.for_user.assert_called_once_with(new_user)
        
        # Verify tokens were stored in session
        self.assertEqual(request.session['jwt_access_token'], 'fake-access-token')
        self.assertEqual(request.session['jwt_refresh_token'], 'fake-refresh-token')
        
        # Verify welcome email was sent
        mock_send_email.assert_called_once_with(new_user)
        
        # Verify UserSession was created
        self.assertTrue(UserSession.objects.filter(user=new_user).exists())
        user_session = UserSession.objects.get(user=new_user)
        self.assertEqual(user_session.ip_address, '192.168.1.1')
        self.assertEqual(user_session.user_agent, 'Test User Agent')
        self.assertEqual(user_session.refresh_token, 'fake-refresh-token')
    
    def test_get_client_ip_with_x_forwarded_for(self):
        """Test getting client IP with X-Forwarded-For header"""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1'
        
        ip = self.adapter.get_client_ip(request)
        self.assertEqual(ip, '192.168.1.1')
    
    def test_get_client_ip_without_x_forwarded_for(self):
        """Test getting client IP without X-Forwarded-For header"""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        ip = self.adapter.get_client_ip(request)
        self.assertEqual(ip, '127.0.0.1')
    
    @patch('django_myuser.adapters.send_async_email.delay')
    def test_send_welcome_email_with_celery(self, mock_send_async):
        """Test sending welcome email with Celery"""
        with patch('django.conf.settings.CELERY_BROKER_URL', 'redis://localhost:6379/0'):
            self.adapter.send_welcome_email(self.user)
        
        mock_send_async.assert_called_once()
        call_kwargs = mock_send_async.call_args[1]
        self.assertEqual(call_kwargs['subject'], 'Welcome to our platform!')
        self.assertEqual(call_kwargs['to_email'], self.user.email)
        self.assertEqual(call_kwargs['template_name'], 'account/email/welcome_message')
    
    @patch('django.core.mail.send_mail')
    @patch('django.template.loader.render_to_string')
    def test_send_welcome_email_without_celery(self, mock_render, mock_send_mail):
        """Test sending welcome email without Celery (fallback)"""
        mock_render.return_value = 'Welcome message'
        
        # Test the fallback path when CELERY_BROKER_URL is not available
        with patch('django_myuser.adapters.hasattr', side_effect=lambda obj, attr: attr != 'CELERY_BROKER_URL'):
            self.adapter.send_welcome_email(self.user)
            
            # Verify synchronous email was sent
            mock_send_mail.assert_called_once()
            mock_render.assert_called_once_with('account/email/welcome_message.txt', {'user': self.user})
    
    def test_populate_user_google_data(self):
        """Test populating user data from Google provider"""
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
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        request = self.factory.get('/')
        data = {'email': 'john.doe@gmail.com'}
        
        # Mock the parent class method so our override is called
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.populate_user', return_value=self.user) as mock_super:
            user = self.adapter.populate_user(request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
    
    def test_populate_user_github_data(self):
        """Test populating user data from GitHub provider"""
        # Create mock social login with GitHub data
        social_account = SocialAccount(
            provider='github',
            uid='987654321',
            extra_data={
                'name': 'Jane Smith',
                'login': 'janesmith'
            }
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        request = self.factory.get('/')
        data = {'email': 'jane.smith@example.com'}
        
        # Mock the parent class method so our override is called
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.populate_user', return_value=self.user) as mock_super:
            user = self.adapter.populate_user(request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'Jane')
        self.assertEqual(user.last_name, 'Smith')
    
    def test_populate_user_facebook_data(self):
        """Test populating user data from Facebook provider"""
        # Create mock social login with Facebook data
        social_account = SocialAccount(
            provider='facebook',
            uid='555666777',
            extra_data={
                'first_name': 'Alice',
                'last_name': 'Johnson'
            }
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        request = self.factory.get('/')
        data = {'email': 'alice.johnson@example.com'}
        
        # Mock the parent class method so our override is called
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.populate_user', return_value=self.user) as mock_super:
            user = self.adapter.populate_user(request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'Alice')
        self.assertEqual(user.last_name, 'Johnson')
    
    def test_populate_user_github_single_name(self):
        """Test populating user data from GitHub with single name"""
        # Create mock social login with GitHub data (single name)
        social_account = SocialAccount(
            provider='github',
            uid='987654321',
            extra_data={
                'name': 'SingleName',
                'login': 'singlename'
            }
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        request = self.factory.get('/')
        data = {'email': 'single@example.com'}
        
        # Mock the parent class method so our override is called
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.populate_user', return_value=self.user) as mock_super:
            user = self.adapter.populate_user(request, mock_sociallogin, data)
        
        self.assertEqual(user.first_name, 'SingleName')
        self.assertEqual(user.last_name, '')


class MyAccountAdapterTestCase(TestCase):
    """Test cases for MyAccountAdapter"""
    
    def setUp(self):
        """Set up test data"""
        self.adapter = MyAccountAdapter()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
    
    @patch('django_myuser.adapters.send_async_email.delay')
    def test_send_mail_with_celery(self, mock_send_async):
        """Test sending email with Celery"""
        with patch('django.conf.settings.CELERY_BROKER_URL', 'redis://localhost:6379/0'):
            self.adapter.send_mail(
                'account/email/email_confirmation',
                'test@example.com',
                {'user': self.user}
            )
        
        mock_send_async.assert_called_once()
        call_kwargs = mock_send_async.call_args[1]
        self.assertEqual(call_kwargs['template_name'], 'account/email/email_confirmation')
        self.assertEqual(call_kwargs['to_email'], 'test@example.com')
        self.assertIsNone(call_kwargs['subject'])  # Will be determined by template
    
    @patch('allauth.account.adapter.DefaultAccountAdapter.send_mail')
    def test_send_mail_without_celery(self, mock_super_send):
        """Test sending email without Celery (fallback to parent)"""
        # Test the fallback path when CELERY_BROKER_URL is not available
        with patch('django_myuser.adapters.hasattr', side_effect=lambda obj, attr: attr != 'CELERY_BROKER_URL'):
            self.adapter.send_mail(
                'account/email/email_confirmation',
                'test@example.com',
                {'user': self.user}
            )
            
            # Verify parent class method was called
            mock_super_send.assert_called_once_with(
                'account/email/email_confirmation',
                'test@example.com',
                {'user': self.user}
            )


class AdapterIntegrationTestCase(TestCase):
    """Integration tests for adapters"""
    
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        self.adapter = MySocialAccountAdapter()
        
        # Create social app
        self.google_app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test_client_id',
            secret='test_secret'
        )
        site = Site.objects.get_current()
        self.google_app.sites.add(site)
    
    @patch('django_myuser.adapters.RefreshToken')
    def test_complete_social_login_flow(self, mock_refresh_token):
        """Test complete social login flow through adapter"""
        # Mock JWT token generation
        mock_token_instance = Mock()
        mock_token_instance.__str__ = Mock(return_value='fake-refresh-token')
        mock_refresh_token.for_user.return_value = mock_token_instance
        mock_token_instance.access_token.__str__ = Mock(return_value='fake-access-token')
        
        # Create request
        request = self.factory.post('/')
        request.session = {}
        request.META = {
            'HTTP_X_FORWARDED_FOR': '192.168.1.1',
            'HTTP_USER_AGENT': 'Test User Agent'
        }
        
        # Create social account and login
        social_account = SocialAccount(
            provider='google',
            uid='123456789',
            extra_data={
                'email': 'newuser@example.com',
                'given_name': 'New',
                'family_name': 'User'
            }
        )
        
        mock_sociallogin = Mock()
        mock_sociallogin.account = social_account
        
        # Mock the parent save_user to create and return a new user
        new_user = User(
            username='newuser',
            email='newuser@example.com',
            first_name='',
            last_name=''
        )
        
        with patch.object(MySocialAccountAdapter, 'save_user') as mock_parent_save:
            mock_parent_save.return_value = new_user
            
            # Test the adapter methods
            # 1. Populate user data
            populated_user = self.adapter.populate_user(request, mock_sociallogin, {})
            
            # 2. Pre-social login (shouldn't find existing user)
            self.adapter.pre_social_login(request, mock_sociallogin)
            
            # Verify user data was populated correctly
            self.assertEqual(populated_user.first_name, 'New')
            self.assertEqual(populated_user.last_name, 'User')
    
    def test_is_open_for_signup_default_true(self):
        """Test that signup is open by default"""
        request = self.factory.get('/')
        mock_sociallogin = Mock()
        
        is_open = self.adapter.is_open_for_signup(request, mock_sociallogin)
        self.assertTrue(is_open)
    
    def test_is_open_for_signup_setting_false(self):
        """Test that signup can be disabled via setting"""
        request = self.factory.get('/')
        mock_sociallogin = Mock()
        
        # Mock getattr to return False for ACCOUNT_ALLOW_REGISTRATION
        with patch('django_myuser.adapters.getattr', side_effect=lambda obj, attr, default: False if attr == 'ACCOUNT_ALLOW_REGISTRATION' else default):
            is_open = self.adapter.is_open_for_signup(request, mock_sociallogin)
            self.assertFalse(is_open)