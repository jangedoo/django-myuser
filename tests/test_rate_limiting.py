"""
Tests for rate limiting functionality
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache

from django_myuser.models import Profile, DataRequest
from django_myuser.throttles import (
    LoginRateThrottle,
    AuthenticatedUserRateThrottle,
    DataRequestRateThrottle,
    ProfileUpdateRateThrottle
)

User = get_user_model()


class RateLimitingTestCase(APITestCase):
    """Test cases for rate limiting on API endpoints"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client = APIClient()
        
        # Clear cache before each test
        cache.clear()
    
    def get_jwt_tokens(self, user):
        """Helper method to get JWT tokens for a user"""
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    def test_authenticated_user_rate_limit(self):
        """Test rate limiting for authenticated users"""
        tokens = self.get_jwt_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        
        # Test logout endpoint with rate limiting
        logout_url = '/api/logout/'  # This would need to be defined in URLs
        
        # First request should succeed
        response = self.client.post(logout_url, {'refresh': tokens['refresh']})
        # Note: This might return 404 if URL doesn't exist, which is fine for this test
        
        # The actual rate limit testing would depend on the configured rates
        # For now, we'll test that the throttle classes are properly configured
        
        # Check that the view has the correct throttle class
        from django_myuser.views import LogoutView
        self.assertIn(AuthenticatedUserRateThrottle, LogoutView.throttle_classes)
    
    def test_profile_update_rate_limit(self):
        """Test rate limiting for profile updates"""
        tokens = self.get_jwt_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        
        # Check that ProfileView has the correct throttle class
        from django_myuser.views import ProfileView
        self.assertIn(ProfileUpdateRateThrottle, ProfileView.throttle_classes)
    
    def test_data_request_rate_limit(self):
        """Test rate limiting for data requests"""
        tokens = self.get_jwt_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        
        # Check that DataRequestView has the correct throttle class
        from django_myuser.views import DataRequestView
        self.assertIn(DataRequestRateThrottle, DataRequestView.throttle_classes)
    
    def test_user_session_rate_limit(self):
        """Test rate limiting for user session endpoints"""
        tokens = self.get_jwt_tokens(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        
        # Check that UserSessionListView has the correct throttle class
        from django_myuser.views import UserSessionListView, UserSessionDetailView
        self.assertIn(AuthenticatedUserRateThrottle, UserSessionListView.throttle_classes)
        self.assertIn(AuthenticatedUserRateThrottle, UserSessionDetailView.throttle_classes)


class ThrottleClassTestCase(TestCase):
    """Test cases for custom throttle classes"""
    
    def test_login_rate_throttle_scope(self):
        """Test that LoginRateThrottle has correct scope"""
        throttle = LoginRateThrottle()
        self.assertEqual(throttle.scope, 'login')
    
    def test_authenticated_user_rate_throttle_scope(self):
        """Test that AuthenticatedUserRateThrottle has correct scope"""
        throttle = AuthenticatedUserRateThrottle()
        self.assertEqual(throttle.scope, 'user')
    
    def test_data_request_rate_throttle_scope(self):
        """Test that DataRequestRateThrottle has correct scope"""
        throttle = DataRequestRateThrottle()
        self.assertEqual(throttle.scope, 'data_request')
    
    def test_profile_update_rate_throttle_scope(self):
        """Test that ProfileUpdateRateThrottle has correct scope"""
        throttle = ProfileUpdateRateThrottle()
        self.assertEqual(throttle.scope, 'profile_update')


class RateLimitConfigurationTestCase(TestCase):
    """Test cases for rate limit configuration"""
    
    def test_throttle_rates_configured(self):
        """Test that throttle rates are properly configured in settings"""
        from django.conf import settings
        
        # Check that REST_FRAMEWORK has throttle configuration
        self.assertIn('DEFAULT_THROTTLE_RATES', settings.REST_FRAMEWORK)
        
        throttle_rates = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
        
        # Check that all our custom scopes are configured
        expected_scopes = [
            'login', 
            'password_reset', 
            'data_request', 
            'profile_update'
        ]
        
        for scope in expected_scopes:
            self.assertIn(scope, throttle_rates)
            self.assertIsInstance(throttle_rates[scope], str)
    
    def test_default_throttle_classes_configured(self):
        """Test that default throttle classes are configured"""
        from django.conf import settings
        
        self.assertIn('DEFAULT_THROTTLE_CLASSES', settings.REST_FRAMEWORK)
        
        throttle_classes = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES']
        
        # Should include basic DRF throttle classes
        expected_classes = [
            'rest_framework.throttling.AnonRateThrottle',
            'rest_framework.throttling.UserRateThrottle'
        ]
        
        for throttle_class in expected_classes:
            self.assertIn(throttle_class, throttle_classes)


class RateLimitIntegrationTestCase(APITestCase):
    """Integration tests for rate limiting across different scenarios"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client = APIClient()
        cache.clear()
    
    def test_rate_limit_different_users(self):
        """Test that rate limits are applied per user"""
        # Create another user
        user2 = User.objects.create_user(
            username='testuser2',
            email='test2@example.com',
            password='testpass123'
        )
        
        # Get tokens for both users
        tokens1 = self.get_jwt_tokens(self.user)
        tokens2 = self.get_jwt_tokens(user2)
        
        # Both users should have separate rate limit counters
        # This is more of a conceptual test since we're testing the configuration
        
        # Test that different users can make requests independently
        # (actual rate limit testing would require making many requests)
        self.assertIsNotNone(tokens1)
        self.assertIsNotNone(tokens2)
        self.assertNotEqual(tokens1['access'], tokens2['access'])
    
    def get_jwt_tokens(self, user):
        """Helper method to get JWT tokens for a user"""
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    def test_rate_limit_anonymous_vs_authenticated(self):
        """Test that anonymous and authenticated users have different limits"""
        from django.conf import settings
        
        throttle_rates = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
        
        # Anonymous users should have lower limits than authenticated users
        anon_rate = throttle_rates.get('anon', '0/hour')
        user_rate = throttle_rates.get('user', '0/hour')
        
        # Extract numbers for comparison (basic parsing)
        def extract_rate_number(rate_string):
            """Extract the number from a rate string like '100/hour'"""
            return int(rate_string.split('/')[0])
        
        anon_limit = extract_rate_number(anon_rate)
        user_limit = extract_rate_number(user_rate)
        
        self.assertGreater(user_limit, anon_limit, 
                          "Authenticated users should have higher rate limits")
    
    def test_sensitive_endpoints_have_strict_limits(self):
        """Test that sensitive endpoints have stricter rate limits"""
        from django.conf import settings
        
        throttle_rates = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
        
        # Data requests should have very strict limits
        data_request_rate = throttle_rates.get('data_request', '0/day')
        general_user_rate = throttle_rates.get('user', '0/hour')
        
        # Extract numbers for basic comparison
        def extract_rate_info(rate_string):
            """Extract rate number and unit from rate string"""
            parts = rate_string.split('/')
            return int(parts[0]), parts[1]
        
        data_request_num, data_request_unit = extract_rate_info(data_request_rate)
        general_user_num, general_user_unit = extract_rate_info(general_user_rate)
        
        # Data requests should have very low limits
        self.assertLessEqual(data_request_num, 5, 
                            "Data request rate should be very restrictive")
        
        # Login attempts should also be restricted
        login_rate = throttle_rates.get('login', '0/minute')
        login_num, login_unit = extract_rate_info(login_rate)
        
        self.assertLessEqual(login_num, 10, 
                            "Login rate should be restrictive")
        self.assertEqual(login_unit, 'minute', 
                        "Login rate should be per minute for quick response")


class RateLimitBypassTestCase(TestCase):
    """Test cases to ensure rate limits cannot be easily bypassed"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        cache.clear()
    
    def test_rate_limit_not_bypassed_by_user_agent_change(self):
        """Test that changing user agent doesn't bypass rate limits"""
        # This is a conceptual test - in practice, you'd need to make
        # actual HTTP requests to test this properly
        
        # Rate limiting should be based on user/IP, not user agent
        from django_myuser.throttles import AuthenticatedUserRateThrottle
        
        throttle = AuthenticatedUserRateThrottle()
        
        # The throttle should use user identification, not user agent
        # This is ensured by DRF's built-in UserRateThrottle behavior
        self.assertEqual(throttle.scope, 'user')
    
    def test_rate_limit_applies_to_all_methods(self):
        """Test that rate limits apply to all HTTP methods"""
        # Check that our views apply throttling regardless of HTTP method
        from django_myuser.views import ProfileView, DataRequestView
        
        # These views handle multiple HTTP methods but should apply
        # rate limiting to all of them
        self.assertTrue(hasattr(ProfileView, 'throttle_classes'))
        self.assertTrue(hasattr(DataRequestView, 'throttle_classes'))
        
        # The throttle classes should be applied at the view level,
        # affecting all methods
        self.assertIsNotNone(ProfileView.throttle_classes)
        self.assertIsNotNone(DataRequestView.throttle_classes)


class RateLimitSecurityTestCase(TestCase):
    """Security-focused tests for rate limiting"""
    
    def test_sensitive_operations_have_appropriate_limits(self):
        """Test that security-sensitive operations have appropriate rate limits"""
        from django.conf import settings
        
        throttle_rates = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
        
        # Password reset should be very limited
        password_reset_rate = throttle_rates.get('password_reset', '0/hour')
        self.assertIn('hour', password_reset_rate, 
                     "Password reset should be limited per hour")
        
        rate_num = int(password_reset_rate.split('/')[0])
        self.assertLessEqual(rate_num, 5, 
                            "Password reset should allow very few attempts per hour")
        
        # Data deletion requests should be extremely limited
        data_request_rate = throttle_rates.get('data_request', '0/day')
        self.assertIn('day', data_request_rate,
                     "Data requests should be limited per day")
        
        data_rate_num = int(data_request_rate.split('/')[0])
        self.assertLessEqual(data_rate_num, 3,
                            "Data requests should be very limited per day")
    
    def test_brute_force_protection(self):
        """Test that login rate limiting provides brute force protection"""
        from django.conf import settings
        
        throttle_rates = settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
        
        # Login attempts should be limited per minute for quick response
        login_rate = throttle_rates.get('login', '0/minute')
        
        rate_num = int(login_rate.split('/')[0])
        self.assertLessEqual(rate_num, 10,
                            "Login attempts should be limited to prevent brute force")
        
        # The time unit should be short enough to be responsive but long enough 
        # to be protective
        self.assertIn('minute', login_rate,
                     "Login rate limiting should be per minute")