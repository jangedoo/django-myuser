"""
Tests for audit logging functionality
"""
from unittest.mock import Mock, patch
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.core import mail
from allauth.account.signals import password_changed, user_signed_up, email_confirmed
from allauth.socialaccount.signals import social_account_added

from django_myuser.models import AuditLog, Profile, DataRequest
from django_myuser.audit_utils import create_audit_log
from django_myuser.audit_signals import (
    log_user_login, 
    log_user_logout, 
    log_login_failed,
    log_password_change,
    log_data_requests
)

User = get_user_model()


class AuditLogModelTestCase(TestCase):
    """Test cases for AuditLog model"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        self.factory = RequestFactory()
    
    def test_audit_log_creation(self):
        """Test creating an audit log entry"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            description='User logged in',
            extra_data={'session_id': 'abc123'}
        )
        
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.LOGIN)
        self.assertEqual(audit_log.ip_address, '192.168.1.1')
        self.assertEqual(audit_log.user_agent, 'Mozilla/5.0')
        self.assertEqual(audit_log.description, 'User logged in')
        self.assertEqual(audit_log.extra_data['session_id'], 'abc123')
        self.assertIsNotNone(audit_log.created_at)
    
    def test_audit_log_without_user(self):
        """Test creating an audit log entry without a user (anonymous)"""
        audit_log = AuditLog.objects.create(
            user=None,
            event_type=AuditLog.EventType.LOGIN_FAILED,
            ip_address='192.168.1.1',
            description='Failed login attempt'
        )
        
        self.assertIsNone(audit_log.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.LOGIN_FAILED)
        self.assertEqual(audit_log.description, 'Failed login attempt')
    
    def test_audit_log_str_representation(self):
        """Test the string representation of AuditLog"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            description='Test event'
        )
        
        expected = f"testuser - Login at {audit_log.created_at}"
        self.assertEqual(str(audit_log), expected)
    
    def test_audit_log_str_representation_anonymous(self):
        """Test the string representation of AuditLog for anonymous users"""
        audit_log = AuditLog.objects.create(
            user=None,
            event_type=AuditLog.EventType.LOGIN_FAILED,
            description='Test event'
        )
        
        expected = f"Anonymous - Login Failed at {audit_log.created_at}"
        self.assertEqual(str(audit_log), expected)
    
    def test_audit_log_ordering(self):
        """Test that audit logs are ordered by creation date (newest first)"""
        # Create multiple audit logs
        log1 = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            description='First log'
        )
        log2 = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGOUT,
            description='Second log'
        )
        log3 = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            description='Third log'
        )
        
        # Get all logs
        logs = list(AuditLog.objects.all())
        
        # Should be ordered newest first
        self.assertEqual(logs[0], log3)
        self.assertEqual(logs[1], log2)
        self.assertEqual(logs[2], log1)


class AuditUtilsTestCase(TestCase):
    """Test cases for audit utility functions"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.factory = RequestFactory()
    
    def test_create_audit_log_with_request(self):
        """Test creating audit log with request metadata"""
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'Test Browser'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        audit_log = create_audit_log(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            request=request,
            description='Test login',
            extra_data={'test': 'data'}
        )
        
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.LOGIN)
        self.assertEqual(audit_log.ip_address, '192.168.1.1')
        self.assertEqual(audit_log.user_agent, 'Test Browser')
        self.assertEqual(audit_log.description, 'Test login')
        self.assertEqual(audit_log.extra_data['test'], 'data')
    
    def test_create_audit_log_with_forwarded_ip(self):
        """Test creating audit log with X-Forwarded-For header"""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.195, 70.41.3.18, 150.172.238.178'
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        audit_log = create_audit_log(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            request=request
        )
        
        # Should use the first IP from X-Forwarded-For
        self.assertEqual(audit_log.ip_address, '203.0.113.195')
    
    def test_create_audit_log_without_request(self):
        """Test creating audit log without request"""
        audit_log = create_audit_log(
            user=self.user,
            event_type=AuditLog.EventType.ACCOUNT_CREATED,
            description='Account created programmatically'
        )
        
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.ACCOUNT_CREATED)
        self.assertIsNone(audit_log.ip_address)
        self.assertEqual(audit_log.user_agent, '')
        self.assertEqual(audit_log.description, 'Account created programmatically')


class AuditSignalsTestCase(TestCase):
    """Test cases for audit signal handlers"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.factory = RequestFactory()
    
    def test_log_user_login_signal(self):
        """Test that user login creates an audit log"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        # Simulate the login signal
        user_logged_in.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN
        )
        self.assertIn('logged in successfully', audit_log.description)
        self.assertEqual(audit_log.ip_address, '192.168.1.1')
    
    def test_log_user_logout_signal(self):
        """Test that user logout creates an audit log"""
        request = self.factory.post('/logout/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        # Simulate the logout signal
        user_logged_out.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            user=self.user,
            event_type=AuditLog.EventType.LOGOUT
        )
        self.assertIn('logged out', audit_log.description)
        self.assertEqual(audit_log.ip_address, '192.168.1.1')
    
    def test_log_login_failed_signal(self):
        """Test that failed login creates an audit log"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        # Simulate the login failed signal
        user_login_failed.send(
            sender=None,
            credentials={'username': 'testuser'},
            request=request
        )
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            event_type=AuditLog.EventType.LOGIN_FAILED
        )
        self.assertIsNone(audit_log.user)  # No user for failed login
        self.assertIn('Failed login attempt', audit_log.description)
        self.assertEqual(audit_log.extra_data['username'], 'testuser')
    
    @patch('django_myuser.audit_signals.send_async_email')
    def test_log_password_change_signal(self, mock_send_email):
        """Test that password change creates audit log and sends email"""
        request = self.factory.post('/password/change/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        # Simulate the password changed signal
        password_changed.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            user=self.user,
            event_type=AuditLog.EventType.PASSWORD_CHANGE
        )
        self.assertIn('Password changed', audit_log.description)
        
        # Check that email task was queued
        mock_send_email.delay.assert_called_once()
        args, kwargs = mock_send_email.delay.call_args
        self.assertEqual(kwargs['subject'], 'Password Changed - Security Alert')
        self.assertEqual(kwargs['to_email'], self.user.email)
    
    def test_log_data_request_creation(self):
        """Test that data request creation creates audit log"""
        data_request = DataRequest.objects.create(
            user=self.user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            user=self.user,
            event_type=AuditLog.EventType.DATA_EXPORT_REQUESTED
        )
        self.assertIn('Data export request submitted', audit_log.description)
        self.assertEqual(
            audit_log.extra_data['request_id'], 
            str(data_request.id)
        )
    
    def test_log_profile_update(self):
        """Test that profile updates create audit logs"""
        # Create profile
        profile = self.user.profile
        
        # Update marketing consent
        profile.marketing_consent = True
        profile.save()
        
        # Check that audit log was created
        audit_log = AuditLog.objects.get(
            user=self.user,
            event_type=AuditLog.EventType.PROFILE_UPDATE
        )
        self.assertIn('Profile updated', audit_log.description)
        changes = audit_log.extra_data['changes']
        self.assertEqual(changes['marketing_consent']['old'], False)
        self.assertEqual(changes['marketing_consent']['new'], True)


class AuditLogQuerySetTestCase(TestCase):
    """Test cases for AuditLog queryset and filtering"""
    
    def setUp(self):
        """Set up test data"""
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com'
        )
        
        # Create some audit logs
        AuditLog.objects.create(
            user=self.user1,
            event_type=AuditLog.EventType.LOGIN,
            description='User1 login'
        )
        AuditLog.objects.create(
            user=self.user1,
            event_type=AuditLog.EventType.LOGOUT,
            description='User1 logout'
        )
        AuditLog.objects.create(
            user=self.user2,
            event_type=AuditLog.EventType.LOGIN,
            description='User2 login'
        )
        AuditLog.objects.create(
            user=None,
            event_type=AuditLog.EventType.LOGIN_FAILED,
            description='Anonymous failed login'
        )
    
    def test_filter_by_user(self):
        """Test filtering audit logs by user"""
        user1_logs = AuditLog.objects.filter(user=self.user1)
        self.assertEqual(user1_logs.count(), 2)
        
        user2_logs = AuditLog.objects.filter(user=self.user2)
        self.assertEqual(user2_logs.count(), 1)
    
    def test_filter_by_event_type(self):
        """Test filtering audit logs by event type"""
        login_logs = AuditLog.objects.filter(event_type=AuditLog.EventType.LOGIN)
        self.assertEqual(login_logs.count(), 2)
        
        failed_login_logs = AuditLog.objects.filter(
            event_type=AuditLog.EventType.LOGIN_FAILED
        )
        self.assertEqual(failed_login_logs.count(), 1)
    
    def test_filter_anonymous_events(self):
        """Test filtering for anonymous events"""
        anonymous_logs = AuditLog.objects.filter(user__isnull=True)
        self.assertEqual(anonymous_logs.count(), 1)
        self.assertEqual(
            anonymous_logs.first().event_type, 
            AuditLog.EventType.LOGIN_FAILED
        )
    
    def test_get_user_activity(self):
        """Test getting all activity for a specific user"""
        user1_activity = AuditLog.objects.filter(
            user=self.user1
        ).order_by('-created_at')
        
        self.assertEqual(user1_activity.count(), 2)
        # Should be ordered newest first
        self.assertEqual(user1_activity.first().event_type, AuditLog.EventType.LOGOUT)
        self.assertEqual(user1_activity.last().event_type, AuditLog.EventType.LOGIN)


class AuditLogIntegrationTestCase(TestCase):
    """Integration tests for audit logging across the system"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.factory = RequestFactory()
    
    @patch('django_myuser.signals.send_async_email.delay')
    def test_full_user_journey_audit_trail(self, mock_send_email):
        """Test that a complete user journey creates proper audit trail"""
        request = self.factory.post('/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Test Browser'
        
        # 1. User signs up (should be logged by signal)
        user_signed_up.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # 2. User logs in
        user_logged_in.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # 3. User updates profile
        profile = self.user.profile
        profile.marketing_consent = True
        profile.save()
        
        # 4. User creates data request
        DataRequest.objects.create(
            user=self.user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        # 5. User logs out
        user_logged_out.send(
            sender=User,
            request=request,
            user=self.user
        )
        
        # Verify all events were logged
        user_logs = AuditLog.objects.filter(user=self.user).order_by('created_at')
        
        self.assertEqual(user_logs.count(), 5)
        
        events = [log.event_type for log in user_logs]
        expected_events = [
            AuditLog.EventType.ACCOUNT_CREATED,
            AuditLog.EventType.LOGIN,
            AuditLog.EventType.PROFILE_UPDATE,
            AuditLog.EventType.DATA_EXPORT_REQUESTED,
            AuditLog.EventType.LOGOUT,
        ]
        
        self.assertEqual(events, expected_events)
        
        # Verify IP addresses were captured
        for log in user_logs:
            if log.event_type in [AuditLog.EventType.LOGIN, AuditLog.EventType.LOGOUT]:
                self.assertEqual(log.ip_address, '192.168.1.1')
                self.assertEqual(log.user_agent, 'Test Browser')
        
        # Verify that welcome email was queued
        mock_send_email.assert_called()