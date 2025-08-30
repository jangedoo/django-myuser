from unittest.mock import Mock, patch
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.template.loader import render_to_string

from django_myuser.tasks import (
    send_async_email,
    send_bulk_async_email,
    cleanup_expired_sessions,
    process_data_request
)
from django_myuser.models import UserSession, DataRequest, Profile

User = get_user_model()


class AsyncEmailTaskTestCase(TestCase):
    """Test cases for async email tasks"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    @patch('django_myuser.tasks.render_to_string')
    def test_send_async_email_with_subject(self, mock_render):
        """Test sending async email with provided subject"""
        context = {'user': self.user}
        
        # Mock the template rendering
        mock_render.return_value = 'Test email content'
        
        result = send_async_email(
            subject='Test Subject',
            template_name='test/email_template',
            context=context,
            to_email=self.user.email
        )
        
        self.assertIn('Email sent successfully', result)
        
        # Verify email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertEqual(sent_email.subject, 'Test Subject')
        self.assertEqual(sent_email.to, [self.user.email])
        self.assertEqual(sent_email.body, 'Test email content')
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    @patch('django_myuser.tasks.render_to_string')
    def test_send_async_email_subject_from_template(self, mock_render):
        """Test sending async email with subject from template"""
        context = {'user': self.user}
        
        # Mock both subject and body templates
        def side_effect(template_name, context):
            if template_name.endswith('_subject.txt'):
                return 'Template Subject'
            else:
                return 'Template email content'
        
        mock_render.side_effect = side_effect
        
        result = send_async_email(
            subject=None,  # Let template determine subject
            template_name='test/email_template',
            context=context,
            to_email=self.user.email
        )
        
        self.assertIn('Email sent successfully', result)
        
        # Verify email was sent with template subject
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertEqual(sent_email.subject, 'Template Subject')
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    @patch('django_myuser.tasks.render_to_string')
    def test_send_async_email_with_html(self, mock_render):
        """Test sending async email with HTML content"""
        context = {'user': self.user}
        
        def side_effect(template_name, context):
            if template_name.endswith('.html'):
                return '<p>HTML email content</p>'
            else:
                return 'Plain text email content'
        
        mock_render.side_effect = side_effect
        
        result = send_async_email(
            subject='Test HTML Email',
            template_name='test/email_template',
            context=context,
            to_email=self.user.email
        )
        
        self.assertIn('Email sent successfully', result)
        
        # Verify email was sent with both text and HTML
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertEqual(sent_email.subject, 'Test HTML Email')
        self.assertTrue(hasattr(sent_email, 'alternatives'))
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch('django_myuser.tasks.render_to_string')
    def test_send_async_email_error_handling(self, mock_render):
        """Test error handling in send_async_email task"""
        mock_render.side_effect = Exception('Template rendering failed')
        
        with self.assertRaises(Exception):
            send_async_email(
                subject='Test Subject',
                template_name='non_existent_template',
                context={'user': self.user},
                to_email=self.user.email
            )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_send_bulk_async_email(self):
        """Test sending bulk async emails"""
        recipient_list = ['user1@example.com', 'user2@example.com', 'user3@example.com']
        context = {'message': 'Bulk email test'}
        
        with patch('django_myuser.tasks.send_async_email.delay') as mock_send:
            mock_send.return_value = Mock()
            
            results = send_bulk_async_email(
                subject='Bulk Email Test',
                template_name='test/bulk_email',
                context=context,
                recipient_list=recipient_list
            )
        
        # Verify all emails were queued
        self.assertEqual(len(results), 3)
        self.assertEqual(mock_send.call_count, 3)
        
        # Check that each result indicates success
        for result in results:
            self.assertIn('Queued email for', result)


class SessionCleanupTaskTestCase(TestCase):
    """Test cases for session cleanup task"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired user sessions"""
        from django.utils import timezone
        from datetime import timedelta
        
        # Create recent session (should not be deleted)
        recent_session = UserSession.objects.create(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Recent Browser',
            refresh_token='recent-token'
        )
        
        # Create old session (should be deleted)
        old_session = UserSession.objects.create(
            user=self.user,
            ip_address='192.168.1.2',
            user_agent='Old Browser',
            refresh_token='old-token'
        )
        
        # Manually set the last_activity to be older than 30 days using update to bypass auto_now
        old_date = timezone.now() - timedelta(days=35)
        UserSession.objects.filter(id=old_session.id).update(last_activity=old_date)
        
        # Run cleanup task
        result = cleanup_expired_sessions()
        
        # Verify old session was deleted
        self.assertFalse(UserSession.objects.filter(id=old_session.id).exists())
        # Verify recent session was kept
        self.assertTrue(UserSession.objects.filter(id=recent_session.id).exists())
        
        self.assertIn('Cleaned up 1 expired sessions', result)


class DataRequestProcessingTaskTestCase(TestCase):
    """Test cases for data request processing task"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        self.profile = Profile.objects.get(user=self.user)
        self.profile.marketing_consent = True
        self.profile.save()
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch('django_myuser.tasks.send_async_email.delay')
    def test_process_data_export_request(self, mock_send_email):
        """Test processing a data export request"""
        # Create a data export request
        data_request = DataRequest.objects.create(
            user=self.user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        # Create some user sessions for export
        UserSession.objects.create(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Test Browser',
            refresh_token='test-token'
        )
        
        # Process the request
        result = process_data_request(data_request.id)
        
        # Verify request was marked as completed
        data_request.refresh_from_db()
        self.assertEqual(data_request.status, DataRequest.RequestStatus.COMPLETED)
        self.assertEqual(data_request.notes, 'Data export completed successfully')
        
        # Verify email was sent
        mock_send_email.assert_called_once()
        call_kwargs = mock_send_email.call_args[1]
        self.assertEqual(call_kwargs['subject'], 'Your data export is ready')
        self.assertEqual(call_kwargs['to_email'], self.user.email)
        
        self.assertIn('processed successfully', result)
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch('django_myuser.tasks.send_async_email.delay')
    def test_process_data_deletion_request(self, mock_send_email):
        """Test processing a data deletion request"""
        # Create a data deletion request
        data_request = DataRequest.objects.create(
            user=self.user,
            request_type=DataRequest.RequestType.DELETE
        )
        
        # Process the request
        result = process_data_request(data_request.id)
        
        # Verify request was marked as completed
        data_request.refresh_from_db()
        self.assertEqual(data_request.status, DataRequest.RequestStatus.COMPLETED)
        self.assertEqual(data_request.notes, 'Account deletion request processed')
        
        # Verify email was sent
        mock_send_email.assert_called_once()
        call_kwargs = mock_send_email.call_args[1]
        self.assertEqual(call_kwargs['subject'], 'Account deletion request processed')
        self.assertEqual(call_kwargs['to_email'], self.user.email)
        
        self.assertIn('processed successfully', result)
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_process_nonexistent_data_request(self):
        """Test processing a non-existent data request"""
        import uuid
        
        fake_id = uuid.uuid4()
        result = process_data_request(fake_id)
        
        self.assertEqual(result, f'Data request {fake_id} not found')
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_process_data_request_with_error(self):
        """Test error handling in data request processing"""
        # Create a data export request
        data_request = DataRequest.objects.create(
            user=self.user,
            request_type=DataRequest.RequestType.EXPORT
        )
        
        # Mock an error during processing
        with patch('django_myuser.tasks.send_async_email.delay') as mock_send_email:
            mock_send_email.side_effect = Exception('Email sending failed')
            
            with self.assertRaises(Exception):
                process_data_request(data_request.id)
            
            # Verify request was marked as failed
            data_request.refresh_from_db()
            self.assertEqual(data_request.status, DataRequest.RequestStatus.FAILED)
            self.assertIn('Processing failed', data_request.notes)


class EmailTemplateRenderingTestCase(TestCase):
    """Test cases for email template rendering"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    @patch('django.template.loader.render_to_string')
    def test_welcome_email_template_rendering(self, mock_render):
        """Test that welcome email templates render correctly"""
        context = {'user': self.user}
        
        def side_effect(template_name, context):
            if 'welcome_message.txt' in template_name:
                return f'Welcome to our platform, {context["user"].username}!'
            elif 'welcome_message.html' in template_name:
                return f'<h1>🎉 Welcome!</h1><p>Welcome {context["user"].username}!</p>'
            return 'Default content'
        
        mock_render.side_effect = side_effect
        
        # Test text template rendering
        text_content = mock_render(
            'account/email/welcome_message.txt',
            context
        )
        self.assertIn('Welcome to our platform', text_content)
        self.assertIn(self.user.username, text_content)
        
        # Test HTML template rendering
        html_content = mock_render(
            'account/email/welcome_message.html',
            context
        )
        self.assertIn('<h1>🎉 Welcome!</h1>', html_content)
        self.assertIn(self.user.username, html_content)
    
    @patch('django.template.loader.render_to_string')
    def test_social_account_connected_template_rendering(self, mock_render):
        """Test social account connected email template rendering"""
        context = {
            'user': self.user,
            'provider': 'google',
            'provider_display': 'Google'
        }
        
        def side_effect(template_name, context):
            if 'social_account_connected.txt' in template_name:
                return f'{context["provider_display"]} account has been successfully connected to {context["user"].username}!'
            elif 'social_account_connected.html' in template_name:
                return f'<h1>🔗 Account Connected</h1><p>{context["provider_display"]} account has been successfully connected!</p>'
            return 'Default content'
        
        mock_render.side_effect = side_effect
        
        # Test text template rendering
        text_content = mock_render(
            'socialaccount/email/social_account_connected.txt',
            context
        )
        self.assertIn('Google account has been successfully connected', text_content)
        self.assertIn(self.user.username, text_content)
        
        # Test HTML template rendering
        html_content = mock_render(
            'socialaccount/email/social_account_connected.html',
            context
        )
        self.assertIn('🔗 Account Connected', html_content)
        self.assertIn('Google account has been successfully connected', html_content)


class EmailIntegrationTestCase(TestCase):
    """Integration tests for email functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    @patch('django_myuser.tasks.render_to_string')
    def test_complete_email_flow(self, mock_render):
        """Test complete email sending flow with templates"""
        # Mock template rendering
        mock_render.return_value = f'Welcome to our platform, {self.user.username}!'
        
        # Test sending welcome email
        result = send_async_email(
            subject='Welcome!',
            template_name='account/email/welcome_message',
            context={'user': self.user},
            to_email=self.user.email
        )
        
        self.assertIn('Email sent successfully', result)
        
        # Verify email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertEqual(sent_email.subject, 'Welcome!')
        self.assertEqual(sent_email.to, [self.user.email])
        
        # Verify content contains user information
        self.assertIn(self.user.username, sent_email.body)
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_email_error_recovery(self):
        """Test email error handling and recovery"""
        # Test with invalid template
        with self.assertRaises(Exception):
            send_async_email(
                subject='Test',
                template_name='non/existent/template',
                context={'user': self.user},
                to_email=self.user.email
            )
    
    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_bulk_email_integration(self):
        """Test bulk email integration"""
        recipients = [
            'user1@example.com',
            'user2@example.com',
            'user3@example.com'
        ]
        
        with patch('django_myuser.tasks.send_async_email.delay') as mock_send:
            # Mock successful email sending
            mock_send.return_value = Mock()
            
            results = send_bulk_async_email(
                subject='Bulk Test',
                template_name='account/email/welcome_message',
                context={'user': self.user},
                recipient_list=recipients
            )
        
        # Verify all emails were queued
        self.assertEqual(len(results), 3)
        self.assertEqual(mock_send.call_count, 3)
        
        # Verify each call was made with correct parameters
        for call in mock_send.call_args_list:
            args = call[0]  # positional arguments
            self.assertEqual(args[0], 'Bulk Test')  # subject
            self.assertEqual(args[1], 'account/email/welcome_message')  # template_name
            self.assertEqual(args[2], {'user': self.user})  # context
            self.assertIn(args[3], recipients)  # to_email