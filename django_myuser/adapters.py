from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from .models import UserSession
from .tasks import send_async_email

User = get_user_model()


class MySocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter to handle JWT token generation
    and user session creation after social authentication.
    """

    def pre_social_login(self, request, sociallogin):
        """
        Invoked just after a user successfully authenticates via a
        social provider, but before the login is actually processed
        """
        # Get the email from the social account
        email = sociallogin.account.extra_data.get('email')
        
        if email:
            try:
                # Try to find existing user with this email
                user = User.objects.get(email=email)
                # Connect the social account to the existing user
                sociallogin.connect(request, user)
            except User.DoesNotExist:
                # User doesn't exist, will be created by allauth
                pass

    def save_user(self, request, sociallogin, form=None):
        """
        Saves a newly signed up social login. In case of auto-signup,
        this method is responsible for creating the new user instance
        """
        user = super().save_user(request, sociallogin, form)
        
        # Generate JWT tokens for the user
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        # Store tokens in the request for later retrieval
        request.session['jwt_access_token'] = str(access)
        request.session['jwt_refresh_token'] = str(refresh)
        
        # Create user session record
        self.create_user_session(request, user, str(refresh))
        
        # Send welcome email asynchronously
        self.send_welcome_email(user)
        
        return user

    def create_user_session(self, request, user, refresh_token):
        """Create a UserSession record for tracking"""
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
        
        UserSession.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token=refresh_token
        )

    def get_client_ip(self, request):
        """Get the client's IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def send_welcome_email(self, user):
        """Send welcome email asynchronously"""
        if hasattr(settings, 'CELERY_BROKER_URL'):
            # Send email asynchronously using Celery
            send_async_email.delay(
                subject='Welcome to our platform!',
                template_name='account/email/welcome_message',
                context={'user': user},
                to_email=user.email
            )
        else:
            # Fallback to synchronous email sending
            from django.core.mail import send_mail
            from django.template.loader import render_to_string
            
            subject = 'Welcome to our platform!'
            message = render_to_string('account/email/welcome_message.txt', {'user': user})
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

    def is_open_for_signup(self, request, sociallogin):
        """
        Checks whether or not the site is open for signups.
        """
        return getattr(settings, 'ACCOUNT_ALLOW_REGISTRATION', True)

    def populate_user(self, request, sociallogin, data):
        """
        Populates user information from social provider data
        """
        user = super().populate_user(request, sociallogin, data)
        
        # Extract additional data from social providers
        extra_data = sociallogin.account.extra_data
        
        # Set first and last name based on provider
        if sociallogin.account.provider == 'google':
            user.first_name = extra_data.get('given_name', '')
            user.last_name = extra_data.get('family_name', '')
        elif sociallogin.account.provider == 'github':
            name = extra_data.get('name', '')
            if name:
                name_parts = name.split(' ', 1)
                user.first_name = name_parts[0]
                if len(name_parts) > 1:
                    user.last_name = name_parts[1]
        elif sociallogin.account.provider == 'facebook':
            user.first_name = extra_data.get('first_name', '')
            user.last_name = extra_data.get('last_name', '')
            
        return user


class MyAccountAdapter(DefaultAccountAdapter):
    """
    Custom account adapter for email-based authentication
    """
    
    def send_mail(self, template_prefix, email, context):
        """
        Override to send emails asynchronously
        """
        if hasattr(settings, 'CELERY_BROKER_URL'):
            # Send email asynchronously using Celery
            send_async_email.delay(
                subject=None,  # Will be determined by template
                template_name=template_prefix,
                context=context,
                to_email=email
            )
        else:
            # Use the default synchronous email sending
            super().send_mail(template_prefix, email, context)