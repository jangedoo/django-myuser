from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from allauth.socialaccount.signals import social_account_added, social_account_updated
from allauth.account.signals import user_signed_up, email_confirmed, password_changed, password_reset
from .models import Profile, AuditLog, DataRequest
from .tasks import send_async_email
from .audit_utils import create_audit_log


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_user_profile(sender, instance, **kwargs):
    # This signal is problematic as it will cause an infinite loop if the user is saved in the profile save method.
    # A better approach is to have the profile saved explicitly when needed.
    # For now, we will just save the profile.
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(pre_save, sender=Profile)
def update_marketing_consent_timestamp(sender, instance, **kwargs):
    """
    Update the marketing_consent_updated_at timestamp when consent changes
    """
    if instance.pk:  # Only for existing profiles
        try:
            old_profile = Profile.objects.get(pk=instance.pk)
            if old_profile.marketing_consent != instance.marketing_consent:
                instance.marketing_consent_updated_at = timezone.now()
        except Profile.DoesNotExist:
            pass


@receiver(social_account_added)
def social_account_added_handler(sender, request, sociallogin, **kwargs):
    """
    Handle when a social account is added to a user
    """
    user = sociallogin.user
    provider = sociallogin.account.provider
    
    # Log the social account connection
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.SOCIAL_ACCOUNT_CONNECTED,
        request=request,
        description=f"Connected {provider} social account",
        extra_data={'provider': provider}
    )
    
    # Send notification email about connected social account
    if hasattr(settings, 'CELERY_BROKER_URL'):
        send_async_email.delay(
            subject=f'{provider.title()} account connected',
            template_name='socialaccount/email/social_account_connected',
            context={
                'user': user,
                'provider': provider,
                'provider_display': provider.title()
            },
            to_email=user.email
        )


@receiver(social_account_updated)
def social_account_updated_handler(sender, request, sociallogin, **kwargs):
    """
    Handle when a social account is updated
    """
    user = sociallogin.user
    provider = sociallogin.account.provider
    
    # Log the update (you might want to add this to AuditLog model in the future)
    print(f"Social account updated: {user.email} - {provider}")


@receiver(user_signed_up)
def user_signed_up_handler(sender, request, user, **kwargs):
    """
    Handle when a new user signs up (either through regular signup or social)
    """
    # Log the account creation
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.ACCOUNT_CREATED,
        request=request,
        description=f"New user account created: {user.username}"
    )
    
    # Send welcome email
    if hasattr(settings, 'CELERY_BROKER_URL'):
        send_async_email.delay(
            subject='Welcome to our platform!',
            template_name='account/email/welcome_message',
            context={'user': user},
            to_email=user.email
        )


@receiver(email_confirmed)
def email_confirmed_handler(sender, request, email_address, **kwargs):
    """
    Handle when a user confirms their email address
    """
    user = email_address.user
    
    # Log the email confirmation event
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.EMAIL_CONFIRMED,
        request=request,
        description=f"Email confirmed: {email_address.email}",
        extra_data={'email': email_address.email}
    )
    
    # Send email confirmation success notification
    if hasattr(settings, 'CELERY_BROKER_URL'):
        send_async_email.delay(
            subject='Email confirmed successfully',
            template_name='account/email/email_confirmed',
            context={
                'user': user,
                'email_address': email_address.email
            },
            to_email=user.email
        )
