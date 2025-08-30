"""
Additional signal handlers for audit logging
"""
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from allauth.account.signals import password_changed, password_reset

from .models import AuditLog, Profile, DataRequest
from .audit_utils import create_audit_log
from .tasks import send_async_email


# Authentication-related audit signals
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful user login"""
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.LOGIN,
        request=request,
        description=f"User {user.username} logged in successfully"
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout"""
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.LOGOUT,
        request=request,
        description=f"User {user.username} logged out"
    )


@receiver(user_login_failed)
def log_login_failed(sender, credentials, request, **kwargs):
    """Log failed login attempts"""
    username = credentials.get('username', 'unknown')
    create_audit_log(
        user=None,
        event_type=AuditLog.EventType.LOGIN_FAILED,
        request=request,
        description=f"Failed login attempt for username: {username}",
        extra_data={'username': username}
    )


@receiver(password_changed)
def log_password_change(sender, request, user, **kwargs):
    """Log password changes"""
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.PASSWORD_CHANGE,
        request=request,
        description=f"Password changed for user {user.username}"
    )
    
    # Send security notification email
    if hasattr(settings, 'CELERY_BROKER_URL'):
        send_async_email.delay(
            subject='Password Changed - Security Alert',
            template_name='account/email/password_change_alert',
            context={'user': user},
            to_email=user.email
        )


@receiver(password_reset)
def log_password_reset(sender, request, user, **kwargs):
    """Log password reset events"""
    create_audit_log(
        user=user,
        event_type=AuditLog.EventType.PASSWORD_RESET,
        request=request,
        description=f"Password reset initiated for user {user.username}"
    )


@receiver(pre_save, sender=Profile)
def log_profile_updates(sender, instance, **kwargs):
    """Log profile updates for audit purposes"""
    if instance.pk:  # Only for existing profiles
        try:
            old_profile = Profile.objects.get(pk=instance.pk)
            changes = {}
            
            if old_profile.marketing_consent != instance.marketing_consent:
                changes['marketing_consent'] = {
                    'old': old_profile.marketing_consent,
                    'new': instance.marketing_consent
                }
            
            if changes:
                create_audit_log(
                    user=instance.user,
                    event_type=AuditLog.EventType.PROFILE_UPDATE,
                    description=f"Profile updated for user {instance.user.username}",
                    extra_data={'changes': changes}
                )
        except Profile.DoesNotExist:
            pass


@receiver(post_save, sender=DataRequest)
def log_data_requests(sender, instance, created, **kwargs):
    """Log data export/deletion requests"""
    if created:
        event_type = (
            AuditLog.EventType.DATA_EXPORT_REQUESTED 
            if instance.request_type == DataRequest.RequestType.EXPORT 
            else AuditLog.EventType.DATA_DELETE_REQUESTED
        )
        
        create_audit_log(
            user=instance.user,
            event_type=event_type,
            description=f"Data {instance.request_type.lower()} request submitted",
            extra_data={
                'request_id': str(instance.id),
                'request_type': instance.request_type
            }
        )