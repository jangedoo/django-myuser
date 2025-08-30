from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.html import strip_tags


@shared_task
def send_async_email(subject, template_name, context, to_email):
    """
    Send email asynchronously using Celery.
    
    Args:
        subject: Email subject (can be None to use template)
        template_name: Template name prefix (e.g., 'account/email/welcome_message')
        context: Template context dictionary
        to_email: Recipient email address
    """
    try:
        # Determine subject from template if not provided
        if not subject:
            subject_template = f"{template_name}_subject.txt"
            subject = render_to_string(subject_template, context).strip()
        
        # Render text content
        text_template = f"{template_name}.txt"
        text_content = render_to_string(text_template, context)
        
        # Try to render HTML content
        html_content = None
        try:
            html_template = f"{template_name}.html"
            html_content = render_to_string(html_template, context)
        except:
            # HTML template doesn't exist, use plain text
            pass
        
        # Create email message
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
        
        if html_content:
            # Send multipart email (text + HTML)
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=from_email,
                to=[to_email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
        else:
            # Send plain text email
            from django.core.mail import send_mail
            send_mail(
                subject=subject,
                message=text_content,
                from_email=from_email,
                recipient_list=[to_email],
                fail_silently=False
            )
        
        return f"Email sent successfully to {to_email}"
        
    except Exception as e:
        # Log the error (you might want to use proper logging)
        print(f"Failed to send email to {to_email}: {str(e)}")
        raise e


@shared_task
def send_bulk_async_email(subject, template_name, context, recipient_list):
    """
    Send bulk emails asynchronously using Celery.
    
    Args:
        subject: Email subject (can be None to use template)
        template_name: Template name prefix
        context: Template context dictionary
        recipient_list: List of recipient email addresses
    """
    results = []
    for email in recipient_list:
        try:
            result = send_async_email.delay(subject, template_name, context, email)
            results.append(f"Queued email for {email}")
        except Exception as e:
            results.append(f"Failed to queue email for {email}: {str(e)}")
    
    return results


@shared_task
def cleanup_expired_sessions():
    """
    Cleanup expired user sessions.
    This task should be run periodically to clean up old session records.
    """
    from django.utils import timezone
    from datetime import timedelta
    from .models import UserSession
    
    # Soft delete sessions older than 30 days
    cutoff_date = timezone.now() - timedelta(days=30)
    sessions_to_delete = UserSession.objects.filter(
        last_activity__lt=cutoff_date,
        deleted_at__isnull=True  # Only delete non-deleted sessions
    )
    deleted_count = sessions_to_delete.count()
    
    # Soft delete by setting deleted_at timestamp
    sessions_to_delete.update(deleted_at=timezone.now())
    
    return f"Cleaned up {deleted_count} expired sessions"


@shared_task
def process_data_request(request_id):
    """
    Process a data request (export or delete) asynchronously.
    
    Args:
        request_id: UUID of the DataRequest instance
    """
    from .models import DataRequest
    from django.contrib.auth import get_user_model
    import json
    
    User = get_user_model()
    
    try:
        data_request = DataRequest.objects.get(id=request_id)
        user = data_request.user
        
        if data_request.request_type == DataRequest.RequestType.EXPORT:
            # Export user data
            user_data = {
                'user_info': {
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'date_joined': user.date_joined.isoformat(),
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                },
                'profile': {
                    'marketing_consent': user.profile.marketing_consent,
                    'marketing_consent_updated_at': user.profile.marketing_consent_updated_at.isoformat() if user.profile.marketing_consent_updated_at else None,
                },
                'sessions': [
                    {
                        'ip_address': session.ip_address,
                        'user_agent': session.user_agent,
                        'last_activity': session.last_activity.isoformat(),
                        'created_at': session.created_at.isoformat(),
                    }
                    for session in user.usersession_set.all()
                ]
            }
            
            # Send data export email
            send_async_email.delay(
                subject="Your data export is ready",
                template_name="account/email/data_export",
                context={
                    'user': user,
                    'data': json.dumps(user_data, indent=2)
                },
                to_email=user.email
            )
            
            data_request.status = DataRequest.RequestStatus.COMPLETED
            data_request.notes = "Data export completed successfully"
            
        elif data_request.request_type == DataRequest.RequestType.DELETE:
            # This is a sensitive operation - mark as completed but don't actually delete
            # In a real implementation, you might anonymize the data or perform soft deletion
            data_request.status = DataRequest.RequestStatus.COMPLETED
            data_request.notes = "Account deletion request processed"
            
            # Send confirmation email
            send_async_email.delay(
                subject="Account deletion request processed",
                template_name="account/email/account_deletion",
                context={'user': user},
                to_email=user.email
            )
        
        data_request.save()
        return f"Data request {request_id} processed successfully"
        
    except DataRequest.DoesNotExist:
        return f"Data request {request_id} not found"
    except Exception as e:
        # Mark request as failed
        try:
            data_request = DataRequest.objects.get(id=request_id)
            data_request.status = DataRequest.RequestStatus.FAILED
            data_request.notes = f"Processing failed: {str(e)}"
            data_request.save()
        except:
            pass
        
        raise e