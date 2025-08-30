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
    from .models import DataRequest, DataExportFile
    from .exporters import export_user_data
    from django.contrib.auth import get_user_model
    from django.conf import settings
    import os
    
    User = get_user_model()
    
    try:
        data_request = DataRequest.objects.get(id=request_id)
        user = data_request.user
        
        if data_request.request_type == DataRequest.RequestType.EXPORT:
            # Use exporter to generate file - exporters handle all data collection
            file_path = export_user_data(data_request, user)
            
            # Get file size
            full_path = os.path.join(settings.MEDIA_ROOT, file_path)
            file_size = os.path.getsize(full_path)
            
            # Create DataExportFile record
            export_file = DataExportFile.objects.create(
                data_request=data_request,
                file_path=file_path,
                file_size=file_size
            )
            
            # Build download URL
            from django.contrib.sites.models import Site
            try:
                site = Site.objects.get_current()
                domain = f"https://{site.domain}"
            except:
                # Fallback if sites framework not configured
                config = getattr(settings, 'DJANGO_MYUSER', {})
                domain = config.get('BASE_URL', 'https://example.com')
            
            download_url = f"{domain}/api/auth/data-export/download/{export_file.download_token}/"
            
            # Send notification email with download link
            send_async_email.delay(
                subject="Your data export is ready",
                template_name="account/email/data_export",
                context={
                    'user_id': str(user.id),
                    'username': user.username,
                    'email': user.email,
                    'download_token': export_file.download_token,
                    'download_url': download_url,
                    'expires_at': export_file.expires_at.isoformat(),
                    'file_size_mb': round(file_size / (1024 * 1024), 2)
                },
                to_email=user.email
            )
            
            data_request.status = DataRequest.RequestStatus.COMPLETED
            data_request.notes = "Data export file created successfully"
            
        elif data_request.request_type == DataRequest.RequestType.DELETE:
            # This is a sensitive operation - mark as completed but don't actually delete
            # In a real implementation, you might anonymize the data or perform soft deletion
            data_request.status = DataRequest.RequestStatus.COMPLETED
            data_request.notes = "Account deletion request processed"
            
            # Send confirmation email
            send_async_email.delay(
                subject="Account deletion request processed",
                template_name="account/email/account_deletion",
                context={
                    'user_id': str(user.id),
                    'username': user.username,
                    'email': user.email
                },
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


@shared_task
def cleanup_expired_exports():
    """
    Cleanup expired data export files.
    
    This task should be run periodically to clean up old export files
    and their database records.
    """
    from .models import DataExportFile
    from django.utils import timezone
    from django.conf import settings
    import os
    
    # Find expired files
    expired_files = DataExportFile.objects.filter(
        expires_at__lt=timezone.now(),
        deleted_at__isnull=True
    )
    
    cleanup_count = 0
    error_count = 0
    
    for export_file in expired_files:
        try:
            # Delete physical file
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
            
            # Soft delete database record
            export_file.delete()
            cleanup_count += 1
            
        except Exception as e:
            error_count += 1
            # Log error but continue with other files
            print(f"Failed to clean up export file {export_file.id}: {str(e)}")
    
    result_message = f"Cleaned up {cleanup_count} expired export files"
    if error_count > 0:
        result_message += f" (with {error_count} errors)"
    
    return result_message