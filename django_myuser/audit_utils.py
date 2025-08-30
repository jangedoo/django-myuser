"""
Utility functions for audit logging
"""
from .models import AuditLog


def create_audit_log(user, event_type, request=None, description='', extra_data=None):
    """
    Create an audit log entry with request metadata
    """
    ip_address = None
    user_agent = ''
    
    if request and hasattr(request, 'META'):
        # Get IP address from request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    return AuditLog.objects.create(
        user=user,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        description=description,
        extra_data=extra_data or {}
    )