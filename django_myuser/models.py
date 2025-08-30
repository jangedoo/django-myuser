import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone


class SoftDeleteManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = SoftDeleteManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False):
        self.deleted_at = timezone.now()
        self.save()

    def hard_delete(self, using=None, keep_parents=False):
        super().delete(using, keep_parents)


class Profile(BaseModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    marketing_consent = models.BooleanField(default=False)
    marketing_consent_updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.user.username


class DataRequest(BaseModel):
    class RequestType(models.TextChoices):
        EXPORT = 'EXPORT', 'Export'
        DELETE = 'DELETE', 'Delete'

    class RequestStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request_type = models.CharField(max_length=10, choices=RequestType.choices)
    status = models.CharField(max_length=10, choices=RequestStatus.choices, default=RequestStatus.PENDING)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_request_type_display()}"


class UserSession(BaseModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=255)
    refresh_token = models.TextField()  # This will be improved later
    last_activity = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"


class AuditLog(BaseModel):
    class EventType(models.TextChoices):
        LOGIN = 'LOGIN', 'Login'
        LOGOUT = 'LOGOUT', 'Logout'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
        PASSWORD_CHANGE = 'PASSWORD_CHANGE', 'Password Change'
        PASSWORD_RESET = 'PASSWORD_RESET', 'Password Reset'
        ACCOUNT_CREATED = 'ACCOUNT_CREATED', 'Account Created'
        ACCOUNT_DELETED = 'ACCOUNT_DELETED', 'Account Deleted'
        PROFILE_UPDATE = 'PROFILE_UPDATE', 'Profile Update'
        SOCIAL_ACCOUNT_CONNECTED = 'SOCIAL_ACCOUNT_CONNECTED', 'Social Account Connected'
        SOCIAL_ACCOUNT_DISCONNECTED = 'SOCIAL_ACCOUNT_DISCONNECTED', 'Social Account Disconnected'
        DATA_EXPORT_REQUESTED = 'DATA_EXPORT_REQUESTED', 'Data Export Requested'
        DATA_DELETE_REQUESTED = 'DATA_DELETE_REQUESTED', 'Data Delete Requested'
        EMAIL_CONFIRMED = 'EMAIL_CONFIRMED', 'Email Confirmed'
        SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY', 'Suspicious Activity'
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        help_text="User associated with the event (null for anonymous events)"
    )
    event_type = models.CharField(max_length=30, choices=EventType.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    extra_data = models.JSONField(
        null=True, 
        blank=True,
        help_text="Additional event-specific data stored as JSON"
    )
    description = models.TextField(
        blank=True,
        help_text="Human-readable description of the event"
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
        ]
    
    def __str__(self):
        user_display = self.user.username if self.user else "Anonymous"
        return f"{user_display} - {self.get_event_type_display()} at {self.created_at}"
