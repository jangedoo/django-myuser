from django.contrib import admin
from django.contrib.auth import get_user_model
from django.utils.html import format_html
from django.utils import timezone
from .models import Profile, DataRequest, UserSession, AuditLog

User = get_user_model()


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'marketing_consent', 'marketing_consent_updated_at', 'created_at', 'updated_at']
    list_filter = ['marketing_consent', 'marketing_consent_updated_at', 'created_at']
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['id', 'created_at', 'updated_at', 'deleted_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (None, {
            'fields': ('user', 'marketing_consent', 'marketing_consent_updated_at')
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at', 'deleted_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(DataRequest)
class DataRequestAdmin(admin.ModelAdmin):
    list_display = ['user', 'request_type', 'status', 'created_at', 'updated_at']
    list_filter = ['request_type', 'status', 'created_at']
    search_fields = ['user__username', 'user__email', 'notes']
    readonly_fields = ['id', 'created_at', 'updated_at', 'deleted_at']
    date_hierarchy = 'created_at'
    actions = ['mark_as_completed', 'mark_as_failed']
    
    fieldsets = (
        (None, {
            'fields': ('user', 'request_type', 'status', 'notes')
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at', 'deleted_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    @admin.action(description='Mark selected requests as completed')
    def mark_as_completed(self, request, queryset):
        updated = queryset.update(status=DataRequest.RequestStatus.COMPLETED)
        self.message_user(request, f'{updated} requests were marked as completed.')

    @admin.action(description='Mark selected requests as failed')
    def mark_as_failed(self, request, queryset):
        updated = queryset.update(status=DataRequest.RequestStatus.FAILED)
        self.message_user(request, f'{updated} requests were marked as failed.')


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'ip_address', 'user_agent_short', 'last_activity', 'created_at', 'is_active']
    list_filter = ['created_at', 'last_activity']
    search_fields = ['user__username', 'user__email', 'ip_address', 'user_agent']
    readonly_fields = ['id', 'created_at', 'updated_at', 'deleted_at', 'refresh_token']
    date_hierarchy = 'created_at'
    actions = ['revoke_sessions']
    
    fieldsets = (
        (None, {
            'fields': ('user', 'ip_address', 'user_agent', 'last_activity')
        }),
        ('Security', {
            'fields': ('refresh_token',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at', 'deleted_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def user_agent_short(self, obj):
        if len(obj.user_agent) > 50:
            return obj.user_agent[:47] + '...'
        return obj.user_agent
    user_agent_short.short_description = 'User Agent'

    def is_active(self, obj):
        if obj.last_activity and obj.last_activity > timezone.now() - timezone.timedelta(hours=24):
            return format_html('<span style="color: green;">●</span> Active')
        return format_html('<span style="color: red;">●</span> Inactive')
    is_active.short_description = 'Status'

    @admin.action(description='Revoke selected sessions (soft delete)')
    def revoke_sessions(self, request, queryset):
        updated = 0
        for session in queryset:
            if not session.deleted_at:
                session.delete()  # This will soft delete
                updated += 1
        self.message_user(request, f'{updated} sessions were revoked.')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'event_type', 'ip_address', 'created_at', 'description_short']
    list_filter = ['event_type', 'created_at', 'ip_address']
    search_fields = ['user__username', 'user__email', 'event_type', 'ip_address', 'description']
    readonly_fields = ['id', 'user', 'event_type', 'ip_address', 'user_agent', 'extra_data', 'description', 'created_at', 'updated_at', 'deleted_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (None, {
            'fields': ('user', 'event_type', 'description')
        }),
        ('Request Details', {
            'fields': ('ip_address', 'user_agent'),
        }),
        ('Additional Data', {
            'fields': ('extra_data',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at', 'deleted_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def description_short(self, obj):
        if obj.description and len(obj.description) > 50:
            return obj.description[:47] + '...'
        return obj.description or '-'
    description_short.short_description = 'Description'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False