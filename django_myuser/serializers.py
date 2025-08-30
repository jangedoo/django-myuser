from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.utils import timezone
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.serializers import SocialLoginSerializer as BaseSocialLoginSerializer
from .models import Profile, DataRequest, UserSession, AuditLog


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer that integrates with Django's authentication signals
    and creates user sessions for tracking.
    """
    
    def validate(self, attrs):
        """
        Validate credentials and emit authentication signals.
        """
        request = self.context.get('request')
        
        try:
            # Call parent validation which will raise ValidationError if credentials are invalid
            data = super().validate(attrs)
            
            # Get user IP and user agent
            ip_address = self._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
            
            # Emit user_logged_in signal (for audit logging)
            user_logged_in.send(
                sender=self.user.__class__,
                request=request,
                user=self.user
            )
            
            # Create or update user session
            refresh_token = data['refresh']
            self._create_user_session(self.user, refresh_token, ip_address, user_agent)
            
            return data
            
        except Exception as e:
            # If validation fails, emit login_failed signal
            username = attrs.get('username', attrs.get('email', 'unknown'))
            user_login_failed.send(
                sender=None,
                credentials={'username': username},
                request=request
            )
            # Re-raise the original exception
            raise e
    
    def _get_client_ip(self, request):
        """Extract the real IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip
    
    def _create_user_session(self, user, refresh_token, ip_address, user_agent):
        """Create a user session entry for tracking."""
        # Remove any existing session with the same refresh token
        UserSession.objects.filter(refresh_token=refresh_token).delete()
        
        # Create new session
        UserSession.objects.create(
            user=user,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            last_activity=timezone.now()
        )


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('marketing_consent', 'marketing_consent_updated_at')
        read_only_fields = ('marketing_consent_updated_at',)


class DataRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataRequest
        fields = ('id', 'request_type', 'status', 'notes', 'created_at', 'updated_at')
        read_only_fields = ('id', 'status', 'created_at', 'updated_at')


class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ('id', 'ip_address', 'user_agent', 'last_activity')


class SocialLoginSerializer(BaseSocialLoginSerializer):
    """
    Custom social login serializer that handles JWT token generation
    """
    def validate(self, attrs):
        """
        Validate social login data and prepare for JWT token generation
        """
        # Call parent validation
        attrs = super().validate(attrs)
        
        # Additional validation can be added here
        # For example, check if the social account is verified
        
        return attrs


class SocialAccountSerializer(serializers.ModelSerializer):
    """
    Serializer for SocialAccount model to show connected social accounts
    """
    provider_display = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()
    profile_url = serializers.SerializerMethodField()
    
    class Meta:
        model = SocialAccount
        fields = (
            'id', 
            'provider', 
            'provider_display',
            'uid', 
            'avatar_url',
            'profile_url',
            'date_joined',
            'last_login'
        )
        read_only_fields = ('id', 'provider', 'uid', 'date_joined', 'last_login')

    def get_provider_display(self, obj):
        """Get human-readable provider name"""
        provider_map = {
            'google': 'Google',
            'github': 'GitHub',
            'facebook': 'Facebook'
        }
        return provider_map.get(obj.provider, obj.provider.title())

    def get_avatar_url(self, obj):
        """Extract avatar URL from extra_data"""
        if obj.provider == 'google':
            return obj.extra_data.get('picture')
        elif obj.provider == 'github':
            return obj.extra_data.get('avatar_url')
        elif obj.provider == 'facebook':
            picture_data = obj.extra_data.get('picture', {})
            if isinstance(picture_data, dict):
                data = picture_data.get('data', {})
                return data.get('url')
        return None

    def get_profile_url(self, obj):
        """Generate profile URL for the social provider"""
        if obj.provider == 'github':
            return obj.extra_data.get('html_url')
        elif obj.provider == 'google':
            # Google doesn't provide a public profile URL in the response
            return None
        elif obj.provider == 'facebook':
            return f"https://facebook.com/{obj.uid}"
        return None


class SocialAccountConnectSerializer(serializers.Serializer):
    """
    Serializer for connecting a social account to an existing user
    """
    access_token = serializers.CharField(required=True)
    provider = serializers.ChoiceField(
        choices=[('google', 'Google'), ('github', 'GitHub'), ('facebook', 'Facebook')],
        required=True
    )

    def validate(self, attrs):
        """
        Validate that the access token is valid and not already connected
        """
        # This would typically involve verifying the token with the provider
        # and checking if the social account is already connected to another user
        
        # Implementation would depend on the specific requirements
        # For now, we'll just return the validated data
        
        return attrs


class SocialAccountDisconnectSerializer(serializers.Serializer):
    """
    Serializer for disconnecting a social account
    """
    provider = serializers.ChoiceField(
        choices=[('google', 'Google'), ('github', 'GitHub'), ('facebook', 'Facebook')],
        required=True
    )
    confirm = serializers.BooleanField(default=False)

    def validate_confirm(self, value):
        """Ensure user confirms the disconnection"""
        if not value:
            raise serializers.ValidationError("Please confirm that you want to disconnect this account.")
        return value


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for AuditLog model (read-only for security)
    """
    user_display = serializers.SerializerMethodField()
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = (
            'id', 
            'user', 
            'user_display',
            'event_type', 
            'event_type_display',
            'ip_address', 
            'user_agent', 
            'description',
            'created_at'
        )
        read_only_fields = (
            'id', 'user', 'user_display', 'event_type', 'event_type_display',
            'ip_address', 'user_agent', 'description', 'created_at'
        )
    
    def get_user_display(self, obj):
        """Get user display name"""
        if obj.user:
            return obj.user.username
        return "Anonymous"