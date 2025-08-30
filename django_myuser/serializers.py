from rest_framework import serializers
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.serializers import SocialLoginSerializer as BaseSocialLoginSerializer
from .models import Profile, DataRequest, UserSession, AuditLog


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('marketing_consent', 'marketing_consent_updated_at')
        read_only_fields = ('marketing_consent_updated_at',)


class DataRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataRequest
        fields = ('request_type', 'status', 'notes')
        read_only_fields = ('status',)


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
        read_only_fields = '__all__'  # All fields are read-only for security
    
    def get_user_display(self, obj):
        """Get user display name"""
        if obj.user:
            return obj.user.username
        return "Anonymous"