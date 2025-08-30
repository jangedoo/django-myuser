from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404

from .serializers import SocialLoginSerializer, SocialAccountSerializer
from .models import UserSession

User = get_user_model()


class GoogleSocialLoginView(SocialLoginView):
    """
    Google OAuth2 Social Login View that returns JWT tokens
    """
    adapter_class = GoogleOAuth2Adapter
    serializer_class = SocialLoginSerializer

    def get_response(self):
        """
        Override to return JWT tokens instead of session auth
        """
        user = self.user
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # Create user session record
        self.create_user_session(user, str(refresh))

        return Response({
            'access_token': str(access),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }, status=status.HTTP_200_OK)

    def create_user_session(self, user, refresh_token):
        """Create a UserSession record for tracking"""
        ip_address = self.get_client_ip() or '127.0.0.1'  # Default to localhost if None
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')[:255]
        
        UserSession.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token=refresh_token
        )

    def get_client_ip(self):
        """Get the client's IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class GitHubSocialLoginView(SocialLoginView):
    """
    GitHub OAuth2 Social Login View that returns JWT tokens
    """
    adapter_class = GitHubOAuth2Adapter
    serializer_class = SocialLoginSerializer

    def get_response(self):
        """
        Override to return JWT tokens instead of session auth
        """
        user = self.user
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # Create user session record
        self.create_user_session(user, str(refresh))

        return Response({
            'access_token': str(access),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }, status=status.HTTP_200_OK)

    def create_user_session(self, user, refresh_token):
        """Create a UserSession record for tracking"""
        ip_address = self.get_client_ip() or '127.0.0.1'  # Default to localhost if None
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')[:255]
        
        UserSession.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token=refresh_token
        )

    def get_client_ip(self):
        """Get the client's IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class FacebookSocialLoginView(SocialLoginView):
    """
    Facebook OAuth2 Social Login View that returns JWT tokens
    """
    adapter_class = FacebookOAuth2Adapter
    serializer_class = SocialLoginSerializer

    def get_response(self):
        """
        Override to return JWT tokens instead of session auth
        """
        user = self.user
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # Create user session record
        self.create_user_session(user, str(refresh))

        return Response({
            'access_token': str(access),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }, status=status.HTTP_200_OK)

    def create_user_session(self, user, refresh_token):
        """Create a UserSession record for tracking"""
        ip_address = self.get_client_ip() or '127.0.0.1'  # Default to localhost if None
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')[:255]
        
        UserSession.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token=refresh_token
        )

    def get_client_ip(self):
        """Get the client's IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class SocialAccountListView(generics.ListAPIView):
    """
    List all social accounts connected to the authenticated user
    """
    permission_classes = [IsAuthenticated]
    serializer_class = SocialAccountSerializer

    def get_queryset(self):
        return SocialAccount.objects.filter(user=self.request.user)


class SocialAccountDisconnectView(APIView):
    """
    Disconnect a social account from the authenticated user
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, provider):
        """
        Disconnect a social account for the specified provider
        """
        try:
            social_account = SocialAccount.objects.get(
                user=request.user,
                provider=provider
            )
            
            # Check if user has other ways to login (password or other social accounts)
            has_password = request.user.has_usable_password()
            other_social_accounts = SocialAccount.objects.filter(
                user=request.user
            ).exclude(id=social_account.id).exists()
            
            if not has_password and not other_social_accounts:
                return Response({
                    'error': 'Cannot disconnect the only login method. Please set a password first.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Disconnect the account
            social_account.delete()
            
            return Response({
                'message': f'{provider} account disconnected successfully'
            }, status=status.HTTP_200_OK)
            
        except SocialAccount.DoesNotExist:
            return Response({
                'error': f'No {provider} account found for this user'
            }, status=status.HTTP_404_NOT_FOUND)


class SocialAccountConnectStatusView(APIView):
    """
    Check connection status for all social providers
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Return connection status for all supported social providers
        """
        user = request.user
        providers = ['google', 'github', 'facebook']
        
        connected_accounts = {}
        for provider in providers:
            try:
                social_account = SocialAccount.objects.get(user=user, provider=provider)
                connected_accounts[provider] = {
                    'connected': True,
                    'uid': social_account.uid,
                    'extra_data': social_account.extra_data
                }
            except SocialAccount.DoesNotExist:
                connected_accounts[provider] = {
                    'connected': False
                }
        
        return Response({
            'user_id': user.id,
            'has_password': user.has_usable_password(),
            'social_accounts': connected_accounts
        }, status=status.HTTP_200_OK)