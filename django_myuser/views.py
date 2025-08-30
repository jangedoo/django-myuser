from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.signals import user_logged_out
from django.http import HttpResponse, Http404, FileResponse
from django.conf import settings
from django.utils import timezone
import os
import mimetypes

from .serializers import (
    LogoutSerializer, ProfileSerializer, DataRequestSerializer, 
    UserSessionSerializer, CustomTokenObtainPairSerializer
)
from .models import Profile, DataRequest, UserSession, DataExportFile
from .throttles import (
    LoginRateThrottle, 
    AuthenticatedUserRateThrottle, 
    DataRequestRateThrottle, 
    ProfileUpdateRateThrottle
)


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT token view that integrates with session tracking and audit logging.
    """
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = [AuthenticatedUserRateThrottle]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            refresh_token = serializer.validated_data["refresh"]
            
            # Remove user session associated with this refresh token
            UserSession.objects.filter(
                user=request.user,
                refresh_token=refresh_token
            ).delete()
            
            # Emit user_logged_out signal for audit logging
            user_logged_out.send(
                sender=request.user.__class__,
                request=request,
                user=request.user
            )
            
            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(status=status.HTTP_205_RESET_CONTENT)
            
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = [ProfileUpdateRateThrottle]
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()

    def get_object(self):
        return self.request.user.profile


class DataRequestView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = [DataRequestRateThrottle]
    serializer_class = DataRequestSerializer

    def get_queryset(self):
        return DataRequest.objects.filter(user=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)



class UserSessionListView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = [AuthenticatedUserRateThrottle]
    serializer_class = UserSessionSerializer

    def get_queryset(self):
        return UserSession.objects.filter(user=self.request.user)


class UserSessionDetailView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = [AuthenticatedUserRateThrottle]
    serializer_class = UserSessionSerializer

    def get_queryset(self):
        return UserSession.objects.filter(user=self.request.user)


class DataExportDownloadView(APIView):
    """
    Secure download endpoint for user data export files.
    
    Uses download tokens for authentication instead of requiring login.
    This allows users to download their data even if they've forgotten their password.
    """
    
    def get(self, request, token):
        try:
            # Find the export file by token
            export_file = DataExportFile.objects.get(
                download_token=token,
                deleted_at__isnull=True
            )
            
            # Check if file has expired
            if export_file.is_expired():
                raise Http404("Download link has expired")
            
            # Check if file exists on disk
            full_path = os.path.join(settings.MEDIA_ROOT, export_file.file_path)
            if not os.path.exists(full_path):
                raise Http404("Export file not found")
            
            # Increment download counter
            export_file.download_count += 1
            export_file.save(update_fields=['download_count'])
            
            # Determine content type
            content_type, _ = mimetypes.guess_type(full_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            # Generate filename for download
            user = export_file.data_request.user
            timestamp = export_file.created_at.strftime('%Y%m%d_%H%M%S')
            download_filename = f"user_data_export_{user.username}_{timestamp}.zip"
            
            # Create file response
            response = FileResponse(
                open(full_path, 'rb'),
                content_type=content_type,
                as_attachment=True,
                filename=download_filename
            )
            
            # Add security headers
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            
            return response
            
        except DataExportFile.DoesNotExist:
            raise Http404("Invalid download token")
        except Exception as e:
            # Log the error in production
            raise Http404("Download failed")
