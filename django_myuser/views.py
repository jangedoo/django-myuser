from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.signals import user_logged_out

from .serializers import (
    LogoutSerializer, ProfileSerializer, DataRequestSerializer, 
    UserSessionSerializer, CustomTokenObtainPairSerializer
)
from .models import Profile, DataRequest, UserSession
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
