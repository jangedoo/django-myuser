from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)

from .views import (
    CustomTokenObtainPairView, LogoutView, ProfileView, DataRequestView, 
    UserSessionListView, UserSessionDetailView, DataExportDownloadView
)
from .social_views import (
    GoogleSocialLoginView,
    GitHubSocialLoginView,
    FacebookSocialLoginView,
    SocialAccountListView,
    SocialAccountDisconnectView,
    SocialAccountConnectStatusView
)

urlpatterns = [
    # JWT Authentication endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # User profile and data management
    path('profile/', ProfileView.as_view(), name='profile'),
    path('data-requests/', DataRequestView.as_view(), name='data_requests'),
    path('data-export/download/<str:token>/', DataExportDownloadView.as_view(), name='data_export_download'),
    path('sessions/', UserSessionListView.as_view(), name='sessions_list'),
    path('sessions/<uuid:pk>/', UserSessionDetailView.as_view(), name='sessions_detail'),
    
    # Social Authentication endpoints
    path('social/google/', GoogleSocialLoginView.as_view(), name='google_login'),
    path('social/github/', GitHubSocialLoginView.as_view(), name='github_login'),
    path('social/facebook/', FacebookSocialLoginView.as_view(), name='facebook_login'),
    
    # Social Account management
    path('social/accounts/', SocialAccountListView.as_view(), name='social_accounts'),
    path('social/accounts/status/', SocialAccountConnectStatusView.as_view(), name='social_accounts_status'),
    path('social/accounts/<str:provider>/disconnect/', SocialAccountDisconnectView.as_view(), name='social_account_disconnect'),
    
    # Include allauth URLs for OAuth callbacks
    path('accounts/', include('allauth.urls')),
]
