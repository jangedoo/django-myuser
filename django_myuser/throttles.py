"""
Custom throttling classes for rate limiting
"""
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """
    Throttle class for login attempts
    """
    scope = 'login'


class AuthenticatedUserRateThrottle(UserRateThrottle):
    """
    Rate throttle for authenticated users
    """
    scope = 'user'


class PasswordResetRateThrottle(AnonRateThrottle):
    """
    Rate throttle for password reset requests
    """
    scope = 'password_reset'


class DataRequestRateThrottle(UserRateThrottle):
    """
    Rate throttle for data export/deletion requests
    """
    scope = 'data_request'


class ProfileUpdateRateThrottle(UserRateThrottle):
    """
    Rate throttle for profile updates
    """
    scope = 'profile_update'