# django-myuser

A vibe coded comprehensive Django package for user authentication, and user data management.
Built for very specific use case for my personal needs. Use at your own risk. Except for this paragraph, almost entirely is written by LLMs.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Django](https://img.shields.io/badge/django-5.0+-green.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

🔐 **Advanced JWT Authentication**
- JWT token authentication with refresh token rotation
- Secure server-side logout with token blacklisting
- Social authentication (Google, GitHub, Facebook)

👤 **User Management**
- Extended user profiles with GDPR compliance
- Soft deletion with UUID primary keys
- User session tracking and management

🛡️ **Security & Compliance**
- GDPR data export and deletion requests with file-based downloads
- Pluggable data export system for custom data collection
- Automatic cleanup of expired export files
- Comprehensive audit logging
- Rate limiting on sensitive endpoints
- Marketing consent management

📧 **Email Integration**
- Async email processing with Celery
- Customizable email templates
- Password reset and email verification

## Quick Start

### 1. Installation

```bash
pip install django-myuser
```

### 2. Add to INSTALLED_APPS

```python
INSTALLED_APPS = [
    # Django apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    
    # Third-party apps
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',
    'allauth.socialaccount.providers.facebook',
    'dj_rest_auth',
    'dj_rest_auth.registration',
    
    # django-myuser
    'django_myuser',
]
```

### 3. Include URLs

```python
# urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('django_myuser.urls')),
]
```

### 4. Run Migrations

```bash
python manage.py migrate
```

### 5. Set Up Celery Worker (Optional but recommended)

```bash
celery -A your_project worker -l info
```

## Configuration

### Required Settings

```python
# settings.py

# Site ID for allauth
SITE_ID = 1

# Redis for Celery and rate limiting
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day'
    }
}
```

### JWT Configuration

```python
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JSON_ENCODER': None,
    'JWK_URL': None,
    'LEEWAY': 0,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}
```

### Social Authentication

```python
# Social account providers
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'github': {
        'SCOPE': [
            'user:email',
        ],
    },
    'facebook': {
        'METHOD': 'oauth2',
        'SDK_URL': '//connect.facebook.net/{locale}/sdk.js',
        'SCOPE': ['email', 'public_profile'],
        'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
        'INIT_PARAMS': {'cookie': True},
        'FIELDS': [
            'id',
            'first_name',
            'last_name',
            'middle_name',
            'name',
            'name_format',
            'picture',
            'short_name'
        ],
        'EXCHANGE_TOKEN': True,
        'LOCALE_FUNC': lambda request: 'en_US',
        'VERIFIED_EMAIL': False,
        'VERSION': 'v13.0',
    }
}

# Social account adapter
SOCIALACCOUNT_ADAPTER = 'django_myuser.adapters.MySocialAccountAdapter'
```

### Email Configuration

```python
# Email backend (configure for production)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# For production, use SMTP:
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.gmail.com'
# EMAIL_PORT = 587
# EMAIL_USE_TLS = True
# EMAIL_HOST_USER = 'your-email@gmail.com'
# EMAIL_HOST_PASSWORD = 'your-password'

# Default from email
DEFAULT_FROM_EMAIL = 'noreply@yourdomain.com'
```

### Allauth Configuration

```python
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_USER_MODEL_EMAIL_FIELD = 'email'
```

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/token/` | POST | Obtain JWT token pair |
| `/api/auth/token/refresh/` | POST | Refresh access token |
| `/api/auth/token/verify/` | POST | Verify token validity |
| `/api/auth/logout/` | POST | Logout and blacklist tokens |

### Social Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/social/google/` | POST | Google OAuth login |
| `/api/auth/social/github/` | POST | GitHub OAuth login |
| `/api/auth/social/facebook/` | POST | Facebook OAuth login |

### User Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/profile/` | GET/PUT | User profile management |
| `/api/auth/data-requests/` | GET/POST | GDPR data requests |
| `/api/auth/data-export/download/{token}/` | GET | Download export files |
| `/api/auth/sessions/` | GET | List active sessions |
| `/api/auth/sessions/{id}/` | DELETE | Revoke specific session |

### Social Account Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/social/accounts/` | GET | List connected social accounts |
| `/api/auth/social/accounts/status/` | GET | Check connection status |
| `/api/auth/social/accounts/{provider}/disconnect/` | POST | Disconnect social account |

## Models

### BaseModel
Abstract model with UUID primary key, timestamps, and soft deletion.

### Profile
Extends user with marketing consent and additional profile data.

### DataRequest
Handles GDPR data export and deletion requests.

### UserSession
Tracks active user sessions for security monitoring.

### AuditLog
Comprehensive logging of security-sensitive events.

### DataExportFile
Manages secure download tokens and file lifecycle for GDPR exports.

## Email Templates

The package includes customizable email templates for:

- Email confirmation
- Password reset
- Welcome messages
- Data export notifications
- Account deletion confirmations
- Password change alerts

### Customizing Templates

Override templates by creating files in your project:

```
templates/
├── account/
│   └── email/
│       ├── email_confirmation_message.html
│       ├── password_reset_key_message.html
│       └── welcome_message.html
└── socialaccount/
    └── email/
        └── account_connected.html
```

## GDPR Compliance & Data Export System

### Data Export with File Downloads
Users can request data exports that are processed asynchronously and delivered via secure download links:

```python
# Request export
POST /api/auth/data-requests/
{
    "request_type": "EXPORT"
}

# User receives email with download link when ready
# Download via secure token (no authentication required)
GET /api/auth/data-export/download/{secure-token}/
```

**Export Features:**
- Multi-file ZIP archives with organized data (JSON, CSV, JSONL)
- Memory-efficient processing for large datasets
- Secure token-based downloads with expiration
- Automatic cleanup of expired files
- Email notifications when export is ready

### Custom Data Exporters
Create custom exporters for application-specific data:

```python
# settings.py
DJANGO_MYUSER = {
    'DATA_EXPORTER_CLASS': 'myapp.exporters.CustomUserDataExporter',
    'EXPORT_FILE_PATH': 'user_exports/',
    'EXPORT_FILE_RETENTION_DAYS': 14,
}

# myapp/exporters.py
from django_myuser.exporters import UserDataExporter

class CustomUserDataExporter(UserDataExporter):
    def generate_data(self, data_request, user):
        with self.create_export_builder(user) as builder:
            # Add custom app data
            builder.add_json_file('orders.json', self.get_user_orders(user))
            builder.add_csv_file('activity.csv', self.get_user_activity(user))
            
            return builder.create_archive('custom_export')
```

### Data Deletion
Users can request account deletion:

```python
POST /api/auth/data-requests/
{
    "request_type": "DELETE"
}
```

### Marketing Consent
Track and manage marketing consent:

```python
PUT /api/auth/profile/
{
    "marketing_consent": true
}
```

## Rate Limiting

Built-in rate limiting on sensitive endpoints:

```python
# Custom throttle rates
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'login': '10/min',
        'password_reset': '5/hour',
        'data_request': '2/day',
    }
}
```

## Audit Logging

All security events are automatically logged:

- Login/logout events
- Password changes
- Social account connections
- Data requests
- Suspicious activities

Access logs through the Django admin or API.

## Running Celery

Start Celery worker for async email processing and data exports:

```bash
# Basic worker
celery -A your_project worker -l info

# With beat scheduler (recommended for cleanup tasks)
celery -A your_project worker -B -l info

# Separate beat process
celery -A your_project beat -l info

# Periodic cleanup of expired export files
celery -A your_project worker -B --scheduler=django_celery_beat.schedulers:DatabaseScheduler
```

### Celery Tasks
The package includes these Celery tasks:
- `send_async_email` - Send notification emails
- `process_data_request` - Process export/deletion requests  
- `cleanup_expired_exports` - Remove expired export files (run daily)

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-django pytest-cov factory-boy

# Run tests
pytest

# Run with coverage
pytest --cov=django_myuser
```

## Security Considerations

- Always use HTTPS in production
- Configure proper CORS settings
- Set strong JWT signing keys
- Use Redis for production Celery broker
- Implement proper rate limiting
- Monitor audit logs for suspicious activity
- Regular security updates

## Contributing

1. Fork the repository: https://github.com/jangedoo/django-myuser
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: https://github.com/jangedoo/django-myuser/issues
- **Documentation**: See `docs/` directory for detailed guides
- **Discussions**: https://github.com/jangedoo/django-myuser/discussions

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.