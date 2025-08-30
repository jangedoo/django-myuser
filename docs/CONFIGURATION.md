# Advanced Configuration Guide

This document provides detailed configuration options for the django-myuser package, covering all settings, environment-specific configurations, and best practices.

## Table of Contents

- [Required Settings](#required-settings)
- [JWT Configuration](#jwt-configuration)
- [Social Authentication](#social-authentication)
- [Email Configuration](#email-configuration)
- [Celery Configuration](#celery-configuration)
- [Rate Limiting](#rate-limiting)
- [Database Configuration](#database-configuration)
- [Security Settings](#security-settings)
- [Environment-Specific Configurations](#environment-specific-configurations)
- [Advanced Features](#advanced-features)

---

## Required Settings

### Minimal Configuration

```python
# settings.py

# Required for allauth
SITE_ID = 1

# Add to INSTALLED_APPS
INSTALLED_APPS = [
    # ... Django apps
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'django_myuser',
]

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}
```

---

## JWT Configuration

### Basic JWT Settings

```python
from datetime import timedelta

SIMPLE_JWT = {
    # Token lifetimes
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
    
    # Token rotation and blacklisting
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    
    # Algorithm and signing
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,
    
    # Authentication
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
    
    # Token types and claims
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    
    # JSON encoding
    'JSON_ENCODER': None,
}
```

### Production JWT Settings

```python
# Recommended production settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),  # Shorter for security
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),     # Longer for UX
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'RS256',  # More secure algorithm
    'SIGNING_KEY': os.environ.get('JWT_PRIVATE_KEY'),
    'VERIFYING_KEY': os.environ.get('JWT_PUBLIC_KEY'),
    'ISSUER': 'your-domain.com',
    'AUDIENCE': ['api', 'web'],
}
```

### JWT with RSA Keys

Generate RSA keys for production:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkcs8 -aes256

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

```python
# Load keys from files
with open('/path/to/private_key.pem', 'r') as f:
    JWT_PRIVATE_KEY = f.read()

with open('/path/to/public_key.pem', 'r') as f:
    JWT_PUBLIC_KEY = f.read()

SIMPLE_JWT = {
    'ALGORITHM': 'RS256',
    'SIGNING_KEY': JWT_PRIVATE_KEY,
    'VERIFYING_KEY': JWT_PUBLIC_KEY,
    # ... other settings
}
```

---

## Social Authentication

### Google OAuth Configuration

```python
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        },
        'OAUTH_PKCE_ENABLED': True,  # Enhanced security
        'FETCH_USERINFO': True,
        'APP': {
            'client_id': os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
            'secret': os.environ.get('GOOGLE_OAUTH_SECRET'),
        }
    }
}
```

### GitHub OAuth Configuration

```python
SOCIALACCOUNT_PROVIDERS = {
    'github': {
        'SCOPE': [
            'user:email',
            'read:user',
        ],
        'VERIFIED_EMAIL': True,
        'APP': {
            'client_id': os.environ.get('GITHUB_CLIENT_ID'),
            'secret': os.environ.get('GITHUB_SECRET'),
        }
    }
}
```

### Facebook OAuth Configuration

```python
SOCIALACCOUNT_PROVIDERS = {
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
        'VERSION': 'v18.0',  # Use latest stable version
        'APP': {
            'client_id': os.environ.get('FACEBOOK_APP_ID'),
            'secret': os.environ.get('FACEBOOK_APP_SECRET'),
        }
    }
}
```

### Social Account Adapter

```python
# Custom social account adapter
SOCIALACCOUNT_ADAPTER = 'django_myuser.adapters.MySocialAccountAdapter'

# Additional social account settings
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'  # Skip email verification for social accounts
SOCIALACCOUNT_STORE_TOKENS = True  # Store OAuth tokens
```

---

## Email Configuration

### Development Email Backend

```python
# Console backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# File backend for testing
EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
EMAIL_FILE_PATH = BASE_DIR / 'emails'
```

### Production SMTP Configuration

```python
# SMTP backend for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'true').lower() == 'true'
EMAIL_USE_SSL = os.environ.get('EMAIL_USE_SSL', 'false').lower() == 'true'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')

# Email settings
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@yoursite.com')
SERVER_EMAIL = os.environ.get('SERVER_EMAIL', DEFAULT_FROM_EMAIL)
EMAIL_SUBJECT_PREFIX = '[Your Site] '

# Email timeout settings
EMAIL_TIMEOUT = 30
EMAIL_SSL_CERTFILE = None
EMAIL_SSL_KEYFILE = None
```

### Email Service Providers

#### SendGrid
```python
# pip install sendgrid
EMAIL_BACKEND = 'sendgrid_backend.SendgridBackend'
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
```

#### Amazon SES
```python
# pip install django-ses
EMAIL_BACKEND = 'django_ses.SESBackend'
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SES_REGION_NAME = 'us-east-1'
AWS_SES_REGION_ENDPOINT = 'email.us-east-1.amazonaws.com'
```

#### Mailgun
```python
# pip install django-anymail
EMAIL_BACKEND = 'anymail.backends.mailgun.EmailBackend'
ANYMAIL = {
    'MAILGUN_API_KEY': os.environ.get('MAILGUN_API_KEY'),
    'MAILGUN_SENDER_DOMAIN': os.environ.get('MAILGUN_DOMAIN'),
}
```

---

## Celery Configuration

### Basic Celery Setup

```python
# Celery broker and result backend
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Celery serialization
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# Celery timezone
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True

# Task routing
CELERY_TASK_ROUTES = {
    'django_myuser.tasks.send_*': {'queue': 'email'},
    'django_myuser.tasks.process_*': {'queue': 'data_processing'},
}

# Task retry settings
CELERY_TASK_RETRY_DELAY = 60  # seconds
CELERY_TASK_MAX_RETRIES = 3
```

### Production Celery Settings

```python
# Production Celery configuration
CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = CELERY_BROKER_URL

# Connection pool settings
CELERY_BROKER_POOL_LIMIT = 10
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Task execution settings
CELERY_TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
CELERY_TASK_TIME_LIMIT = 600  # 10 minutes
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# Monitoring and logging
CELERY_SEND_TASK_EVENTS = True
CELERY_WORKER_SEND_TASK_EVENTS = True
CELERY_TASK_SEND_SENT_EVENT = True

# Error handling
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_IGNORE_RESULT = False
```

### Redis Configuration

```python
# Redis configuration for Celery
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Redis connection pool
CELERY_BROKER_TRANSPORT_OPTIONS = {
    'master_name': 'mymaster',
    'retry_policy': {
        'timeout': 5.0
    },
    'socket_keepalive': True,
    'socket_keepalive_options': {
        1: 1,  # TCP_KEEPIDLE
        2: 3,  # TCP_KEEPINTVL
        3: 5,  # TCP_KEEPCNT
    }
}
```

---

## Rate Limiting

### Basic Rate Limiting

```python
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'django_myuser.throttles.LoginRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
        'login': '10/min',
    }
}
```

### Advanced Rate Limiting

```python
# Custom throttle rates for different endpoints
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        # General rates
        'anon': '100/day',
        'user': '1000/day',
        
        # Authentication rates
        'login': '10/min',
        'social_login': '5/min',
        'password_reset': '5/hour',
        'email_verification': '3/hour',
        
        # Data management rates
        'data_request': '2/day',
        'profile_update': '20/hour',
        'session_management': '50/hour',
        
        # API rates by user type
        'premium_user': '10000/day',
        'free_user': '1000/day',
    }
}

# Redis-based rate limiting for distributed systems
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

### Custom Throttle Classes

```python
# settings.py
# Custom throttle for sensitive operations
class SensitiveOperationThrottle(UserRateThrottle):
    scope = 'sensitive_ops'
    rate = '5/hour'
    
    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
```

---

## Database Configuration

### PostgreSQL (Recommended)

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'django_myuser'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'sslmode': 'require',
        },
        'CONN_MAX_AGE': 60,
    }
}

# Database connection pooling
DATABASE_CONNECTION_POOLING = {
    'default': {
        'ENGINE': 'django_postgres_pool',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST'),
        'PORT': os.environ.get('DB_PORT'),
        'OPTIONS': {
            'MAX_CONNS': 20,
            'MIN_CONNS': 5,
        }
    }
}
```

### MySQL Configuration

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '3306'),
        'OPTIONS': {
            'sql_mode': 'STRICT_TRANS_TABLES',
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        }
    }
}
```

### SQLite (Development Only)

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}
```

---

## Security Settings

### Basic Security

```python
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'

# Allowed hosts
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Security middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # For static files
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # For CORS
    # ... other middleware
]

# HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### CORS Configuration

```python
# pip install django-cors-headers
CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "https://www.yourdomain.com",
    "http://localhost:3000",  # React dev server
    "http://127.0.0.1:3000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
```

### Content Security Policy

```python
# pip install django-csp
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
```

---

## Environment-Specific Configurations

### Development Settings

```python
# settings/development.py
from .base import *

DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Development database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Console email backend
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Disable HTTPS for development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Development logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
    },
}
```

### Staging Settings

```python
# settings/staging.py
from .production import *

# Staging-specific overrides
DEBUG = False
ALLOWED_HOSTS = ['staging.yourdomain.com']

# Different database
DATABASES['default']['NAME'] = 'staging_db'

# Email to file for testing
EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
EMAIL_FILE_PATH = '/var/log/django/emails'

# Reduced security for testing
SECURE_HSTS_SECONDS = 0
```

### Production Settings

```python
# settings/production.py
from .base import *
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.celery import CeleryIntegration

DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']

# Production database with connection pooling
DATABASES = {
    'default': {
        'ENGINE': 'django_postgres_pool',
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': os.environ['DB_HOST'],
        'PORT': os.environ['DB_PORT'],
        'OPTIONS': {
            'MAX_CONNS': 20,
            'MIN_CONNS': 5,
        }
    }
}

# Sentry error tracking
sentry_sdk.init(
    dsn=os.environ['SENTRY_DSN'],
    integrations=[
        DjangoIntegration(auto_enabling=True),
        CeleryIntegration(auto_enabling=True),
    ],
    traces_sample_rate=0.1,
    send_default_pii=True
)

# Production caching
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ['REDIS_URL'],
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            }
        }
    }
}

# Production logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/django/django.log',
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'django_myuser': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
```

---

## Advanced Features

### Custom User Model Integration

```python
# If using a custom user model
AUTH_USER_MODEL = 'accounts.User'

# Ensure compatibility with django-myuser
class User(AbstractUser):
    # Your custom fields
    pass

# Update foreign keys if needed
class Profile(BaseModel):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='profile'
    )
```

### Multi-tenancy Support

```python
# Tenant-aware settings
TENANT_APPS = [
    'django_myuser',
    # other tenant apps
]

# Tenant-specific JWT settings
SIMPLE_JWT = {
    'USER_ID_CLAIM': 'tenant_user_id',
    # Add tenant information to JWT payload
}

# Custom JWT token class
class TenantAccessToken(AccessToken):
    def for_user(cls, user):
        token = super().for_user(user)
        token['tenant_id'] = user.tenant.id
        return token
```

### API Versioning

```python
# URL patterns with versioning
urlpatterns = [
    path('api/v1/auth/', include('django_myuser.urls')),
    path('api/v2/auth/', include('django_myuser.v2.urls')),
]

# Version-specific settings
REST_FRAMEWORK = {
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1', 'v2'],
    'VERSION_PARAM': 'version',
}
```

### Monitoring and Observability

```python
# Prometheus metrics
INSTALLED_APPS += [
    'django_prometheus',
]

MIDDLEWARE = [
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
    # ... other middleware
    'django_prometheus.middleware.PrometheusAfterMiddleware',
]

# Health checks
HEALTH_CHECKS = {
    'database': 'health_check.db.backends.DatabaseBackend',
    'cache': 'health_check.cache.backends.CacheBackend',
    'celery': 'health_check.celery.backends.CeleryHealthCheck',
    'email': 'health_check.email.backends.EmailBackend',
}
```

---

## Best Practices

### Environment Variables

```python
# Use python-decouple for better env var handling
# pip install python-decouple
from decouple import config, Csv

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())

# Database URL parsing
import dj_database_url
DATABASES = {
    'default': dj_database_url.config(
        default='sqlite:///db.sqlite3',
        conn_max_age=600,
        conn_health_checks=True,
    )
}
```

### Docker Configuration

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8000"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=false
      - DATABASE_URL=postgresql://user:pass@db:5432/dbname
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: dbname
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    
  celery:
    build: .
    command: celery -A myproject worker -l info
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/dbname
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
```

### Testing Configuration

```python
# settings/testing.py
from .base import *

# Fast password hashing for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# In-memory database for speed
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable migrations for tests
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Disable Celery for tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
```

This comprehensive configuration guide covers all aspects of setting up django-myuser for different environments and use cases. Always review and adjust settings based on your specific security, performance, and operational requirements.