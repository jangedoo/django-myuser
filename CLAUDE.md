# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

django-myuser is a comprehensive Django package for advanced user authentication and user data management. It provides JWT authentication with refresh token rotation, social authentication (Google, GitHub, Facebook), GDPR compliance features, audit logging, and comprehensive user management capabilities.

## Architecture

### Core Components

- **BaseModel**: Abstract model with UUID primary keys, timestamps, and soft deletion
- **Profile**: Extended user profiles with GDPR marketing consent tracking  
- **DataRequest**: GDPR compliance for data export/deletion requests
- **UserSession**: Session tracking for security monitoring
- **AuditLog**: Comprehensive security event logging

### Key Apps Structure

- `django_myuser/models.py`: Core data models
- `django_myuser/views.py`: Main API views for authentication and user management  
- `django_myuser/social_views.py`: Social authentication views
- `django_myuser/serializers.py`: DRF serializers
- `django_myuser/urls.py`: URL routing
- `django_myuser/tasks.py`: Celery async tasks
- `django_myuser/signals.py`: Django signals for user creation
- `django_myuser/audit_signals.py`: Audit logging signals
- `django_myuser/adapters.py`: Custom allauth adapters

### Technology Stack

- **Django 5.0+** with Django REST Framework
- **JWT Authentication** via djangorestframework-simplejwt with token blacklisting
- **Social Auth** via django-allauth (Google, GitHub, Facebook)
- **Async Processing** via Celery with Redis
- **Testing** with pytest-django, factory-boy, faker

## Development Commands

Poetry is used to manage the packages and virtual envs. Use poetry run prefix while running any commands to use the correct virtual env.

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=django_myuser --cov-report=html

# Run specific test categories
pytest tests/unit/           # Unit tests
pytest tests/integration/    # API integration tests  
pytest tests/security/       # Security tests

# Run single test file
pytest tests/integration/test_auth_api.py

# Run with verbose output
pytest -v

# Debug failing test
pytest --pdb tests/path/to/test.py::TestClass::test_method
```

### Project Structure for Testing

The project uses a comprehensive test setup in `tests/`:
- Uses **pytest-django** with automatic database access
- **Real database testing** approach (minimal mocking)
- Test factories via `factory-boy` for realistic test data
- Organized into unit/, integration/, security/, e2e/ categories
- Global fixtures in `tests/conftest.py`

### Key Settings Configuration

Located in `tests/test_project/settings.py`:
- JWT tokens: 5min access, 1day refresh with rotation
- Rate limiting: login(5/min), password_reset(3/hour), data_request(2/day)
- Celery with Redis backend for async email processing
- Console email backend for development

## API Endpoints Structure

### Authentication
- `POST /api/auth/token/` - JWT token obtain
- `POST /api/auth/token/refresh/` - Refresh access token
- `POST /api/auth/token/verify/` - Verify token
- `POST /api/auth/logout/` - Logout with token blacklisting

### User Management  
- `GET/PUT /api/auth/profile/` - User profile management
- `GET/POST /api/auth/data-requests/` - GDPR data requests
- `GET /api/auth/sessions/` - List active sessions
- `DELETE /api/auth/sessions/{id}/` - Revoke session

### Social Authentication
- `POST /api/auth/social/{provider}/` - Social login (google, github, facebook)
- `GET /api/auth/social/accounts/` - List connected accounts
- `POST /api/auth/social/accounts/{provider}/disconnect/` - Disconnect account

## Development Practices

### Models
- All models extend `BaseModel` for UUID keys and soft deletion
- Use `objects` manager for active records, `all_objects` for all records including deleted
- Audit logging happens automatically via signals

### Views & Serializers
- Use DRF class-based views with proper permissions
- Custom throttling for sensitive endpoints (login, password reset)
- Comprehensive error handling with audit trail

### Testing Approach
- Use pytest with `@pytest.mark.django_db` or global `enable_db_access_for_all_tests` fixture
- Test real database operations, not mocked behavior
- Use factories from `tests/factories.py` for consistent test data
- Security-first testing: verify both success and failure paths
- Integration tests verify complete workflows including audit logs

### Security Considerations
- JWT tokens with rotation and blacklisting
- Comprehensive audit logging for all security events
- Rate limiting on sensitive operations
- GDPR compliance with data export/deletion
- Soft deletion preserves audit trails

## Common Patterns

### Creating Test Data
```python
from tests.factories import UserFactory, UserWithProfileFactory
user = UserFactory(email='test@example.com')
users = UserFactory.create_batch(5)
```

### API Testing Pattern
```python
@pytest.mark.django_db
class TestAPIEndpoint:
    def test_endpoint(self, api_client):
        user = UserFactory()
        api_client.force_authenticate(user=user)
        response = api_client.get('/api/endpoint/')
        assert response.status_code == 200
```

### Verifying Audit Logs
```python
from django_myuser.models import AuditLog
assert AuditLog.objects.filter(
    user=user, 
    event_type=AuditLog.EventType.LOGIN
).exists()
```

## File Locations

- Main package: `django_myuser/`
- Test settings: `tests/test_project/settings.py`  
- Test configuration: `pytest.ini`
- Global test fixtures: `tests/conftest.py`
- Test factories: `tests/factories.py`
- Dependencies: `pyproject.toml`