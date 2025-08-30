"""
Global test configuration and fixtures for Django MyUser tests.
"""
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.models import SocialApp

from django_myuser.models import Profile, UserSession

User = get_user_model()


@pytest.fixture
def api_client():
    """
    Returns a DRF APIClient instance for making API requests.
    """
    return APIClient()


@pytest.fixture
def django_client():
    """
    Returns a Django test client for making requests.
    """
    return Client()


@pytest.fixture
def user(db):
    """
    Creates a basic test user with profile.
    """
    from .factories import UserFactory
    return UserFactory()


@pytest.fixture
def users(db):
    """
    Creates multiple test users for multi-user scenarios.
    """
    from .factories import UserFactory
    return UserFactory.create_batch(3)


@pytest.fixture
def admin_user(db):
    """
    Creates an admin/superuser for testing admin functionality.
    """
    from .factories import UserFactory
    return UserFactory(is_staff=True, is_superuser=True)


@pytest.fixture
def authenticated_client(api_client, user):
    """
    Returns an API client authenticated with a test user.
    """
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def authenticated_admin_client(api_client, admin_user):
    """
    Returns an API client authenticated with an admin user.
    """
    api_client.force_authenticate(user=admin_user)
    return api_client


@pytest.fixture
def user_with_token(user):
    """
    Returns a user with JWT tokens (access and refresh).
    """
    refresh = RefreshToken.for_user(user)
    user.access_token = str(refresh.access_token)
    user.refresh_token = str(refresh)
    return user


@pytest.fixture
def jwt_client(api_client, user_with_token):
    """
    Returns an API client with JWT authentication headers.
    """
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {user_with_token.access_token}')
    return api_client


@pytest.fixture
def social_apps(db):
    """
    Creates social authentication apps for testing OAuth flows.
    """
    apps = {}
    providers = [
        ('google', 'Google'),
        ('github', 'GitHub'), 
        ('facebook', 'Facebook')
    ]
    
    for provider_id, provider_name in providers:
        app, created = SocialApp.objects.get_or_create(
            provider=provider_id,
            defaults={
                'name': provider_name,
                'client_id': f'test-{provider_id}-client-id',
                'secret': f'test-{provider_id}-secret',
            }
        )
        apps[provider_id] = app
    
    return apps


@pytest.fixture
def user_session(user, db):
    """
    Creates a user session for testing session management.
    """
    return UserSession.objects.create(
        user=user,
        ip_address='127.0.0.1',
        user_agent='test-user-agent',
        refresh_token='test-refresh-token-123'
    )


@pytest.fixture
def mock_celery_task(monkeypatch):
    """
    Mock Celery tasks to run synchronously in tests.
    """
    def mock_delay(*args, **kwargs):
        # Run the task synchronously for testing
        return None
    
    # Mock common Celery tasks
    monkeypatch.setattr('django_myuser.tasks.send_async_email.delay', mock_delay)
    monkeypatch.setattr('django_myuser.tasks.process_data_request.delay', mock_delay)
    

@pytest.fixture
def rate_limit_reset(db):
    """
    Fixture to reset rate limits for testing.
    Can be extended to clear rate limit caches if needed.
    """
    from django.core.cache import cache
    # Clear rate limiting cache before test
    cache.clear()
    yield
    # Clear rate limiting cache after test
    cache.clear()
    

@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """
    Automatically enable database access for all tests.
    This removes the need to mark every test with @pytest.mark.django_db.
    Also clear rate limiting cache for clean state per test.
    """
    # Clear rate limiting cache before each test
    from django.core.cache import cache
    cache.clear()
    yield
    # Clear again after test
    cache.clear()


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    """
    Configure the test database with necessary data.
    """
    with django_db_blocker.unblock():
        # Force creation of tables by running migrations
        from django.core.management import call_command
        call_command('migrate', verbosity=0, interactive=False, run_syncdb=True)


# Test data constants
TEST_USER_DATA = {
    'username': 'testuser',
    'email': 'test@example.com', 
    'password': 'TestPassword123!',
    'first_name': 'Test',
    'last_name': 'User'
}

TEST_CREDENTIALS = {
    'username': 'testuser',
    'password': 'TestPassword123!'
}

# API endpoints for testing
API_ENDPOINTS = {
    'token_obtain': '/token/',
    'token_refresh': '/token/refresh/',
    'token_verify': '/token/verify/',
    'logout': '/logout/',
    'profile': '/profile/',
    'data_requests': '/data-requests/',
    'sessions': '/sessions/',
    'social_google': '/social/google/',
    'social_github': '/social/github/',
    'social_facebook': '/social/facebook/',
    'social_accounts': '/social/accounts/',
}