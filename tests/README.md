# Django MyUser Test Suite

This directory contains a comprehensive, well-organized test suite for the Django MyUser authentication and user management library. The test suite follows modern testing best practices and focuses on integration testing with real database operations rather than excessive mocking.

## Test Organization

### Directory Structure

```
tests/
├── conftest.py              # Global fixtures and configuration
├── factories.py             # Test data factories using factory_boy
├── utils.py                 # Base test classes and utilities
├── README.md               # This documentation
├── unit/                   # Unit tests for individual components
│   ├── __init__.py
│   └── test_models.py      # Model unit tests
├── integration/            # Integration tests for API endpoints
│   ├── __init__.py
│   ├── test_auth_api.py    # Authentication API tests
│   ├── test_profile_api.py # Profile management API tests
│   ├── test_session_api.py # Session management API tests
│   └── test_data_request_api.py # GDPR data request API tests
├── e2e/                    # End-to-end workflow tests
│   └── __init__.py
├── security/               # Security-focused tests
│   ├── __init__.py
│   └── test_authentication_security.py # Authentication security tests
├── performance/            # Performance and load tests
│   └── __init__.py
└── legacy/                 # Original tests (to be migrated/removed)
    └── ...existing test files...
```

## Testing Philosophy

### 1. Minimize Mocking
- Use real database transactions and API calls
- Mock only external services (email providers, OAuth providers)
- Test actual behavior that clients will experience

### 2. Integration-First Approach
- Focus on end-to-end API testing
- Verify database state changes alongside API responses
- Test complete user workflows

### 3. Security-First Testing
- Comprehensive authentication and authorization testing
- Security boundary testing
- Vulnerability prevention testing

### 4. Real Data Testing
- Use realistic test data via factories
- Test with various data scenarios
- Avoid brittle test fixtures

### 5. Pytest-First Approach
- Use `@pytest.mark.django_db` for database access instead of Django TestCase
- Leverage pytest fixtures and assertions for cleaner, more maintainable tests
- Follow pytest naming conventions (`Test*` classes, `test_*` methods)

## Key Features

### Test Utilities (`utils.py`)
- `BaseAPITestCase`: Common API testing functionality
- `SecurityTestCase`: Security-focused test utilities  
- `AuditTestMixin`: Audit logging verification helpers
- `SessionTestMixin`: Session management test helpers
- `ProfileTestMixin`: Profile testing utilities

### Test Factories (`factories.py`)
- Realistic test data generation using factory_boy
- User, Profile, Session, and Request factories
- Specialized factories for different scenarios
- Consistent, maintainable test data

### Global Fixtures (`conftest.py`)
- Pre-configured API clients
- Authenticated user fixtures
- Social app configurations
- Celery task mocking

## Running Tests

### Prerequisites
```bash
# Install test dependencies
pip install pytest pytest-django factory-boy faker
```

### Basic Test Execution
```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/security/

# Run specific test files
pytest tests/integration/test_auth_api.py
pytest tests/security/test_authentication_security.py

# Run with coverage
pytest --cov=django_myuser --cov-report=html
```

### Test Configuration

Tests are configured via `pytest.ini`:
- Uses test-specific Django settings
- Automatically enables database access with `@pytest.mark.django_db`
- Configures test discovery patterns (`Test*` classes, `test_*` methods)
- Uses `--reuse-db` flag for faster subsequent test runs
- Proper database setup via `django_db_setup` fixture with migrations

## Test Categories

### Unit Tests (`unit/`)
Tests individual components in isolation:
- Model behavior and validation
- Serializer functionality  
- Signal handlers
- Utility functions
- Business logic

**Example**: Model validation, field constraints, string representations

### Integration Tests (`integration/`)
Tests complete API workflows with real database operations:
- Authentication flows (login, logout, token refresh)
- Profile management (CRUD operations)
- Session management (list, delete)
- Data requests (GDPR compliance)
- Error handling and validation

**Example**: Login via API → Verify tokens work → Check session created → Verify audit log

### Security Tests (`security/`)
Tests security aspects and vulnerability prevention:
- Token security (signature verification, expiration)
- Authentication security (brute force protection, timing attacks)
- Authorization boundaries (cross-user access prevention)
- Input validation (SQL injection, XSS prevention)
- Rate limiting effectiveness

**Example**: Attempt to use tampered JWT token → Verify rejection → Check no unauthorized access

### End-to-End Tests (`e2e/`)
Tests complete user workflows across multiple components:
- User registration and email verification
- Complete login/logout cycles
- Social authentication flows
- GDPR data export/deletion workflows

**Example**: Register → Verify email → Login → Update profile → Request data export → Delete account

### Performance Tests (`performance/`)
Tests system performance under various conditions:
- Concurrent user operations
- Load testing scenarios
- Rate limiting under pressure
- Database query optimization

**Example**: Simulate 100 concurrent logins → Verify response times → Check database performance

## Writing Tests

### Test Naming Conventions

```python
# Test class names (pytest-style)
@pytest.mark.django_db
class TestProfileAPI:
class TestTokenSecurity:

# Test method names - descriptive and specific
def test_get_profile_success(self):
def test_login_with_invalid_credentials_fails(self):
def test_rate_limiting_prevents_brute_force_attacks(self):
```

### Using Pytest-Style Tests

```python
import pytest
from tests.factories import UserFactory
from django_myuser.models import AuditLog

@pytest.mark.django_db
class TestProfileAPI:
    def test_api_endpoint(self, api_client):
        # Create test data directly in test method
        user = UserFactory()
        api_client.force_authenticate(user=user)
        
        response = api_client.get('/api/profile/')
        
        # Use pytest assertions
        assert response.status_code == 200
        assert response.data['marketing_consent'] is False
        
        # Verify audit log created
        assert AuditLog.objects.filter(
            user=user, 
            event_type=AuditLog.EventType.PROFILE_ACCESSED
        ).exists()
```

### Using Test Factories

```python
import pytest
from tests.factories import UserFactory, UserWithProfileFactory

@pytest.mark.django_db
class TestSomething:
    def test_something(self):
        # Create realistic test data
        user = UserFactory(username='testuser', email='test@example.com')
        user_with_profile = UserWithProfileFactory(marketing_consent=True)
        
        # Create batches of data
        users = UserFactory.create_batch(5)
        
        # Use specialized factories
        verified_user = VerifiedUserFactory()
        admin_user = AdminUserFactory()
```

### Database Testing Approach

```python
import pytest
from django.contrib.auth import get_user_model
from django_myuser.models import Profile, AuditLog

User = get_user_model()

@pytest.mark.django_db
class TestUserWorkflow:
    def test_user_creation_workflow(self, api_client):
        # Initial state
        initial_count = User.objects.count()
        
        # Perform operation
        user_data = {'email': 'test@example.com', 'password': 'testpass123'}
        response = api_client.post('/api/register/', user_data)
        
        # Verify API response
        assert response.status_code == 201
        
        # Verify database state
        assert User.objects.count() == initial_count + 1
        new_user = User.objects.latest('date_joined')
        assert new_user.email == user_data['email']
        
        # Verify related objects created
        assert Profile.objects.filter(user=new_user).exists()
        
        # Verify audit trail
        assert AuditLog.objects.filter(
            user=new_user, 
            event_type=AuditLog.EventType.ACCOUNT_CREATED
        ).exists()
```

## Security Testing Guidelines

### Authentication Security
- Test token tampering and forgery attempts
- Verify proper token expiration handling
- Test refresh token rotation and blacklisting
- Check for timing attack vulnerabilities

### Authorization Security  
- Test cross-user data access prevention
- Verify admin privilege boundaries
- Test permission escalation attempts
- Check for information disclosure

### Input Validation Security
- Test SQL injection prevention
- Test XSS prevention in API responses
- Test parameter tampering
- Verify proper error handling

### Rate Limiting Security
- Test brute force attack prevention
- Test distributed attack simulation
- Verify rate limit bypass prevention
- Test legitimate user impact

## Common Testing Patterns

### API Testing Pattern
```python
@pytest.mark.django_db
class TestAPIEndpoint:
    def test_api_endpoint_success(self, api_client):
        # Setup: Create test data
        user = UserFactory()
        api_client.force_authenticate(user=user)
        
        # Action: Make API call
        response = api_client.get('/api/endpoint/')
        
        # Verify: Check response and side effects
        assert response.status_code == 200
        assert User.objects.count() == 1
        assert AuditLog.objects.filter(user=user, event_type='EXPECTED_EVENT').exists()
```

### Security Testing Pattern
```python
@pytest.mark.django_db
class TestSecurity:
    def test_unauthorized_access_prevention(self, api_client):
        # Setup: Create resources for different users
        user1 = UserFactory()
        user2 = UserFactory()
        user1_resource = ResourceFactory(user=user1)
        
        # Action: Try to access as different user
        api_client.force_authenticate(user=user2)
        response = api_client.get(f'/api/resource/{user1_resource.id}/')
        
        # Verify: Access denied
        assert response.status_code == 404  # Not 403 to avoid info disclosure
        
        # Verify: Resource unchanged
        user1_resource.refresh_from_db()
        # ... verify no changes
```

### Concurrency Testing Pattern
```python
import pytest
from threading import Thread

@pytest.mark.django_db
class TestConcurrency:
    def test_concurrent_operations(self):
        results = []
        
        def operation():
            # Perform operation in separate thread
            user = UserFactory()
            results.append(user.id)
        
        # Start multiple threads
        threads = [Thread(target=operation) for _ in range(5)]
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 5
        assert len(set(results)) == 5  # All unique IDs
```

## Coverage Goals

### Minimum Coverage Targets
- **Overall**: 90% line coverage
- **Critical paths**: 100% (authentication, authorization, data handling)
- **API endpoints**: 95%
- **Security functions**: 100%
- **Model methods**: 90%

### Coverage Exclusions
- Third-party integrations (mocked)
- Development/debug code
- Error handling for truly exceptional cases
- Deprecated code paths

## Best Practices

### Do's
✅ Test behavior, not implementation  
✅ Use descriptive test names that explain what's being tested  
✅ Test both success and failure scenarios  
✅ Verify database state alongside API responses  
✅ Use realistic test data via factories  
✅ Test security boundaries thoroughly  
✅ Include performance considerations in tests  
✅ Document complex test scenarios  

### Don'ts
❌ Over-mock internal application code  
❌ Test implementation details instead of behavior  
❌ Create brittle tests tied to internal structure  
❌ Ignore error conditions and edge cases  
❌ Use hardcoded test data that breaks easily  
❌ Skip security testing "because it's obvious"  
❌ Write tests that depend on external services  
❌ Ignore test performance and execution time  

## Troubleshooting

### Common Test Issues

**Tests failing due to "no such table" errors:**
```python
# Ensure @pytest.mark.django_db is applied to test classes
# Check that django_db_setup fixture is properly configured in conftest.py
# Verify database migrations are running in test setup
```

**Database transaction issues:**
```python
# Use pytest.mark.django_db(transaction=True) for transaction-dependent tests
# Use database fixtures from conftest.py for proper cleanup
```

**Race conditions in concurrent tests:**
```python
# Add proper synchronization
# Use database constraints where appropriate
```

**Flaky tests due to timing:**
```python
# Use deterministic test data with factories
# Mock time-dependent functionality properly
# Use pytest fixtures for consistent test setup
```

### Debugging Tests
```bash
# Run tests with verbose output
pytest -v

# Run specific test with pdb
pytest --pdb tests/integration/test_auth_api.py::TestAuthAPI::test_method

# Run with print statements (use --capture=no)
pytest -s tests/

# Generate coverage report
pytest --cov=django_myuser --cov-report=term-missing
```

## Maintenance

### Regular Maintenance Tasks
- Review and update test data factories
- Check for obsolete or redundant tests
- Update security tests for new vulnerabilities
- Monitor test execution performance
- Review coverage reports for gaps

### Test Migration from Legacy
- Analyze existing tests in `legacy/` folder
- Identify gaps in new test structure
- Migrate valuable tests to appropriate categories
- Improve test quality during migration
- Remove obsolete tests

## Contributing

### Adding New Tests
1. Determine appropriate test category (unit/integration/security/e2e)
2. Use existing base classes and utilities
3. Follow naming conventions and patterns
4. Include both positive and negative test cases
5. Update documentation if adding new patterns

### Test Review Guidelines
- Tests should be readable and maintainable
- Security implications should be considered
- Performance impact should be minimal
- Coverage should be meaningful, not just numerical

## Pytest-Django Configuration

### Database Setup
The test suite uses pytest-django for database handling:

```python
# conftest.py
@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    """Configure the test database with necessary data."""
    with django_db_blocker.unblock():
        from django.core.management import call_command
        call_command('migrate', verbosity=0, interactive=False, run_syncdb=True)
```

### Pytest Configuration
```ini
# pytest.ini
[pytest]
DJANGO_SETTINGS_MODULE = tests.test_project.settings
testpaths = tests/
python_classes = *TestCase *Test Test*
python_functions = test_*
addopts = 
    --tb=short
    -v
    --reuse-db
```

### Test Database Settings
```python
# tests/test_project/settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'test_db.sqlite3',
        'TEST': {
            'NAME': BASE_DIR / 'test_db.sqlite3',
        },
    }
}
```

### Key Benefits of This Setup
- **Automatic database creation**: Tables are created automatically via migrations
- **Database isolation**: Each test run gets a clean database state
- **Fast execution**: `--reuse-db` flag speeds up subsequent test runs
- **Proper cleanup**: pytest-django handles transaction rollback between tests

---

This test suite represents a comprehensive approach to testing Django MyUser, prioritizing real-world scenarios, security, and maintainability over simple metrics.