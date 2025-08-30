"""
Test data factories for creating realistic test objects.
Using factory_boy for consistent and flexible test data generation.
"""
import factory
from django.contrib.auth import get_user_model
from django.utils import timezone
from faker import Faker
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.account.models import EmailAddress

from django_myuser.models import Profile, UserSession, DataRequest, AuditLog

User = get_user_model()
fake = Faker()


class UserFactory(factory.django.DjangoModelFactory):
    """Factory for creating User instances with realistic data."""
    
    class Meta:
        model = User
        skip_postgeneration_save = True
    
    username = factory.Sequence(lambda n: f'user{n}')
    email = factory.LazyAttribute(lambda obj: f'{obj.username}@example.com')
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    is_active = True
    is_staff = False
    is_superuser = False
    date_joined = factory.Faker('date_time_this_year', tzinfo=timezone.get_current_timezone())
    
    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        """Set password after user creation."""
        if not create:
            return
        
        password = extracted or 'TestPassword123!'
        self.set_password(password)
        self.save()


class AdminUserFactory(UserFactory):
    """Factory for creating admin users."""
    
    is_staff = True
    is_superuser = True
    username = factory.Sequence(lambda n: f'admin{n}')
    email = factory.LazyAttribute(lambda obj: f'{obj.username}@admin.com')


class ProfileFactory(factory.django.DjangoModelFactory):
    """Factory for creating Profile instances."""
    
    class Meta:
        model = Profile
    
    user = factory.SubFactory(UserFactory)
    marketing_consent = factory.Faker('boolean', chance_of_getting_true=30)
    marketing_consent_updated_at = factory.Maybe(
        'marketing_consent',
        yes_declaration=factory.Faker('date_time_this_month', tzinfo=timezone.get_current_timezone()),
        no_declaration=None
    )


class UserSessionFactory(factory.django.DjangoModelFactory):
    """Factory for creating UserSession instances."""
    
    class Meta:
        model = UserSession
    
    user = factory.SubFactory(UserFactory)
    ip_address = factory.Faker('ipv4')
    user_agent = factory.Faker('user_agent')
    refresh_token = factory.Faker('uuid4')
    created_at = factory.Faker('date_time_this_month', tzinfo=timezone.get_current_timezone())
    last_activity = factory.Faker('date_time_between', start_date='-1d', end_date='now', tzinfo=timezone.get_current_timezone())


class DataRequestFactory(factory.django.DjangoModelFactory):
    """Factory for creating DataRequest instances."""
    
    class Meta:
        model = DataRequest
    
    user = factory.SubFactory(UserFactory)
    request_type = factory.Iterator([choice[0] for choice in DataRequest.RequestType.choices])
    status = factory.Iterator([choice[0] for choice in DataRequest.RequestStatus.choices])
    notes = factory.Faker('sentence', nb_words=6)


class AuditLogFactory(factory.django.DjangoModelFactory):
    """Factory for creating AuditLog instances."""
    
    class Meta:
        model = AuditLog
    
    user = factory.SubFactory(UserFactory)
    event_type = factory.Iterator([choice[0] for choice in AuditLog.EventType.choices])
    ip_address = factory.Faker('ipv4')
    user_agent = factory.Faker('user_agent')
    description = factory.Faker('sentence', nb_words=6)
    timestamp = factory.Faker('date_time_this_month', tzinfo=timezone.get_current_timezone())
    
    @factory.lazy_attribute
    def extra_data(self):
        """Generate realistic extra data based on event type."""
        if self.event_type == AuditLog.EventType.LOGIN_SUCCESS:
            return {'login_method': 'password'}
        elif self.event_type == AuditLog.EventType.SOCIAL_ACCOUNT_CONNECTED:
            return {'provider': fake.random_element(['google', 'github', 'facebook'])}
        elif self.event_type == AuditLog.EventType.PROFILE_UPDATED:
            return {'fields_updated': ['marketing_consent']}
        return {}


class SocialAppFactory(factory.django.DjangoModelFactory):
    """Factory for creating SocialApp instances."""
    
    class Meta:
        model = SocialApp
    
    provider = factory.Iterator(['google', 'github', 'facebook'])
    name = factory.LazyAttribute(lambda obj: obj.provider.title())
    client_id = factory.LazyAttribute(lambda obj: f'test-{obj.provider}-client-id')
    secret = factory.LazyAttribute(lambda obj: f'test-{obj.provider}-secret')


class SocialAccountFactory(factory.django.DjangoModelFactory):
    """Factory for creating SocialAccount instances."""
    
    class Meta:
        model = SocialAccount
    
    user = factory.SubFactory(UserFactory)
    provider = factory.Iterator(['google', 'github', 'facebook'])
    uid = factory.Faker('uuid4')
    
    @factory.lazy_attribute
    def extra_data(self):
        """Generate realistic extra data based on provider."""
        base_data = {
            'id': self.uid,
            'name': f'{self.user.first_name} {self.user.last_name}',
            'email': self.user.email,
        }
        
        if self.provider == 'google':
            return {
                **base_data,
                'picture': fake.image_url(),
                'locale': 'en',
                'verified_email': True
            }
        elif self.provider == 'github':
            return {
                **base_data,
                'login': self.user.username,
                'avatar_url': fake.image_url(),
                'public_repos': fake.random_int(0, 50)
            }
        elif self.provider == 'facebook':
            return {
                **base_data,
                'picture': {'data': {'url': fake.image_url()}},
                'locale': 'en_US'
            }
        
        return base_data


class EmailAddressFactory(factory.django.DjangoModelFactory):
    """Factory for creating EmailAddress instances."""
    
    class Meta:
        model = EmailAddress
    
    user = factory.SubFactory(UserFactory)
    email = factory.LazyAttribute(lambda obj: obj.user.email)
    verified = factory.Faker('boolean', chance_of_getting_true=80)
    primary = True


# Specialized factories for common test scenarios

class UserWithProfileFactory(UserFactory):
    """Factory that creates a user with an explicit profile."""
    
    @factory.post_generation
    def create_profile(self, create, extracted, **kwargs):
        if create:
            ProfileFactory(user=self, **kwargs)


class UserWithSocialAccountFactory(UserFactory):
    """Factory that creates a user with a social account."""
    
    @factory.post_generation
    def create_social_account(self, create, extracted, **kwargs):
        if create:
            provider = extracted or 'google'
            SocialAccountFactory(user=self, provider=provider, **kwargs)


class UserWithSessionFactory(UserFactory):
    """Factory that creates a user with an active session."""
    
    @factory.post_generation
    def create_session(self, create, extracted, **kwargs):
        if create:
            UserSessionFactory(user=self, **kwargs)


class UserWithDataRequestFactory(UserFactory):
    """Factory that creates a user with a data request."""
    
    @factory.post_generation
    def create_data_request(self, create, extracted, **kwargs):
        if create:
            request_type = extracted or 'EXPORT'
            DataRequestFactory(user=self, request_type=request_type, **kwargs)


# Trait factories for specific user states

class VerifiedUserFactory(UserFactory):
    """Factory for users with verified email addresses."""
    
    @factory.post_generation
    def verify_email(self, create, extracted, **kwargs):
        if create:
            EmailAddressFactory(user=self, verified=True)


class UnverifiedUserFactory(UserFactory):
    """Factory for users with unverified email addresses."""
    
    @factory.post_generation
    def unverified_email(self, create, extracted, **kwargs):
        if create:
            EmailAddressFactory(user=self, verified=False)


class InactiveUserFactory(UserFactory):
    """Factory for inactive users."""
    
    is_active = False


class RecentUserFactory(UserFactory):
    """Factory for recently created users."""
    
    date_joined = factory.Faker('date_time_between', start_date='-1d', end_date='now', tzinfo=timezone.get_current_timezone())


# Batch creation helpers

def create_users_batch(count=5, **kwargs):
    """Create a batch of users with optional common attributes."""
    return UserFactory.create_batch(count, **kwargs)


def create_mixed_user_types():
    """Create a mix of different user types for comprehensive testing."""
    return {
        'regular': UserFactory(),
        'admin': AdminUserFactory(),
        'with_profile': UserWithProfileFactory(),
        'with_social': UserWithSocialAccountFactory(),
        'verified': VerifiedUserFactory(),
        'unverified': UnverifiedUserFactory(),
        'inactive': InactiveUserFactory(),
        'recent': RecentUserFactory(),
    }


def create_realistic_user_data():
    """Create realistic user data for forms and API testing."""
    return {
        'username': fake.user_name(),
        'email': fake.email(),
        'password': 'TestPassword123!',
        'first_name': fake.first_name(),
        'last_name': fake.last_name(),
    }


def create_realistic_profile_data():
    """Create realistic profile data for testing."""
    return {
        'marketing_consent': fake.boolean(chance_of_getting_true=30),
    }