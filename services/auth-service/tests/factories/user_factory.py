"""
User model factories for testing.
Uses Factory Boy to generate realistic test data with Faker.
"""
import factory
from factory import Faker, SubFactory, LazyAttribute, LazyFunction, post_generation
from faker import Faker as FakerInstance
from datetime import datetime, timedelta
import secrets
import string
from typing import List

from src.models.user import User, Role, Permission
from src.core.security import SecurityService

fake = FakerInstance()


class PermissionFactory(factory.Factory):
    """Factory for Permission model."""
    
    class Meta:
        model = Permission
    
    name = factory.LazyFunction(lambda: f"{fake.word()}:{fake.random_element(['create', 'read', 'update', 'delete'])}")
    description = Faker('sentence', nb_words=6)
    resource = Faker('word')
    action = Faker('random_element', elements=['create', 'read', 'update', 'delete'])
    
    created_at = Faker('date_time_between', start_date='-30d', end_date='now')
    updated_at = LazyAttribute(lambda obj: obj.created_at)
    is_deleted = False


class RoleFactory(factory.Factory):
    """Factory for Role model."""
    
    class Meta:
        model = Role
    
    name = Faker('job')
    description = Faker('sentence', nb_words=8)
    
    created_at = Faker('date_time_between', start_date='-30d', end_date='now')
    updated_at = LazyAttribute(lambda obj: obj.created_at)
    is_deleted = False
    
    @post_generation
    def permissions(self, create, extracted, **kwargs):
        """Add permissions to role after creation."""
        if not create:
            return
        
        if extracted:
            for permission in extracted:
                self.permissions.append(permission)


class UserFactory(factory.Factory):
    """Factory for User model."""
    
    class Meta:
        model = User
    
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    phone_number = Faker('phone_number')
    
    # Generate secure password
    password_hash = LazyFunction(
        lambda: SecurityService.get_password_hash("TestPassword123!")
    )
    
    is_active = True
    is_verified = Faker('boolean', chance_of_getting_true=80)
    email_verified_at = LazyAttribute(
        lambda obj: fake.date_time_between(start_date='-7d', end_date='now') if obj.is_verified else None
    )
    
    # Login tracking
    failed_login_attempts = 0
    last_login_at = Faker('date_time_between', start_date='-7d', end_date='now')
    last_login_ip = Faker('ipv4')
    account_locked_until = None
    
    # GDPR/Compliance fields
    data_processing_consent = True
    data_processing_consent_date = Faker('date_time_between', start_date='-30d', end_date='now')
    marketing_consent = Faker('boolean', chance_of_getting_true=60)
    marketing_consent_date = LazyAttribute(
        lambda obj: fake.date_time_between(start_date='-30d', end_date='now') if obj.marketing_consent else None
    )
    
    # Profile data (JSON field simulation)
    profile_data = LazyFunction(lambda: {
        "avatar_url": fake.image_url(),
        "bio": fake.text(max_nb_chars=200),
        "timezone": fake.timezone(),
        "language": fake.language_code()
    })
    
    # User preferences (JSON field simulation)
    preferences = LazyFunction(lambda: {
        "theme": fake.random_element(["light", "dark", "auto"]),
        "notifications": {
            "email": fake.boolean(),
            "push": fake.boolean(),
            "sms": fake.boolean()
        },
        "privacy": {
            "profile_visibility": fake.random_element(["public", "friends", "private"]),
            "activity_tracking": fake.boolean()
        }
    })
    
    created_at = Faker('date_time_between', start_date='-90d', end_date='now')
    updated_at = LazyAttribute(lambda obj: obj.created_at)
    is_deleted = False
    deleted_at = None
    
    @post_generation
    def roles(self, create, extracted, **kwargs):
        """Add roles to user after creation."""
        if not create:
            return
        
        if extracted:
            for role in extracted:
                self.roles.append(role)
        else:
            # Default to user role if none specified
            default_role = RoleFactory(name="user", description="Standard user role")
            self.roles.append(default_role)


class AdminUserFactory(UserFactory):
    """Factory for admin users."""
    
    email = LazyFunction(lambda: f"admin.{fake.user_name()}@example.com")
    is_active = True
    is_verified = True
    failed_login_attempts = 0
    
    @post_generation
    def roles(self, create, extracted, **kwargs):
        """Add admin role."""
        if not create:
            return
        
        admin_role = RoleFactory(name="admin", description="Administrator role")
        self.roles.append(admin_role)


class InactiveUserFactory(UserFactory):
    """Factory for inactive users."""
    
    is_active = False
    is_verified = False
    email_verified_at = None
    last_login_at = None


class LockedUserFactory(UserFactory):
    """Factory for locked user accounts."""
    
    failed_login_attempts = 5
    account_locked_until = LazyFunction(lambda: datetime.utcnow() + timedelta(hours=1))
    is_active = True


class UnverifiedUserFactory(UserFactory):
    """Factory for unverified users."""
    
    is_verified = False
    email_verified_at = None


class TestUserFactory(UserFactory):
    """Factory for test users with known credentials."""
    
    email = "test@example.com"
    first_name = "Test"
    last_name = "User"
    password_hash = LazyFunction(
        lambda: SecurityService.get_password_hash("TestPassword123!")
    )
    is_active = True
    is_verified = True


class BulkUserFactory:
    """Factory for creating multiple users efficiently."""
    
    @staticmethod
    def create_users(count: int, **kwargs) -> List[User]:
        """Create multiple users with shared characteristics."""
        users = []
        for i in range(count):
            user_data = {
                "email": f"user{i}@example.com",
                "first_name": f"User{i}",
                "last_name": "Test",
                "password_hash": SecurityService.get_password_hash(f"Password{i}123!"),
                "is_active": True,
                "is_verified": True,
                **kwargs
            }
            users.append(User(**user_data))
        return users
    
    @staticmethod
    def create_test_dataset() -> dict:
        """Create a comprehensive test dataset."""
        return {
            "active_users": BulkUserFactory.create_users(10, is_active=True),
            "inactive_users": BulkUserFactory.create_users(5, is_active=False),
            "unverified_users": BulkUserFactory.create_users(3, is_verified=False),
            "admin_users": [
                UserFactory(
                    email="admin@example.com",
                    first_name="Admin",
                    last_name="User",
                    is_active=True,
                    is_verified=True
                )
            ]
        }


class SecurityTestUserFactory(UserFactory):
    """Factory for security testing scenarios."""
    
    @classmethod
    def create_with_weak_password(cls):
        """Create user with weak password for testing."""
        return cls(
            password_hash=SecurityService.get_password_hash("123456")
        )
    
    @classmethod
    def create_with_malicious_data(cls):
        """Create user with potentially malicious data."""
        return cls(
            first_name="<script>alert('xss')</script>",
            last_name="'; DROP TABLE users; --",
            profile_data={
                "bio": "javascript:alert('xss')",
                "website": "http://malicious-site.com"
            }
        )


class ComplianceTestUserFactory(UserFactory):
    """Factory for compliance testing (GDPR, HIPAA, etc.)."""
    
    # Ensure PII fields are present for compliance testing
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    phone_number = Faker('phone_number')
    
    # Additional PII fields that might be present
    date_of_birth = Faker('date_of_birth', minimum_age=18, maximum_age=80)
    social_security_number = LazyFunction(
        lambda: f"{fake.random_int(100, 999)}-{fake.random_int(10, 99)}-{fake.random_int(1000, 9999)}"
    )
    
    # Compliance-specific fields
    data_processing_consent = True
    data_processing_consent_date = Faker('date_time_between', start_date='-30d', end_date='now')
    marketing_consent = False  # More conservative for compliance testing
    
    # HIPAA-relevant fields (if applicable)
    medical_record_number = LazyFunction(
        lambda: f"MRN{fake.random_int(100000, 999999)}"
    )
    
    profile_data = LazyFunction(lambda: {
        "medical_conditions": ["Condition A", "Condition B"],  # For HIPAA testing
        "emergency_contact": {
            "name": fake.name(),
            "phone": fake.phone_number(),
            "relationship": fake.random_element(["spouse", "parent", "sibling", "friend"])
        }
    })


# Custom trait factories for specific testing scenarios
class UserTraits:
    """Predefined user traits for common testing scenarios."""
    
    @staticmethod
    def recently_created():
        """User created within the last 24 hours."""
        return {
            "created_at": fake.date_time_between(start_date='-1d', end_date='now')
        }
    
    @staticmethod
    def long_time_user():
        """User created over a year ago."""
        return {
            "created_at": fake.date_time_between(start_date='-2y', end_date='-1y'),
            "last_login_at": fake.date_time_between(start_date='-7d', end_date='now')
        }
    
    @staticmethod
    def suspicious_activity():
        """User with suspicious activity patterns."""
        return {
            "failed_login_attempts": fake.random_int(2, 4),
            "last_login_ip": fake.ipv4(),
            "profile_data": {
                "login_locations": [
                    {"country": "US", "city": "New York"},
                    {"country": "RU", "city": "Moscow"},  # Suspicious location change
                    {"country": "CN", "city": "Beijing"}
                ]
            }
        }
    
    @staticmethod
    def gdpr_deletion_requested():
        """User who has requested GDPR deletion."""
        return {
            "is_active": False,
            "profile_data": {
                "gdpr_deletion_requested": True,
                "gdpr_deletion_date": fake.date_time_between(start_date='-7d', end_date='now')
            }
        }


# Factory sequences for unique data
class UserSequences:
    """Sequences for generating unique user data."""
    
    email_sequence = factory.Sequence(lambda n: f"user{n}@example.com")
    username_sequence = factory.Sequence(lambda n: f"user{n}")
    phone_sequence = factory.Sequence(lambda n: f"+1555{n:07d}")


# Load testing factory
class LoadTestUserFactory:
    """Factory optimized for load testing scenarios."""
    
    @staticmethod
    def create_batch(batch_size: int = 1000):
        """Create a batch of users for load testing."""
        users = []
        for i in range(batch_size):
            user = User(
                id=i + 1,
                email=f"loadtest{i}@example.com",
                password_hash=SecurityService.get_password_hash("LoadTest123!"),
                first_name=f"LoadTest",
                last_name=f"User{i}",
                is_active=True,
                is_verified=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            users.append(user)
        return users