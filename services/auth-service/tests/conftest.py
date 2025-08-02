"""
Pytest configuration and fixtures for auth service testing.
Provides database, Redis, and application fixtures with proper cleanup.
"""
import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from httpx import AsyncClient
import fakeredis
import redis
from datetime import datetime, timedelta

# Import app and models
from src.main import app
from src.core.database import get_db, Base
from src.core.redis import redis_manager, get_cache_service
from src.core.config import settings
from src.models.user import User, Role, Permission
from src.models.session import UserSession
from src.models.audit import AuditLog
from src.services.auth_service import AuthService
from src.services.user_service import UserService
from src.services.session_service import SessionService

# Test database URL - use SQLite for faster tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
TEST_REDIS_URL = "redis://localhost:6379/15"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False}
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for each test."""
    async_session = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture
def mock_redis():
    """Create a fake Redis instance for testing."""
    fake_redis = fakeredis.FakeStrictRedis(decode_responses=True)
    return fake_redis


@pytest_asyncio.fixture
async def redis_client(mock_redis):
    """Create Redis client fixture."""
    # Mock the redis manager
    original_redis = redis_manager.redis
    redis_manager.redis = mock_redis
    
    yield mock_redis
    
    # Restore original
    redis_manager.redis = original_redis


@pytest.fixture
def override_get_db(db_session):
    """Override the database dependency."""
    async def _override_get_db():
        yield db_session
    return _override_get_db


@pytest.fixture
def client(override_get_db, redis_client):
    """Create FastAPI test client."""
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as client:
        yield client
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(override_get_db, redis_client):
    """Create async HTTP client for testing."""
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_permissions(db_session: AsyncSession):
    """Create test permissions."""
    permissions = [
        Permission(name="users:create", resource="users", action="create", description="Create users"),
        Permission(name="users:read", resource="users", action="read", description="Read users"),
        Permission(name="users:update", resource="users", action="update", description="Update users"),
        Permission(name="users:delete", resource="users", action="delete", description="Delete users"),
        Permission(name="roles:create", resource="roles", action="create", description="Create roles"),
        Permission(name="roles:read", resource="roles", action="read", description="Read roles"),
        Permission(name="sessions:read", resource="sessions", action="read", description="Read sessions"),
        Permission(name="sessions:delete", resource="sessions", action="delete", description="Delete sessions"),
    ]
    
    for permission in permissions:
        db_session.add(permission)
    
    await db_session.commit()
    
    # Refresh to get IDs
    for permission in permissions:
        await db_session.refresh(permission)
    
    return permissions


@pytest_asyncio.fixture
async def test_roles(db_session: AsyncSession, test_permissions):
    """Create test roles with permissions."""
    # Admin role with all permissions
    admin_role = Role(name="admin", description="Administrator role")
    db_session.add(admin_role)
    
    # User role with basic permissions
    user_role = Role(name="user", description="Standard user role")
    db_session.add(user_role)
    
    # Manager role with some admin permissions
    manager_role = Role(name="manager", description="Manager role")
    db_session.add(manager_role)
    
    await db_session.commit()
    
    # Refresh to get IDs
    await db_session.refresh(admin_role)
    await db_session.refresh(user_role)
    await db_session.refresh(manager_role)
    
    # Assign permissions
    admin_role.permissions.extend(test_permissions)  # All permissions
    user_role.permissions.extend([p for p in test_permissions if p.resource == "sessions" and p.action == "read"])
    manager_role.permissions.extend([p for p in test_permissions if p.resource in ["users", "sessions"]])
    
    await db_session.commit()
    
    return {"admin": admin_role, "user": user_role, "manager": manager_role}


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession, test_roles):
    """Create a test user."""
    user = await User.create_user(
        db=db_session,
        email="test@example.com",
        password="TestPassword123!",
        first_name="Test",
        last_name="User",
        is_active=True
    )
    
    # Assign user role
    user.roles.append(test_roles["user"])
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest_asyncio.fixture
async def test_admin_user(db_session: AsyncSession, test_roles):
    """Create a test admin user."""
    admin = await User.create_user(
        db=db_session,
        email="admin@example.com",
        password="AdminPassword123!",
        first_name="Admin",
        last_name="User",
        is_active=True
    )
    
    # Assign admin role
    admin.roles.append(test_roles["admin"])
    await db_session.commit()
    await db_session.refresh(admin)
    
    return admin


@pytest_asyncio.fixture
async def test_inactive_user(db_session: AsyncSession):
    """Create an inactive test user."""
    user = await User.create_user(
        db=db_session,
        email="inactive@example.com",
        password="InactivePassword123!",
        first_name="Inactive",
        last_name="User",
        is_active=False
    )
    
    return user


@pytest_asyncio.fixture
async def test_session(db_session: AsyncSession, test_user):
    """Create a test session."""
    session = await UserSession.create_session(
        db=db_session,
        user_id=test_user.id,
        ip_address="127.0.0.1",
        user_agent="TestAgent/1.0",
        device_info={"device": "test"},
        location_data={"country": "US"},
        session_lifetime=3600
    )
    
    return session


@pytest_asyncio.fixture
async def expired_session(db_session: AsyncSession, test_user):
    """Create an expired test session."""
    session = await UserSession.create_session(
        db=db_session,
        user_id=test_user.id,
        ip_address="127.0.0.1",
        user_agent="TestAgent/1.0",
        device_info={"device": "test"},
        location_data={"country": "US"},
        session_lifetime=1  # 1 second
    )
    
    # Make it expired
    session.expires_at = datetime.utcnow() - timedelta(hours=1)
    await session.save(db_session)
    
    return session


@pytest.fixture
def auth_service():
    """Create AuthService instance."""
    return AuthService()


@pytest.fixture
def user_service():
    """Create UserService instance."""
    return UserService()


@pytest.fixture
def session_service():
    """Create SessionService instance."""
    return SessionService()


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger."""
    mock = AsyncMock()
    return mock


@pytest.fixture
def mock_cache_service():
    """Mock cache service."""
    mock = AsyncMock()
    mock.get.return_value = None
    mock.set.return_value = True
    mock.delete.return_value = True
    mock.delete_pattern.return_value = True
    return mock


@pytest.fixture
def mock_security_service():
    """Mock security service methods."""
    mock = MagicMock()
    mock.create_access_token.return_value = "test-access-token"
    mock.create_refresh_token.return_value = "test-refresh-token"
    mock.decode_token.return_value = {"sub": "1", "type": "access", "session_id": "test-session"}
    mock.generate_password_reset_token.return_value = "test-reset-token"
    mock.verify_password_reset_token.return_value = "test@example.com"
    return mock


@pytest.fixture
def client_info():
    """Standard client info for tests."""
    return {
        "ip_address": "127.0.0.1",
        "user_agent": "TestAgent/1.0 (Testing)",
        "device_info": {
            "device_type": "desktop",
            "os": "Linux",
            "browser": "TestBrowser"
        },
        "location_data": {
            "country": "US",
            "city": "Test City",
            "latitude": 40.7128,
            "longitude": -74.0060
        }
    }


@pytest.fixture
def valid_login_data():
    """Valid login request data."""
    return {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "remember_me": False,
        "device_info": {
            "device_type": "desktop",
            "os": "Linux",
            "browser": "TestBrowser"
        }
    }


@pytest.fixture
def invalid_login_data():
    """Invalid login request data."""
    return {
        "email": "nonexistent@example.com",
        "password": "WrongPassword123!",
        "remember_me": False
    }


@pytest_asyncio.fixture
async def authenticated_headers(test_user, auth_service, db_session):
    """Create authenticated headers for API requests."""
    # Create a session and tokens
    session = await UserSession.create_session(
        db=db_session,
        user_id=test_user.id,
        ip_address="127.0.0.1",
        user_agent="TestAgent/1.0",
        session_lifetime=3600
    )
    
    access_token = "test-access-token"
    
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def mock_email_service():
    """Mock email service for testing."""
    mock = AsyncMock()
    mock.send_password_reset_email.return_value = True
    mock.send_verification_email.return_value = True
    return mock


# Performance testing fixtures
@pytest.fixture
def benchmark_user_data():
    """User data for performance benchmarking."""
    return [
        {
            "email": f"user{i}@example.com",
            "password": f"Password{i}123!",
            "first_name": f"User{i}",
            "last_name": "Test"
        }
        for i in range(100)
    ]


# Security testing fixtures
@pytest.fixture
def malicious_inputs():
    """Common malicious inputs for security testing."""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --"
        ],
        "xss_payloads": [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "&lt;script&gt;alert('xss')&lt;/script&gt;",
            "onerror=alert('xss')"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`"
        ]
    }


@pytest.fixture
def compliance_test_data():
    """Test data for compliance testing."""
    return {
        "pii_data": {
            "email": "pii.test@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "phone_number": "+1234567890",
            "ssn": "123-45-6789",
            "date_of_birth": "1990-01-01"
        },
        "sensitive_data": {
            "credit_card": "4111111111111111",
            "bank_account": "123456789",
            "medical_record": "MR123456789"
        }
    }


# Cleanup fixtures
@pytest.fixture(autouse=True)
async def cleanup_test_data(db_session):
    """Automatically cleanup test data after each test."""
    yield
    
    # Cleanup in reverse dependency order
    try:
        await db_session.execute(text("DELETE FROM audit_log"))
        await db_session.execute(text("DELETE FROM user_session"))
        await db_session.execute(text("DELETE FROM user_roles"))
        await db_session.execute(text("DELETE FROM role_permissions"))
        await db_session.execute(text("DELETE FROM user"))
        await db_session.execute(text("DELETE FROM role"))
        await db_session.execute(text("DELETE FROM permission"))
        await db_session.commit()
    except Exception as e:
        await db_session.rollback()
        print(f"Cleanup error: {e}")


@pytest.fixture(autouse=True)
def reset_mocks():
    """Reset all mocks after each test."""
    yield
    # This will be called after each test
    pass


# Parametrized fixtures for different test scenarios
@pytest.fixture(params=[True, False])
def remember_me(request):
    """Parametrized fixture for remember_me testing."""
    return request.param


@pytest.fixture(params=["admin", "user", "manager"])
def user_role(request):
    """Parametrized fixture for different user roles."""
    return request.param


@pytest.fixture(params=[1, 5, 10, 50])
def bulk_operation_size(request):
    """Parametrized fixture for bulk operation testing."""
    return request.param