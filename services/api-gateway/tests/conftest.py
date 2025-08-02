"""
Comprehensive test configuration and fixtures for API Gateway tests.
Provides shared fixtures, mocks, and testing utilities.
"""
import asyncio
import pytest
import httpx
import time
import uuid
from typing import Dict, Any, Optional, AsyncGenerator
from unittest.mock import AsyncMock, Mock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
import fakeredis.aioredis

from src.main import create_app
from src.core.config import Settings, get_settings
from src.services.auth_service import UserInfo, AuthService
from src.services.rate_limiter import RateLimitResult, RateLimitType, RateLimit
from src.services.circuit_breaker import CircuitBreakerState, CircuitState, CircuitBreakerConfig
from src.services.service_registry import ServiceEndpoint, ServiceRegistry


class TestSettings(Settings):
    """Test-specific settings with safe defaults."""
    
    environment: str = "test"
    debug: bool = True
    
    # Use in-memory/test databases
    database_url: str = "sqlite+aiosqlite:///:memory:"
    redis_url: str = "redis://localhost:6379/15"
    
    # Test service URLs
    auth_service_url: str = "http://test-auth:8000"
    user_service_url: str = "http://test-user:8000"
    business_service_urls: Dict[str, str] = {
        "orders": "http://test-orders:8000",
        "products": "http://test-products:8000",
        "inventory": "http://test-inventory:8000"
    }
    
    # Security settings for testing
    secret_key: str = "test-secret-key-for-jwt-signing-very-long-key-for-testing"
    cors_origins: list = ["*"]
    allowed_hosts: list = ["*"]
    
    # Reduced timeouts for faster tests
    circuit_breaker_timeout: int = 1
    circuit_breaker_reset_timeout: int = 5
    request_timeout: int = 5
    
    # Lower rate limits for easier testing
    global_rate_limit_requests: int = 100
    global_rate_limit_window: int = 60
    user_rate_limit_requests: int = 50
    user_rate_limit_window: int = 60
    
    # Disable external dependencies in tests
    metrics_enabled: bool = False
    tracing_enabled: bool = False
    jaeger_endpoint: Optional[str] = None
    
    class Config:
        env_file = ".env.test"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings():
    """Provide test settings."""
    return TestSettings()


@pytest.fixture
async def fake_redis():
    """Provide fake Redis client for testing."""
    redis_client = fakeredis.aioredis.FakeRedis()
    await redis_client.flushall()
    yield redis_client
    await redis_client.close()


@pytest.fixture
def mock_auth_service():
    """Mock authentication service with comprehensive responses."""
    mock_service = AsyncMock(spec=AuthService)
    
    # Default successful user
    default_user = UserInfo(
        user_id="test-user-123",
        email="test@example.com",
        roles=["user"],
        permissions=["read", "write"],
        is_active=True,
        is_verified=True,
        metadata={"test": True, "department": "engineering"}
    )
    
    # Admin user for privileged operations
    admin_user = UserInfo(
        user_id="admin-user-456",
        email="admin@example.com",
        roles=["admin", "user"],
        permissions=["read", "write", "admin", "delete"],
        is_active=True,
        is_verified=True,
        metadata={"test": True, "department": "admin"}
    )
    
    # Token validation responses
    async def mock_validate_token(token: str) -> Optional[UserInfo]:
        if token == "valid-user-token":
            return default_user
        elif token == "valid-admin-token":
            return admin_user
        elif token == "inactive-user-token":
            return UserInfo(
                user_id="inactive-user",
                email="inactive@example.com",
                roles=["user"],
                permissions=["read"],
                is_active=False,  # Inactive user
                is_verified=True
            )
        elif token == "unverified-user-token":
            return UserInfo(
                user_id="unverified-user",
                email="unverified@example.com",
                roles=["user"],
                permissions=["read"],
                is_active=True,
                is_verified=False  # Unverified user
            )
        return None
    
    mock_service.validate_token.side_effect = mock_validate_token
    mock_service.initialize.return_value = None
    mock_service.cleanup.return_value = None
    mock_service.health_check.return_value = {
        "status": "healthy",
        "auth_service": "healthy",
        "response_time": 0.05
    }
    
    return mock_service


@pytest.fixture
def mock_service_registry():
    """Mock service registry with test services."""
    mock_registry = AsyncMock(spec=ServiceRegistry)
    
    # Define test services
    test_services = {
        "auth": ServiceEndpoint(
            name="auth",
            url="http://test-auth:8000",
            health_check_url="http://test-auth:8000/health",
            version="1.0.0",
            status="healthy",
            last_health_check=time.time(),
            metadata={"type": "auth"}
        ),
        "user": ServiceEndpoint(
            name="user",
            url="http://test-user:8000",
            health_check_url="http://test-user:8000/health",
            version="1.0.0",
            status="healthy",
            last_health_check=time.time(),
            metadata={"type": "user"}
        ),
        "orders": ServiceEndpoint(
            name="orders",
            url="http://test-orders:8000",
            health_check_url="http://test-orders:8000/health",
            version="1.0.0",
            status="healthy",
            last_health_check=time.time(),
            metadata={"type": "business"}
        ),
        "products": ServiceEndpoint(
            name="products",
            url="http://test-products:8000",
            health_check_url="http://test-products:8000/health",
            version="1.0.0",
            status="healthy",
            last_health_check=time.time(),
            metadata={"type": "business"}
        )
    }
    
    # Mock methods
    mock_registry.get_service_url.side_effect = lambda name: test_services.get(name, {}).get("url")
    mock_registry.get_service_endpoint.side_effect = lambda name: test_services.get(name)
    mock_registry.get_all_services_status.return_value = {
        name: {
            "status": service.status,
            "url": service.url,
            "last_check": service.last_health_check,
            "version": service.version,
            "response_time": 0.05
        }
        for name, service in test_services.items()
    }
    mock_registry.get_healthy_services.return_value = [
        name for name, service in test_services.items() 
        if service.status == "healthy"
    ]
    mock_registry.health_check_all_services.return_value = None
    mock_registry.initialize.return_value = None
    mock_registry.cleanup.return_value = None
    
    return mock_registry


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for external service calls."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    # Default successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.content = b'{"status": "success"}'
    mock_response.json.return_value = {"status": "success"}
    
    mock_client.request.return_value = mock_response
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    mock_client.put.return_value = mock_response
    mock_client.delete.return_value = mock_response
    mock_client.patch.return_value = mock_response
    
    return mock_client


@pytest.fixture
def mock_circuit_breaker_manager():
    """Mock circuit breaker manager."""
    mock_manager = AsyncMock()
    
    # Default to allowing calls (circuit closed)
    async def mock_call_with_breaker(service_name: str, func, *args, **kwargs):
        return await func(*args, **kwargs)
    
    mock_manager.call_with_circuit_breaker.side_effect = mock_call_with_breaker
    mock_manager.get_all_states.return_value = {
        "auth": {
            "name": "auth",
            "state": "closed",
            "failure_count": 0,
            "success_count": 100,
            "total_calls": 100
        }
    }
    mock_manager.reset_circuit_breaker.return_value = True
    mock_manager.health_check.return_value = {
        "total_breakers": 1,
        "open_breakers": 0,
        "half_open_breakers": 0,
        "closed_breakers": 1,
        "health": "healthy"
    }
    
    return mock_manager


@pytest.fixture
def mock_rate_limiter_manager():
    """Mock rate limiter manager."""
    mock_manager = AsyncMock()
    
    # Default to allowing requests
    default_result = RateLimitResult(
        allowed=True,
        remaining=99,
        reset_time=time.time() + 60,
        limit_type="user"
    )
    
    mock_manager.check_rate_limit.return_value = default_result
    mock_manager.get_rate_limit_status.return_value = {
        "limit": 100,
        "used": 1,
        "remaining": 99,
        "reset_time": time.time() + 60,
        "window": 60
    }
    mock_manager.reset_rate_limit.return_value = True
    mock_manager.get_global_rate_limit_stats.return_value = {
        "total_keys": 10,
        "by_type": {"user": 5, "ip": 3, "global": 1, "api_key": 1}
    }
    
    return mock_manager


@pytest.fixture
async def app_with_mocks(
    test_settings,
    fake_redis,
    mock_auth_service,
    mock_service_registry,
    mock_circuit_breaker_manager,
    mock_rate_limiter_manager
):
    """Create FastAPI app with all dependencies mocked."""
    
    with patch("src.core.config.get_settings", return_value=test_settings), \
         patch("src.core.database.init_db"), \
         patch("src.core.redis.init_redis"), \
         patch("src.core.redis.get_redis", return_value=fake_redis), \
         patch("src.core.redis.redis_manager.get_client") as mock_redis_client, \
         patch("src.services.auth_service.auth_service", mock_auth_service):
        
        # Configure Redis client context manager
        mock_redis_client.return_value.__aenter__.return_value = fake_redis
        mock_redis_client.return_value.__aexit__.return_value = None
        
        app = create_app()
        
        # Set up app state with mocked services
        app.state.service_registry = mock_service_registry
        app.state.circuit_breaker_manager = mock_circuit_breaker_manager
        app.state.rate_limiter_manager = mock_rate_limiter_manager
        app.state.auth_service = mock_auth_service
        app.state.start_time = time.time()
        app.state.redis_manager = fake_redis
        
        yield app


@pytest.fixture
def client(app_with_mocks):
    """Test client with mocked dependencies."""
    return TestClient(app_with_mocks)


@pytest.fixture
def auth_headers():
    """Common authentication headers for tests."""
    return {
        "valid_user": {"Authorization": "Bearer valid-user-token"},
        "valid_admin": {"Authorization": "Bearer valid-admin-token"},
        "inactive_user": {"Authorization": "Bearer inactive-user-token"},
        "unverified_user": {"Authorization": "Bearer unverified-user-token"},
        "invalid": {"Authorization": "Bearer invalid-token"},
        "malformed": {"Authorization": "InvalidFormat token"},
        "missing": {}
    }


@pytest.fixture
def sample_request_data():
    """Sample request data for various test scenarios."""
    return {
        "user_creation": {
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "first_name": "John",
            "last_name": "Doe"
        },
        "user_update": {
            "first_name": "Jane",
            "last_name": "Smith",
            "phone": "+1234567890"
        },
        "order_creation": {
            "items": [
                {"product_id": "prod-123", "quantity": 2, "price": 29.99},
                {"product_id": "prod-456", "quantity": 1, "price": 49.99}
            ],
            "customer_id": "cust-789",
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "12345"
            }
        },
        "large_payload": {
            "data": "x" * (5 * 1024 * 1024)  # 5MB payload
        },
        "malicious_payload": {
            "script": "<script>alert('xss')</script>",
            "sql_injection": "'; DROP TABLE users; --",
            "path_traversal": "../../../etc/passwd",
            "command_injection": "; rm -rf /"
        }
    }


@pytest.fixture
async def performance_test_data():
    """Generate test data for performance testing."""
    return {
        "concurrent_users": 50,
        "requests_per_user": 10,
        "test_duration": 30,  # seconds
        "expected_latency_p95": 200,  # milliseconds
        "expected_throughput": 100  # requests per second
    }


class MockBackendService:
    """Mock backend service for integration testing."""
    
    def __init__(self, name: str, port: int = 8001):
        self.name = name
        self.port = port
        self.responses = {}
        self.delay = 0
        self.failure_rate = 0
        self.is_healthy = True
    
    def set_response(self, endpoint: str, response: Dict[str, Any], status: int = 200):
        """Set mock response for an endpoint."""
        self.responses[endpoint] = (response, status)
    
    def set_delay(self, delay: float):
        """Set response delay in seconds."""
        self.delay = delay
    
    def set_failure_rate(self, rate: float):
        """Set failure rate (0.0 to 1.0)."""
        self.failure_rate = rate
    
    def set_health_status(self, is_healthy: bool):
        """Set service health status."""
        self.is_healthy = is_healthy


@pytest.fixture
def mock_backend_services():
    """Create mock backend services for testing."""
    services = {
        "auth": MockBackendService("auth", 8001),
        "user": MockBackendService("user", 8002),
        "orders": MockBackendService("orders", 8003),
        "products": MockBackendService("products", 8004)
    }
    
    # Set default responses
    services["auth"].set_response("/health", {"status": "healthy"})
    services["user"].set_response("/health", {"status": "healthy"})
    services["orders"].set_response("/health", {"status": "healthy"})
    services["products"].set_response("/health", {"status": "healthy"})
    
    return services


@pytest.fixture
def compliance_test_data():
    """Test data for compliance testing."""
    return {
        "gdpr": {
            "eu_user_data": {
                "user_id": "eu-user-123",
                "email": "user@example.eu",
                "ip_address": "192.168.1.1",
                "location": "Germany",
                "consent_status": True,
                "data_processing_purposes": ["authentication", "analytics"]
            },
            "data_subject_request": {
                "type": "access",
                "user_id": "eu-user-123",
                "verification_token": "gdpr-token-123"
            }
        },
        "hipaa": {
            "phi_data": {
                "patient_id": "patient-456",
                "medical_record_number": "MRN-789",
                "diagnosis_codes": ["Z00.00", "M79.3"],
                "sensitive": True
            },
            "audit_entry": {
                "user_id": "healthcare-provider-123",
                "action": "view_patient_record",
                "resource": "patient-456",
                "timestamp": time.time()
            }
        },
        "soc2": {
            "security_event": {
                "event_type": "authentication_failure",
                "user_id": "user-123",
                "ip_address": "10.0.0.1",
                "user_agent": "test-client/1.0",
                "timestamp": time.time(),
                "details": {"reason": "invalid_credentials"}
            },
            "access_control": {
                "resource": "/admin/users",
                "required_permissions": ["admin", "user_management"],
                "user_permissions": ["user", "read"]
            }
        }
    }


# Utility functions for tests

def generate_jwt_token(user_id: str, expires_in: int = 3600) -> str:
    """Generate a test JWT token."""
    import jwt
    payload = {
        "user_id": user_id,
        "exp": time.time() + expires_in,
        "iat": time.time()
    }
    return jwt.encode(payload, "test-secret", algorithm="HS256")


def create_test_request_id() -> str:
    """Generate a test request ID."""
    return f"test-req-{uuid.uuid4()}"


async def wait_for_async_operations(timeout: float = 1.0):
    """Wait for any pending async operations to complete."""
    await asyncio.sleep(timeout)


# Performance testing utilities

class PerformanceMonitor:
    """Monitor performance metrics during testing."""
    
    def __init__(self):
        self.requests = []
        self.start_time = None
        self.end_time = None
    
    def start(self):
        """Start monitoring."""
        self.start_time = time.time()
    
    def stop(self):
        """Stop monitoring."""
        self.end_time = time.time()
    
    def record_request(self, duration: float, status_code: int):
        """Record a request."""
        self.requests.append({
            "duration": duration,
            "status_code": status_code,
            "timestamp": time.time()
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.requests:
            return {}
        
        durations = [r["duration"] for r in self.requests]
        success_count = len([r for r in self.requests if 200 <= r["status_code"] < 300])
        
        return {
            "total_requests": len(self.requests),
            "successful_requests": success_count,
            "success_rate": success_count / len(self.requests) if self.requests else 0,
            "avg_duration": sum(durations) / len(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "p95_duration": sorted(durations)[int(len(durations) * 0.95)],
            "total_duration": self.end_time - self.start_time if self.end_time else 0,
            "throughput": len(self.requests) / (self.end_time - self.start_time) if self.end_time and self.start_time else 0
        }


@pytest.fixture
def performance_monitor():
    """Performance monitoring fixture."""
    return PerformanceMonitor()