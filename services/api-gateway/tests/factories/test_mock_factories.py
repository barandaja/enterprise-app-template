"""
Mock factories for external services and dependencies.
Provides realistic mock data and service responses for comprehensive testing.
"""
import pytest
import time
import json
import uuid
import random
from typing import Dict, Any, List, Optional
from unittest.mock import AsyncMock, MagicMock
from dataclasses import dataclass, asdict

from src.services.auth_service import UserInfo
from src.services.service_registry import ServiceEndpoint
from src.services.rate_limiter import RateLimit, RateLimitResult, RateLimitType
from src.services.circuit_breaker import CircuitBreakerConfig, CircuitBreakerState, CircuitState


class MockDataFactory:
    """Factory for generating realistic mock data."""
    
    @staticmethod
    def user_data(user_id: Optional[str] = None, **overrides) -> Dict[str, Any]:
        """Generate mock user data."""
        default_data = {
            "user_id": user_id or f"user_{uuid.uuid4().hex[:8]}",
            "email": f"user_{random.randint(1000, 9999)}@example.com",
            "first_name": random.choice(["John", "Jane", "Alice", "Bob", "Charlie"]),
            "last_name": random.choice(["Doe", "Smith", "Johnson", "Brown", "Wilson"]),
            "roles": random.choice([["user"], ["user", "premium"], ["admin", "user"]]),
            "permissions": random.choice([["read"], ["read", "write"], ["read", "write", "admin"]]),
            "is_active": random.choice([True, True, True, False]),  # 75% active
            "is_verified": random.choice([True, True, False]),  # 66% verified
            "created_at": time.time() - random.randint(0, 365 * 24 * 3600),  # Random time in past year
            "last_login": time.time() - random.randint(0, 7 * 24 * 3600),  # Random time in past week
            "metadata": {
                "registration_ip": f"192.168.1.{random.randint(1, 254)}",
                "user_agent": "Mozilla/5.0 (compatible; TestClient/1.0)",
                "preferences": {
                    "theme": random.choice(["light", "dark", "auto"]),
                    "language": random.choice(["en", "es", "fr", "de"]),
                    "notifications": random.choice([True, False])
                }
            }
        }
        default_data.update(overrides)
        return default_data
    
    @staticmethod
    def transaction_data(transaction_id: Optional[str] = None, **overrides) -> Dict[str, Any]:
        """Generate mock transaction data."""
        default_data = {
            "transaction_id": transaction_id or f"txn_{uuid.uuid4().hex[:12]}",
            "user_id": f"user_{uuid.uuid4().hex[:8]}",
            "amount": round(random.uniform(10.0, 1000.0), 2),
            "currency": random.choice(["USD", "EUR", "GBP", "CAD"]),
            "type": random.choice(["payment", "refund", "transfer", "fee"]),
            "status": random.choice(["pending", "completed", "failed"]),
            "timestamp": time.time() - random.randint(0, 30 * 24 * 3600),
            "description": f"Test transaction {random.randint(1000, 9999)}",
            "metadata": {
                "payment_method": random.choice(["credit_card", "bank_transfer", "paypal"]),
                "ip_address": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "device_id": f"device_{uuid.uuid4().hex[:8]}"
            }
        }
        default_data.update(overrides)
        return default_data
    
    @staticmethod
    def service_data(service_name: Optional[str] = None, **overrides) -> Dict[str, Any]:
        """Generate mock service data."""
        default_data = {
            "name": service_name or random.choice(["auth", "user", "orders", "payments", "notifications"]),
            "url": f"http://{service_name or 'service'}-{random.randint(1, 10)}:8000",
            "version": f"{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            "status": random.choice(["healthy", "healthy", "healthy", "unhealthy"]),  # 75% healthy
            "last_health_check": time.time() - random.randint(0, 300),  # Last 5 minutes
            "response_time": round(random.uniform(0.01, 0.5), 3),
            "instances": random.randint(1, 5),
            "metadata": {
                "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
                "environment": random.choice(["production", "staging", "development"]),
                "load": round(random.uniform(0.1, 0.9), 2)
            }
        }
        default_data.update(overrides)
        return default_data
    
    @staticmethod
    def audit_event_data(event_id: Optional[str] = None, **overrides) -> Dict[str, Any]:
        """Generate mock audit event data."""
        default_data = {
            "event_id": event_id or f"evt_{uuid.uuid4().hex[:12]}",
            "user_id": f"user_{uuid.uuid4().hex[:8]}",
            "action": random.choice(["login", "logout", "create", "update", "delete", "view"]),
            "resource": random.choice(["user", "transaction", "order", "product", "settings"]),
            "timestamp": time.time() - random.randint(0, 24 * 3600),  # Last 24 hours
            "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "user_agent": "Mozilla/5.0 (compatible; TestClient/1.0)",
            "result": random.choice(["success", "success", "success", "failure"]),  # 75% success
            "details": {
                "request_id": f"req_{uuid.uuid4().hex[:8]}",
                "duration": round(random.uniform(0.01, 2.0), 3),
                "changes": {"field": "old_value -> new_value"}
            }
        }
        default_data.update(overrides)
        return default_data


class MockServiceFactory:
    """Factory for creating mock service instances."""
    
    @staticmethod
    def create_auth_service_mock() -> AsyncMock:
        """Create comprehensive auth service mock."""
        mock_service = AsyncMock()
        
        # User database
        users_db = {
            "valid-user-token": UserInfo(
                user_id="user_123",
                email="user@example.com",
                roles=["user"],
                permissions=["read", "write"],
                is_active=True,
                is_verified=True,
                metadata={"test": True}
            ),
            "valid-admin-token": UserInfo(
                user_id="admin_456",
                email="admin@example.com",
                roles=["admin", "user"],
                permissions=["read", "write", "admin", "delete"],
                is_active=True,
                is_verified=True,
                metadata={"test": True, "admin": True}
            ),
            "inactive-user-token": UserInfo(
                user_id="inactive_789",
                email="inactive@example.com",
                roles=["user"],
                permissions=["read"],
                is_active=False,
                is_verified=True
            ),
            "unverified-user-token": UserInfo(
                user_id="unverified_101",
                email="unverified@example.com", 
                roles=["user"],
                permissions=["read"],
                is_active=True,
                is_verified=False
            )
        }
        
        async def mock_validate_token(token: str) -> Optional[UserInfo]:
            return users_db.get(token)
        
        mock_service.validate_token.side_effect = mock_validate_token
        mock_service.initialize.return_value = None
        mock_service.cleanup.return_value = None
        mock_service.health_check.return_value = {
            "status": "healthy",
            "response_time": 0.05,
            "active_users": len([u for u in users_db.values() if u.is_active])
        }
        
        return mock_service
    
    @staticmethod
    def create_service_registry_mock(services: Optional[List[str]] = None) -> AsyncMock:
        """Create comprehensive service registry mock."""
        mock_registry = AsyncMock()
        
        # Default services
        if services is None:
            services = ["auth", "user", "orders", "products", "notifications"]
        
        # Service database
        services_db = {}
        for service_name in services:
            service_data = MockDataFactory.service_data(service_name)
            services_db[service_name] = ServiceEndpoint(
                name=service_data["name"],
                url=service_data["url"],
                health_check_url=f"{service_data['url']}/health",
                version=service_data["version"],
                status=service_data["status"],
                last_health_check=service_data["last_health_check"],
                response_time=service_data["response_time"],
                metadata=service_data["metadata"]
            )
        
        # Mock methods
        mock_registry.get_service_url.side_effect = lambda name: services_db.get(name, {}).url if services_db.get(name) else None
        mock_registry.get_service_endpoint.side_effect = lambda name: services_db.get(name)
        mock_registry.get_all_services_status.return_value = {
            name: {
                "status": service.status,
                "url": service.url,
                "version": service.version,
                "last_check": service.last_health_check,
                "response_time": service.response_time
            }
            for name, service in services_db.items()
        }
        mock_registry.get_healthy_services.return_value = [
            name for name, service in services_db.items() 
            if service.status == "healthy"
        ]
        mock_registry.health_check_all_services.return_value = None
        mock_registry.initialize.return_value = None
        mock_registry.cleanup.return_value = None
        
        return mock_registry
    
    @staticmethod
    def create_rate_limiter_mock(allow_requests: bool = True) -> AsyncMock:
        """Create comprehensive rate limiter mock."""
        mock_limiter = AsyncMock()
        
        # Rate limit tracking
        request_counts = {}
        
        async def mock_check_rate_limit(identifier: str, limit_type: RateLimitType, custom_limit: Optional[RateLimit] = None):
            # Track request count
            key = f"{limit_type.value}:{identifier}"
            current_count = request_counts.get(key, 0) + 1
            request_counts[key] = current_count
            
            # Default limits
            default_limits = {
                RateLimitType.GLOBAL: 1000,
                RateLimitType.USER: 100,
                RateLimitType.IP: 200,
                RateLimitType.API_KEY: 500
            }
            
            limit_value = custom_limit.requests if custom_limit else default_limits.get(limit_type, 100)
            
            if allow_requests and current_count <= limit_value:
                return RateLimitResult(
                    allowed=True,
                    remaining=max(0, limit_value - current_count),
                    reset_time=time.time() + 60,
                    limit_type=limit_type.value
                )
            else:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=time.time() + 60,
                    retry_after=60,
                    limit_type=limit_type.value
                )
        
        mock_limiter.check_rate_limit.side_effect = mock_check_rate_limit
        mock_limiter.get_rate_limit_status.return_value = {
            "limit": 100,
            "used": random.randint(0, 50),
            "remaining": random.randint(50, 100),
            "reset_time": time.time() + 60,
            "window": 60
        }
        mock_limiter.reset_rate_limit.return_value = True
        mock_limiter.get_global_rate_limit_stats.return_value = {
            "total_keys": len(request_counts),
            "by_type": {"user": 10, "ip": 5, "global": 1}
        }
        
        return mock_limiter
    
    @staticmethod
    def create_circuit_breaker_mock(allow_calls: bool = True) -> AsyncMock:
        """Create comprehensive circuit breaker mock."""
        mock_breaker = AsyncMock()
        
        # Circuit breaker states
        breaker_states = {}
        
        async def mock_call_with_circuit_breaker(service_name: str, func, *args, **kwargs):
            if allow_calls:
                # Update state
                if service_name not in breaker_states:
                    breaker_states[service_name] = {
                        "state": "closed",
                        "failure_count": 0,
                        "success_count": random.randint(50, 200)
                    }
                
                # Execute function
                result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
                breaker_states[service_name]["success_count"] += 1
                return result
            else:
                from src.services.circuit_breaker import CircuitBreakerError
                breaker_states[service_name] = {
                    "state": "open",
                    "failure_count": random.randint(5, 20),
                    "success_count": 0
                }
                raise CircuitBreakerError(f"Circuit breaker open for {service_name}")
        
        mock_breaker.call_with_circuit_breaker.side_effect = mock_call_with_circuit_breaker
        mock_breaker.get_all_states.return_value = breaker_states
        mock_breaker.reset_circuit_breaker.return_value = True
        mock_breaker.health_check.return_value = {
            "total_breakers": len(breaker_states),
            "open_breakers": len([s for s in breaker_states.values() if s["state"] == "open"]),
            "closed_breakers": len([s for s in breaker_states.values() if s["state"] == "closed"]),
            "health": "healthy"
        }
        
        return mock_breaker


class MockBackendServiceFactory:
    """Factory for creating mock backend service responses."""
    
    @staticmethod
    def create_http_response_mock(status_code: int = 200, content: Optional[Dict[str, Any]] = None, 
                                 headers: Optional[Dict[str, str]] = None, delay: float = 0) -> MagicMock:
        """Create mock HTTP response."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        
        if content is None:
            content = {"status": "success", "data": f"Mock response {random.randint(1000, 9999)}"}
        
        mock_response.content = json.dumps(content).encode()
        mock_response.json.return_value = content
        mock_response.text = json.dumps(content)
        
        if headers is None:
            headers = {"content-type": "application/json"}
        mock_response.headers = headers
        
        # Simulate response delay if specified
        if delay > 0:
            time.sleep(delay)
        
        return mock_response
    
    @staticmethod
    def create_auth_service_responses() -> Dict[str, MagicMock]:
        """Create auth service specific responses."""
        return {
            "login_success": MockBackendServiceFactory.create_http_response_mock(
                200,
                {
                    "access_token": f"token_{uuid.uuid4().hex[:16]}",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "user_id": f"user_{uuid.uuid4().hex[:8]}"
                }
            ),
            "login_failure": MockBackendServiceFactory.create_http_response_mock(
                401,
                {"error": "invalid_credentials", "message": "Invalid username or password"}
            ),
            "profile_success": MockBackendServiceFactory.create_http_response_mock(
                200,
                MockDataFactory.user_data()
            ),
            "profile_not_found": MockBackendServiceFactory.create_http_response_mock(
                404,
                {"error": "user_not_found", "message": "User profile not found"}
            )
        }
    
    @staticmethod
    def create_user_service_responses() -> Dict[str, MagicMock]:
        """Create user service specific responses."""
        return {
            "create_user_success": MockBackendServiceFactory.create_http_response_mock(
                201,
                {
                    "user_id": f"user_{uuid.uuid4().hex[:8]}",
                    "status": "created",
                    "message": "User created successfully"
                }
            ),
            "create_user_conflict": MockBackendServiceFactory.create_http_response_mock(
                409,
                {"error": "user_exists", "message": "User with this email already exists"}
            ),
            "update_user_success": MockBackendServiceFactory.create_http_response_mock(
                200,
                {
                    "user_id": f"user_{uuid.uuid4().hex[:8]}",
                    "status": "updated",
                    "changes": ["email", "preferences"]
                }
            ),
            "users_list": MockBackendServiceFactory.create_http_response_mock(
                200,
                {
                    "users": [MockDataFactory.user_data() for _ in range(5)],
                    "total": 5,
                    "page": 1,
                    "per_page": 10
                }
            )
        }
    
    @staticmethod
    def create_business_service_responses() -> Dict[str, MagicMock]:
        """Create business service specific responses."""
        return {
            "orders_list": MockBackendServiceFactory.create_http_response_mock(
                200,
                {
                    "orders": [MockDataFactory.transaction_data() for _ in range(3)],
                    "total": 3,
                    "status": "success"
                }
            ),
            "create_order_success": MockBackendServiceFactory.create_http_response_mock(
                201,
                {
                    "order_id": f"order_{uuid.uuid4().hex[:8]}",
                    "status": "created",
                    "total_amount": round(random.uniform(50.0, 500.0), 2)
                }
            ),
            "payment_processing": MockBackendServiceFactory.create_http_response_mock(
                202,
                {
                    "payment_id": f"pay_{uuid.uuid4().hex[:8]}",
                    "status": "processing",
                    "message": "Payment is being processed"
                }
            ),
            "inventory_check": MockBackendServiceFactory.create_http_response_mock(
                200,
                {
                    "product_id": f"prod_{uuid.uuid4().hex[:8]}",
                    "available": random.choice([True, False]),
                    "quantity": random.randint(0, 100)
                }
            )
        }


class MockExternalServiceFactory:
    """Factory for creating mock external service integrations."""
    
    @staticmethod
    def create_database_mock() -> AsyncMock:
        """Create database connection mock."""
        mock_db = AsyncMock()
        
        # In-memory data store
        data_store = {
            "users": {},
            "transactions": {},
            "sessions": {}
        }
        
        async def mock_execute(query: str, *args):
            # Simple query simulation
            if "SELECT" in query.upper():
                return [MockDataFactory.user_data() for _ in range(random.randint(0, 5))]
            elif "INSERT" in query.upper():
                return {"id": random.randint(1000, 9999), "affected_rows": 1}
            elif "UPDATE" in query.upper():
                return {"affected_rows": random.randint(0, 1)}
            elif "DELETE" in query.upper():
                return {"affected_rows": random.randint(0, 1)}
            else:
                return {"status": "executed"}
        
        mock_db.execute.side_effect = mock_execute
        mock_db.fetch_all.return_value = [MockDataFactory.user_data() for _ in range(3)]
        mock_db.fetch_one.return_value = MockDataFactory.user_data()
        mock_db.close.return_value = None
        
        return mock_db
    
    @staticmethod
    def create_redis_mock() -> AsyncMock:
        """Create Redis client mock."""
        mock_redis = AsyncMock()
        
        # In-memory cache
        cache_store = {}
        
        async def mock_get(key: str):
            return cache_store.get(key)
        
        async def mock_set(key: str, value: Any, ttl: Optional[int] = None):
            cache_store[key] = value
            return True
        
        async def mock_delete(key: str):
            return cache_store.pop(key, None) is not None
        
        async def mock_keys(pattern: str = "*"):
            if pattern == "*":
                return list(cache_store.keys())
            else:
                # Simple pattern matching
                return [k for k in cache_store.keys() if pattern.replace("*", "") in k]
        
        mock_redis.get.side_effect = mock_get
        mock_redis.set.side_effect = mock_set
        mock_redis.delete.side_effect = mock_delete
        mock_redis.keys.side_effect = mock_keys
        mock_redis.ping.return_value = "PONG"
        mock_redis.flushall.return_value = True
        mock_redis.close.return_value = None
        
        # Rate limiting operations
        mock_redis.zcard.return_value = random.randint(0, 10)
        mock_redis.zadd.return_value = 1
        mock_redis.zremrangebyscore.return_value = random.randint(0, 5)
        mock_redis.expire.return_value = True
        
        return mock_redis
    
    @staticmethod
    def create_metrics_collector_mock() -> AsyncMock:
        """Create metrics collector mock."""
        mock_collector = AsyncMock()
        
        # Metrics storage
        metrics_data = {
            "requests_total": random.randint(1000, 10000),
            "requests_duration_seconds": random.uniform(0.1, 2.0),
            "active_connections": random.randint(10, 100),
            "error_rate": random.uniform(0.01, 0.05)
        }
        
        mock_collector.record_request.return_value = None
        mock_collector.increment_counter.return_value = None
        mock_collector.observe_histogram.return_value = None
        mock_collector.set_gauge.return_value = None
        mock_collector.get_metrics.return_value = metrics_data
        
        return mock_collector


@pytest.fixture
def mock_data_factory():
    """Provide mock data factory."""
    return MockDataFactory()


@pytest.fixture
def mock_service_factory():
    """Provide mock service factory."""
    return MockServiceFactory()


@pytest.fixture  
def mock_backend_factory():
    """Provide mock backend service factory."""
    return MockBackendServiceFactory()


@pytest.fixture
def mock_external_factory():
    """Provide mock external service factory."""
    return MockExternalServiceFactory()


@pytest.fixture
def comprehensive_mocks(mock_service_factory, mock_external_factory):
    """Provide comprehensive mock setup."""
    return {
        "auth_service": mock_service_factory.create_auth_service_mock(),
        "service_registry": mock_service_factory.create_service_registry_mock(),
        "rate_limiter": mock_service_factory.create_rate_limiter_mock(),
        "circuit_breaker": mock_service_factory.create_circuit_breaker_mock(),
        "database": mock_external_factory.create_database_mock(),
        "redis": mock_external_factory.create_redis_mock(),
        "metrics": mock_external_factory.create_metrics_collector_mock()
    }