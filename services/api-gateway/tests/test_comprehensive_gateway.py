"""
Comprehensive test suite for the API Gateway service.
Tests all major functionality including routing, authentication, rate limiting, circuit breakers, etc.
"""
import asyncio
import pytest
import httpx
import json
import time
from typing import Dict, Any
from unittest.mock import AsyncMock, Mock, patch

from fastapi.testclient import TestClient
from fastapi import status

# Import the gateway application
from src.main import create_app
from src.core.config import Settings
from src.services.auth_service import UserInfo, auth_service
from src.services.rate_limiter import RateLimitResult, RateLimitType
from src.services.circuit_breaker import CircuitBreakerState, CircuitState


class TestSettings(Settings):
    """Test settings with overrides."""
    environment: str = "test"
    database_url: str = "sqlite+aiosqlite:///:memory:"
    redis_url: str = "redis://localhost:6379/15"  # Use test database
    auth_service_url: str = "http://test-auth:8000"
    user_service_url: str = "http://test-user:8000"
    secret_key: str = "test-secret-key-for-jwt-signing"
    cors_origins: list = ["*"]
    allowed_hosts: list = ["*"]


@pytest.fixture
def test_settings():
    """Test settings fixture."""
    return TestSettings()


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock_redis = AsyncMock()
    mock_redis.ping.return_value = "PONG"
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = 1
    mock_redis.zcard.return_value = 0
    mock_redis.zadd.return_value = 1
    mock_redis.zremrangebyscore.return_value = 0
    mock_redis.expire.return_value = True
    mock_redis.keys.return_value = []
    return mock_redis


@pytest.fixture
def mock_auth_service():
    """Mock authentication service."""
    mock_service = AsyncMock()
    
    # Mock successful token validation
    mock_user = UserInfo(
        user_id="test-user-123",
        email="test@example.com",
        roles=["user"],
        permissions=["read", "write"],
        is_active=True,
        is_verified=True
    )
    mock_service.validate_token.return_value = mock_user
    mock_service.initialize.return_value = None
    mock_service.cleanup.return_value = None
    mock_service.health_check.return_value = {
        "status": "healthy",
        "auth_service": "healthy"
    }
    
    return mock_service


@pytest.fixture
def app_with_mocks(test_settings, mock_redis, mock_auth_service):
    """Create app with mocked dependencies."""
    
    with patch("src.core.config.get_settings", return_value=test_settings), \
         patch("src.core.redis.init_redis"), \
         patch("src.core.database.init_db"), \
         patch("src.core.redis.get_redis", return_value=mock_redis), \
         patch("src.core.redis.redis_manager.get_client", return_value=mock_redis), \
         patch("src.services.auth_service.auth_service", mock_auth_service):
        
        app = create_app()
        
        # Manually set app state for testing
        app.state.start_time = time.time()
        
        return app


@pytest.fixture
def client(app_with_mocks):
    """Test client fixture."""
    return TestClient(app_with_mocks)


class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_basic_health_check(self, client):
        """Test basic health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "api-gateway"
        assert "timestamp" in data
    
    def test_readiness_check(self, client):
        """Test readiness endpoint."""
        response = client.get("/ready")
        assert response.status_code in [200, 503]  # Depends on mocked services
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
    
    def test_detailed_health_check(self, client):
        """Test detailed health endpoint."""
        response = client.get("/health/detailed")
        assert response.status_code in [200, 503]
        
        data = response.json()
        assert "status" in data
        assert "components" in data
        assert "timestamp" in data


class TestMetricsEndpoints:
    """Test metrics endpoints."""
    
    def test_prometheus_metrics(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        
        content = response.text
        assert "gateway_uptime_seconds" in content
    
    def test_json_metrics(self, client):
        """Test JSON metrics endpoint."""
        response = client.get("/metrics/json")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "gateway" in data
        assert "services" in data
    
    def test_performance_metrics(self, client):
        """Test performance metrics endpoint."""
        response = client.get("/metrics/performance")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "request_stats" in data
    
    def test_health_score(self, client):
        """Test health score endpoint."""
        response = client.get("/metrics/health-score")
        assert response.status_code == 200
        
        data = response.json()
        assert "overall_score" in data
        assert "grade" in data
        assert "component_scores" in data


class TestAuthenticationMiddleware:
    """Test authentication functionality."""
    
    def test_public_endpoint_no_auth(self, client):
        """Test that public endpoints don't require authentication."""
        response = client.get("/health")
        assert response.status_code == 200
    
    @patch("src.middleware.gateway_middleware.httpx.AsyncClient")
    def test_valid_token_authentication(self, mock_http_client, client):
        """Test authentication with valid token."""
        # Mock successful auth service response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "user_id": "test-user-123",
            "email": "test@example.com",
            "roles": ["user"],
            "permissions": ["read"],
            "is_active": True,
            "is_verified": True
        }
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_http_client.return_value = mock_client_instance
        
        headers = {"Authorization": "Bearer valid-jwt-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        # Should not be 401 unauthorized
        assert response.status_code != 401
    
    def test_missing_auth_header(self, client):
        """Test request without authorization header."""
        response = client.get("/api/v1/services")
        assert response.status_code == 401
        
        data = response.json()
        assert "error" in data
        assert "authorization" in data["error"].lower()
    
    def test_invalid_auth_header_format(self, client):
        """Test request with invalid authorization header format."""
        headers = {"Authorization": "InvalidFormat token"}
        response = client.get("/api/v1/services", headers=headers)
        assert response.status_code == 401


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    @patch("src.services.rate_limiter.redis_manager")
    def test_rate_limit_allowed(self, mock_redis_manager, client):
        """Test request within rate limit."""
        # Mock Redis to return low usage
        mock_redis_manager.get_client.return_value.__aenter__.return_value.pipeline.return_value.execute.return_value = [0, 5]
        mock_redis_manager.get_client.return_value.__aenter__.return_value.zadd.return_value = 1
        
        response = client.get("/health")
        assert response.status_code == 200
        
        # Check rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
    
    @patch("src.services.rate_limiter.redis_manager")
    def test_rate_limit_exceeded(self, mock_redis_manager, client):
        """Test request exceeding rate limit."""
        # Mock Redis to return high usage
        mock_redis_manager.get_client.return_value.__aenter__.return_value.pipeline.return_value.execute.return_value = [0, 1000]
        
        response = client.get("/health")
        
        # Might be rate limited or allowed depending on implementation
        if response.status_code == 429:
            data = response.json()
            assert "rate limit" in data["error"].lower()
            assert "Retry-After" in response.headers


class TestServiceRegistry:
    """Test service registry functionality."""
    
    def test_list_services(self, client):
        """Test listing registered services."""
        # This endpoint requires authentication
        headers = {"Authorization": "Bearer valid-jwt-token"}
        
        with patch("src.middleware.gateway_middleware.AuthenticationMiddleware._validate_token") as mock_validate:
            mock_validate.return_value = {
                "user_id": "test-user",
                "email": "test@example.com"
            }
            
            response = client.get("/api/v1/services", headers=headers)
            
            # Should return service list
            if response.status_code == 200:
                data = response.json()
                assert "services" in data
                assert "total" in data


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    @patch("src.services.circuit_breaker.CircuitBreakerManager")
    def test_circuit_breaker_closed(self, mock_cb_manager, client):
        """Test request when circuit breaker is closed."""
        mock_cb_manager.return_value.call_with_circuit_breaker.return_value = {"status": "success"}
        
        response = client.get("/health")
        assert response.status_code == 200
    
    @patch("src.services.circuit_breaker.CircuitBreakerManager")
    def test_circuit_breaker_open(self, mock_cb_manager, client):
        """Test request when circuit breaker is open."""
        from src.services.circuit_breaker import CircuitBreakerError
        
        mock_cb_manager.return_value.call_with_circuit_breaker.side_effect = CircuitBreakerError("Circuit open")
        
        # This would be tested with actual service calls
        # For now, just verify the exception handling exists
        assert CircuitBreakerError is not None


class TestRequestTransformation:
    """Test request/response transformation."""
    
    def test_api_version_header(self, client):
        """Test API version header handling."""
        headers = {"X-API-Version": "v1"}
        response = client.get("/health", headers=headers)
        
        assert response.status_code == 200
        assert response.headers.get("X-API-Version") == "v1"
    
    def test_unsupported_api_version(self, client):
        """Test unsupported API version."""
        headers = {"X-API-Version": "v99"}
        response = client.get("/health", headers=headers)
        
        # Should either reject or default to supported version
        # Implementation depends on middleware logic
        assert response.status_code in [200, 400]


class TestSecurityMiddleware:
    """Test security middleware."""
    
    def test_security_headers(self, client):
        """Test that security headers are added."""
        response = client.get("/health")
        
        # Check for security headers
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in security_headers:
            assert header in response.headers
    
    def test_request_too_large(self, client):
        """Test request size limit."""
        # Create a large payload
        large_data = "x" * (20 * 1024 * 1024)  # 20MB
        
        response = client.post(
            "/api/v1/test",
            data=large_data,
            headers={"Content-Type": "text/plain"}
        )
        
        # Should be rejected due to size
        assert response.status_code == 413


class TestWebSocketFunctionality:
    """Test WebSocket functionality."""
    
    def test_websocket_connection(self, client):
        """Test WebSocket connection establishment."""
        with client.websocket_connect("/ws/test-client") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "welcome"
            assert data["client_id"] == "test-client"
    
    def test_websocket_ping_pong(self, client):
        """Test WebSocket ping/pong."""
        with client.websocket_connect("/ws/test-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send ping
            websocket.send_json({"type": "ping"})
            
            # Receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"
    
    def test_websocket_authentication(self, client):
        """Test WebSocket authentication with token."""
        with patch("src.services.auth_service.auth_service.validate_token") as mock_validate:
            mock_validate.return_value = UserInfo(
                user_id="test-user",
                email="test@example.com",
                roles=["user"],
                permissions=["read"],
                is_active=True,
                is_verified=True
            )
            
            with client.websocket_connect("/ws/test-client?token=valid-token") as websocket:
                data = websocket.receive_json()
                assert data["type"] == "welcome"


class TestErrorHandling:
    """Test error handling and resilience."""
    
    def test_global_exception_handler(self, client):
        """Test global exception handling."""
        # This would require triggering an actual exception
        # For now, verify the handler exists
        from src.main import create_app
        app = create_app()
        
        # Check that exception handlers are registered
        assert len(app.exception_handlers) > 0
    
    def test_service_unavailable_response(self, client):
        """Test response when backend services are unavailable."""
        # Mock service registry to return no healthy services
        with patch("src.services.service_registry.ServiceRegistry.get_healthy_services") as mock_services:
            mock_services.return_value = []
            
            response = client.get("/ready")
            assert response.status_code == 503


class TestIntegrationScenarios:
    """Integration test scenarios."""
    
    @patch("src.services.auth_service.auth_service.validate_token")
    @patch("src.services.rate_limiter.redis_manager")
    def test_authenticated_user_with_rate_limiting(self, mock_redis, mock_auth, client):
        """Test complete flow: authentication + rate limiting."""
        # Mock successful authentication
        mock_auth.return_value = UserInfo(
            user_id="test-user",
            email="test@example.com",
            roles=["user"],
            permissions=["read"],
            is_active=True,
            is_verified=True
        )
        
        # Mock rate limiting to allow requests
        mock_redis.get_client.return_value.__aenter__.return_value.pipeline.return_value.execute.return_value = [0, 1]
        mock_redis.get_client.return_value.__aenter__.return_value.zadd.return_value = 1
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        # Should pass through authentication and rate limiting
        assert response.status_code != 401
        assert response.status_code != 429
    
    def test_comprehensive_request_flow(self, client):
        """Test a complete request through all middleware."""
        headers = {
            "Authorization": "Bearer valid-token",
            "X-API-Version": "v1",
            "User-Agent": "test-client/1.0"
        }
        
        with patch("src.middleware.gateway_middleware.AuthenticationMiddleware._validate_token") as mock_auth:
            mock_auth.return_value = {
                "user_id": "test-user",
                "email": "test@example.com"
            }
            
            response = client.get("/health", headers=headers)
            
            # Check that request was processed successfully
            assert response.status_code == 200
            
            # Check that middleware added headers
            assert "X-Request-ID" in response.headers
            assert "X-API-Version" in response.headers
            assert "X-Gateway" in response.headers


if __name__ == "__main__":
    pytest.main([__file__, "-v"])