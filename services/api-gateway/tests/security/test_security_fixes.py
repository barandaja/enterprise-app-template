"""
Test suite to validate security fixes in the API Gateway.
Tests CORS, rate limiting, WebSocket auth, circuit breaker, and token caching.
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect

from src.core.config import Settings
from src.services.rate_limiter import RateLimiterManager, RateLimitType
from src.services.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from src.services.auth_service import AuthenticationService


class TestSecurityFixes:
    """Test security fixes implementation."""

    def test_cors_configuration(self):
        """Test that CORS is properly configured with explicit domains."""
        settings = Settings(
            JWT_SECRET_KEY="test-secret-key-that-is-at-least-32-characters",
            DATABASE_URL="postgresql://test",
            REDIS_URL="redis://test"
        )
        
        # Verify CORS origins are not wildcards
        assert "*" not in settings.cors_origins
        assert "http://localhost:3000" in settings.cors_origins
        assert "https://app.example.com" in settings.cors_origins
        assert "https://www.example.com" in settings.cors_origins
        
        # Verify allowed hosts are not wildcards
        assert "*" not in settings.allowed_hosts
        assert "localhost" in settings.allowed_hosts
        assert "app.example.com" in settings.allowed_hosts

    def test_jwt_secret_validation(self):
        """Test JWT secret key validation."""
        # Test missing JWT secret
        with pytest.raises(ValueError, match="JWT_SECRET_KEY environment variable must be set"):
            Settings(
                JWT_SECRET_KEY="",
                DATABASE_URL="postgresql://test",
                REDIS_URL="redis://test"
            )
        
        # Test short JWT secret
        with pytest.raises(ValueError, match="JWT_SECRET_KEY must be at least 32 characters long"):
            Settings(
                JWT_SECRET_KEY="short-key",
                DATABASE_URL="postgresql://test",
                REDIS_URL="redis://test"
            )

    @pytest.mark.asyncio
    async def test_rate_limiter_fails_securely_on_redis_error(self):
        """Test that rate limiter denies requests when Redis fails."""
        rate_limiter = RateLimiterManager()
        
        # Mock Redis failure
        with patch('src.services.rate_limiter.redis_manager.get_client') as mock_redis:
            mock_redis.side_effect = Exception("Redis connection failed")
            
            result = await rate_limiter.check_rate_limit(
                "test-user",
                RateLimitType.USER
            )
            
            # Verify request is denied on Redis failure
            assert result.allowed is False
            assert result.retry_after is not None

    @pytest.mark.asyncio
    async def test_websocket_requires_authentication(self):
        """Test that WebSocket connections require authentication."""
        from src.api.gateway import websocket_endpoint
        from fastapi import WebSocket
        
        # Create mock WebSocket
        mock_websocket = AsyncMock(spec=WebSocket)
        mock_websocket.query_params = {}  # No token
        
        # Test connection without token
        await websocket_endpoint(mock_websocket, "test-client")
        
        # Verify connection was closed with authentication required
        mock_websocket.close.assert_called_once_with(
            code=1008,
            reason="Authentication required"
        )

    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_rate_calculation(self):
        """Test circuit breaker opens correctly based on failure rate."""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            minimum_throughput=10
        )
        breaker = CircuitBreaker("test-service", config)
        
        # Simulate successful calls to meet minimum throughput
        async def success_func():
            return "success"
        
        for _ in range(5):
            await breaker.call(success_func)
        
        # Simulate failures
        async def failure_func():
            raise Exception("Service error")
        
        # Add 5 failures (total: 5 success, 5 failures = 50% failure rate)
        for _ in range(5):
            try:
                await breaker.call(failure_func)
            except:
                pass
        
        # Verify circuit is now open (50% failure rate triggers opening)
        assert breaker.state.state.value == "open"

    @pytest.mark.asyncio
    async def test_token_cache_ttl(self):
        """Test that token cache TTL is set to 2 minutes."""
        settings = Settings(
            JWT_SECRET_KEY="test-secret-key-that-is-at-least-32-characters",
            DATABASE_URL="postgresql://test",
            REDIS_URL="redis://test"
        )
        
        # Verify cache TTL is 2 minutes (120 seconds)
        assert settings.cache_auth_ttl == 120

    def test_connection_pool_sizes(self):
        """Test connection pool sizes are optimized for 1000 concurrent users."""
        settings = Settings(
            JWT_SECRET_KEY="test-secret-key-that-is-at-least-32-characters",
            DATABASE_URL="postgresql://test",
            REDIS_URL="redis://test"
        )
        
        # Database pool settings
        assert settings.database_pool_size == 50
        assert settings.database_max_overflow == 150
        # Total max connections: 50 + 150 = 200
        
        # Redis pool settings
        assert settings.redis_pool_size == 50

    @pytest.mark.asyncio
    async def test_environment_variables_usage(self):
        """Test that sensitive configuration uses environment variables."""
        import os
        
        # Set environment variables
        os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-at-least-32-characters"
        os.environ["DATABASE_URL"] = "postgresql://env-test"
        os.environ["REDIS_URL"] = "redis://env-test"
        
        settings = Settings()
        
        # Verify environment variables are used
        assert settings.secret_key == "test-secret-key-that-is-at-least-32-characters"
        assert settings.database_url == "postgresql://env-test"
        assert settings.redis_url == "redis://env-test"
        
        # Cleanup
        del os.environ["JWT_SECRET_KEY"]
        del os.environ["DATABASE_URL"]
        del os.environ["REDIS_URL"]


class TestSecurityHeaders:
    """Test security headers in responses."""
    
    def test_security_headers_present(self, client: TestClient):
        """Test that security headers are present in responses."""
        response = client.get("/health")
        
        # Check security headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert response.headers.get("Content-Security-Policy") == "default-src 'self'"


class TestRateLimitHeaders:
    """Test rate limit headers in responses."""
    
    def test_rate_limit_headers(self, client: TestClient):
        """Test that rate limit headers are included in responses."""
        response = client.get("/api/v1/services")
        
        # Check rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers