"""
Tests for the configurable middleware system.
Tests middleware factory, configurations, and middleware implementations.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException, status

from src.middleware.middleware_factory import MiddlewareFactory
from src.middleware.middleware_config import (
    MiddlewareType,
    SecurityHeadersConfig,
    RateLimitConfig,
    AuthenticationConfig,
    CORSConfig,
    RequestTrackingConfig
)
from src.middleware.configurable_middleware import (
    ConfigurableSecurityHeadersMiddleware,
    ConfigurableRateLimitMiddleware,
    ConfigurableAuthenticationMiddleware,
    ConfigurableCORSMiddleware,
    ConfigurableRequestTrackingMiddleware
)
from src.compatibility.middleware_adapter import MiddlewareAdapter


class TestMiddlewareConfigs:
    """Test cases for middleware configuration classes."""
    
    def test_security_headers_config_default(self):
        """Test SecurityHeadersConfig with default values."""
        # Act
        config = SecurityHeadersConfig()
        
        # Assert
        assert config.enabled is True
        assert config.priority == 10
        assert "X-Content-Type-Options" in config.headers
        assert config.headers["X-Content-Type-Options"] == "nosniff"
    
    def test_security_headers_config_custom(self):
        """Test SecurityHeadersConfig with custom values."""
        # Arrange
        custom_headers = {"X-Custom-Header": "custom-value"}
        
        # Act
        config = SecurityHeadersConfig(
            enabled=False,
            priority=20,
            custom_headers=custom_headers
        )
        
        # Assert
        assert config.enabled is False
        assert config.priority == 20
        assert config.custom_headers == custom_headers
        
        all_headers = config.get_all_headers()
        assert "X-Custom-Header" in all_headers
        assert all_headers["X-Custom-Header"] == "custom-value"
    
    def test_rate_limit_config_default(self):
        """Test RateLimitConfig with default values."""
        # Act
        config = RateLimitConfig()
        
        # Assert
        assert config.enabled is True
        assert config.priority == 20
        assert config.requests_per_minute == 60
        assert config.window_size == 60
        assert "/health" in config.excluded_paths
    
    def test_authentication_config_default(self):
        """Test AuthenticationConfig with default values."""
        # Act
        config = AuthenticationConfig()
        
        # Assert
        assert config.enabled is True
        assert config.priority == 30
        assert "/health" in config.public_paths
        assert "/api/v1/auth/login" in config.public_paths
        assert config.token_header == "Authorization"
        assert config.token_prefix == "Bearer "
    
    def test_cors_config_default(self):
        """Test CORSConfig with default values."""
        # Act
        config = CORSConfig()
        
        # Assert
        assert config.enabled is True
        assert config.priority == 15
        assert "*" in config.allowed_origins
        assert "GET" in config.allowed_methods
        assert "Authorization" in config.allowed_headers
        assert config.allow_credentials is True
    
    def test_request_tracking_config_default(self):
        """Test RequestTrackingConfig with default values."""
        # Act
        config = RequestTrackingConfig()
        
        # Assert
        assert config.enabled is True
        assert config.priority == 5
        assert config.generate_request_id is True
        assert config.log_requests is True
        assert config.track_performance is True
        assert "method" in config.log_fields


class TestMiddlewareFactory:
    """Test cases for MiddlewareFactory."""
    
    @pytest.fixture
    def factory(self):
        """Create middleware factory for testing."""
        return MiddlewareFactory()
    
    def test_create_security_headers_middleware(self, factory):
        """Test creating security headers middleware."""
        # Arrange
        config = {"enabled": True, "priority": 10}
        
        # Act
        middleware = factory.create_middleware(
            MiddlewareType.SECURITY_HEADERS, 
            config
        )
        
        # Assert
        assert isinstance(middleware, ConfigurableSecurityHeadersMiddleware)
        assert middleware.config.enabled is True
        assert middleware.config.priority == 10
        assert middleware.name == "SecurityHeaders"
    
    def test_create_rate_limit_middleware(self, factory):
        """Test creating rate limit middleware."""
        # Arrange
        config = {"requests_per_minute": 100, "window_size": 120}
        
        # Act
        middleware = factory.create_middleware(
            MiddlewareType.RATE_LIMIT,
            config
        )
        
        # Assert
        assert isinstance(middleware, ConfigurableRateLimitMiddleware)
        assert middleware.config.requests_per_minute == 100
        assert middleware.config.window_size == 120
    
    def test_create_unknown_middleware_type(self, factory):
        """Test creating unknown middleware type raises error."""
        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            factory.create_middleware("unknown_type", {})
        
        assert "Unknown middleware type" in str(exc_info.value)
    
    def test_create_middleware_stack(self, factory):
        """Test creating middleware stack from configuration."""
        # Arrange
        configs = [
            {"type": MiddlewareType.SECURITY_HEADERS, "enabled": True, "priority": 10},
            {"type": MiddlewareType.RATE_LIMIT, "enabled": True, "priority": 20},
            {"type": MiddlewareType.CORS, "enabled": False}  # Should be excluded
        ]
        
        # Act
        middleware_stack = factory.create_middleware_stack(configs)
        
        # Assert
        assert len(middleware_stack) == 2  # Only enabled middleware
        assert middleware_stack[0].priority <= middleware_stack[1].priority  # Sorted by priority
    
    def test_get_available_middleware(self, factory):
        """Test getting available middleware types."""
        # Act
        available = factory.get_available_middleware()
        
        # Assert
        assert MiddlewareType.SECURITY_HEADERS in available
        assert MiddlewareType.RATE_LIMIT in available
        assert MiddlewareType.AUTHENTICATION in available
        assert MiddlewareType.CORS in available
    
    def test_register_custom_middleware_type(self, factory):
        """Test registering custom middleware type."""
        # Arrange
        class CustomMiddleware:
            def __init__(self, config):
                self.config = config
                self.name = "Custom"
                self.priority = config.priority
        
        # Act
        result = factory.register_middleware_type("custom", CustomMiddleware)
        
        # Assert
        assert result is True
        assert "custom" in factory.get_available_middleware()
        
        # Test creating the custom middleware
        middleware = factory.create_middleware("custom", {"priority": 50})
        assert isinstance(middleware, CustomMiddleware)
    
    def test_get_default_config(self, factory):
        """Test getting default configuration for middleware type."""
        # Act
        config = factory.get_default_config(MiddlewareType.SECURITY_HEADERS)
        
        # Assert
        assert "enabled" in config
        assert "priority" in config
        assert "headers" in config
        assert config["enabled"] is True
        assert config["priority"] == 10
    
    def test_validate_config_valid(self, factory):
        """Test validating valid configuration."""
        # Arrange
        config = {"enabled": True, "priority": 10}
        
        # Act
        is_valid, errors = factory.validate_config(MiddlewareType.SECURITY_HEADERS, config)
        
        # Assert
        assert is_valid is True
        assert len(errors) == 0
    
    def test_validate_config_invalid_type(self, factory):
        """Test validating configuration for unknown type."""
        # Act
        is_valid, errors = factory.validate_config("unknown_type", {})
        
        # Assert
        assert is_valid is False
        assert len(errors) > 0
        assert "Unknown middleware type" in errors[0]


class TestConfigurableMiddleware:
    """Test cases for configurable middleware implementations."""
    
    def create_mock_request(self, path="/test", method="GET", headers=None):
        """Create mock request for testing."""
        request = MagicMock(spec=Request)
        request.url.path = path
        request.method = method
        request.headers = headers or {}
        request.client.host = "127.0.0.1"
        request.state = MagicMock()
        return request
    
    def create_mock_response(self, status_code=200):
        """Create mock response for testing."""
        response = MagicMock(spec=Response)
        response.status_code = status_code
        response.headers = {}
        return response
    
    @pytest.mark.asyncio
    async def test_security_headers_middleware(self):
        """Test SecurityHeadersMiddleware."""
        # Arrange
        config = SecurityHeadersConfig(custom_headers={"X-Test": "test-value"})
        middleware = ConfigurableSecurityHeadersMiddleware(config)
        request = self.create_mock_request()
        response = self.create_mock_response()
        
        # Act
        processed_response = await middleware.process_response(request, response)
        
        # Assert
        assert processed_response == response
        assert "X-Content-Type-Options" in response.headers
        assert "X-Test" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Test"] == "test-value"
    
    @pytest.mark.asyncio
    async def test_security_headers_middleware_disabled(self):
        """Test SecurityHeadersMiddleware when disabled."""
        # Arrange
        config = SecurityHeadersConfig(enabled=False)
        middleware = ConfigurableSecurityHeadersMiddleware(config)
        request = self.create_mock_request()
        response = self.create_mock_response()
        
        # Act
        processed_response = await middleware.process_response(request, response)
        
        # Assert
        assert processed_response == response
        assert len(response.headers) == 0  # No headers should be added
    
    @pytest.mark.asyncio
    async def test_cors_middleware_preflight(self):
        """Test CORS middleware handling preflight request."""
        # Arrange
        config = CORSConfig(allowed_origins={"https://example.com"})
        middleware = ConfigurableCORSMiddleware(config)
        request = self.create_mock_request(
            method="OPTIONS",
            headers={"origin": "https://example.com"}
        )
        
        # Act
        processed_request = await middleware.process_request(request)
        
        # Assert
        assert hasattr(processed_request.state, 'cors_preflight_response')
        preflight_response = processed_request.state.cors_preflight_response
        assert "Access-Control-Allow-Origin" in preflight_response.headers
        assert preflight_response.headers["Access-Control-Allow-Origin"] == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_cors_middleware_regular_request(self):
        """Test CORS middleware handling regular request."""
        # Arrange
        config = CORSConfig(allowed_origins={"https://example.com"})
        middleware = ConfigurableCORSMiddleware(config)
        request = self.create_mock_request(headers={"origin": "https://example.com"})
        response = self.create_mock_response()
        
        # Act
        processed_response = await middleware.process_response(request, response)
        
        # Assert
        assert "Access-Control-Allow-Origin" in response.headers
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert "Access-Control-Allow-Credentials" in response.headers
    
    @pytest.mark.asyncio
    async def test_request_tracking_middleware(self):
        """Test RequestTrackingMiddleware."""
        # Arrange
        config = RequestTrackingConfig()
        middleware = ConfigurableRequestTrackingMiddleware(config)
        request = self.create_mock_request()
        response = self.create_mock_response()
        
        with patch('uuid.uuid4', return_value="test-request-id"), \
             patch('time.time', side_effect=[100.0, 101.5]):  # 1.5 second processing time
            
            # Act
            processed_request = await middleware.process_request(request)
            processed_response = await middleware.process_response(processed_request, response)
            
            # Assert
            assert hasattr(processed_request.state, 'request_id')
            assert processed_request.state.request_id == "test-request-id"
            assert "X-Request-ID" in response.headers
            assert response.headers["X-Request-ID"] == "test-request-id"
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_within_limit(self):
        """Test RateLimitMiddleware when within limits."""
        # Arrange
        config = RateLimitConfig(requests_per_minute=10)
        middleware = ConfigurableRateLimitMiddleware(config)
        middleware._cache_service = AsyncMock()
        middleware._cache_service.increment.return_value = 5  # Within limit
        
        request = self.create_mock_request()
        
        # Act
        processed_request = await middleware.process_request(request)
        
        # Assert
        assert processed_request == request
        assert hasattr(request.state, 'rate_limit_remaining')
        assert request.state.rate_limit_remaining == 5  # 10 - 5
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_exceeds_limit(self):
        """Test RateLimitMiddleware when limit exceeded."""
        # Arrange
        config = RateLimitConfig(requests_per_minute=10)
        middleware = ConfigurableRateLimitMiddleware(config)
        middleware._cache_service = AsyncMock()
        middleware._cache_service.increment.return_value = 15  # Exceeds limit
        
        request = self.create_mock_request()
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await middleware.process_request(request)
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.asyncio
    async def test_rate_limit_middleware_excluded_path(self):
        """Test RateLimitMiddleware with excluded path."""
        # Arrange
        config = RateLimitConfig()
        middleware = ConfigurableRateLimitMiddleware(config)
        request = self.create_mock_request(path="/health")
        
        # Act
        processed_request = await middleware.process_request(request)
        
        # Assert
        assert processed_request == request
        # Should not check rate limits for excluded paths
    
    @pytest.mark.asyncio
    async def test_authentication_middleware_public_path(self):
        """Test AuthenticationMiddleware with public path."""
        # Arrange
        config = AuthenticationConfig()
        middleware = ConfigurableAuthenticationMiddleware(config)
        request = self.create_mock_request(path="/health")
        
        # Act
        processed_request = await middleware.process_request(request)
        
        # Assert
        assert processed_request == request
        # Should not require authentication for public paths
    
    @pytest.mark.asyncio
    async def test_authentication_middleware_no_token(self):
        """Test AuthenticationMiddleware without token."""
        # Arrange
        config = AuthenticationConfig()
        middleware = ConfigurableAuthenticationMiddleware(config)
        request = self.create_mock_request(path="/protected")
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await middleware.process_request(request)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_authentication_middleware_with_valid_token(self):
        """Test AuthenticationMiddleware with valid token."""
        # Arrange
        config = AuthenticationConfig()
        middleware = ConfigurableAuthenticationMiddleware(config)
        request = self.create_mock_request(
            path="/protected",
            headers={"Authorization": "Bearer valid-token"}
        )
        
        with patch('src.middleware.configurable_middleware.get_container') as mock_get_container, \
             patch('src.middleware.configurable_middleware.get_db') as mock_get_db:
            
            # Mock dependencies
            mock_container = MagicMock()
            mock_auth_service = MagicMock()
            mock_user = MagicMock()
            mock_user.id = 1
            
            mock_get_container.return_value = mock_container
            mock_container.get.return_value = mock_auth_service
            mock_auth_service.validate_token = AsyncMock(return_value=mock_user)
            mock_get_db.return_value.__next__.return_value = AsyncMock()
            
            # Act
            processed_request = await middleware.process_request(request)
            
            # Assert
            assert processed_request == request
            assert hasattr(request.state, 'current_user')
            assert request.state.current_user == mock_user


class TestMiddlewareAdapter:
    """Test cases for MiddlewareAdapter."""
    
    @pytest.fixture
    def mock_app(self):
        """Create mock FastAPI app."""
        return MagicMock()
    
    @pytest.fixture
    def adapter(self, mock_app):
        """Create MiddlewareAdapter for testing."""
        config = [
            {"type": MiddlewareType.SECURITY_HEADERS, "enabled": True, "priority": 10},
            {"type": MiddlewareType.REQUEST_TRACKING, "enabled": True, "priority": 5}
        ]
        return MiddlewareAdapter(mock_app, middleware_config=config)
    
    def test_adapter_initialization(self, adapter):
        """Test MiddlewareAdapter initialization."""
        # Assert
        assert len(adapter.middleware_stack) == 2
        assert adapter.middleware_stack[0].priority <= adapter.middleware_stack[1].priority
    
    def test_get_middleware_info(self, adapter):
        """Test getting middleware information."""
        # Act
        info = adapter.get_middleware_info()
        
        # Assert
        assert len(info) == 2
        assert all("name" in item for item in info)
        assert all("priority" in item for item in info)
        assert all("enabled" in item for item in info)
    
    def test_add_middleware(self, adapter):
        """Test adding middleware dynamically."""
        # Arrange
        config = CORSConfig()
        new_middleware = ConfigurableCORSMiddleware(config)
        original_count = len(adapter.middleware_stack)
        
        # Act
        adapter.add_middleware(new_middleware)
        
        # Assert
        assert len(adapter.middleware_stack) == original_count + 1
        assert new_middleware in adapter.middleware_stack
    
    def test_remove_middleware(self, adapter):
        """Test removing middleware by name."""
        # Arrange
        original_count = len(adapter.middleware_stack)
        middleware_name = adapter.middleware_stack[0].name
        
        # Act
        result = adapter.remove_middleware(middleware_name)
        
        # Assert
        assert result is True
        assert len(adapter.middleware_stack) == original_count - 1
        assert not any(m.name == middleware_name for m in adapter.middleware_stack)
    
    def test_remove_nonexistent_middleware(self, adapter):
        """Test removing non-existent middleware."""
        # Act
        result = adapter.remove_middleware("NonExistentMiddleware")
        
        # Assert
        assert result is False
    
    def test_reload_middleware(self, adapter):
        """Test reloading middleware with new configuration."""
        # Arrange
        new_config = [
            {"type": MiddlewareType.CORS, "enabled": True, "priority": 15}
        ]
        
        # Act
        adapter.reload_middleware(new_config)
        
        # Assert
        assert len(adapter.middleware_stack) == 1
        assert adapter.middleware_stack[0].name == "CORS"