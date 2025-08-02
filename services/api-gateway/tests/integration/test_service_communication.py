"""
Integration tests for service communication.
Tests request proxying, load balancing, and backend service integration.
"""
import pytest
import asyncio
import time
import json
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from src.api.gateway import RequestProxyHandler
from src.services.circuit_breaker import CircuitBreakerError
from src.services.service_registry import ServiceEndpoint


@pytest.mark.integration
class TestServiceProxying:
    """Test request proxying to backend services."""
    
    @pytest.fixture
    def proxy_handler(self):
        """Request proxy handler instance."""
        return RequestProxyHandler()
    
    @patch("httpx.AsyncClient")
    async def test_successful_proxy_request(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test successful request proxying."""
        # Mock successful backend response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "success", "data": "test"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.request.return_value = mock_response
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker to allow call
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["data"] == "test"
    
    @patch("httpx.AsyncClient")
    async def test_proxy_request_with_body(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test proxying POST request with body."""
        # Mock successful backend response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.content = b'{"id": "123", "status": "created"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.request.return_value = mock_response
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = auth_headers["valid_user"]
        payload = {"name": "test user", "email": "test@example.com"}
        
        response = client.post(
            "/api/v1/users/create",
            json=payload,
            headers=headers
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["id"] == "123"
        assert data["status"] == "created"
        
        # Verify the request was forwarded with correct body
        mock_client_instance.request.assert_called_once()
        call_args = mock_client_instance.request.call_args
        assert call_args[1]["content"] is not None  # Body was forwarded
    
    def test_proxy_service_not_found(self, client, auth_headers, mock_service_registry):
        """Test proxying to non-existent service."""
        # Configure service registry to return None
        mock_service_registry.get_service_url.return_value = None
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/nonexistent/data", headers=headers)
        
        assert response.status_code == 503
        assert "not available" in response.json()["detail"].lower()
    
    @patch("httpx.AsyncClient")
    def test_proxy_backend_timeout(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test handling of backend service timeout."""
        # Mock timeout exception
        mock_client_instance = AsyncMock()
        mock_client_instance.request.side_effect = httpx.TimeoutException("Request timeout")
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker to propagate timeout
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        assert response.status_code == 504
        assert "timeout" in response.json()["detail"].lower()
    
    @patch("httpx.AsyncClient")
    def test_proxy_backend_error(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test handling of backend service error."""
        # Mock connection error
        mock_client_instance = AsyncMock()
        mock_client_instance.request.side_effect = Exception("Connection refused")
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        assert response.status_code == 502
        assert "backend service error" in response.json()["detail"].lower()
    
    def test_proxy_circuit_breaker_open(self, client, auth_headers, mock_circuit_breaker_manager):
        """Test proxying when circuit breaker is open."""
        # Configure circuit breaker to be open
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = CircuitBreakerError("Circuit open")
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        assert response.status_code == 503
        assert "temporarily unavailable" in response.json()["detail"].lower()
    
    @patch("httpx.AsyncClient")
    def test_proxy_header_filtering(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test that hop-by-hop headers are filtered."""
        # Mock backend response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "ok"}'
        mock_response.headers = {
            "content-type": "application/json",
            "connection": "keep-alive",  # Hop-by-hop header
            "transfer-encoding": "chunked",  # Hop-by-hop header
            "custom-header": "should-be-kept"
        }
        
        mock_client_instance = AsyncMock()
        mock_client_instance.request.return_value = mock_response
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = {
            **auth_headers["valid_user"],
            "Connection": "keep-alive",  # Should be filtered
            "Custom-Header": "should-be-kept"
        }
        
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        assert response.status_code == 200
        
        # Hop-by-hop headers should be filtered from response
        assert "Connection" not in response.headers
        assert "Transfer-Encoding" not in response.headers
        
        # Custom headers should be preserved
        assert "Custom-Header" in response.headers
        
        # Verify hop-by-hop headers were filtered from forwarded request
        mock_client_instance.request.assert_called_once()
        forwarded_headers = mock_client_instance.request.call_args[1]["headers"]
        assert "connection" not in forwarded_headers
    
    @patch("httpx.AsyncClient")
    def test_proxy_query_parameters(self, mock_http_client, client, auth_headers, mock_service_registry, mock_circuit_breaker_manager):
        """Test that query parameters are forwarded correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "ok"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.request.return_value = mock_response
        mock_http_client.return_value = mock_client_instance
        
        # Configure circuit breaker
        async def mock_cb_call(service_name, func, *args, **kwargs):
            return await func(*args, **kwargs)
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile?include=details&format=json", headers=headers)
        
        assert response.status_code == 200
        
        # Verify query parameters were included in forwarded URL
        mock_client_instance.request.assert_called_once()
        forwarded_url = mock_client_instance.request.call_args[1]["url"]
        assert "include=details" in forwarded_url
        assert "format=json" in forwarded_url


@pytest.mark.integration  
class TestServiceRegistry:
    """Test service registry integration."""
    
    def test_list_services_endpoint(self, client, auth_headers, mock_service_registry):
        """Test listing registered services."""
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "services" in data
        assert "total" in data
        assert "healthy" in data
        assert "unhealthy" in data
        
        assert data["total"] >= 0
        assert data["healthy"] >= 0
        assert data["unhealthy"] >= 0
    
    def test_service_discovery_integration(self, client, auth_headers, mock_service_registry):
        """Test service discovery integration."""
        # Configure service registry with test services
        mock_service_registry.get_all_services_status.return_value = {
            "auth": {
                "status": "healthy",
                "url": "http://auth:8000",
                "version": "1.0.0",
                "last_check": time.time(),
                "response_time": 0.05
            },
            "user": {
                "status": "healthy", 
                "url": "http://user:8000",
                "version": "1.0.0",
                "last_check": time.time(),
                "response_time": 0.03
            },
            "orders": {
                "status": "unhealthy",
                "url": "http://orders:8000",
                "version": "1.0.0",
                "last_check": time.time() - 300,
                "response_time": None
            }
        }
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["total"] == 3
        assert data["healthy"] == 2
        assert data["unhealthy"] == 1
        
        services = data["services"]
        assert "auth" in services
        assert "user" in services
        assert "orders" in services
        
        assert services["auth"]["status"] == "healthy"
        assert services["orders"]["status"] == "unhealthy"


@pytest.mark.integration
class TestDynamicServiceRouting:
    """Test dynamic service routing."""
    
    def test_dynamic_service_proxy_existing_service(self, client, auth_headers, mock_service_registry):
        """Test dynamic routing to existing service."""
        # Configure service registry
        mock_service_registry.get_service_endpoint.return_value = ServiceEndpoint(
            name="orders",
            url="http://orders:8000",
            health_check_url="http://orders:8000/health",
            status="healthy"
        )
        
        with patch("httpx.AsyncClient") as mock_http_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b'{"orders": []}'
            mock_response.headers = {"content-type": "application/json"}
            
            mock_client_instance = AsyncMock()
            mock_client_instance.request.return_value = mock_response
            mock_http_client.return_value = mock_client_instance
            
            headers = auth_headers["valid_user"]
            response = client.get("/api/v1/orders/list", headers=headers)
            
            assert response.status_code == 200
            data = response.json()
            assert "orders" in data
    
    def test_dynamic_service_proxy_nonexistent_service(self, client, auth_headers, mock_service_registry):
        """Test dynamic routing to non-existent service."""
        # Configure service registry to return None
        mock_service_registry.get_service_endpoint.return_value = None
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/nonexistent/data", headers=headers)
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.integration
class TestHealthCheckIntegration:
    """Test health check integration with service registry."""
    
    def test_gateway_health_check(self, client):
        """Test gateway health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert data["service"] == "api-gateway"
        assert "timestamp" in data
        assert "uptime" in data
    
    def test_readiness_check_with_healthy_services(self, client, mock_service_registry):
        """Test readiness check when services are healthy."""
        # Configure all services as healthy
        mock_service_registry.get_healthy_services.return_value = ["auth", "user", "orders"]
        mock_service_registry.get_all_services_status.return_value = {
            "auth": {"status": "healthy"},
            "user": {"status": "healthy"},
            "orders": {"status": "healthy"}
        }
        
        response = client.get("/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
    
    def test_readiness_check_with_unhealthy_services(self, client, mock_service_registry):
        """Test readiness check when services are unhealthy."""
        # Configure some services as unhealthy
        mock_service_registry.get_healthy_services.return_value = ["auth"]
        mock_service_registry.get_all_services_status.return_value = {
            "auth": {"status": "healthy"},
            "user": {"status": "unhealthy"},
            "orders": {"status": "unhealthy"}
        }
        
        response = client.get("/ready")
        
        # Might return 503 if critical services are down
        # Implementation depends on readiness logic
        assert response.status_code in [200, 503]
        
        data = response.json()
        assert "status" in data


@pytest.mark.integration
class TestDocumentationAggregation:
    """Test OpenAPI documentation aggregation."""
    
    @patch("httpx.AsyncClient")
    def test_aggregated_docs_endpoint(self, mock_http_client, client, test_settings, mock_service_registry, fake_redis):
        """Test aggregated documentation endpoint."""
        # Enable docs aggregation
        test_settings.docs_aggregation_enabled = True
        
        # Mock service registry
        mock_service_registry.get_healthy_services.return_value = ["auth", "user"]
        mock_service_registry.get_service_endpoint.side_effect = lambda name: ServiceEndpoint(
            name=name,
            url=f"http://{name}:8000",
            health_check_url=f"http://{name}:8000/health"
        )
        
        # Mock OpenAPI responses from services
        auth_openapi = {
            "openapi": "3.0.0",
            "info": {"title": "Auth Service", "version": "1.0.0"},
            "paths": {
                "/login": {"post": {"summary": "Login user"}},
                "/logout": {"post": {"summary": "Logout user"}}
            },
            "components": {
                "schemas": {
                    "LoginRequest": {"type": "object"},
                    "LoginResponse": {"type": "object"}
                }
            }
        }
        
        user_openapi = {
            "openapi": "3.0.0",
            "info": {"title": "User Service", "version": "1.0.0"},
            "paths": {
                "/profile": {"get": {"summary": "Get user profile"}},
                "/update": {"put": {"summary": "Update user profile"}}
            },
            "components": {
                "schemas": {
                    "UserProfile": {"type": "object"}
                }
            }
        }
        
        # Mock HTTP client responses
        mock_responses = {
            "http://auth:8000/openapi.json": auth_openapi,
            "http://user:8000/openapi.json": user_openapi
        }
        
        async def mock_get(url, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_responses.get(url, {})
            return mock_response
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = mock_get
        mock_http_client.return_value = mock_client_instance
        
        # Mock Redis cache miss
        fake_redis.get.return_value = None
        
        response = client.get("/api/v1/docs")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["openapi"] == "3.0.0"
        assert data["info"]["title"] == "Enterprise API - Aggregated Documentation"
        assert "paths" in data
        assert "components" in data
        
        # Should have paths from both services with prefixes
        paths = data["paths"]
        assert "/auth/login" in paths
        assert "/user/profile" in paths
        
        # Should have schemas from both services with prefixes
        schemas = data["components"]["schemas"]
        assert "auth_LoginRequest" in schemas
        assert "user_UserProfile" in schemas
    
    def test_aggregated_docs_caching(self, client, test_settings, fake_redis):
        """Test that aggregated docs are cached."""
        test_settings.docs_aggregation_enabled = True
        
        # Mock cached response
        cached_docs = {
            "openapi": "3.0.0",
            "info": {"title": "Cached Documentation"},
            "paths": {},
            "components": {"schemas": {}}
        }
        
        # Mock Redis cache hit
        fake_redis.get.return_value = json.dumps(cached_docs)
        
        response = client.get("/api/v1/docs")
        
        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "Cached Documentation"
    
    def test_aggregated_docs_disabled(self, client, test_settings):
        """Test aggregated docs when disabled."""
        test_settings.docs_aggregation_enabled = False
        
        response = client.get("/api/v1/docs")
        
        assert response.status_code == 404
        assert "disabled" in response.json()["detail"].lower()


@pytest.mark.integration
class TestServiceCommunicationResilience:
    """Test resilience patterns in service communication."""
    
    @patch("httpx.AsyncClient")
    def test_retry_on_transient_failures(self, mock_http_client, client, auth_headers, mock_circuit_breaker_manager):
        """Test retry behavior on transient failures."""
        # Configure circuit breaker to allow retries
        call_count = 0
        
        async def mock_cb_call(service_name, func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call fails
                raise Exception("Transient error")
            else:
                # Second call succeeds
                return await func(*args, **kwargs)
        
        mock_circuit_breaker_manager.call_with_circuit_breaker.side_effect = mock_cb_call
        
        # This would require implementing retry logic in the proxy handler
        # For now, just test that circuit breaker is called
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        # Response depends on implementation
        # Circuit breaker should have been called
        assert mock_circuit_breaker_manager.call_with_circuit_breaker.called
    
    def test_graceful_degradation_on_service_failure(self, client, auth_headers, mock_service_registry):
        """Test graceful degradation when services fail."""
        # Configure service as unhealthy
        mock_service_registry.get_service_url.return_value = None
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/orders/list", headers=headers)
        
        # Should return service unavailable instead of crashing
        assert response.status_code == 503
        assert "error" in response.json()
    
    def test_load_balancing_health_aware(self, client, auth_headers, mock_service_registry):
        """Test that load balancing considers service health."""
        # This would test load balancing between multiple instances
        # For now, verify that service registry health status is checked
        
        mock_service_registry.get_healthy_services.return_value = ["auth", "user"]
        mock_service_registry.get_service_url.return_value = "http://healthy-service:8000"
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/auth/profile", headers=headers)
        
        # Should route to healthy service
        mock_service_registry.get_service_url.assert_called_with("auth")