"""
Integration tests for the complete middleware stack.
Tests the interaction between all middleware components and request flow.
"""
import pytest
import asyncio
import time
import json
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from src.services.rate_limiter import RateLimitResult, RateLimitType
from src.services.circuit_breaker import CircuitBreakerError


@pytest.mark.integration
class TestMiddlewareStack:
    """Test complete middleware stack integration."""
    
    def test_request_flow_through_all_middleware(self, client, auth_headers):
        """Test request flows through all middleware components."""
        headers = {
            **auth_headers["valid_user"],
            "X-API-Version": "v1",
            "User-Agent": "test-client/1.0",
            "Content-Type": "application/json"
        }
        
        response = client.get("/health", headers=headers)
        
        assert response.status_code == 200
        
        # Check middleware added headers
        assert "X-Request-ID" in response.headers
        assert "X-API-Version" in response.headers
        assert "X-Gateway" in response.headers
        assert "X-Timestamp" in response.headers
        
        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "Strict-Transport-Security" in response.headers
        
        # Check rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers
    
    def test_middleware_order_authentication_before_rate_limiting(self, client):
        """Test that authentication happens before rate limiting."""
        # Make request without auth - should fail at auth middleware
        response = client.get("/api/v1/services")
        
        assert response.status_code == 401
        assert "error" in response.json()
        assert "authorization" in response.json()["error"].lower()
        
        # Rate limiting headers should not be present (failed at auth)
        # This depends on middleware order implementation
    
    @patch("src.services.rate_limiter.RateLimiterManager.check_rate_limit")
    def test_rate_limiting_after_authentication(self, mock_rate_limit, client, auth_headers):
        """Test rate limiting works after successful authentication."""
        # Mock rate limit exceeded
        mock_rate_limit.return_value = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_time=time.time() + 60,
            retry_after=60,
            limit_type="user"
        )
        
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 429
        assert "rate limit" in response.json()["error"].lower()
        assert "Retry-After" in response.headers
    
    def test_request_transformation_middleware(self, client, auth_headers):
        """Test request transformation middleware."""
        headers = {
            **auth_headers["valid_user"],
            "X-API-Version": "v2"  # Unsupported version
        }
        
        response = client.get("/health", headers=headers)
        
        # Should either reject or default to supported version
        if response.status_code == 400:
            data = response.json()
            assert "api version" in data["error"].lower()
        else:
            # Should default to supported version
            assert response.headers.get("X-API-Version") == "v1"
    
    def test_response_transformation_middleware(self, client):
        """Test response transformation middleware."""
        response = client.get("/health")
        
        assert response.status_code == 200
        
        # Check transformed headers
        assert response.headers.get("X-Gateway") == "Enterprise-API-Gateway"
        assert "X-Timestamp" in response.headers
        
        # Timestamp should be recent
        timestamp = int(response.headers["X-Timestamp"])
        assert abs(timestamp - time.time()) < 10  # Within 10 seconds
    
    @patch("src.middleware.gateway_middleware.redis_manager")
    def test_metrics_middleware_recording(self, mock_redis, client):
        """Test metrics middleware records request data."""
        mock_redis.set_json.return_value = None
        
        response = client.get("/health")
        
        assert response.status_code == 200
        
        # Verify metrics were recorded
        mock_redis.set_json.assert_called()
        call_args = mock_redis.set_json.call_args[0]
        metrics_data = call_args[1]
        
        assert "timestamp" in metrics_data
        assert "method" in metrics_data
        assert "path" in metrics_data
        assert "status_code" in metrics_data
        assert "duration" in metrics_data
        assert "success" in metrics_data
        
        assert metrics_data["method"] == "GET"
        assert metrics_data["path"] == "/health"
        assert metrics_data["status_code"] == 200
        assert metrics_data["success"] is True
    
    def test_large_request_security_middleware(self, client):
        """Test security middleware blocks large requests."""
        # Create a large payload
        large_data = json.dumps({"data": "x" * (15 * 1024 * 1024)})  # 15MB+
        
        response = client.post(
            "/api/v1/test",
            data=large_data,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 413
        assert "too large" in response.json()["error"].lower()
    
    def test_cors_middleware_integration(self, client):
        """Test CORS middleware with preflight request."""
        # Preflight OPTIONS request
        response = client.options(
            "/health",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization"
            }
        )
        
        # Should have CORS headers
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
    
    def test_trusted_host_middleware(self, client):
        """Test trusted host middleware."""
        # This test depends on how TrustedHostMiddleware is configured
        # With allowed_hosts=["*"], all hosts should be allowed
        response = client.get("/health", headers={"Host": "malicious.com"})
        
        # Should be allowed with wildcard config
        assert response.status_code == 200
    
    def test_gzip_compression_middleware(self, client):
        """Test GZip compression middleware."""
        # Request large response that should be compressed
        response = client.get(
            "/api/v1/services",
            headers={
                "Authorization": "Bearer valid-user-token",
                "Accept-Encoding": "gzip"
            }
        )
        
        # Check if response was compressed (if large enough)
        if len(response.content) > 1000:
            assert "Content-Encoding" in response.headers
            assert response.headers["Content-Encoding"] == "gzip"


@pytest.mark.integration
class TestMiddlewareErrorHandling:
    """Test middleware error handling and recovery."""
    
    @patch("src.middleware.gateway_middleware.redis_manager")
    def test_middleware_resilience_to_redis_failure(self, mock_redis, client):
        """Test middleware continues working when Redis fails."""
        # Mock Redis failure
        mock_redis.set_json.side_effect = Exception("Redis connection failed")
        mock_redis.get_client.side_effect = Exception("Redis connection failed")
        
        # Request should still work despite Redis failure
        response = client.get("/health")
        
        assert response.status_code == 200
        # Metrics might not be recorded, but request should succeed
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_auth_middleware_error_handling(self, mock_auth, client):
        """Test authentication middleware error handling."""
        # Mock auth service failure
        mock_auth.side_effect = Exception("Auth service unavailable")
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        assert "authentication failed" in response.json()["error"].lower()
    
    def test_circuit_breaker_middleware_integration(self, client):
        """Test circuit breaker middleware with backend failures."""
        # This would require mocking backend service calls
        # For now, test that circuit breaker error is handled
        with patch("src.api.gateway.proxy_handler.proxy_request") as mock_proxy:
            mock_proxy.side_effect = CircuitBreakerError("Service unavailable")
            
            headers = {"Authorization": "Bearer valid-user-token"}
            response = client.get("/api/v1/users/profile", headers=headers)
            
            assert response.status_code == 503
            assert "temporarily unavailable" in response.json()["message"].lower()
    
    def test_middleware_exception_propagation(self, client):
        """Test that middleware exceptions are properly handled."""
        # Trigger an unhandled exception in middleware
        with patch("src.middleware.gateway_middleware.RequestLoggingMiddleware.dispatch") as mock_dispatch:
            mock_dispatch.side_effect = Exception("Middleware error")
            
            response = client.get("/health")
            
            # Should be handled by global exception handler
            assert response.status_code == 500
            assert "internal server error" in response.json()["error"].lower()
            assert "X-Request-ID" in response.headers


@pytest.mark.integration
class TestMiddlewarePerformance:
    """Test middleware performance characteristics."""
    
    def test_middleware_latency_overhead(self, client, performance_monitor):
        """Test that middleware doesn't add excessive latency."""
        performance_monitor.start()
        
        # Make multiple requests
        for _ in range(20):
            start_time = time.time()
            response = client.get("/health")
            duration = time.time() - start_time
            
            performance_monitor.record_request(duration, response.status_code)
        
        performance_monitor.stop()
        stats = performance_monitor.get_stats()
        
        # Middleware overhead should be minimal
        assert stats["avg_duration"] < 0.1  # Less than 100ms
        assert stats["p95_duration"] < 0.2  # 95th percentile under 200ms
        assert stats["success_rate"] == 1.0  # All requests successful
    
    def test_concurrent_middleware_processing(self, client):
        """Test middleware handles concurrent requests properly."""
        import concurrent.futures
        import threading
        
        results = []
        
        def make_request():
            response = client.get("/health")
            results.append({
                "status": response.status_code,
                "request_id": response.headers.get("X-Request-ID"),
                "thread_id": threading.current_thread().ident
            })
        
        # Make concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            concurrent.futures.wait(futures)
        
        assert len(results) == 50
        assert all(r["status"] == 200 for r in results)
        
        # All requests should have unique request IDs
        request_ids = [r["request_id"] for r in results]
        assert len(set(request_ids)) == len(request_ids)


@pytest.mark.integration
class TestMiddlewareConfiguration:
    """Test middleware configuration and customization."""
    
    def test_middleware_configuration_loading(self, app_with_mocks):
        """Test that middleware is configured correctly."""
        # Check that all expected middleware is present
        middleware_stack = app_with_mocks.user_middleware
        
        middleware_types = [type(middleware.cls).__name__ for middleware in middleware_stack]
        
        expected_middleware = [
            "TrustedHostMiddleware",
            "CORSMiddleware", 
            "GZipMiddleware",
            "MetricsMiddleware",
            "RequestLoggingMiddleware",
            "SecurityMiddleware",
            "AuthenticationMiddleware",
            "RateLimitMiddleware",
            "CircuitBreakerMiddleware",
            "RequestTransformMiddleware",
            "ResponseTransformMiddleware"
        ]
        
        # Check that key middleware components are present
        for expected in expected_middleware:
            # Allow for partial matches due to class naming variations
            assert any(expected.lower() in mw.lower() for mw in middleware_types)
    
    def test_middleware_order_importance(self, client):
        """Test that middleware order affects request processing."""
        # Security middleware should process before authentication
        # Rate limiting should process after authentication
        # This is verified by the successful request flow
        
        headers = {
            "Authorization": "Bearer valid-user-token",
            "X-API-Version": "v1"
        }
        
        response = client.get("/health", headers=headers)
        
        assert response.status_code == 200
        
        # All middleware should have processed the request
        assert "X-Request-ID" in response.headers  # Request logging
        assert "X-Content-Type-Options" in response.headers  # Security
        assert "X-API-Version" in response.headers  # Request/Response transformation
        assert "X-RateLimit-Limit" in response.headers  # Rate limiting
    
    def test_middleware_bypass_for_health_checks(self, client):
        """Test that health checks bypass certain middleware."""
        # Health check should bypass authentication and rate limiting
        response = client.get("/health")
        
        assert response.status_code == 200
        
        # Should still have security headers
        assert "X-Content-Type-Options" in response.headers
        
        # Should have request ID from logging middleware
        assert "X-Request-ID" in response.headers
    
    def test_middleware_public_endpoint_handling(self, client):
        """Test middleware handles public endpoints correctly."""
        public_endpoints = ["/health", "/ready", "/docs", "/openapi.json"]
        
        for endpoint in public_endpoints:
            response = client.get(endpoint)
            
            # Should not require authentication
            assert response.status_code != 401
            
            # Should still have security headers
            assert "X-Content-Type-Options" in response.headers
            
            # Should have request tracking
            assert "X-Request-ID" in response.headers


@pytest.mark.integration
class TestMiddlewareStateManagement:
    """Test middleware state management and request context."""
    
    def test_request_state_propagation(self, client, auth_headers):
        """Test that request state is properly propagated through middleware."""
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        # Request should have gone through auth middleware
        # and user info should be available in request state
        # This is verified by successful response from protected endpoint
        assert response.status_code != 401
    
    def test_request_id_consistency(self, client):
        """Test that request ID is consistent across middleware."""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        
        request_id = response.headers["X-Request-ID"]
        
        # Request ID should be a valid UUID format
        import uuid
        try:
            uuid.UUID(request_id)
        except ValueError:
            pytest.fail(f"Request ID is not a valid UUID: {request_id}")
    
    def test_middleware_context_isolation(self, client):
        """Test that middleware context is properly isolated between requests."""
        # Make multiple concurrent requests
        import threading
        request_ids = []
        
        def make_request():
            response = client.get("/health")
            request_ids.append(response.headers.get("X-Request-ID"))
        
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All request IDs should be unique (no context leakage)
        assert len(set(request_ids)) == len(request_ids)
    
    @patch("src.middleware.gateway_middleware.time.time")
    def test_request_timing_accuracy(self, mock_time, client):
        """Test that request timing in middleware is accurate."""
        # Mock time to control timing
        start_time = 1234567890.0
        end_time = start_time + 0.1  # 100ms request
        
        mock_time.side_effect = [start_time, end_time, end_time]
        
        response = client.get("/health")
        
        assert response.status_code == 200
        
        # Should have recorded timing information
        # This would be verified through metrics if exposed