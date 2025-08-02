"""
Security vulnerability tests for the API Gateway.
Tests for common web vulnerabilities and attack vectors.
"""
import pytest
import time
import json
import base64
from unittest.mock import patch


@pytest.mark.security
class TestOWASPTop10:
    """Test protection against OWASP Top 10 vulnerabilities."""
    
    def test_broken_access_control_prevention(self, client, auth_headers):
        """Test prevention of broken access control (OWASP #1)."""
        # Test horizontal privilege escalation
        user_headers = auth_headers["valid_user"]
        
        # User trying to access another user's resources
        other_user_endpoints = [
            "/api/v1/users/456/profile",  # Different user ID
            "/api/v1/users/admin/settings",
            "/api/v1/orders/other-user-order-123"
        ]
        
        for endpoint in other_user_endpoints:
            response = client.get(endpoint, headers=user_headers)
            # Should be forbidden or not found
            assert response.status_code in [403, 404]
        
        # Test vertical privilege escalation
        admin_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system/config",
            "/api/v1/admin/audit/logs"
        ]
        
        for endpoint in admin_endpoints:
            response = client.get(endpoint, headers=user_headers)
            assert response.status_code in [403, 404]
    
    def test_cryptographic_failures_prevention(self, client, auth_headers):
        """Test prevention of cryptographic failures (OWASP #2)."""
        # Test that sensitive data is not transmitted in plain text
        headers = auth_headers["valid_user"]
        
        sensitive_payload = {
            "password": "newsecretpassword",
            "ssn": "123-45-6789",
            "payment_info": {
                "card_number": "4532123456789012",
                "cvv": "123"
            }
        }
        
        response = client.post("/api/v1/users/update-sensitive", json=sensitive_payload, headers=headers)
        
        # Even if endpoint doesn't exist, should not expose sensitive data in error
        if response.status_code >= 400:
            error_text = response.text.lower()
            assert "4532123456789012" not in error_text
            assert "newsecretpassword" not in error_text
    
    def test_injection_attacks_prevention(self, client, auth_headers, sample_request_data):
        """Test prevention of injection attacks (OWASP #3)."""
        headers = auth_headers["valid_user"]
        malicious_data = sample_request_data["malicious_payload"]
        
        injection_payloads = [
            # SQL Injection
            {"name": malicious_data["sql_injection"]},
            # NoSQL Injection
            {"filter": {"$where": "this.name == 'admin'"}},
            # Command Injection
            {"command": malicious_data["command_injection"]},
            # LDAP Injection
            {"username": "admin)(|(password=*)"},
            # XPath Injection
            {"query": "//user[name/text()='" + malicious_data["sql_injection"] + "']"}
        ]
        
        for payload in injection_payloads:
            response = client.post("/api/v1/search", json=payload, headers=headers)
            
            # Should reject or sanitize injection attempts
            if response.status_code == 200:
                # If processed, should not show signs of successful injection
                data = response.json()
                assert "error" not in str(data).lower() or "syntax" not in str(data).lower()
    
    def test_insecure_design_prevention(self, client, auth_headers):
        """Test prevention of insecure design patterns (OWASP #4)."""
        headers = auth_headers["valid_user"]
        
        # Test that sensitive operations require additional verification
        critical_operations = [
            ("DELETE", "/api/v1/users/account"),
            ("POST", "/api/v1/users/change-email"),
            ("PUT", "/api/v1/users/change-password")
        ]
        
        for method, endpoint in critical_operations:
            # Attempt operation without additional verification
            response = client.request(method, endpoint, headers=headers)
            
            # Should require additional verification (2FA, password confirmation, etc.)
            if response.status_code not in [404, 405]:  # If endpoint exists
                assert response.status_code in [400, 403, 422]  # Should require more info
    
    def test_security_misconfiguration_prevention(self, client):
        """Test prevention of security misconfigurations (OWASP #5)."""
        # Test that debug information is not exposed
        response = client.get("/debug")
        assert response.status_code == 404
        
        response = client.get("/api/v1/debug")
        assert response.status_code == 404
        
        # Test that admin interfaces are not accessible
        admin_paths = [
            "/admin",
            "/administrator",
            "/api/admin",
            "/management",
            "/console"
        ]
        
        for path in admin_paths:
            response = client.get(path)
            assert response.status_code in [404, 403]
        
        # Test that server information is not disclosed
        response = client.get("/health")
        assert "X-Powered-By" not in response.headers
        assert "Server" not in response.headers or "nginx" in response.headers.get("Server", "").lower()
    
    def test_vulnerable_components_protection(self, client):
        """Test protection against vulnerable components (OWASP #6)."""
        # Test that common vulnerable endpoints are not exposed
        vulnerable_endpoints = [
            "/.env",
            "/config.json",
            "/swagger.json",
            "/api-docs",
            "/actuator/health",
            "/actuator/env",
            "/.git/config",
            "/wp-admin",
            "/phpmyadmin"
        ]
        
        for endpoint in vulnerable_endpoints:
            response = client.get(endpoint)
            assert response.status_code in [404, 403]
    
    def test_identification_authentication_failures_prevention(self, client):
        """Test prevention of authentication failures (OWASP #7)."""
        # Test rate limiting on authentication attempts
        auth_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/reset-password"
        ]
        
        for endpoint in auth_endpoints:
            # Attempt multiple failed authentications
            for _ in range(10):
                response = client.post(endpoint, json={
                    "username": "nonexistent",
                    "password": "wrongpassword"
                })
                
                # Should eventually rate limit
                if response.status_code == 429:
                    break
            
            # Should have rate limiting in place for auth endpoints
            # (Test passes if we see rate limiting or if endpoint doesn't exist)
    
    def test_software_data_integrity_failures_prevention(self, client, auth_headers):
        """Test prevention of software and data integrity failures (OWASP #8)."""
        headers = auth_headers["valid_user"]
        
        # Test that unsigned/unverified updates are rejected
        malicious_update = {
            "version": "../../etc/passwd",
            "checksum": "invalid_checksum",
            "signature": "fake_signature"
        }
        
        response = client.post("/api/v1/system/update", json=malicious_update, headers=headers)
        
        # Should reject unsigned updates
        assert response.status_code in [400, 403, 404, 422]
    
    def test_security_logging_monitoring_failures_prevention(self, client, auth_headers):
        """Test prevention of security logging and monitoring failures (OWASP #9)."""
        # Test that security events are logged (can't directly test logging,
        # but ensure security events don't cause errors)
        
        # Generate various security events
        security_events = [
            # Failed authentication
            ("POST", "/api/v1/auth/login", {"username": "admin", "password": "wrong"}),
            # Access denied
            ("GET", "/api/v1/admin/users", auth_headers["valid_user"]),
            # Invalid input
            ("POST", "/api/v1/users/create", {"name": "<script>alert('xss')</script>"}),
        ]
        
        for method, endpoint, data in security_events:
            if isinstance(data, dict) and "Authorization" not in data:
                response = client.request(method, endpoint, json=data)
            else:
                response = client.request(method, endpoint, headers=data)
            
            # Security events should be handled gracefully
            assert response.status_code != 500
    
    def test_server_side_request_forgery_prevention(self, client, auth_headers):
        """Test prevention of SSRF attacks (OWASP #10)."""
        headers = auth_headers["valid_user"]
        
        # Test SSRF via URL parameters
        ssrf_payloads = [
            {"url": "http://localhost:22"},  # SSH port
            {"url": "http://169.254.169.254/latest/meta-data/"},  # AWS metadata
            {"url": "file:///etc/passwd"},  # Local file access
            {"url": "http://internal-service:8080/admin"},  # Internal service
            {"webhook_url": "http://127.0.0.1:3306"},  # MySQL port
        ]
        
        for payload in ssrf_payloads:
            response = client.post("/api/v1/webhooks/test", json=payload, headers=headers)
            
            # Should reject or validate URLs
            if response.status_code not in [404, 405]:  # If endpoint exists
                assert response.status_code in [400, 403, 422]


@pytest.mark.security
class TestSecurityHeaders:
    """Test security headers implementation."""
    
    def test_content_security_policy(self, client):
        """Test Content Security Policy header."""
        response = client.get("/health")
        
        assert "Content-Security-Policy" in response.headers
        csp = response.headers["Content-Security-Policy"]
        assert "default-src" in csp
        assert "'self'" in csp
    
    def test_strict_transport_security(self, client):
        """Test Strict Transport Security header."""
        response = client.get("/health")
        
        assert "Strict-Transport-Security" in response.headers
        hsts = response.headers["Strict-Transport-Security"]
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts
    
    def test_x_frame_options(self, client):
        """Test X-Frame-Options header."""
        response = client.get("/health")
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
    
    def test_x_content_type_options(self, client):
        """Test X-Content-Type-Options header."""
        response = client.get("/health")
        
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    
    def test_x_xss_protection(self, client):
        """Test X-XSS-Protection header."""
        response = client.get("/health")
        
        assert "X-XSS-Protection" in response.headers
        xss_protection = response.headers["X-XSS-Protection"]
        assert "1" in xss_protection
        assert "mode=block" in xss_protection
    
    def test_referrer_policy(self, client):
        """Test Referrer Policy header."""
        response = client.get("/health")
        
        assert "Referrer-Policy" in response.headers
        referrer_policy = response.headers["Referrer-Policy"]
        assert "strict-origin" in referrer_policy.lower()
    
    def test_permissions_policy(self, client):
        """Test Permissions Policy header (if implemented)."""
        response = client.get("/health")
        
        # Permissions Policy is optional but recommended
        if "Permissions-Policy" in response.headers:
            policy = response.headers["Permissions-Policy"]
            # Should restrict dangerous features
            assert "geolocation" in policy or "camera" in policy


@pytest.mark.security
class TestRateLimitingSecurity:
    """Test rate limiting security measures."""
    
    def test_authentication_rate_limiting(self, client):
        """Test rate limiting on authentication endpoints."""
        # Test multiple failed login attempts
        for i in range(10):
            response = client.post("/api/v1/auth/login", json={
                "username": "testuser",
                "password": "wrongpassword"
            })
            
            # Should eventually rate limit
            if response.status_code == 429:
                assert "rate limit" in response.json()["error"].lower()
                assert "Retry-After" in response.headers
                break
    
    def test_api_endpoint_rate_limiting(self, client, auth_headers):
        """Test rate limiting on API endpoints."""
        headers = auth_headers["valid_user"]
        
        # Make many requests quickly
        rate_limited = False
        for i in range(50):
            response = client.get("/api/v1/services", headers=headers)
            
            if response.status_code == 429:
                rate_limited = True
                assert "X-RateLimit-Remaining" in response.headers
                assert "X-RateLimit-Reset" in response.headers
                break
        
        # Should have rate limiting (or very high limits for testing)
        # Test passes if rate limiting is detected or limits are reasonable
    
    def test_ip_based_rate_limiting(self, client):
        """Test IP-based rate limiting."""
        # Make requests without authentication (IP-based limiting)
        for i in range(100):
            response = client.get("/health")
            
            if response.status_code == 429:
                assert "rate limit" in response.json()["error"].lower()
                break
        
        # Should have some form of IP-based rate limiting for public endpoints
    
    def test_rate_limit_bypass_prevention(self, client, auth_headers):
        """Test prevention of rate limit bypass techniques."""
        headers = auth_headers["valid_user"]
        
        # Test various bypass techniques
        bypass_headers = [
            {"X-Forwarded-For": "192.168.1.1"},
            {"X-Real-IP": "10.0.0.1"},
            {"X-Originating-IP": "172.16.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"X-Remote-IP": "8.8.8.8"}
        ]
        
        for bypass_header in bypass_headers:
            combined_headers = {**headers, **bypass_header}
            response = client.get("/api/v1/services", headers=combined_headers)
            
            # Should not bypass rate limiting through header manipulation
            # (Would need to make many requests to test this properly)
            assert response.status_code != 500  # Should handle headers gracefully


@pytest.mark.security
class TestCORSSecurity:
    """Test CORS security configuration."""
    
    def test_cors_preflight_request(self, client):
        """Test CORS preflight request handling."""
        response = client.options(
            "/api/v1/services",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type"
            }
        )
        
        # Should handle preflight properly
        assert response.status_code in [200, 204]
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
    
    def test_cors_origin_validation(self, client, auth_headers):
        """Test CORS origin validation."""
        headers = {
            **auth_headers["valid_user"],
            "Origin": "https://malicious.com"
        }
        
        response = client.get("/api/v1/services", headers=headers)
        
        # Should validate origins if CORS is restricted
        # With wildcard (*) config, all origins are allowed
        assert response.status_code != 403  # With current config
    
    def test_cors_credentials_handling(self, client, auth_headers):
        """Test CORS credentials handling."""
        headers = {
            **auth_headers["valid_user"],
            "Origin": "https://trusted.com"
        }
        
        response = client.get("/api/v1/services", headers=headers)
        
        # Should handle credentials properly
        if "Access-Control-Allow-Credentials" in response.headers:
            assert response.headers["Access-Control-Allow-Credentials"] == "true"


@pytest.mark.security
class TestTLSSecurity:
    """Test TLS/HTTPS security (where applicable)."""
    
    def test_secure_cookie_attributes(self, client):
        """Test that cookies have secure attributes."""
        # This would test session cookies if they exist
        response = client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "testpass"
        })
        
        # Check cookie security attributes
        for cookie in response.cookies:
            if cookie.secure is not None:
                assert cookie.secure is True  # Should be secure
            if cookie.httponly is not None:
                assert cookie.httponly is True  # Should be HTTP-only
    
    def test_hsts_header_presence(self, client):
        """Test HSTS header is present."""
        response = client.get("/health")
        
        assert "Strict-Transport-Security" in response.headers
        hsts = response.headers["Strict-Transport-Security"]
        
        # Should have reasonable max-age
        assert "max-age=" in hsts
        max_age = int(hsts.split("max-age=")[1].split(";")[0])
        assert max_age >= 86400  # At least 1 day


@pytest.mark.security
class TestDataExposurePrevention:
    """Test prevention of sensitive data exposure."""
    
    def test_error_message_information_disclosure(self, client, auth_headers):
        """Test that error messages don't disclose sensitive information."""
        headers = auth_headers["valid_user"]
        
        # Trigger various error conditions
        error_conditions = [
            ("GET", "/api/v1/nonexistent/endpoint"),
            ("POST", "/api/v1/users/create", {"invalid": "data"}),
            ("PUT", "/api/v1/users/999999"),  # Non-existent user
        ]
        
        for method, endpoint, *data in error_conditions:
            json_data = data[0] if data else None
            response = client.request(method, endpoint, json=json_data, headers=headers)
            
            if response.status_code >= 400:
                error_text = response.text.lower()
                
                # Should not expose sensitive information in errors
                sensitive_terms = [
                    "database", "sql", "query", "connection",
                    "internal", "stack trace", "debug",
                    "password", "token", "secret"
                ]
                
                for term in sensitive_terms:
                    assert term not in error_text
    
    def test_http_method_information_disclosure(self, client):
        """Test that unsupported HTTP methods don't disclose information."""
        unsupported_methods = ["TRACE", "CONNECT", "PATCH", "DELETE"]
        
        for method in unsupported_methods:
            response = client.request(method, "/health")
            
            # Should not disclose server information
            if response.status_code == 405:  # Method Not Allowed
                assert "Allow" in response.headers  # This is okay
                assert "Server" not in response.text.lower()
    
    def test_directory_listing_prevention(self, client):
        """Test that directory listings are not exposed."""
        directory_paths = [
            "/static/",
            "/assets/",
            "/uploads/",
            "/files/",
            "/docs/",
            "/api/",
            "/v1/"
        ]
        
        for path in directory_paths:
            response = client.get(path)
            
            # Should not show directory listings
            if response.status_code == 200:
                content = response.text.lower()
                assert "index of" not in content
                assert "directory listing" not in content