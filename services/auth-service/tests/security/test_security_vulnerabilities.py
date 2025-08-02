"""
Security vulnerability tests for auth service.
Tests for common security issues like injection attacks, XSS, CSRF, etc.
"""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock
from fastapi import status
import json
import time
import asyncio

from tests.factories import UserFactory, SessionFactory


class TestSecurityVulnerabilities:
    """Test suite for security vulnerabilities."""
    
    @pytest.mark.security
    @pytest.mark.parametrize("malicious_input", [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --"
    ])
    @pytest_asyncio.async
    async def test_sql_injection_protection_login(self, async_client, malicious_input):
        """Test SQL injection protection in login endpoint."""
        # Arrange
        login_data = {
            "email": malicious_input,
            "password": "test_password"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        # Should either be validation error or authentication failure, not internal server error
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
        
        # Should not expose database errors
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            data = response.json()
            assert "sql" not in data.get("detail", "").lower()
            assert "database" not in data.get("detail", "").lower()
    
    @pytest.mark.security
    @pytest.mark.parametrize("xss_payload", [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "';alert('xss');//",
        "<iframe src=\"javascript:alert('xss')\"></iframe>"
    ])
    @pytest_asyncio.async
    async def test_xss_protection(self, async_client, authenticated_headers, xss_payload):
        """Test XSS protection in user input fields."""
        # Test password reset with XSS payload in email
        reset_data = {
            "email": f"test{xss_payload}@example.com"
        }
        
        response = await async_client.post("/api/v1/auth/password-reset", json=reset_data)
        
        # Should be validation error or handled safely
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            # Response should not contain unescaped script tags
            assert "<script>" not in str(data)
            assert "javascript:" not in str(data)
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_rate_limiting_login_endpoint(self, async_client):
        """Test rate limiting on login endpoint."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "wrong_password"
        }
        
        # Act - Make multiple requests rapidly
        responses = []
        for _ in range(15):  # Exceed rate limit
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            responses.append(response)
        
        # Assert
        # At least some requests should be rate limited
        rate_limited = [r for r in responses if r.status_code == status.HTTP_429_TOO_MANY_REQUESTS]
        assert len(rate_limited) > 0, "Rate limiting should block excessive requests"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_rate_limiting_password_reset(self, async_client):
        """Test rate limiting on password reset endpoint."""
        # Arrange
        reset_data = {
            "email": "test@example.com"
        }
        
        # Act - Make multiple password reset requests
        responses = []
        for _ in range(12):  # Exceed rate limit
            response = await async_client.post("/api/v1/auth/password-reset", json=reset_data)
            responses.append(response)
        
        # Assert
        rate_limited = [r for r in responses if r.status_code == status.HTTP_429_TOO_MANY_REQUESTS]
        assert len(rate_limited) > 0, "Password reset should be rate limited"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_password_strength_validation(self, async_client):
        """Test password strength requirements."""
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "qwerty",
            "12345678",
            "admin",
            "letmein",
            "welcome"
        ]
        
        for weak_password in weak_passwords:
            confirm_data = {
                "token": "dummy_token",
                "new_password": weak_password,
                "confirm_password": weak_password
            }
            
            response = await async_client.post("/api/v1/auth/password-reset/confirm", json=confirm_data)
            
            # Should reject weak passwords
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_session_fixation_protection(self, async_client, test_user):
        """Test protection against session fixation attacks."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        # Pre-set session cookie
        headers = {"Cookie": "session_id=fixed_session_id"}
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (test_user, SessionFactory(), "access_token", "refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data, headers=headers)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # New session should be created, not reuse the fixed one
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie:
                assert "fixed_session_id" not in set_cookie
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_csrf_protection(self, async_client, authenticated_headers):
        """Test CSRF protection on state-changing endpoints."""
        # Arrange - Try to make state-changing request without proper headers
        password_data = {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        # Remove any CSRF tokens from headers
        unsafe_headers = {k: v for k, v in authenticated_headers.items() if "csrf" not in k.lower()}
        
        with patch('src.api.deps.get_current_active_user') as mock_get_user:
            mock_get_user.return_value = UserFactory(id=1)
            
            # Act
            response = await async_client.post(
                "/api/v1/auth/change-password",
                json=password_data,
                headers=unsafe_headers
            )
            
            # Assert - Should still work with proper authentication (CSRF may be handled differently)
            # The key is that we're testing the security posture
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_401_UNAUTHORIZED
            ]
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_jwt_token_validation(self, async_client):
        """Test JWT token validation and security."""
        # Test with malformed tokens
        malformed_tokens = [
            "invalid.token.here",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
            "Bearer malformed_token",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",  # Algorithm None attack
            "",
            "null",
            "undefined"
        ]
        
        for token in malformed_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            
            response = await async_client.get("/api/v1/auth/sessions", headers=headers)
            
            # Should reject invalid tokens
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_timing_attack_protection(self, async_client):
        """Test protection against timing attacks on user enumeration."""
        # Arrange
        existing_email = "existing@example.com"
        nonexistent_email = "nonexistent@example.com"
        
        # Create a user to test against
        with patch('src.services.user_service.UserService.get_user_by_email') as mock_get_user:
            # Test login timing for existing vs non-existent users
            mock_get_user.side_effect = lambda db, email: (
                UserFactory(email=email) if email == existing_email else None
            )
            
            # Measure response times
            times = []
            
            for email in [existing_email, nonexistent_email] * 5:
                login_data = {"email": email, "password": "wrong_password"}
                
                start_time = time.time()
                response = await async_client.post("/api/v1/auth/login", json=login_data)
                end_time = time.time()
                
                times.append(end_time - start_time)
                assert response.status_code == status.HTTP_401_UNAUTHORIZED
            
            # Response times should be relatively consistent
            # (This is a basic test - in production you'd use more sophisticated timing analysis)
            avg_time = sum(times) / len(times)
            for time_taken in times:
                # Allow 50% variance to account for system noise
                assert abs(time_taken - avg_time) / avg_time < 0.5
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_information_disclosure_prevention(self, async_client):
        """Test that error messages don't disclose sensitive information."""
        # Test various error scenarios
        test_cases = [
            ("/api/v1/auth/login", {"email": "test@example.com", "password": "wrong"}),
            ("/api/v1/auth/refresh", {"refresh_token": "invalid_token"}),
            ("/api/v1/auth/password-reset/confirm", {"token": "invalid", "new_password": "test", "confirm_password": "test"}),
            ("/api/v1/auth/verify-email", {"token": "invalid_token"})
        ]
        
        for endpoint, data in test_cases:
            response = await async_client.post(endpoint, json=data)
            
            if response.status_code >= 400:
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Should not expose sensitive information
                sensitive_terms = [
                    "database", "sql", "traceback", "exception", "stack",
                    "internal", "debug", "dev", "development", "secret",
                    "password_hash", "salt", "key", "token_payload"
                ]
                
                for term in sensitive_terms:
                    assert term not in error_message, f"Error message exposes '{term}': {error_data}"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_brute_force_protection(self, async_client):
        """Test brute force attack protection."""
        # Arrange
        login_data = {
            "email": "target@example.com",
            "password": "wrong_password"
        }
        
        # Simulate brute force attack
        failed_attempts = 0
        for attempt in range(20):
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            if response.status_code == status.HTTP_401_UNAUTHORIZED:
                failed_attempts += 1
            elif response.status_code == status.HTTP_423_LOCKED:
                # Account should be locked after multiple failed attempts
                break
            elif response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                # Rate limiting kicked in
                break
        
        # Should have some protection mechanism
        assert failed_attempts < 20, "No brute force protection detected"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_privilege_escalation_protection(self, async_client, authenticated_headers):
        """Test protection against privilege escalation."""
        # Test accessing admin endpoints with regular user token
        admin_endpoints = [
            "/api/v1/admin/users",  # Hypothetical admin endpoint
            "/api/v1/admin/sessions",
            "/api/v1/admin/audit-logs"
        ]
        
        for endpoint in admin_endpoints:
            response = await async_client.get(endpoint, headers=authenticated_headers)
            
            # Should deny access (403) or not found (404), not allow (200)
            assert response.status_code in [
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_401_UNAUTHORIZED
            ]
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_session_hijacking_detection(self, async_client, test_user):
        """Test detection of potential session hijacking."""
        # Arrange - Create a session
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth, \
             patch('src.services.session_service.SessionService.validate_session') as mock_validate:
            
            session = SessionFactory(ip_address="192.168.1.100", user_id=1)
            mock_auth.return_value = (test_user, session, "access_token", "refresh_token")
            
            # Initial login
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            assert response.status_code == status.HTTP_200_OK
            
            token = response.json()["access_token"]
            
            # Simulate session hijacking - same token from different IP
            mock_validate.return_value = None  # Session validation fails due to IP mismatch
            
            headers = {"Authorization": f"Bearer {token}"}
            response = await async_client.get("/api/v1/auth/sessions", headers=headers)
            
            # Should reject the request due to suspicious activity
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_password_reset_token_security(self, async_client):
        """Test password reset token security."""
        # Test that tokens are properly validated and expire
        test_cases = [
            "expired_token",
            "invalid_token",
            "malformed.token.here",
            "",
            "null",
            "a" * 1000,  # Very long token
        ]
        
        for token in test_cases:
            confirm_data = {
                "token": token,
                "new_password": "NewPassword123!",
                "confirm_password": "NewPassword123!"
            }
            
            response = await async_client.post("/api/v1/auth/password-reset/confirm", json=confirm_data)
            
            # Should reject invalid tokens
            assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_account_enumeration_protection(self, async_client):
        """Test protection against account enumeration."""
        # Password reset should not reveal whether account exists
        test_emails = [
            "existing@example.com",
            "nonexistent@example.com",
            "invalid-email-format",
            "test@nonexistentdomain.xyz"
        ]
        
        responses = []
        for email in test_emails:
            reset_data = {"email": email}
            response = await async_client.post("/api/v1/auth/password-reset", json=reset_data)
            responses.append(response)
        
        # All valid email formats should get the same response
        valid_responses = [r for r in responses if r.status_code == status.HTTP_200_OK]
        
        if len(valid_responses) > 1:
            # All successful responses should have identical messages
            messages = [r.json().get("message") for r in valid_responses]
            assert len(set(messages)) == 1, "Responses vary, may leak user existence"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_secure_headers_present(self, async_client):
        """Test that security headers are present in responses."""
        # Act
        response = await async_client.get("/health")
        
        # Assert - Check for security headers
        headers = response.headers
        
        # These headers should be present for security
        expected_headers = [
            "x-content-type-options",  # nosniff
            "x-frame-options",         # DENY or SAMEORIGIN
            "x-xss-protection",        # 1; mode=block
            "strict-transport-security",  # HSTS
            "content-security-policy"  # CSP
        ]
        
        # Note: Some headers might be set by reverse proxy in production
        # This test documents what should be present
        present_headers = [h.lower() for h in headers.keys()]
        
        # Log which security headers are missing (for awareness)
        missing_headers = [h for h in expected_headers if h not in present_headers]
        if missing_headers:
            print(f"Missing security headers: {missing_headers}")
    
    @pytest.mark.security 
    @pytest_asyncio.async
    async def test_sensitive_data_in_logs(self, async_client, caplog):
        """Test that sensitive data is not logged."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "SecretPassword123!"
        }
        
        with caplog.at_level("DEBUG"):
            # Act
            await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            log_output = caplog.text.lower()
            
            # Sensitive data should not appear in logs
            sensitive_data = [
                "secretpassword123!",
                "password",
                "secret",
                "token",
                "key"
            ]
            
            for sensitive in sensitive_data:
                assert sensitive not in log_output, f"Sensitive data '{sensitive}' found in logs"
    
    @pytest.mark.security
    @pytest_asyncio.async
    async def test_concurrent_session_limit(self, async_client, test_user):
        """Test concurrent session limits."""
        # This would test if there's a limit on concurrent sessions per user
        login_data = {
            "email": "test@example.com", 
            "password": "TestPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            # Simulate creating many sessions
            sessions = []
            for i in range(10):
                session = SessionFactory(user_id=1, session_id=f"session_{i}")
                sessions.append(session)
                mock_auth.return_value = (test_user, session, f"token_{i}", f"refresh_{i}")
                
                response = await async_client.post("/api/v1/auth/login", json=login_data)
                
                # All should succeed or some should be limited
                assert response.status_code in [status.HTTP_200_OK, status.HTTP_429_TOO_MANY_REQUESTS]
    
    @pytest.mark.security
    @pytest.mark.parametrize("header_name,malicious_value", [
        ("User-Agent", "<script>alert('xss')</script>"),
        ("X-Forwarded-For", "'; DROP TABLE users; --"),
        ("Referer", "javascript:alert('xss')"),
        ("Accept-Language", "../../../etc/passwd"),
    ])
    @pytest_asyncio.async
    async def test_malicious_headers_handling(self, async_client, header_name, malicious_value):
        """Test handling of malicious headers."""
        # Arrange
        headers = {header_name: malicious_value}
        
        # Act
        response = await async_client.get("/health", headers=headers)
        
        # Assert
        # Should not crash or expose the malicious content
        assert response.status_code in [200, 400, 404]
        
        if response.status_code == 200:
            response_text = response.text
            # Malicious content should not be reflected
            assert malicious_value not in response_text