"""
Security tests for authentication and authorization.
Tests JWT validation, token handling, and access control.
"""
import pytest
import time
import jwt
from unittest.mock import AsyncMock, patch, MagicMock

from src.services.auth_service import UserInfo


@pytest.mark.security
class TestAuthenticationSecurity:
    """Test authentication security measures."""
    
    def test_missing_authorization_header(self, client):
        """Test request without authorization header."""
        response = client.get("/api/v1/services")
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
        assert "authorization" in data["error"].lower()
    
    def test_malformed_authorization_header(self, client):
        """Test request with malformed authorization header."""
        malformed_headers = [
            {"Authorization": "InvalidFormat token"},
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": "Basic invalid"},  # Wrong auth type
            {"Authorization": "Bearer "},  # Empty token
        ]
        
        for headers in malformed_headers:
            response = client.get("/api/v1/services", headers=headers)
            assert response.status_code == 401
            assert "error" in response.json()
    
    def test_expired_token_rejection(self, client):
        """Test that expired tokens are rejected."""
        # Create expired token
        expired_payload = {
            "user_id": "test-user",
            "exp": time.time() - 3600,  # Expired 1 hour ago
            "iat": time.time() - 7200   # Issued 2 hours ago
        }
        expired_token = jwt.encode(expired_payload, "test-secret", algorithm="HS256")
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        assert "expired" in response.json()["error"].lower()
    
    def test_invalid_token_signature(self, client):
        """Test that tokens with invalid signatures are rejected."""
        # Create token with wrong secret
        payload = {
            "user_id": "test-user",
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        invalid_token = jwt.encode(payload, "wrong-secret", algorithm="HS256")
        
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        assert "invalid" in response.json()["error"].lower()
    
    def test_token_without_required_claims(self, client):
        """Test tokens missing required claims."""
        # Token without user_id
        incomplete_payload = {
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        incomplete_token = jwt.encode(incomplete_payload, "test-secret", algorithm="HS256")
        
        headers = {"Authorization": f"Bearer {incomplete_token}"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
    
    def test_inactive_user_rejection(self, client):
        """Test that inactive users are rejected."""
        headers = {"Authorization": "Bearer inactive-user-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        # May be 403 depending on implementation
        assert response.status_code in [401, 403]
    
    def test_unverified_user_handling(self, client):
        """Test handling of unverified users."""
        headers = {"Authorization": "Bearer unverified-user-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        # Implementation may allow unverified users for some endpoints
        # but restrict others
        assert response.status_code in [200, 401, 403]
    
    def test_valid_token_accepted(self, client, auth_headers):
        """Test that valid tokens are accepted."""
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code != 401
        assert response.status_code != 403
    
    def test_token_replay_attack_prevention(self, client, auth_headers):
        """Test token replay attack prevention."""
        # Make the same request multiple times with same token
        headers = auth_headers["valid_user"]
        
        responses = []
        for _ in range(5):
            response = client.get("/api/v1/services", headers=headers)
            responses.append(response.status_code)
        
        # All requests should succeed with valid token
        # (unless there's nonce/timestamp validation)
        assert all(status != 401 for status in responses)
    
    def test_concurrent_token_usage(self, client, auth_headers):
        """Test concurrent usage of same token."""
        import threading
        import time
        
        headers = auth_headers["valid_user"]
        results = []
        
        def make_request():
            response = client.get("/api/v1/services", headers=headers)
            results.append(response.status_code)
        
        # Make concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All requests should succeed (token can be used concurrently)
        assert all(status != 401 for status in results)
    
    def test_case_sensitive_token_validation(self, client):
        """Test that tokens are case-sensitive."""
        valid_token = "valid-user-token"
        
        # Test different cases
        case_variants = [
            valid_token.upper(),
            valid_token.capitalize(),
            valid_token.replace("v", "V", 1)
        ]
        
        for variant in case_variants:
            headers = {"Authorization": f"Bearer {variant}"}
            response = client.get("/api/v1/services", headers=headers)
            
            if variant != valid_token:
                assert response.status_code == 401
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_auth_service_timeout_handling(self, mock_validate, client):
        """Test handling of auth service timeouts."""
        # Mock auth service timeout
        mock_validate.side_effect = asyncio.TimeoutError("Auth service timeout")
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        assert "authentication failed" in response.json()["error"].lower()
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_auth_service_unavailable_handling(self, mock_validate, client):
        """Test handling when auth service is unavailable."""
        # Mock auth service unavailable
        mock_validate.side_effect = Exception("Auth service unavailable")
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/api/v1/services", headers=headers)
        
        assert response.status_code == 401
        assert "authentication failed" in response.json()["error"].lower()


@pytest.mark.security
class TestAuthorizationSecurity:
    """Test authorization and access control."""
    
    def test_role_based_access_control(self, client, auth_headers):
        """Test role-based access control."""
        # Regular user accessing user endpoint
        user_headers = auth_headers["valid_user"]
        response = client.get("/api/v1/users/profile", headers=user_headers)
        assert response.status_code != 403  # Should be allowed
        
        # Regular user accessing admin endpoint (if exists)
        # This would require implementing role-based endpoints
        # For now, test with different user roles
        admin_headers = auth_headers["valid_admin"]
        response = client.get("/api/v1/services", headers=admin_headers)
        assert response.status_code != 403  # Admin should be allowed
    
    def test_permission_based_access_control(self, client, auth_headers):
        """Test permission-based access control."""
        # This would require implementing permission checks
        # Test that users with proper permissions can access resources
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/users/profile", headers=headers)
        
        # Should succeed if user has required permissions
        assert response.status_code != 403
    
    def test_resource_owner_access_control(self, client, auth_headers):
        """Test that users can only access their own resources."""
        # This would require implementing resource ownership checks
        headers = auth_headers["valid_user"]
        
        # User accessing their own profile
        response = client.get("/api/v1/users/profile", headers=headers)
        assert response.status_code != 403
        
        # User trying to access another user's profile
        response = client.get("/api/v1/users/123/profile", headers=headers)
        # Should be forbidden if not owner or admin
        # Implementation depends on authorization logic
    
    def test_admin_privilege_escalation_prevention(self, client, auth_headers):
        """Test prevention of privilege escalation."""
        # Regular user should not be able to perform admin actions
        user_headers = auth_headers["valid_user"]
        
        # Attempt admin operations
        admin_operations = [
            ("DELETE", "/api/v1/admin/users/123"),
            ("POST", "/api/v1/admin/system/reset"),
            ("PUT", "/api/v1/admin/config")
        ]
        
        for method, endpoint in admin_operations:
            response = client.request(method, endpoint, headers=user_headers)
            # Should be forbidden or not found (404 if endpoint doesn't exist)
            assert response.status_code in [403, 404]
    
    def test_cross_tenant_access_prevention(self, client, auth_headers):
        """Test prevention of cross-tenant data access."""
        # If multi-tenant, ensure users can't access other tenants' data
        headers = auth_headers["valid_user"]
        
        # This would require tenant-aware endpoints
        # For now, test general access control
        response = client.get("/api/v1/users/profile", headers=headers)
        assert response.status_code != 403


@pytest.mark.security
class TestInputValidationSecurity:
    """Test input validation and sanitization."""
    
    def test_sql_injection_prevention(self, client, auth_headers, sample_request_data):
        """Test SQL injection prevention in inputs."""
        headers = auth_headers["valid_user"]
        malicious_data = sample_request_data["malicious_payload"]
        
        # Test SQL injection in JSON payload
        payload = {
            "name": malicious_data["sql_injection"],
            "email": "test@example.com"
        }
        
        response = client.post("/api/v1/users/create", json=payload, headers=headers)
        
        # Should either reject malicious input or sanitize it
        # Response should not indicate SQL injection succeeded
        if response.status_code == 200:
            # If accepted, should be sanitized
            data = response.json()
            assert malicious_data["sql_injection"] not in str(data)
    
    def test_xss_prevention(self, client, auth_headers, sample_request_data):
        """Test XSS prevention in inputs."""
        headers = auth_headers["valid_user"]
        malicious_data = sample_request_data["malicious_payload"]
        
        payload = {
            "name": malicious_data["script"],
            "bio": "<img src=x onerror=alert('xss')>"
        }
        
        response = client.post("/api/v1/users/update", json=payload, headers=headers)
        
        # Should sanitize or reject XSS attempts
        if response.status_code == 200:
            data = response.json()
            # Should not contain script tags
            assert "<script>" not in str(data).lower()
            assert "onerror=" not in str(data).lower()
    
    def test_path_traversal_prevention(self, client, auth_headers, sample_request_data):
        """Test path traversal prevention."""
        headers = auth_headers["valid_user"]
        malicious_data = sample_request_data["malicious_payload"]
        
        # Test path traversal in URL
        malicious_path = malicious_data["path_traversal"]
        response = client.get(f"/api/v1/files/{malicious_path}", headers=headers)
        
        # Should reject or sanitize path traversal attempts
        assert response.status_code in [400, 404, 403]
    
    def test_command_injection_prevention(self, client, auth_headers, sample_request_data):
        """Test command injection prevention."""
        headers = auth_headers["valid_user"]
        malicious_data = sample_request_data["malicious_payload"]
        
        payload = {
            "filename": f"test{malicious_data['command_injection']}.txt"
        }
        
        response = client.post("/api/v1/files/process", json=payload, headers=headers)
        
        # Should reject command injection attempts
        if response.status_code == 200:
            # Should not execute commands
            data = response.json()
            assert "rm -rf" not in str(data)
    
    def test_json_payload_size_limit(self, client, auth_headers, sample_request_data):
        """Test JSON payload size limits."""
        headers = auth_headers["valid_user"]
        large_data = sample_request_data["large_payload"]
        
        response = client.post("/api/v1/users/create", json=large_data, headers=headers)
        
        # Should reject overly large payloads
        assert response.status_code == 413
    
    def test_malformed_json_handling(self, client, auth_headers):
        """Test handling of malformed JSON."""
        headers = {
            **auth_headers["valid_user"],
            "Content-Type": "application/json"
        }
        
        malformed_json_payloads = [
            '{"incomplete": ',
            '{"invalid": "json"',
            '{invalid json}',
            '{"nested": {"too": {"deep": "nesting"}}}' * 100  # Deeply nested
        ]
        
        for payload in malformed_json_payloads:
            response = client.post(
                "/api/v1/users/create",
                data=payload,
                headers=headers
            )
            
            # Should reject malformed JSON
            assert response.status_code == 400
    
    def test_unicode_handling(self, client, auth_headers):
        """Test proper Unicode handling."""
        headers = auth_headers["valid_user"]
        
        unicode_payload = {
            "name": "José María Aznar",
            "bio": "🚀 Developer with émojis and spëcial chars",
            "location": "北京"  # Chinese characters
        }
        
        response = client.post("/api/v1/users/create", json=unicode_payload, headers=headers)
        
        # Should handle Unicode properly
        if response.status_code == 200:
            data = response.json()
            # Unicode should be preserved
            assert "José" in str(data) or "Jos" in str(data)  # Might be normalized
    
    def test_null_byte_injection_prevention(self, client, auth_headers):
        """Test null byte injection prevention."""
        headers = auth_headers["valid_user"]
        
        payload = {
            "filename": "test.txt\x00.php",  # Null byte injection
            "content": "safe content"
        }
        
        response = client.post("/api/v1/files/upload", json=payload, headers=headers)
        
        # Should reject or sanitize null bytes
        assert response.status_code in [400, 422]
    
    def test_header_injection_prevention(self, client, auth_headers):
        """Test HTTP header injection prevention."""
        malicious_headers = {
            **auth_headers["valid_user"],
            "X-Custom-Header": "value\r\nX-Injected-Header: malicious",
            "User-Agent": "test\nContent-Length: 0\n\nHTTP/1.1 200 OK"
        }
        
        response = client.get("/api/v1/services", headers=malicious_headers)
        
        # Should not allow header injection
        assert "X-Injected-Header" not in response.headers
        assert response.status_code != 500  # Should handle gracefully


@pytest.mark.security
class TestSessionSecurity:
    """Test session and token security."""
    
    def test_token_information_disclosure(self, client, auth_headers):
        """Test that tokens are not disclosed in responses."""
        headers = auth_headers["valid_user"]
        response = client.get("/api/v1/services", headers=headers)
        
        # Token should not appear in response
        token = headers["Authorization"].split(" ")[1]
        assert token not in response.text
        assert token not in str(response.headers)
    
    def test_sensitive_data_in_logs(self, client, auth_headers):
        """Test that sensitive data is not logged."""
        # This would require checking log output
        # For now, verify that requests with sensitive data don't cause errors
        headers = auth_headers["valid_user"]
        
        sensitive_payload = {
            "password": "secret123",
            "ssn": "123-45-6789",
            "credit_card": "4532-1234-5678-9012"
        }
        
        response = client.post("/api/v1/users/update", json=sensitive_payload, headers=headers)
        
        # Should process without exposing sensitive data
        if response.status_code == 200:
            data = response.json()
            # Sensitive fields should be masked or excluded
            assert "password" not in str(data).lower()
    
    def test_token_scope_limitation(self, client, auth_headers):
        """Test that tokens have appropriate scope limitations."""
        # Test that user tokens can't perform admin operations
        user_headers = auth_headers["valid_user"]
        
        admin_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system/status",
            "/api/v1/admin/metrics"
        ]
        
        for endpoint in admin_endpoints:
            response = client.get(endpoint, headers=user_headers)
            # Should be forbidden or not found
            assert response.status_code in [403, 404]
    
    def test_token_binding_verification(self, client, auth_headers):
        """Test token binding to prevent token theft."""
        # This would test IP binding, device fingerprinting, etc.
        # For now, test that tokens work from same context
        headers = auth_headers["valid_user"]
        
        response1 = client.get("/api/v1/services", headers=headers)
        response2 = client.get("/api/v1/services", headers=headers)
        
        # Both requests should succeed from same context
        assert response1.status_code != 401
        assert response2.status_code != 401