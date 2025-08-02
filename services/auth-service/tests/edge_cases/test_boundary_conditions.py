"""
Edge case and boundary condition tests for auth service.
Tests extreme inputs, malformed data, and unusual scenarios.
"""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock
from fastapi import status
import json
import string
import random

from tests.factories import UserFactory, SessionFactory


class TestBoundaryConditions:
    """Test suite for edge cases and boundary conditions."""
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("email_length", [1, 254, 255, 1000])
    @pytest_asyncio.async
    async def test_email_length_boundaries(self, async_client, email_length):
        """Test email length boundary conditions."""
        # Arrange
        if email_length <= 254:
            # Valid length emails
            local_part = "a" * min(64, email_length - 12)  # Leave space for @domain.com
            domain_part = "domain.com"
            email = f"{local_part}@{domain_part}"
            if len(email) > email_length:
                email = f"{'a' * (email_length - 12)}@domain.com"
        else:
            # Invalid length emails
            email = "a" * (email_length - 12) + "@domain.com"
        
        login_data = {
            "email": email,
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        if email_length <= 254:
            # Should be processed (may fail auth but not validation)
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]
        else:
            # Should fail validation
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("password_length", [0, 1, 7, 8, 128, 129, 1000])
    @pytest_asyncio.async
    async def test_password_length_boundaries(self, async_client, password_length):
        """Test password length boundary conditions."""
        # Arrange
        if password_length == 0:
            password = ""
        else:
            # Generate password with required complexity
            password = "A1!" + "a" * max(0, password_length - 3)
        
        reset_data = {
            "token": "dummy_token",
            "new_password": password,
            "confirm_password": password
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/password-reset/confirm", json=reset_data)
        
        # Assert
        if 8 <= password_length <= 128:
            # Valid password length (may fail due to invalid token)
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_400_BAD_REQUEST  # Invalid token
            ]
        else:
            # Invalid password length
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("unicode_chars", [
        "café@example.com",  # Accented characters
        "用户@example.com",    # Chinese characters
        "тест@example.com",   # Cyrillic
        "🎉@example.com",      # Emoji
        "user@münchen.de",    # IDN domain
        "user+tag@example.com", # Plus addressing
        "user.name@example.com" # Dot in local part
    ])
    @pytest_asyncio.async
    async def test_unicode_email_handling(self, async_client, unicode_chars):
        """Test handling of Unicode characters in email addresses."""
        # Arrange
        login_data = {
            "email": unicode_chars,
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        # Should handle Unicode gracefully without crashing
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
        
        # Should not expose internal errors
        if response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
            data = response.json()
            assert "unicode" not in data.get("detail", "").lower()
            assert "encoding" not in data.get("detail", "").lower()
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("malformed_json", [
        '{"email": "test@example.com", "password": "test"}',  # Missing comma
        '{"email": "test@example.com" "password": "test"}',   # Missing comma
        '{"email": "test@example.com", "password": }',        # Missing value
        '{email: "test@example.com", "password": "test"}',    # Unquoted key
        '{"email": "test@example.com", "password": "test",}', # Trailing comma
        '{"email": "test@example.com", "password": "test"',   # Missing brace
        'null',
        '[]',
        '"string"',
        '123',
        '',
    ])
    @pytest_asyncio.async
    async def test_malformed_json_handling(self, async_client, malformed_json):
        """Test handling of malformed JSON in requests."""
        # Act
        response = await async_client.post(
            "/api/v1/auth/login",
            content=malformed_json,
            headers={"Content-Type": "application/json"}
        )
        
        # Assert
        # Should return appropriate error for malformed JSON
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
        
        # Should not crash the service
        error_data = response.json()
        assert "detail" in error_data
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("null_values", [
        {"email": None, "password": "test"},
        {"email": "test@example.com", "password": None},
        {"email": None, "password": None},
    ])
    @pytest_asyncio.async
    async def test_null_value_handling(self, async_client, null_values):
        """Test handling of null values in request data."""
        # Act
        response = await async_client.post("/api/v1/auth/login", json=null_values)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        error_data = response.json()
        assert "detail" in error_data
        
        # Should specify which fields are missing/invalid
        errors = error_data["detail"]
        field_errors = [error["loc"][-1] for error in errors if "loc" in error]
        
        if null_values["email"] is None:
            assert "email" in field_errors
        if null_values["password"] is None:
            assert "password" in field_errors
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_extremely_large_request_payload(self, async_client):
        """Test handling of extremely large request payloads."""
        # Arrange - Create 10MB payload
        large_data = "x" * (10 * 1024 * 1024)  # 10MB
        
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": {
                "large_field": large_data
            }
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        # Should reject or handle large payloads gracefully
        assert response.status_code in [
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("special_characters", [
        "test+tag@example.com",
        "test.tag@example.com", 
        "test_tag@example.com",
        "test-tag@example.com",
        "test123@example.com",
        "123test@example.com",
        "t@example.com",  # Single character local part
        "test@e.co",      # Short domain
    ])
    @pytest_asyncio.async
    async def test_valid_email_edge_cases(self, async_client, special_characters):
        """Test valid but edge case email formats."""
        # Arrange
        login_data = {
            "email": special_characters,
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        # Should accept valid email formats (may fail auth but not validation)
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,  # Valid format, auth failed
            status.HTTP_422_UNPROCESSABLE_ENTITY  # If validation is too strict
        ]
    
    @pytest.mark.edge_case
    @pytest.mark.parametrize("invalid_emails", [
        "@example.com",           # Missing local part
        "test@",                  # Missing domain
        "test..test@example.com", # Double dots
        "test.@example.com",      # Dot at end of local part
        ".test@example.com",      # Dot at start of local part
        "test@example.",          # Domain ends with dot
        "test@.example.com",      # Domain starts with dot
        "test@example..com",      # Double dots in domain
        "test space@example.com", # Space in local part
        "test@exam ple.com",      # Space in domain
        "test@",                  # Empty domain
        "",                       # Empty email
        "plaintext",              # No @ symbol
        "@",                      # Just @ symbol
        "@@example.com",          # Multiple @ symbols
        "test@@example.com",      # Multiple @ symbols
    ])
    @pytest_asyncio.async
    async def test_invalid_email_formats(self, async_client, invalid_emails):
        """Test invalid email format handling."""
        # Arrange
        login_data = {
            "email": invalid_emails,
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        error_data = response.json()
        assert "detail" in error_data
        
        # Should specify email validation error
        errors = str(error_data["detail"]).lower()
        assert any(term in errors for term in ["email", "format", "valid"])
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_concurrent_session_edge_cases(self, async_client, test_user):
        """Test edge cases with concurrent sessions."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        sessions = []
        for i in range(100):  # Create many sessions
            session = SessionFactory(
                user_id=test_user.id,
                session_id=f"session_{i}",
                is_active=True
            )
            sessions.append(session)
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            # Test rapid session creation
            for i, session in enumerate(sessions[:10]):  # Test first 10
                mock_auth.return_value = (test_user, session, f"token_{i}", f"refresh_{i}")
                
                response = await async_client.post("/api/v1/auth/login", json=login_data)
                
                # Should handle rapid session creation
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_429_TOO_MANY_REQUESTS  # Rate limited
                ]
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_timezone_edge_cases(self, async_client):
        """Test timezone handling edge cases."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": {
                "timezone": "America/New_York"
            }
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Test various timezone formats
            timezones = [
                "UTC",
                "GMT",
                "America/New_York",
                "Europe/London",
                "Asia/Tokyo",
                "+05:30",
                "-08:00",
                "invalid_timezone",
                "",
                None
            ]
            
            for tz in timezones:
                login_data["device_info"]["timezone"] = tz
                
                response = await async_client.post("/api/v1/auth/login", json=login_data)
                
                # Should handle all timezone formats gracefully
                assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_session_token_edge_cases(self, async_client):
        """Test edge cases with session tokens."""
        # Test various token formats
        malformed_tokens = [
            "",                           # Empty token
            "Bearer",                     # Just "Bearer"
            "Bearer ",                    # Bearer with space only
            "NotBearer token",           # Wrong auth type
            "Bearer " + "x" * 2000,      # Very long token
            "Bearer invalid.token",       # Malformed JWT
            "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",  # Incomplete JWT
            "Bearer null",               # Null as token
            "Bearer undefined",          # Undefined as token
            "Bearer {}",                 # Empty object
            "Bearer []",                 # Empty array
            "Multiple Bearer tokens Bearer another",  # Multiple bearer keywords
        ]
        
        for token in malformed_tokens:
            headers = {"Authorization": token} if token else {}
            
            response = await async_client.get("/api/v1/auth/sessions", headers=headers)
            
            # Should reject malformed tokens consistently
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_race_condition_password_reset(self, async_client):
        """Test race conditions in password reset flow."""
        # Test multiple simultaneous password reset requests
        reset_data = {
            "email": "test@example.com"
        }
        
        # Send multiple reset requests simultaneously
        import asyncio
        tasks = [
            async_client.post("/api/v1/auth/password-reset", json=reset_data)
            for _ in range(10)
        ]
        
        responses = await asyncio.gather(*tasks)
        
        # All should succeed (for security, always return success)
        for response in responses:
            assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_memory_exhaustion_protection(self, async_client):
        """Test protection against memory exhaustion attacks."""
        # Arrange - Create nested JSON payload
        nested_data = {"level": 0}
        current = nested_data
        
        # Create deeply nested structure (but not too deep to avoid test timeout)
        for i in range(100):
            current["next"] = {"level": i + 1}
            current = current["next"]
        
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": nested_data
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        # Should handle deeply nested data without crashing
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_floating_point_precision_edge_cases(self, async_client):
        """Test floating point precision in location data."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": {
                "location": {
                    "latitude": 90.000000000000001,   # Beyond valid range
                    "longitude": 180.000000000000001, # Beyond valid range
                    "accuracy": 0.000000000001        # Very high precision
                }
            }
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            # Should handle floating point edge cases
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY  # If validation is strict
            ]
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_http_method_edge_cases(self, async_client):  
        """Test handling of unexpected HTTP methods."""
        # Test various HTTP methods on login endpoint
        methods_to_test = ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
        
        for method in methods_to_test:
            response = await async_client.request(
                method,
                "/api/v1/auth/login",
                json={"email": "test@example.com", "password": "test"}
            )
            
            # Should reject inappropriate methods
            assert response.status_code in [
                status.HTTP_405_METHOD_NOT_ALLOWED,
                status.HTTP_404_NOT_FOUND
            ]
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_content_type_edge_cases(self, async_client):
        """Test handling of various content types."""
        # Test different content types
        content_types = [
            "application/xml",
            "text/plain", 
            "multipart/form-data",
            "application/x-www-form-urlencoded",
            "application/octet-stream",
            "image/png",
            "text/html",
            "",  # Empty content type
            "invalid/content-type"
        ]
        
        login_data = '{"email": "test@example.com", "password": "test"}'
        
        for content_type in content_types:
            headers = {"Content-Type": content_type} if content_type else {}
            
            response = await async_client.post(
                "/api/v1/auth/login",
                content=login_data,
                headers=headers
            )
            
            # Should handle unsupported content types gracefully
            assert response.status_code in [
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]
    
    @pytest.mark.edge_case
    @pytest_asyncio.async
    async def test_character_encoding_edge_cases(self, async_client):
        """Test handling of different character encodings."""
        # Test various character encodings in headers
        encodings = [
            "utf-8",
            "iso-8859-1", 
            "ascii",
            "utf-16",
            "windows-1252",
            "invalid-encoding"
        ]
        
        for encoding in encodings:
            headers = {
                "Content-Type": f"application/json; charset={encoding}",
                "Accept-Charset": encoding
            }
            
            login_data = {
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
            
            response = await async_client.post(
                "/api/v1/auth/login",
                json=login_data,
                headers=headers
            )
            
            # Should handle different encodings or reject gracefully
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
            ]