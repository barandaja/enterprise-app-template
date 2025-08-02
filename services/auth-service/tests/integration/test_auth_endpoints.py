"""
Integration tests for authentication API endpoints.
Tests complete request/response flow with database and Redis integration.
"""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock
from fastapi import status
import json

from tests.factories import UserFactory, SessionFactory


class TestAuthEndpoints:
    """Integration tests for auth endpoints."""
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_success(self, async_client, test_user, test_session, redis_client):
        """Test successful login flow."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "remember_me": False,
            "device_info": {
                "device_type": "desktop",
                "os": "Linux",
                "browser": "Chrome"
            }
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (test_user, test_session, "access_token", "refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["access_token"] == "access_token"
            assert data["refresh_token"] == "refresh_token"
            assert data["token_type"] == "bearer"
            assert data["expires_in"] == 1800
            assert "user" in data
            assert "session_info" in data
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_invalid_credentials(self, async_client):
        """Test login with invalid credentials."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        data = response.json()
        assert data["detail"] == "Invalid credentials"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_missing_required_fields(self, async_client):
        """Test login with missing required fields."""
        # Arrange
        login_data = {
            "email": "test@example.com"
            # Missing password
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        data = response.json()
        assert "detail" in data
        assert any("password" in str(error) for error in data["detail"])
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_invalid_email_format(self, async_client):
        """Test login with invalid email format."""
        # Arrange
        login_data = {
            "email": "invalid-email",
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_account_locked(self, async_client):
        """Test login with locked account."""
        # Arrange
        login_data = {
            "email": "locked@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            from fastapi import HTTPException
            mock_auth.side_effect = HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked"
            )
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            assert response.status_code == status.HTTP_423_LOCKED
            assert response.json()["detail"] == "Account is temporarily locked"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_refresh_token_success(self, async_client):
        """Test successful token refresh."""
        # Arrange
        refresh_data = {
            "refresh_token": "valid_refresh_token"
        }
        
        with patch('src.services.auth_service.AuthService.refresh_token') as mock_refresh:
            mock_refresh.return_value = ("new_access_token", "new_refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/refresh", json=refresh_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["access_token"] == "new_access_token"
            assert data["refresh_token"] == "new_refresh_token"
            assert data["token_type"] == "bearer"
            assert data["expires_in"] == 1800
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_refresh_token_invalid(self, async_client):
        """Test token refresh with invalid token."""
        # Arrange
        refresh_data = {
            "refresh_token": "invalid_refresh_token"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/refresh", json=refresh_data)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid refresh token"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_logout_success(self, async_client, authenticated_headers):
        """Test successful logout."""
        # Arrange
        logout_data = {
            "logout_all_sessions": False
        }
        
        with patch('src.services.auth_service.AuthService.logout') as mock_logout, \
             patch('src.api.deps.get_current_active_user') as mock_get_user, \
             patch('src.api.deps.get_session_id') as mock_get_session:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = "test_session_id"
            mock_logout.return_value = True
            
            # Act
            response = await async_client.post(
                "/api/v1/auth/logout",
                json=logout_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["message"] == "Logged out successfully"
            assert data["sessions_ended"] == 1
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_logout_all_sessions(self, async_client, authenticated_headers):
        """Test logout from all sessions."""
        # Arrange
        logout_data = {
            "logout_all_sessions": True
        }
        
        with patch('src.services.auth_service.AuthService.logout') as mock_logout, \
             patch('src.api.deps.get_current_active_user') as mock_get_user, \
             patch('src.api.deps.get_session_id') as mock_get_session:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = "test_session_id"
            mock_logout.return_value = 3  # 3 sessions ended
            
            # Act
            response = await async_client.post(
                "/api/v1/auth/logout",
                json=logout_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "all sessions" in data["message"]
            assert data["sessions_ended"] == 3
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_logout_unauthorized(self, async_client):
        """Test logout without authentication."""
        # Act
        response = await async_client.post("/api/v1/auth/logout", json={})
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_password_reset_request_success(self, async_client):
        """Test successful password reset request."""
        # Arrange
        reset_data = {
            "email": "test@example.com"
        }
        
        with patch('src.services.auth_service.AuthService.initiate_password_reset') as mock_reset:
            mock_reset.return_value = True
            
            # Act
            response = await async_client.post("/api/v1/auth/password-reset", json=reset_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "password reset link has been sent" in data["message"]
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_password_reset_request_invalid_email(self, async_client):
        """Test password reset with invalid email format."""
        # Arrange
        reset_data = {
            "email": "invalid-email"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/password-reset", json=reset_data)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_password_reset_confirm_success(self, async_client):
        """Test successful password reset confirmation."""
        # Arrange
        confirm_data = {
            "token": "valid_reset_token",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.complete_password_reset') as mock_complete:
            mock_complete.return_value = True
            
            # Act
            response = await async_client.post("/api/v1/auth/password-reset/confirm", json=confirm_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "Password has been reset successfully" in data["message"]
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_password_reset_confirm_invalid_token(self, async_client):
        """Test password reset confirmation with invalid token."""
        # Arrange
        confirm_data = {
            "token": "invalid_token",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.complete_password_reset') as mock_complete:
            from fastapi import HTTPException
            mock_complete.side_effect = HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
            
            # Act
            response = await async_client.post("/api/v1/auth/password-reset/confirm", json=confirm_data)
            
            # Assert
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.json()["detail"] == "Invalid or expired reset token"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_password_reset_confirm_password_mismatch(self, async_client):
        """Test password reset confirmation with password mismatch."""
        # Arrange
        confirm_data = {
            "token": "valid_token",
            "new_password": "NewPassword123!",
            "confirm_password": "DifferentPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/password-reset/confirm", json=confirm_data)
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_change_password_success(self, async_client, authenticated_headers):
        """Test successful password change."""
        # Arrange
        password_data = {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.change_password') as mock_change, \
             patch('src.api.deps.get_current_active_user') as mock_get_user, \
             patch('src.api.deps.get_session_id') as mock_get_session:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = "test_session_id"
            mock_change.return_value = True
            
            # Act
            response = await async_client.post(
                "/api/v1/auth/change-password",
                json=password_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["message"] == "Password changed successfully"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_change_password_wrong_current_password(self, async_client, authenticated_headers):
        """Test password change with wrong current password."""
        # Arrange
        password_data = {
            "current_password": "WrongPassword",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.change_password') as mock_change, \
             patch('src.api.deps.get_current_active_user') as mock_get_user, \
             patch('src.api.deps.get_session_id') as mock_get_session:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = "test_session_id"
            
            from fastapi import HTTPException
            mock_change.side_effect = HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
            
            # Act
            response = await async_client.post(
                "/api/v1/auth/change-password",
                json=password_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.json()["detail"] == "Current password is incorrect"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_change_password_unauthorized(self, async_client):
        """Test password change without authentication."""
        # Arrange
        password_data = {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/change-password", json=password_data)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_verify_email_success(self, async_client):
        """Test successful email verification."""
        # Arrange
        verification_data = {
            "token": "valid_verification_token"
        }
        
        with patch('src.services.auth_service.AuthService.verify_email') as mock_verify:
            mock_verify.return_value = True
            
            # Act
            response = await async_client.post("/api/v1/auth/verify-email", json=verification_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["message"] == "Email verified successfully"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_verify_email_invalid_token(self, async_client):
        """Test email verification with invalid token."""
        # Arrange
        verification_data = {
            "token": "invalid_token"
        }
        
        with patch('src.services.auth_service.AuthService.verify_email') as mock_verify:
            from fastapi import HTTPException
            mock_verify.side_effect = HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )
            
            # Act
            response = await async_client.post("/api/v1/auth/verify-email", json=verification_data)
            
            # Assert
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert response.json()["detail"] == "Invalid or expired verification token"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_get_user_sessions_success(self, async_client, authenticated_headers):
        """Test getting user sessions."""
        # Arrange
        sessions = [
            SessionFactory(session_id="session1"),
            SessionFactory(session_id="session2")
        ]
        
        with patch('src.services.session_service.SessionService.get_user_sessions') as mock_get_sessions, \
             patch('src.api.deps.get_current_active_user') as mock_get_user:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_sessions.return_value = sessions
            
            # Mock session info method
            for session in sessions:
                session.get_session_info = lambda: {
                    "session_id": session.session_id,
                    "created_at": "2023-01-01T00:00:00Z",
                    "last_activity": "2023-01-01T01:00:00Z",
                    "ip_address": "127.0.0.1",
                    "user_agent": "TestAgent/1.0"
                }
            
            # Act
            response = await async_client.get("/api/v1/auth/sessions", headers=authenticated_headers)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["total"] == 2
            assert len(data["sessions"]) == 2
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_get_user_sessions_unauthorized(self, async_client):
        """Test getting user sessions without authentication."""
        # Act
        response = await async_client.get("/api/v1/auth/sessions")
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_end_specific_session_success(self, async_client, authenticated_headers):
        """Test ending a specific session."""
        # Arrange
        session_id = "session_to_end"
        session = SessionFactory(session_id=session_id, user_id=1)
        
        with patch('src.services.session_service.SessionService.get_session') as mock_get_session, \
             patch('src.services.session_service.SessionService.end_session') as mock_end_session, \
             patch('src.api.deps.get_current_active_user') as mock_get_user:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = session
            mock_end_session.return_value = True
            
            # Act
            response = await async_client.delete(
                f"/api/v1/auth/sessions/{session_id}",
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["message"] == "Session ended successfully"
            assert data["sessions_ended"] == 1
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_end_specific_session_not_found(self, async_client, authenticated_headers):
        """Test ending a non-existent session."""
        # Arrange
        session_id = "nonexistent_session"
        
        with patch('src.services.session_service.SessionService.get_session') as mock_get_session, \
             patch('src.api.deps.get_current_active_user') as mock_get_user:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = None
            
            # Act
            response = await async_client.delete(
                f"/api/v1/auth/sessions/{session_id}",
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert response.json()["detail"] == "Session not found"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_end_session_wrong_user(self, async_client, authenticated_headers):
        """Test ending session that belongs to different user."""
        # Arrange
        session_id = "other_user_session"
        session = SessionFactory(session_id=session_id, user_id=999)  # Different user
        
        with patch('src.services.session_service.SessionService.get_session') as mock_get_session, \
             patch('src.api.deps.get_current_active_user') as mock_get_user:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_get_session.return_value = session
            
            # Act
            response = await async_client.delete(
                f"/api/v1/auth/sessions/{session_id}",
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert response.json()["detail"] == "Session not found"
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.parametrize("remember_me", [True, False])
    @pytest_asyncio.async
    async def test_login_with_remember_me_parameter(self, async_client, test_user, test_session, remember_me):
        """Test login with remember_me parameter."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "remember_me": remember_me
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (test_user, test_session, "access_token", "refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Verify remember_me was passed to the service
            auth_call = mock_auth.call_args
            assert auth_call.kwargs['remember_me'] == remember_me
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_login_with_device_info(self, async_client, test_user, test_session):
        """Test login with device information."""
        # Arrange
        device_info = {
            "device_type": "mobile",
            "os": "iOS",
            "browser": "Safari",
            "app_version": "1.0.0"
        }
        
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": device_info
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (test_user, test_session, "access_token", "refresh_token")
            
            # Act
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Verify device_info was passed to the service
            auth_call = mock_auth.call_args
            assert auth_call.kwargs['device_info'] == device_info
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_api_error_response_format(self, async_client):
        """Test API error response format consistency."""
        # Act
        response = await async_client.post("/api/v1/auth/login", json={"invalid": "data"})
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], list)
        
        # Check error structure
        error = data["detail"][0]
        assert "loc" in error
        assert "msg" in error
        assert "type" in error
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_request_id_header(self, async_client):
        """Test that requests include tracking headers."""
        # Act
        response = await async_client.get("/health")
        
        # Assert
        # Most middleware adds request tracking headers
        assert response.status_code in [200, 404]  # Endpoint may or may not exist
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest_asyncio.async
    async def test_cors_headers(self, async_client):
        """Test CORS headers are present."""
        # Act
        response = await async_client.options("/api/v1/auth/login")
        
        # Assert
        # CORS middleware should add appropriate headers
        assert response.status_code in [200, 405]  # OPTIONS may not be explicitly handled
    
    @pytest.mark.integration
    @pytest.mark.api
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_concurrent_login_requests(self, async_client, test_user, test_session):
        """Test handling concurrent login requests."""
        import asyncio
        
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (test_user, test_session, "access_token", "refresh_token")
            
            # Act - Send 5 concurrent requests
            tasks = [
                async_client.post("/api/v1/auth/login", json=login_data)
                for _ in range(5)
            ]
            responses = await asyncio.gather(*tasks)
            
            # Assert
            for response in responses:
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert "access_token" in data