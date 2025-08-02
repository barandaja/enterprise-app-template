"""
Comprehensive unit tests for AuthService class.
Tests all authentication flows, security features, and edge cases.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException, status

from src.services.auth_service import AuthService
from src.models.user import User
from src.models.session import UserSession
from src.models.audit import AuditEventType, AuditSeverity
from tests.factories import UserFactory, SessionFactory


class TestAuthService:
    """Test suite for AuthService class."""
    
    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance with mocked dependencies."""
        with patch('src.services.auth_service.UserService') as mock_user_service, \
             patch('src.services.auth_service.SessionService') as mock_session_service, \
             patch('src.services.auth_service.get_cache_service') as mock_cache_service, \
             patch('src.services.auth_service.AuditLogger') as mock_audit_logger:
            
            service = AuthService()
            service.user_service = mock_user_service.return_value
            service.session_service = mock_session_service.return_value
            service.cache_service = mock_cache_service.return_value
            service.audit_logger = mock_audit_logger.return_value
            
            return service
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_success(self, auth_service, db_session):
        """Test successful user authentication."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True, is_verified=True)
        session = SessionFactory(user_id=user.id)
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.session_service.create_session.return_value = session
        
        user.is_locked = MagicMock(return_value=False)
        user.verify_password = AsyncMock(return_value=True)
        user.record_login_attempt = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.create_access_token.return_value = "access_token"
            mock_security.create_refresh_token.return_value = "refresh_token"
            
            # Act
            result = await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!",
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0"
            )
            
            # Assert
            user_result, session_result, access_token, refresh_token = result
            assert user_result == user
            assert session_result == session
            assert access_token == "access_token"
            assert refresh_token == "refresh_token"
            
            # Verify service calls
            auth_service.user_service.get_user_by_email.assert_called_once_with(db_session, "test@example.com")
            user.verify_password.assert_called_once_with("TestPassword123!")
            user.record_login_attempt.assert_called_once_with(db_session, success=True, ip_address="127.0.0.1")
            auth_service.session_service.create_session.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_not_found(self, auth_service, db_session):
        """Test authentication with non-existent user."""
        # Arrange
        auth_service.user_service.get_user_by_email.return_value = None
        auth_service._log_failed_login = AsyncMock()
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=db_session,
                email="nonexistent@example.com",
                password="password",
                ip_address="127.0.0.1"
            )
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Invalid credentials"
        auth_service._log_failed_login.assert_called_once_with(
            db_session, "nonexistent@example.com", "user_not_found", "127.0.0.1"
        )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_locked_account(self, auth_service, db_session):
        """Test authentication with locked account."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        user.is_locked = MagicMock(return_value=True)
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service._log_failed_login = AsyncMock()
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="password",
                ip_address="127.0.0.1"
            )
        
        assert exc_info.value.status_code == status.HTTP_423_LOCKED
        assert exc_info.value.detail == "Account is temporarily locked"
        auth_service._log_failed_login.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_inactive_account(self, auth_service, db_session):
        """Test authentication with inactive account."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=False)
        user.is_locked = MagicMock(return_value=False)
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service._log_failed_login = AsyncMock()
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="password",
                ip_address="127.0.0.1"
            )
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Account is not active"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_wrong_password(self, auth_service, db_session):
        """Test authentication with wrong password."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        user.is_locked = MagicMock(return_value=False)
        user.verify_password = AsyncMock(return_value=False)
        user.record_login_attempt = AsyncMock()
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service._log_failed_login = AsyncMock()
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="wrongpassword",
                ip_address="127.0.0.1"
            )
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Invalid credentials"
        
        user.verify_password.assert_called_once_with("wrongpassword")
        user.record_login_attempt.assert_called_once_with(db_session, success=False, ip_address="127.0.0.1")
        auth_service._log_failed_login.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_refresh_token_success(self, auth_service, db_session):
        """Test successful token refresh."""
        # Arrange
        session = SessionFactory()
        
        auth_service.session_service.refresh_session.return_value = session
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "refresh",
                "sub": "1",
                "jti": "refresh_token_id"
            }
            mock_security.create_access_token.return_value = "new_access_token"
            mock_security.create_refresh_token.return_value = "new_refresh_token"
            
            # Act
            access_token, refresh_token = await auth_service.refresh_token(
                db=db_session,
                refresh_token="valid_refresh_token",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert access_token == "new_access_token"
            assert refresh_token == "new_refresh_token"
            
            auth_service.session_service.refresh_session.assert_called_once_with(
                db=db_session,
                refresh_token_id="refresh_token_id",
                ip_address="127.0.0.1"
            )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_refresh_token_invalid_type(self, auth_service, db_session):
        """Test token refresh with invalid token type."""
        # Arrange
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "access",  # Wrong type
                "sub": "1",
                "jti": "token_id"
            }
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.refresh_token(
                    db=db_session,
                    refresh_token="invalid_token",
                    ip_address="127.0.0.1"
                )
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Invalid token type"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_refresh_token_expired_session(self, auth_service, db_session):
        """Test token refresh with expired session."""
        # Arrange
        auth_service.session_service.refresh_session.return_value = None
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "refresh",
                "sub": "1",
                "jti": "expired_token_id"
            }
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.refresh_token(
                    db=db_session,
                    refresh_token="expired_refresh_token",
                    ip_address="127.0.0.1"
                )
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Invalid or expired refresh token"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_logout_single_session_success(self, auth_service, db_session):
        """Test successful single session logout."""
        # Arrange
        auth_service.session_service.end_session.return_value = True
        
        # Act
        result = await auth_service.logout(
            db=db_session,
            session_id="test_session_id",
            user_id=1,
            logout_all_sessions=False
        )
        
        # Assert
        assert result is True
        auth_service.session_service.end_session.assert_called_once_with(
            db=db_session,
            session_id="test_session_id",
            reason="logout"
        )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_logout_all_sessions_success(self, auth_service, db_session):
        """Test successful all sessions logout."""
        # Arrange
        auth_service.session_service.end_all_user_sessions.return_value = 3
        
        # Act
        result = await auth_service.logout(
            db=db_session,
            session_id="test_session_id",
            user_id=1,
            logout_all_sessions=True
        )
        
        # Assert
        assert result is True
        auth_service.session_service.end_all_user_sessions.assert_called_once_with(
            db=db_session,
            user_id=1,
            reason="logout_all"
        )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_initiate_password_reset_success(self, auth_service, db_session):
        """Test successful password reset initiation."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.cache_service.set = AsyncMock(return_value=True)
        auth_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.generate_password_reset_token.return_value = "reset_token"
            
            # Act
            result = await auth_service.initiate_password_reset(
                db=db_session,
                email="test@example.com",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is True
            auth_service.cache_service.set.assert_called_once()
            auth_service.audit_logger.log_auth_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_initiate_password_reset_nonexistent_user(self, auth_service, db_session):
        """Test password reset for non-existent user (should still return True for security)."""
        # Arrange
        auth_service.user_service.get_user_by_email.return_value = None
        auth_service.audit_logger.log_auth_event = AsyncMock()
        
        # Act
        result = await auth_service.initiate_password_reset(
            db=db_session,
            email="nonexistent@example.com",
            ip_address="127.0.0.1"
        )
        
        # Assert
        assert result is True  # Always returns True for security
        auth_service.audit_logger.log_auth_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_complete_password_reset_success(self, auth_service, db_session):
        """Test successful password reset completion."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        user.update_password = AsyncMock()
        user.save = AsyncMock()
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.cache_service.get.return_value = {"token": "valid_token", "email": "test@example.com"}  
        auth_service.cache_service.delete = AsyncMock()
        auth_service.session_service.end_all_user_sessions = AsyncMock()
        auth_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.verify_password_reset_token.return_value = "test@example.com"
            
            # Act
            result = await auth_service.complete_password_reset(
                db=db_session,
                token="valid_token",
                new_password="NewPassword123!",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is True
            user.update_password.assert_called_once_with(db_session, "NewPassword123!")
            auth_service.cache_service.delete.assert_called_once()
            auth_service.session_service.end_all_user_sessions.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_complete_password_reset_invalid_token(self, auth_service, db_session):
        """Test password reset with invalid token."""
        # Arrange
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.verify_password_reset_token.return_value = None
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.complete_password_reset(
                    db=db_session,
                    token="invalid_token",
                    new_password="NewPassword123!",
                    ip_address="127.0.0.1"
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Invalid or expired reset token"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_verify_email_success(self, auth_service, db_session):
        """Test successful email verification."""
        # Arrange
        user = UserFactory(email="test@example.com", is_verified=False)
        user.save = AsyncMock()
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.audit_logger.log_data_access = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.verify_email_verification_token.return_value = "test@example.com"
            
            # Act
            result = await auth_service.verify_email(
                db=db_session,
                token="valid_verification_token"
            )
            
            # Assert
            assert result is True
            assert user.is_verified is True
            assert user.email_verified_at is not None
            user.save.assert_called_once_with(db_session)
            auth_service.audit_logger.log_data_access.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_verify_email_invalid_token(self, auth_service, db_session):
        """Test email verification with invalid token."""
        # Arrange
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.verify_email_verification_token.return_value = None
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.verify_email(
                    db=db_session,
                    token="invalid_token"
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Invalid or expired verification token"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_change_password_success(self, auth_service, db_session):
        """Test successful password change."""
        # Arrange
        auth_service.user_service.change_password = AsyncMock()
        auth_service.session_service.end_all_user_sessions = AsyncMock()
        
        # Act
        result = await auth_service.change_password(
            db=db_session,
            user_id=1,
            current_password="OldPassword123!",
            new_password="NewPassword123!",
            session_id="current_session_id"
        )
        
        # Assert
        assert result is True
        auth_service.user_service.change_password.assert_called_once_with(
            db=db_session,
            user_id=1,
            current_password="OldPassword123!",
            new_password="NewPassword123!",
            changed_by_user_id=1
        )
        auth_service.session_service.end_all_user_sessions.assert_called_once_with(
            db=db_session,
            user_id=1,
            except_session_id="current_session_id",
            reason="password_change"
        )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_validate_token_success(self, auth_service, db_session):
        """Test successful token validation."""
        # Arrange
        user = UserFactory(is_active=True)
        session = SessionFactory(user_id=user.id)
        
        auth_service.user_service.get_user_by_id.return_value = user
        auth_service.session_service.validate_session.return_value = session
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "access",
                "sub": str(user.id),
                "session_id": session.session_id
            }
            
            # Act
            result = await auth_service.validate_token(
                db=db_session,
                token="valid_token",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result == user
            auth_service.user_service.get_user_by_id.assert_called_once_with(db_session, user.id)
            auth_service.session_service.validate_session.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_validate_token_invalid_type(self, auth_service, db_session):
        """Test token validation with invalid token type."""
        # Arrange
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "refresh",  # Wrong type
                "sub": "1"
            }
            
            # Act
            result = await auth_service.validate_token(
                db=db_session,
                token="invalid_token",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is None
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_validate_token_inactive_user(self, auth_service, db_session):
        """Test token validation with inactive user."""
        # Arrange
        user = UserFactory(is_active=False)
        
        auth_service.user_service.get_user_by_id.return_value = user
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "access",
                "sub": str(user.id)
            }
            
            # Act
            result = await auth_service.validate_token(
                db=db_session,
                token="token_for_inactive_user",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is None
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_validate_token_invalid_session(self, auth_service, db_session):
        """Test token validation with invalid session."""
        # Arrange
        user = UserFactory(is_active=True)
        
        auth_service.user_service.get_user_by_id.return_value = user
        auth_service.session_service.validate_session.return_value = None
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = {
                "type": "access",
                "sub": str(user.id),
                "session_id": "invalid_session_id"
            }
            
            # Act
            result = await auth_service.validate_token(
                db=db_session,
                token="token_with_invalid_session",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is None
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_log_failed_login(self, auth_service, db_session):
        """Test failed login logging."""
        # Arrange
        auth_service.audit_logger.log_auth_event = AsyncMock()
        
        # Act
        await auth_service._log_failed_login(
            db=db_session,
            email="test@example.com",
            reason="invalid_password",
            ip_address="127.0.0.1",
            user_id=1
        )
        
        # Assert
        auth_service.audit_logger.log_auth_event.assert_called_once_with(
            db=db_session,
            event_type=AuditEventType.LOGIN_FAILURE,
            user_id=1,
            ip_address="127.0.0.1",
            success=False,
            description="Login failed: invalid_password",
            event_data={"reason": "invalid_password"},
            severity=AuditSeverity.MEDIUM
        )
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest.mark.parametrize("remember_me", [True, False])
    @pytest_asyncio.async
    async def test_authenticate_user_remember_me(self, auth_service, db_session, remember_me):
        """Test authentication with remember_me parameter."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        session = SessionFactory(user_id=user.id)
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.session_service.create_session.return_value = session
        
        user.is_locked = MagicMock(return_value=False)
        user.verify_password = AsyncMock(return_value=True)
        user.record_login_attempt = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.create_access_token.return_value = "access_token"
            mock_security.create_refresh_token.return_value = "refresh_token"
            
            # Act
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!",
                remember_me=remember_me
            )
            
            # Assert
            create_session_call = auth_service.session_service.create_session.call_args
            assert create_session_call.kwargs['remember_me'] == remember_me
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_with_device_info(self, auth_service, db_session):
        """Test authentication with device information."""
        # Arrange
        user = UserFactory(email="test@example.com", is_active=True)
        session = SessionFactory(user_id=user.id)
        
        device_info = {"device_type": "mobile", "os": "iOS"}
        location_data = {"country": "US", "city": "New York"}
        
        auth_service.user_service.get_user_by_email.return_value = user
        auth_service.session_service.create_session.return_value = session
        
        user.is_locked = MagicMock(return_value=False)
        user.verify_password = AsyncMock(return_value=True)
        user.record_login_attempt = AsyncMock()
        
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.create_access_token.return_value = "access_token"
            mock_security.create_refresh_token.return_value = "refresh_token"
            
            # Act
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="TestPassword123!",
                device_info=device_info,
                location_data=location_data
            )
            
            # Assert
            create_session_call = auth_service.session_service.create_session.call_args
            assert create_session_call.kwargs['device_info'] == device_info
            assert create_session_call.kwargs['location_data'] == location_data
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_authenticate_user_exception_handling(self, auth_service, db_session):
        """Test authentication exception handling."""
        # Arrange
        auth_service.user_service.get_user_by_email.side_effect = Exception("Database error")
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=db_session,
                email="test@example.com",
                password="password"
            )
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Authentication failed"
    
    @pytest.mark.unit
    @pytest.mark.auth
    @pytest_asyncio.async
    async def test_refresh_token_exception_handling(self, auth_service, db_session):
        """Test refresh token exception handling."""
        # Arrange
        with patch('src.services.auth_service.SecurityService') as mock_security:
            mock_security.decode_token.side_effect = Exception("Token decode error")
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.refresh_token(
                    db=db_session,
                    refresh_token="invalid_token"
                )
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Invalid refresh token"