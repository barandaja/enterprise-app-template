"""
Tests for the decomposed authentication services.
Tests AuthenticationService, TokenService, PasswordService, and EmailVerificationService.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException, status

from src.services.auth.authentication_service import AuthenticationService
from src.services.auth.token_service import TokenService
from src.services.auth.password_service import PasswordService
from src.services.auth.email_verification_service import EmailVerificationService
from src.models.user import User
from src.models.session import UserSession
from src.events.auth_events import (
    UserAuthenticatedEvent,
    TokenCreatedEvent,
    PasswordResetInitiatedEvent,
    EmailVerificationRequestedEvent
)


class TestAuthenticationService:
    """Test cases for AuthenticationService."""
    
    @pytest.fixture
    def mock_dependencies(self):
        """Create mock dependencies for AuthenticationService."""
        return {
            'user_repository': AsyncMock(),
            'cache_service': AsyncMock(),
            'event_bus': AsyncMock(),
            'session_service': AsyncMock(),
            'token_service': AsyncMock()
        }
    
    @pytest.fixture
    def auth_service(self, mock_dependencies):
        """Create AuthenticationService instance with mocked dependencies."""
        return AuthenticationService(**mock_dependencies)
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = 1
        user.email = "test@example.com"
        user.is_active = True
        user.is_locked.return_value = False
        user.record_login_attempt = AsyncMock()
        return user
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock session for testing."""
        session = MagicMock(spec=UserSession)
        session.session_id = "test-session-id"
        session.user_id = 1
        return session
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(
        self, 
        auth_service, 
        mock_dependencies, 
        mock_user, 
        mock_session
    ):
        """Test successful user authentication."""
        # Arrange
        mock_db = AsyncMock()
        email = "test@example.com"
        password = "password123"
        
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        mock_dependencies['user_repository'].verify_password.return_value = True
        mock_dependencies['session_service'].create_session.return_value = mock_session
        mock_dependencies['token_service'].create_access_token.return_value = "access-token"
        mock_dependencies['token_service'].create_refresh_token.return_value = "refresh-token"
        
        # Act
        result = await auth_service.authenticate_user(
            db=mock_db,
            email=email,
            password=password,
            ip_address="127.0.0.1"
        )
        
        # Assert
        user, session, access_token, refresh_token = result
        assert user == mock_user
        assert session == mock_session
        assert access_token == "access-token"
        assert refresh_token == "refresh-token"
        
        # Verify dependencies were called correctly
        mock_dependencies['user_repository'].get_by_email.assert_called_once_with(mock_db, email)
        mock_dependencies['user_repository'].verify_password.assert_called_once_with(mock_db, 1, password)
        mock_dependencies['event_bus'].publish.assert_called_once()
        
        # Verify event was published
        published_event = mock_dependencies['event_bus'].publish.call_args[0][0]
        assert isinstance(published_event, UserAuthenticatedEvent)
        assert published_event.user_id == 1
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service, mock_dependencies):
        """Test authentication with non-existent user."""
        # Arrange
        mock_db = AsyncMock()
        mock_dependencies['user_repository'].get_by_email.return_value = None
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=mock_db,
                email="nonexistent@example.com",
                password="password123"
            )
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid credentials" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_authenticate_user_locked_account(
        self, 
        auth_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test authentication with locked account."""
        # Arrange
        mock_db = AsyncMock()
        mock_user.is_locked.return_value = True
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=mock_db,
                email="test@example.com",
                password="password123"
            )
        
        assert exc_info.value.status_code == status.HTTP_423_LOCKED
        assert "Account is temporarily locked" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_password(
        self, 
        auth_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test authentication with invalid password."""
        # Arrange
        mock_db = AsyncMock()
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        mock_dependencies['user_repository'].verify_password.return_value = False
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.authenticate_user(
                db=mock_db,
                email="test@example.com",
                password="wrongpassword"
            )
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid credentials" in str(exc_info.value.detail)
        
        # Verify failed login was recorded
        mock_user.record_login_attempt.assert_called_once_with(mock_db, success=False, ip_address=None)


class TestTokenService:
    """Test cases for TokenService."""
    
    @pytest.fixture
    def mock_dependencies(self):
        """Create mock dependencies for TokenService."""
        return {
            'cache_service': AsyncMock(),
            'event_bus': AsyncMock(),
            'session_service': AsyncMock()
        }
    
    @pytest.fixture
    def token_service(self, mock_dependencies):
        """Create TokenService instance with mocked dependencies."""
        return TokenService(**mock_dependencies)
    
    @pytest.mark.asyncio
    async def test_create_access_token(self, token_service, mock_dependencies):
        """Test access token creation."""
        # Arrange
        user_id = 1
        session_id = "test-session"
        
        with patch('src.services.auth.token_service.SecurityService') as mock_security:
            mock_security.create_access_token.return_value = "access-token"
            
            # Act
            token = await token_service.create_access_token(user_id, session_id)
            
            # Assert
            assert token == "access-token"
            mock_security.create_access_token.assert_called_once()
            mock_dependencies['event_bus'].publish.assert_called_once()
            
            # Verify event was published
            published_event = mock_dependencies['event_bus'].publish.call_args[0][0]
            assert isinstance(published_event, TokenCreatedEvent)
            assert published_event.user_id == user_id
            assert published_event.token_type == "access"
    
    @pytest.mark.asyncio
    async def test_validate_access_token_success(self, token_service, mock_dependencies):
        """Test successful access token validation."""
        # Arrange
        token = "valid-token"
        expected_payload = {"type": "access", "sub": "1", "jti": "token-id"}
        
        with patch('src.services.auth.token_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = expected_payload
            mock_dependencies['cache_service'].exists.return_value = False
            
            # Act
            payload = await token_service.validate_access_token(token)
            
            # Assert
            assert payload == expected_payload
            mock_security.decode_token.assert_called_once_with(token)
            mock_dependencies['cache_service'].exists.assert_called_once_with("blacklist:token:token-id")
    
    @pytest.mark.asyncio
    async def test_validate_access_token_blacklisted(self, token_service, mock_dependencies):
        """Test validation of blacklisted token."""
        # Arrange
        token = "blacklisted-token"
        payload = {"type": "access", "sub": "1", "jti": "token-id"}
        
        with patch('src.services.auth.token_service.SecurityService') as mock_security:
            mock_security.decode_token.return_value = payload
            mock_dependencies['cache_service'].exists.return_value = True
            
            # Act
            result = await token_service.validate_access_token(token)
            
            # Assert
            assert result is None
    
    @pytest.mark.asyncio
    async def test_blacklist_token(self, token_service, mock_dependencies):
        """Test token blacklisting."""
        # Arrange
        token_id = "test-token-id"
        mock_dependencies['cache_service'].set.return_value = True
        
        # Act
        result = await token_service.blacklist_token(token_id)
        
        # Assert
        assert result is True
        mock_dependencies['cache_service'].set.assert_called_once_with(
            f"blacklist:token:{token_id}",
            True,
            ttl=pytest.approx(7 * 24 * 3600, rel=1e-3)  # 7 days in seconds
        )


class TestPasswordService:
    """Test cases for PasswordService."""
    
    @pytest.fixture
    def mock_dependencies(self):
        """Create mock dependencies for PasswordService."""
        return {
            'user_repository': AsyncMock(),
            'cache_service': AsyncMock(),
            'event_bus': AsyncMock(),
            'session_service': AsyncMock()
        }
    
    @pytest.fixture
    def password_service(self, mock_dependencies):
        """Create PasswordService instance with mocked dependencies."""
        return PasswordService(**mock_dependencies)
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = 1
        user.email = "test@example.com"
        user.is_active = True
        return user
    
    @pytest.mark.asyncio
    async def test_initiate_password_reset_success(
        self, 
        password_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test successful password reset initiation."""
        # Arrange
        mock_db = AsyncMock()
        email = "test@example.com"
        
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        
        with patch('src.services.auth.password_service.SecurityService') as mock_security:
            mock_security.generate_password_reset_token.return_value = "reset-token"
            
            # Act
            result = await password_service.initiate_password_reset(
                db=mock_db,
                email=email,
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is True
            mock_dependencies['user_repository'].get_by_email.assert_called_once_with(mock_db, email)
            mock_security.generate_password_reset_token.assert_called_once_with(email)
            mock_dependencies['cache_service'].set.assert_called_once()
            mock_dependencies['event_bus'].publish.assert_called_once()
            
            # Verify event
            published_event = mock_dependencies['event_bus'].publish.call_args[0][0]
            assert isinstance(published_event, PasswordResetInitiatedEvent)
            assert published_event.user_id == 1
            assert published_event.email == email
    
    @pytest.mark.asyncio
    async def test_initiate_password_reset_user_not_found(
        self, 
        password_service, 
        mock_dependencies
    ):
        """Test password reset initiation with non-existent user."""
        # Arrange
        mock_db = AsyncMock()
        email = "nonexistent@example.com"
        
        mock_dependencies['user_repository'].get_by_email.return_value = None
        
        # Act
        result = await password_service.initiate_password_reset(
            db=mock_db,
            email=email
        )
        
        # Assert - Should still return True for security
        assert result is True
        mock_dependencies['event_bus'].publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_complete_password_reset_success(
        self, 
        password_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test successful password reset completion."""
        # Arrange
        mock_db = AsyncMock()
        token = "valid-reset-token"
        new_password = "newpassword123"
        
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        mock_dependencies['cache_service'].get.return_value = {"token": token, "email": "test@example.com"}
        
        with patch('src.services.auth.password_service.SecurityService') as mock_security:
            mock_security.verify_password_reset_token.return_value = "test@example.com"
            
            # Act
            result = await password_service.complete_password_reset(
                db=mock_db,
                token=token,
                new_password=new_password,
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result is True
            mock_dependencies['user_repository'].update_password.assert_called_once_with(
                mock_db, 1, new_password
            )
            mock_dependencies['cache_service'].delete.assert_called_once()
            mock_dependencies['session_service'].end_all_user_sessions.assert_called_once()
            mock_dependencies['event_bus'].publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_password_strength(self, password_service):
        """Test password strength validation."""
        with patch('src.services.auth.password_service.SecurityService') as mock_security:
            mock_security.validate_password_strength.return_value = (True, [])
            
            # Act
            is_valid, errors = await password_service.validate_password_strength("StrongPass123!")
            
            # Assert
            assert is_valid is True
            assert errors == []
            mock_security.validate_password_strength.assert_called_once_with("StrongPass123!")


class TestEmailVerificationService:
    """Test cases for EmailVerificationService."""
    
    @pytest.fixture
    def mock_dependencies(self):
        """Create mock dependencies for EmailVerificationService."""
        return {
            'user_repository': AsyncMock(),
            'cache_service': AsyncMock(),
            'event_bus': AsyncMock()
        }
    
    @pytest.fixture
    def email_service(self, mock_dependencies):
        """Create EmailVerificationService instance with mocked dependencies."""
        return EmailVerificationService(**mock_dependencies)
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock(spec=User)
        user.id = 1
        user.email = "test@example.com"
        user.is_active = True
        user.is_verified = False
        return user
    
    @pytest.mark.asyncio
    async def test_send_verification_email_success(
        self, 
        email_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test successful email verification sending."""
        # Arrange
        mock_db = AsyncMock()
        user_id = 1
        email = "test@example.com"
        
        mock_dependencies['user_repository'].get_by_id.return_value = mock_user
        mock_dependencies['cache_service'].exists.return_value = False  # Not rate limited
        
        with patch('src.services.auth.email_verification_service.SecurityService') as mock_security:
            mock_security.generate_email_verification_token.return_value = "verification-token"
            
            # Act
            result = await email_service.send_verification_email(
                db=mock_db,
                user_id=user_id,
                email=email
            )
            
            # Assert
            assert result is True
            mock_dependencies['user_repository'].get_by_id.assert_called_once_with(mock_db, user_id)
            mock_security.generate_email_verification_token.assert_called_once_with(email)
            mock_dependencies['cache_service'].set.assert_called()  # Called twice (token + rate limit)
            mock_dependencies['event_bus'].publish.assert_called_once()
            
            # Verify event
            published_event = mock_dependencies['event_bus'].publish.call_args[0][0]
            assert isinstance(published_event, EmailVerificationRequestedEvent)
            assert published_event.user_id == user_id
            assert published_event.email == email
    
    @pytest.mark.asyncio
    async def test_send_verification_email_rate_limited(
        self, 
        email_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test email verification sending when rate limited."""
        # Arrange
        mock_db = AsyncMock()
        user_id = 1
        email = "test@example.com"
        
        mock_dependencies['user_repository'].get_by_id.return_value = mock_user
        mock_dependencies['cache_service'].exists.return_value = True  # Rate limited
        
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await email_service.send_verification_email(
                db=mock_db,
                user_id=user_id,
                email=email
            )
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.asyncio
    async def test_verify_email_success(
        self, 
        email_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test successful email verification."""
        # Arrange
        mock_db = AsyncMock()
        token = "valid-verification-token"
        
        mock_dependencies['user_repository'].get_by_email.return_value = mock_user
        mock_dependencies['cache_service'].get.return_value = {
            "token": token, 
            "email": "test@example.com"
        }
        
        with patch('src.services.auth.email_verification_service.SecurityService') as mock_security:
            mock_security.verify_email_verification_token.return_value = "test@example.com"
            
            # Act
            result = await email_service.verify_email(
                db=mock_db,
                token=token
            )
            
            # Assert
            assert result is True
            mock_dependencies['user_repository'].update.assert_called_once()
            mock_dependencies['cache_service'].delete.assert_called_once()
            mock_dependencies['event_bus'].publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_verification_status(
        self, 
        email_service, 
        mock_dependencies, 
        mock_user
    ):
        """Test checking email verification status."""
        # Arrange
        mock_db = AsyncMock()
        user_id = 1
        
        mock_user.is_verified = True
        mock_user.email_verified_at = datetime.utcnow()
        mock_dependencies['user_repository'].get_by_id.return_value = mock_user
        mock_dependencies['cache_service'].exists.side_effect = [True, False]  # Has pending, not rate limited
        
        # Act
        result = await email_service.check_verification_status(mock_db, user_id)
        
        # Assert
        assert result["is_verified"] is True
        assert result["has_pending_verification"] is True
        assert result["can_resend"] is True
        assert result["user_id"] == user_id
        assert "email_verified_at" in result