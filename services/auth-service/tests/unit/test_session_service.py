"""
Comprehensive unit tests for SessionService class.
Tests session lifecycle, validation, security features, and cleanup.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from fastapi import HTTPException, status

from src.services.session_service import SessionService
from src.models.user import User
from src.models.session import UserSession, SessionManager
from src.models.audit import AuditEventType, AuditSeverity
from tests.factories import UserFactory, SessionFactory


class TestSessionService:
    """Test suite for SessionService class."""
    
    @pytest.fixture
    def session_service(self):
        """Create SessionService instance with mocked dependencies."""
        with patch('src.services.session_service.get_cache_service') as mock_cache_service, \
             patch('src.services.session_service.SessionManager') as mock_session_manager, \
             patch('src.services.session_service.AuditLogger') as mock_audit_logger:
            
            service = SessionService()
            service.cache_service = mock_cache_service.return_value
            service.session_manager = mock_session_manager.return_value
            service.audit_logger = mock_audit_logger.return_value
            
            return service
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_create_session_success(self, session_service, db_session):
        """Test successful session creation."""
        # Arrange
        user = UserFactory(id=1)
        session = SessionFactory(user_id=user.id)
        
        session_service.session_manager.cache_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.create_session') as mock_create_session, \
             patch('src.services.session_service.settings') as mock_settings:
            
            mock_settings.SESSION_LIFETIME_SECONDS = 3600
            mock_create_session.return_value = session
            
            # Act
            result = await session_service.create_session(
                db=db_session,
                user=user,
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0",
                device_info={"device": "test"},
                location_data={"country": "US"},
                remember_me=False
            )
            
            # Assert
            assert result == session
            mock_create_session.assert_called_once_with(
                db=db_session,
                user_id=user.id,
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0",
                device_info={"device": "test"},
                location_data={"country": "US"},
                session_lifetime=3600
            )
            session_service.session_manager.cache_session.assert_called_once_with(session)
            session_service.audit_logger.log_auth_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_create_session_remember_me(self, session_service, db_session):
        """Test session creation with remember_me option."""
        # Arrange
        user = UserFactory(id=1)
        session = SessionFactory(user_id=user.id)
        
        session_service.session_manager.cache_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.create_session') as mock_create_session, \
             patch('src.services.session_service.settings') as mock_settings:
            
            mock_settings.SESSION_LIFETIME_SECONDS = 3600
            mock_create_session.return_value = session
            
            # Act
            await session_service.create_session(
                db=db_session,
                user=user,
                remember_me=True
            )
            
            # Assert
            # Session lifetime should be extended by 7x for remember_me
            create_call = mock_create_session.call_args
            assert create_call.kwargs['session_lifetime'] == 3600 * 7
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_create_session_exception_handling(self, session_service, db_session):
        """Test session creation exception handling."""
        # Arrange
        user = UserFactory(id=1)
        
        with patch('src.models.session.UserSession.create_session') as mock_create_session:
            mock_create_session.side_effect = Exception("Database error")
            
            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await session_service.create_session(
                    db=db_session,
                    user=user
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Failed to create session"
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_get_session_from_cache(self, session_service, db_session):
        """Test getting session from cache."""
        # Arrange
        cached_session_data = {"session_id": "test_session", "user_id": 1}
        session_service.session_manager.get_cached_session = AsyncMock(return_value=cached_session_data)
        
        # Act
        result = await session_service.get_session(
            db=db_session,
            session_id="test_session",
            validate=False
        )
        
        # Assert
        session_service.session_manager.get_cached_session.assert_called_once_with("test_session")
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_get_session_from_database(self, session_service, db_session):
        """Test getting session from database."""
        # Arrange
        session = SessionFactory(session_id="test_session")
        session.is_valid = MagicMock(return_value=True)
        
        session_service.session_manager.get_cached_session = AsyncMock(return_value=None)
        
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            result = await session_service.get_session(
                db=db_session,
                session_id="test_session",
                validate=True
            )
            
            # Assert
            assert result == session
            mock_get_session.assert_called_once_with(db_session, "test_session")
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_get_session_invalid_expires(self, session_service, db_session):
        """Test getting invalid/expired session."""
        # Arrange
        session = SessionFactory(session_id="test_session")
        session.is_valid = MagicMock(return_value=False)
        
        session_service.session_manager.get_cached_session = AsyncMock(return_value=None)
        session_service.end_session = AsyncMock(return_value=True)
        
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            result = await session_service.get_session(
                db=db_session,
                session_id="test_session",
                validate=True
            )
            
            # Assert
            assert result is None
            session_service.end_session.assert_called_once_with(db_session, "test_session", reason="expired")
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_validate_session_success(self, session_service, db_session):
        """Test successful session validation."""
        # Arrange
        session = SessionFactory(
            session_id="test_session",
            user_id=1,
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
            suspicious_activity=False
        )
        session.update_activity = AsyncMock()
        
        session_service.get_session = AsyncMock(return_value=session)
        
        with patch('src.services.session_service.settings') as mock_settings:
            mock_settings.ENFORCE_IP_VALIDATION = False
            
            # Act
            result = await session_service.validate_session(
                db=db_session,
                session_id="test_session",
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0"
            )
            
            # Assert
            assert result == session
            session.update_activity.assert_called_once_with(db_session)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_validate_session_ip_mismatch(self, session_service, db_session):
        """Test session validation with IP address mismatch."""
        # Arrange
        session = SessionFactory(
            session_id="test_session",
            user_id=1,
            ip_address="127.0.0.1",
            suspicious_activity=False
        )
        session.mark_suspicious = AsyncMock()
        
        session_service.get_session = AsyncMock(return_value=session)
        session_service.end_session = AsyncMock(return_value=True)
        session_service.audit_logger.log_security_event = AsyncMock()
        
        with patch('src.services.session_service.settings') as mock_settings:
            mock_settings.ENFORCE_IP_VALIDATION = True
            
            # Act
            result = await session_service.validate_session(
                db=db_session,
                session_id="test_session",
                ip_address="192.168.1.100",  # Different IP
                user_agent="TestAgent/1.0"
            )
            
            # Assert
            assert result is None
            session.mark_suspicious.assert_called_once()
            session_service.audit_logger.log_security_event.assert_called_once()
            session_service.end_session.assert_called_once_with(
                db_session, "test_session", reason="security_violation"
            )
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_validate_session_suspicious_activity(self, session_service, db_session):
        """Test session validation with suspicious activity flag."""
        # Arrange
        session = SessionFactory(
            session_id="test_session",
            user_id=1,
            suspicious_activity=True
        )
        session.mark_suspicious = AsyncMock()
        
        session_service.get_session = AsyncMock(return_value=session)
        session_service.audit_logger.log_security_event = AsyncMock()
        
        with patch('src.services.session_service.settings') as mock_settings:
            mock_settings.ENFORCE_IP_VALIDATION = False
            
            # Act
            result = await session_service.validate_session(
                db=db_session,
                session_id="test_session"
            )
            
            # Assert
            session.mark_suspicious.assert_called_once()
            session_service.audit_logger.log_security_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_refresh_session_success(self, session_service, db_session):
        """Test successful session refresh."""
        # Arrange
        session = SessionFactory(refresh_token_id="old_token")
        session.is_valid = MagicMock(return_value=True)
        session.rotate_tokens = AsyncMock(return_value="new_token")
        session.extend_session = AsyncMock()
        session.expires_at = datetime.utcnow() + timedelta(minutes=30)  # Soon to expire
        
        session_service.session_manager.cache_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_by_refresh_token_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            result = await session_service.refresh_session(
                db=db_session,
                refresh_token_id="old_token",
                ip_address="127.0.0.1"
            )
            
            # Assert
            assert result == session
            session.rotate_tokens.assert_called_once_with(db_session)
            session.extend_session.assert_called_once_with(db_session)
            session_service.session_manager.cache_session.assert_called_once_with(session)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_refresh_session_invalid_token(self, session_service, db_session):
        """Test session refresh with invalid token."""
        # Arrange
        with patch('src.models.session.UserSession.get_by_refresh_token_id') as mock_get_session:
            mock_get_session.return_value = None
            
            # Act
            result = await session_service.refresh_session(
                db=db_session,
                refresh_token_id="invalid_token"
            )
            
            # Assert
            assert result is None
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_end_session_success(self, session_service, db_session):
        """Test successful session termination."""
        # Arrange
        session = SessionFactory(session_id="test_session", user_id=1)
        session.end_session = AsyncMock()
        
        session_service.session_manager.invalidate_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            result = await session_service.end_session(
                db=db_session,
                session_id="test_session",
                reason="logout",
                ended_by_user_id=1
            )
            
            # Assert
            assert result is True
            session.end_session.assert_called_once_with(db_session, reason="logout")
            session_service.session_manager.invalidate_session.assert_called_once_with("test_session")
            session_service.audit_logger.log_auth_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_end_session_not_found(self, session_service, db_session):
        """Test ending non-existent session."""
        # Arrange
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.return_value = None
            
            # Act
            result = await session_service.end_session(
                db=db_session,
                session_id="nonexistent_session"
            )
            
            # Assert
            assert result is False
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_end_all_user_sessions_success(self, session_service, db_session):
        """Test ending all user sessions."""
        # Arrange
        sessions = [
            SessionFactory(session_id="session1", user_id=1),
            SessionFactory(session_id="session2", user_id=1),
            SessionFactory(session_id="session3", user_id=1)
        ]
        
        for session in sessions:
            session.end_session = AsyncMock()
        
        session_service.session_manager.invalidate_session = AsyncMock()
        session_service.session_manager.invalidate_user_sessions = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_active_sessions_for_user') as mock_get_sessions:
            mock_get_sessions.return_value = sessions
            
            # Act
            result = await session_service.end_all_user_sessions(
                db=db_session,
                user_id=1,
                reason="admin_action"
            )
            
            # Assert
            assert result == 3
            for session in sessions:
                session.end_session.assert_called_once_with(db_session, reason="admin_action")
            assert session_service.session_manager.invalidate_session.call_count == 3
            session_service.session_manager.invalidate_user_sessions.assert_called_once_with(1)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_end_all_user_sessions_except_current(self, session_service, db_session):
        """Test ending all user sessions except current one."""
        # Arrange
        sessions = [
            SessionFactory(session_id="session1", user_id=1),
            SessionFactory(session_id="current_session", user_id=1),
            SessionFactory(session_id="session3", user_id=1)
        ]
        
        for session in sessions:
            session.end_session = AsyncMock()
        
        session_service.session_manager.invalidate_session = AsyncMock()
        session_service.session_manager.invalidate_user_sessions = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_active_sessions_for_user') as mock_get_sessions:
            mock_get_sessions.return_value = sessions
            
            # Act
            result = await session_service.end_all_user_sessions(
                db=db_session,
                user_id=1,
                except_session_id="current_session",
                reason="password_change"
            )
            
            # Assert
            assert result == 2  # Only 2 sessions should be ended
            # Current session should not be ended
            assert not sessions[1].end_session.called
            # Other sessions should be ended
            sessions[0].end_session.assert_called_once()
            sessions[2].end_session.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_get_user_sessions_active_only(self, session_service, db_session):
        """Test getting user's active sessions only."""
        # Arrange
        sessions = [
            SessionFactory(user_id=1, is_active=True),
            SessionFactory(user_id=1, is_active=True)
        ]
        
        with patch('src.models.session.UserSession.get_active_sessions_for_user') as mock_get_sessions:
            mock_get_sessions.return_value = sessions
            
            # Act
            result = await session_service.get_user_sessions(
                db=db_session,
                user_id=1,
                active_only=True,
                limit=10
            )
            
            # Assert
            assert result == sessions
            mock_get_sessions.assert_called_once_with(db_session, 1, 10)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_cleanup_expired_sessions(self, session_service, db_session):
        """Test cleaning up expired sessions."""
        # Arrange
        with patch('src.models.session.UserSession.cleanup_expired_sessions') as mock_cleanup:
            mock_cleanup.return_value = 5
            
            # Act
            result = await session_service.cleanup_expired_sessions(db_session)
            
            # Assert
            assert result == 5
            mock_cleanup.assert_called_once_with(db_session)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_get_session_analytics(self, session_service, db_session):
        """Test getting session analytics."""
        # Act
        result = await session_service.get_session_analytics(
            db=db_session,
            user_id=1
        )
        
        # Assert
        assert isinstance(result, dict)
        assert "total_sessions" in result
        assert "active_sessions" in result
        assert "expired_sessions" in result
        assert "suspicious_sessions" in result
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_mark_device_as_trusted_success(self, session_service, db_session):
        """Test marking device as trusted."""
        # Arrange
        session = SessionFactory(session_id="test_session", user_id=1)
        session.save = AsyncMock()
        
        session_service.get_session = AsyncMock(return_value=session)
        session_service.session_manager.cache_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        # Act
        result = await session_service.mark_device_as_trusted(
            db=db_session,
            session_id="test_session",
            user_id=1
        )
        
        # Assert
        assert result is True
        assert session.is_trusted_device is True
        session.save.assert_called_once_with(db_session)
        session_service.session_manager.cache_session.assert_called_once_with(session)
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_mark_device_as_trusted_wrong_user(self, session_service, db_session):
        """Test marking device as trusted with wrong user."""
        # Arrange
        session = SessionFactory(session_id="test_session", user_id=1)
        session_service.get_session = AsyncMock(return_value=session)
        
        # Act
        result = await session_service.mark_device_as_trusted(
            db=db_session,
            session_id="test_session",
            user_id=999  # Different user
        )
        
        # Assert
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_mark_device_as_trusted_session_not_found(self, session_service, db_session):
        """Test marking device as trusted with non-existent session."""
        # Arrange
        session_service.get_session = AsyncMock(return_value=None)
        
        # Act
        result = await session_service.mark_device_as_trusted(
            db=db_session,
            session_id="nonexistent_session",
            user_id=1
        )
        
        # Assert
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest.mark.parametrize("reason", ["logout", "expired", "security_violation"])
    @pytest_asyncio.async
    async def test_end_session_different_reasons(self, session_service, db_session, reason):
        """Test ending session with different reasons."""
        # Arrange
        session = SessionFactory(session_id="test_session", user_id=1)
        session.end_session = AsyncMock()
        
        session_service.session_manager.invalidate_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            await session_service.end_session(
                db=db_session,
                session_id="test_session", 
                reason=reason
            )
            
            # Assert
            session.end_session.assert_called_once_with(db_session, reason=reason)
            
            # Check audit event type is appropriate for reason
            audit_call = session_service.audit_logger.log_auth_event.call_args
            if reason == "expired":
                assert audit_call.kwargs['event_type'] == AuditEventType.LOGIN_FAILURE
            elif reason == "security_violation":
                assert audit_call.kwargs['event_type'] == AuditEventType.SECURITY_ALERT
            else:
                assert audit_call.kwargs['event_type'] == AuditEventType.LOGOUT
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_session_service_exception_handling(self, session_service, db_session):
        """Test exception handling in session service methods."""
        # Arrange
        with patch('src.models.session.UserSession.get_by_session_id') as mock_get_session:
            mock_get_session.side_effect = Exception("Database error")
            
            # Act
            result = await session_service.end_session(
                db=db_session,
                session_id="test_session"
            )
            
            # Assert
            assert result is False  # Should handle exception gracefully
    
    @pytest.mark.unit
    @pytest.mark.session
    @pytest_asyncio.async
    async def test_refresh_session_no_extension_needed(self, session_service, db_session):
        """Test session refresh when no extension is needed."""
        # Arrange
        session = SessionFactory(refresh_token_id="token")
        session.is_valid = MagicMock(return_value=True)
        session.rotate_tokens = AsyncMock(return_value="new_token")
        session.expires_at = datetime.utcnow() + timedelta(hours=5)  # Not expiring soon
        
        session_service.session_manager.cache_session = AsyncMock()
        session_service.audit_logger.log_auth_event = AsyncMock()
        
        with patch('src.models.session.UserSession.get_by_refresh_token_id') as mock_get_session:
            mock_get_session.return_value = session
            
            # Act
            result = await session_service.refresh_session(
                db=db_session,
                refresh_token_id="token"
            )
            
            # Assert
            assert result == session
            session.rotate_tokens.assert_called_once()
            # extend_session should not be called
            assert not hasattr(session, 'extend_session') or not session.extend_session.called