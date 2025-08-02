"""
Tests for the event-driven architecture implementation.
Tests event bus, events, and event handlers.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.events.event_bus import InMemoryEventBus
from src.events.base_event import BaseEvent
from src.events.auth_events import (
    UserAuthenticatedEvent,
    UserLoggedOutEvent,
    LoginFailedEvent,
    TokenCreatedEvent,
    PasswordResetInitiatedEvent,
    EmailVerificationRequestedEvent
)
from src.events.audit_handlers import AuditEventHandler
from src.interfaces.event_interface import IEvent


class TestEvent(BaseEvent):
    """Test event for testing purposes."""
    
    def __init__(self, test_data: str):
        super().__init__()
        self.test_data = test_data


class TestBaseEvent:
    """Test cases for BaseEvent."""
    
    def test_event_creation(self):
        """Test basic event creation."""
        # Act
        event = TestEvent("test data")
        
        # Assert
        assert event.test_data == "test data"
        assert event.event_type == "TestEvent"
        assert isinstance(event.timestamp, datetime)
        assert isinstance(event.correlation_id, str)
        assert len(event.correlation_id) > 0
    
    def test_event_data_property(self):
        """Test event data property excludes system fields."""
        # Act
        event = TestEvent("test data")
        
        # Assert
        data = event.data
        assert "test_data" in data
        assert data["test_data"] == "test data"
        assert "correlation_id" not in data
        assert "timestamp" not in data
    
    def test_to_dict(self):
        """Test event serialization to dictionary."""
        # Act
        event = TestEvent("test data")
        event_dict = event.to_dict()
        
        # Assert
        assert "event_type" in event_dict
        assert "correlation_id" in event_dict
        assert "timestamp" in event_dict
        assert "data" in event_dict
        assert event_dict["event_type"] == "TestEvent"
        assert event_dict["data"]["test_data"] == "test data"
    
    def test_str_representation(self):
        """Test string representation of event."""
        # Act
        event = TestEvent("test data")
        str_repr = str(event)
        
        # Assert
        assert "TestEvent" in str_repr
        assert event.correlation_id in str_repr


class TestAuthEvents:
    """Test cases for authentication events."""
    
    def test_user_authenticated_event(self):
        """Test UserAuthenticatedEvent creation."""
        # Act
        event = UserAuthenticatedEvent(
            user_id=1,
            session_id="session-123",
            ip_address="127.0.0.1",
            user_agent="test-agent"
        )
        
        # Assert
        assert event.user_id == 1
        assert event.session_id == "session-123"
        assert event.ip_address == "127.0.0.1"
        assert event.user_agent == "test-agent"
        assert event.event_type == "UserAuthenticatedEvent"
        
        data = event.data
        assert data["user_id"] == 1
        assert data["session_id"] == "session-123"
    
    def test_login_failed_event(self):
        """Test LoginFailedEvent creation."""
        # Act
        event = LoginFailedEvent(
            email="test@example.com",
            reason="invalid_password",
            ip_address="127.0.0.1",
            user_id=1
        )
        
        # Assert
        assert event.email == "test@example.com"
        assert event.reason == "invalid_password"
        assert event.ip_address == "127.0.0.1"
        assert event.user_id == 1
        assert event.event_type == "LoginFailedEvent"
    
    def test_token_created_event(self):
        """Test TokenCreatedEvent creation."""
        # Act
        event = TokenCreatedEvent(
            user_id=1,
            token_type="access",
            session_id="session-123"
        )
        
        # Assert
        assert event.user_id == 1
        assert event.token_type == "access"
        assert event.session_id == "session-123"
        assert event.event_type == "TokenCreatedEvent"
    
    def test_password_reset_initiated_event(self):
        """Test PasswordResetInitiatedEvent creation."""
        # Act
        event = PasswordResetInitiatedEvent(
            user_id=1,
            email="test@example.com",
            reset_token="token-123",
            ip_address="127.0.0.1"
        )
        
        # Assert
        assert event.user_id == 1
        assert event.email == "test@example.com"
        assert event.reset_token == "token-123"
        assert event.ip_address == "127.0.0.1"
        assert event.event_type == "PasswordResetInitiatedEvent"
    
    def test_email_verification_requested_event(self):
        """Test EmailVerificationRequestedEvent creation."""
        # Act
        event = EmailVerificationRequestedEvent(
            user_id=1,
            email="test@example.com",
            verification_token="token-123",
            is_resend=True
        )
        
        # Assert
        assert event.user_id == 1
        assert event.email == "test@example.com"
        assert event.verification_token == "token-123"
        assert event.is_resend is True
        assert event.event_type == "EmailVerificationRequestedEvent"


class TestInMemoryEventBus:
    """Test cases for InMemoryEventBus."""
    
    @pytest.fixture
    def event_bus(self):
        """Create event bus instance for testing."""
        return InMemoryEventBus()
    
    @pytest.fixture
    def test_event(self):
        """Create test event for testing."""
        return TestEvent("test data")
    
    @pytest.mark.asyncio
    async def test_publish_with_no_handlers(self, event_bus, test_event):
        """Test publishing event with no registered handlers."""
        # Act
        result = await event_bus.publish(test_event)
        
        # Assert
        assert result is True
    
    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, event_bus, test_event):
        """Test subscribing to events and publishing."""
        # Arrange
        handler_called = False
        received_event = None
        
        async def test_handler(event: IEvent):
            nonlocal handler_called, received_event
            handler_called = True
            received_event = event
        
        # Act
        await event_bus.subscribe("TestEvent", test_handler)
        result = await event_bus.publish(test_event)
        
        # Assert
        assert result is True
        assert handler_called is True
        assert received_event == test_event
    
    @pytest.mark.asyncio
    async def test_multiple_handlers(self, event_bus, test_event):
        """Test multiple handlers for same event type."""
        # Arrange
        handler1_called = False
        handler2_called = False
        
        async def handler1(event: IEvent):
            nonlocal handler1_called
            handler1_called = True
        
        async def handler2(event: IEvent):
            nonlocal handler2_called
            handler2_called = True
        
        # Act
        await event_bus.subscribe("TestEvent", handler1)
        await event_bus.subscribe("TestEvent", handler2)
        await event_bus.publish(test_event)
        
        # Assert
        assert handler1_called is True
        assert handler2_called is True
    
    @pytest.mark.asyncio
    async def test_unsubscribe(self, event_bus, test_event):
        """Test unsubscribing from events."""
        # Arrange
        handler_called = False
        
        async def test_handler(event: IEvent):
            nonlocal handler_called
            handler_called = True
        
        # Act
        await event_bus.subscribe("TestEvent", test_handler)
        await event_bus.unsubscribe("TestEvent", test_handler)
        await event_bus.publish(test_event)
        
        # Assert
        assert handler_called is False
    
    @pytest.mark.asyncio
    async def test_subscribe_to_all(self, event_bus, test_event):
        """Test global event subscription."""
        # Arrange
        handler_called = False
        
        async def global_handler(event: IEvent):
            nonlocal handler_called
            handler_called = True
        
        # Act
        await event_bus.subscribe_to_all(global_handler)
        await event_bus.publish(test_event)
        
        # Assert
        assert handler_called is True
    
    @pytest.mark.asyncio
    async def test_get_handlers(self, event_bus):
        """Test getting handlers for event type."""
        # Arrange
        async def test_handler(event: IEvent):
            pass
        
        # Act
        await event_bus.subscribe("TestEvent", test_handler)
        handlers = await event_bus.get_handlers("TestEvent")
        
        # Assert
        assert len(handlers) == 1
        assert test_handler in handlers
    
    @pytest.mark.asyncio
    async def test_clear_handlers(self, event_bus):
        """Test clearing handlers for event type."""
        # Arrange
        async def test_handler(event: IEvent):
            pass
        
        await event_bus.subscribe("TestEvent", test_handler)
        
        # Act
        result = await event_bus.clear_handlers("TestEvent")
        handlers = await event_bus.get_handlers("TestEvent")
        
        # Assert
        assert result is True
        assert len(handlers) == 0
    
    @pytest.mark.asyncio
    async def test_handler_exception_handling(self, event_bus, test_event):
        """Test that handler exceptions don't break event publishing."""
        # Arrange
        handler1_called = False
        handler2_called = False
        
        async def failing_handler(event: IEvent):
            raise Exception("Handler failed")
        
        async def working_handler(event: IEvent):
            nonlocal handler1_called
            handler1_called = True
        
        async def another_working_handler(event: IEvent):
            nonlocal handler2_called
            handler2_called = True
        
        # Act
        await event_bus.subscribe("TestEvent", failing_handler)
        await event_bus.subscribe("TestEvent", working_handler)
        await event_bus.subscribe("TestEvent", another_working_handler)
        
        result = await event_bus.publish(test_event)
        
        # Assert
        assert result is True  # Should still return True despite handler failure
        assert handler1_called is True  # Working handlers should still be called
        assert handler2_called is True
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, event_bus):
        """Test getting event bus statistics."""
        # Arrange
        async def test_handler(event: IEvent):
            pass
        
        async def global_handler(event: IEvent):
            pass
        
        await event_bus.subscribe("TestEvent", test_handler)
        await event_bus.subscribe("AnotherEvent", test_handler)
        await event_bus.subscribe_to_all(global_handler)
        
        # Act
        stats = await event_bus.get_statistics()
        
        # Assert
        assert "total_event_types" in stats
        assert "total_handlers" in stats
        assert "global_handlers" in stats
        assert stats["total_event_types"] == 2
        assert stats["total_handlers"] == 2
        assert stats["global_handlers"] == 1
        assert "handlers_TestEvent" in stats
        assert "handlers_AnotherEvent" in stats


class TestAuditEventHandler:
    """Test cases for AuditEventHandler."""
    
    @pytest.fixture
    def mock_audit_logger(self):
        """Create mock audit logger."""
        audit_logger = MagicMock()
        audit_logger.log_auth_event = AsyncMock()
        audit_logger.log_data_access = AsyncMock()
        return audit_logger
    
    @pytest.fixture
    def audit_handler(self, mock_audit_logger):
        """Create audit event handler with mocked dependencies."""
        handler = AuditEventHandler()
        handler.audit_logger = mock_audit_logger
        return handler
    
    @pytest.mark.asyncio
    async def test_handle_user_authenticated_event(self, audit_handler, mock_audit_logger):
        """Test handling UserAuthenticatedEvent."""
        # Arrange
        event = UserAuthenticatedEvent(
            user_id=1,
            session_id="session-123",
            ip_address="127.0.0.1",
            user_agent="test-agent"
        )
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act
            await audit_handler.handle_event(event)
            
            # Assert
            mock_audit_logger.log_auth_event.assert_called_once()
            call_args = mock_audit_logger.log_auth_event.call_args[1]
            assert call_args["user_id"] == 1
            assert call_args["ip_address"] == "127.0.0.1"
            assert call_args["success"] is True
            assert "session_id" in call_args["event_data"]
    
    @pytest.mark.asyncio
    async def test_handle_login_failed_event(self, audit_handler, mock_audit_logger):
        """Test handling LoginFailedEvent."""
        # Arrange
        event = LoginFailedEvent(
            email="test@example.com",
            reason="invalid_password",
            ip_address="127.0.0.1",
            user_id=1
        )
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act
            await audit_handler.handle_event(event)
            
            # Assert
            mock_audit_logger.log_auth_event.assert_called_once()
            call_args = mock_audit_logger.log_auth_event.call_args[1]
            assert call_args["user_id"] == 1
            assert call_args["ip_address"] == "127.0.0.1"
            assert call_args["success"] is False
            assert "reason" in call_args["event_data"]
    
    @pytest.mark.asyncio
    async def test_handle_token_created_event(self, audit_handler, mock_audit_logger):
        """Test handling TokenCreatedEvent."""
        # Arrange
        event = TokenCreatedEvent(
            user_id=1,
            token_type="access",
            session_id="session-123"
        )
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act
            await audit_handler.handle_event(event)
            
            # Assert
            mock_audit_logger.log_auth_event.assert_called_once()
            call_args = mock_audit_logger.log_auth_event.call_args[1]
            assert call_args["user_id"] == 1
            assert call_args["success"] is True
            assert call_args["event_data"]["token_type"] == "access"
    
    @pytest.mark.asyncio
    async def test_handle_password_reset_initiated_event(self, audit_handler, mock_audit_logger):
        """Test handling PasswordResetInitiatedEvent."""
        # Arrange
        event = PasswordResetInitiatedEvent(
            user_id=1,
            email="test@example.com",
            reset_token="token-123",
            ip_address="127.0.0.1"
        )
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act
            await audit_handler.handle_event(event)
            
            # Assert
            mock_audit_logger.log_auth_event.assert_called_once()
            call_args = mock_audit_logger.log_auth_event.call_args[1]
            assert call_args["user_id"] == 1
            assert call_args["ip_address"] == "127.0.0.1"
            assert call_args["success"] is True
    
    @pytest.mark.asyncio
    async def test_handle_email_verification_requested_event(self, audit_handler, mock_audit_logger):
        """Test handling EmailVerificationRequestedEvent."""
        # Arrange
        event = EmailVerificationRequestedEvent(
            user_id=1,
            email="test@example.com",
            verification_token="token-123",
            is_resend=True
        )
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act
            await audit_handler.handle_event(event)
            
            # Assert
            mock_audit_logger.log_data_access.assert_called_once()
            call_args = mock_audit_logger.log_data_access.call_args[1]
            assert call_args["user_id"] == 1
            assert call_args["success"] is True
            assert call_args["event_data"]["is_resend"] is True
    
    @pytest.mark.asyncio
    async def test_handle_unknown_event(self, audit_handler):
        """Test handling unknown event type."""
        # Arrange
        event = TestEvent("test data")
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_db = AsyncMock()
            mock_get_db.return_value = mock_db
            
            # Act & Assert - Should not raise exception
            await audit_handler.handle_event(event)
    
    @pytest.mark.asyncio
    async def test_handle_event_exception(self, audit_handler):
        """Test exception handling in event handler."""
        # Arrange
        event = UserAuthenticatedEvent(user_id=1, session_id="session-123")
        
        with patch('src.events.audit_handlers.get_db') as mock_get_db:
            mock_get_db.side_effect = Exception("Database error")
            
            # Act & Assert - Should not raise exception
            await audit_handler.handle_event(event)