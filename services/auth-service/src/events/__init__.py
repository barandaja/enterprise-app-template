"""
Event system implementation for decoupled audit logging and business logic.
Provides event-driven architecture with async event bus and handlers.
"""

from .event_bus import EventBus, InMemoryEventBus
from .base_event import BaseEvent
from .auth_events import (
    UserAuthenticatedEvent,
    UserLoggedOutEvent,
    LoginFailedEvent,
    TokenCreatedEvent,
    TokenRefreshedEvent,
    PasswordResetInitiatedEvent,
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
    PasswordChangedEvent,
    EmailVerificationRequestedEvent,
    EmailVerifiedEvent
)
from .audit_handlers import AuditEventHandler

__all__ = [
    "EventBus",
    "InMemoryEventBus",
    "BaseEvent",
    "UserAuthenticatedEvent",
    "UserLoggedOutEvent",
    "LoginFailedEvent",
    "TokenCreatedEvent",
    "TokenRefreshedEvent",
    "PasswordResetInitiatedEvent",
    "PasswordResetCompletedEvent",
    "PasswordResetFailedEvent",
    "PasswordChangedEvent",
    "EmailVerificationRequestedEvent",
    "EmailVerifiedEvent",
    "AuditEventHandler"
]