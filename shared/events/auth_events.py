"""
Authentication domain events
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from .base import DomainEvent


@dataclass
class UserRegistered(DomainEvent):
    """Event raised when a new user is registered"""
    
    user_id: UUID
    email: str
    username: str
    roles: list[str]
    
    @property
    def event_name(self) -> str:
        return "user.registered"


@dataclass
class UserLoggedIn(DomainEvent):
    """Event raised when a user logs in"""
    
    user_id: UUID
    session_id: UUID
    ip_address: str
    user_agent: str
    
    @property
    def event_name(self) -> str:
        return "user.logged_in"


@dataclass
class UserLoggedOut(DomainEvent):
    """Event raised when a user logs out"""
    
    user_id: UUID
    session_id: UUID
    
    @property
    def event_name(self) -> str:
        return "user.logged_out"


@dataclass
class UserPasswordChanged(DomainEvent):
    """Event raised when a user changes their password"""
    
    user_id: UUID
    changed_by: UUID  # User who changed the password (could be admin)
    
    @property
    def event_name(self) -> str:
        return "user.password_changed"


@dataclass
class UserEmailVerified(DomainEvent):
    """Event raised when a user verifies their email"""
    
    user_id: UUID
    email: str
    verified_at: datetime
    
    @property
    def event_name(self) -> str:
        return "user.email_verified"


@dataclass
class UserAccountLocked(DomainEvent):
    """Event raised when a user account is locked"""
    
    user_id: UUID
    reason: str
    locked_until: Optional[datetime]
    locked_by: Optional[UUID]  # Admin who locked the account
    
    @property
    def event_name(self) -> str:
        return "user.account_locked"


@dataclass
class UserAccountUnlocked(DomainEvent):
    """Event raised when a user account is unlocked"""
    
    user_id: UUID
    unlocked_by: Optional[UUID]  # Admin who unlocked the account
    
    @property
    def event_name(self) -> str:
        return "user.account_unlocked"


@dataclass
class UserRoleAssigned(DomainEvent):
    """Event raised when a role is assigned to a user"""
    
    user_id: UUID
    role_name: str
    assigned_by: UUID
    
    @property
    def event_name(self) -> str:
        return "user.role_assigned"


@dataclass
class UserRoleRevoked(DomainEvent):
    """Event raised when a role is revoked from a user"""
    
    user_id: UUID
    role_name: str
    revoked_by: UUID
    
    @property
    def event_name(self) -> str:
        return "user.role_revoked"


@dataclass
class UserDeleted(DomainEvent):
    """Event raised when a user account is deleted"""
    
    user_id: UUID
    deleted_by: UUID
    deletion_reason: str
    
    @property
    def event_name(self) -> str:
        return "user.deleted"


@dataclass
class PasswordResetRequested(DomainEvent):
    """Event raised when a password reset is requested"""
    
    user_id: UUID
    email: str
    reset_token_id: UUID
    expires_at: datetime
    
    @property
    def event_name(self) -> str:
        return "user.password_reset_requested"


@dataclass
class PasswordResetCompleted(DomainEvent):
    """Event raised when a password reset is completed"""
    
    user_id: UUID
    reset_token_id: UUID
    
    @property
    def event_name(self) -> str:
        return "user.password_reset_completed"


@dataclass
class MFAEnabled(DomainEvent):
    """Event raised when MFA is enabled for a user"""
    
    user_id: UUID
    mfa_method: str  # "totp", "sms", "email"
    
    @property
    def event_name(self) -> str:
        return "user.mfa_enabled"


@dataclass
class MFADisabled(DomainEvent):
    """Event raised when MFA is disabled for a user"""
    
    user_id: UUID
    disabled_by: UUID  # User who disabled MFA (could be admin)
    reason: str
    
    @property
    def event_name(self) -> str:
        return "user.mfa_disabled"


@dataclass
class SessionExpired(DomainEvent):
    """Event raised when a user session expires"""
    
    user_id: UUID
    session_id: UUID
    expired_at: datetime
    
    @property
    def event_name(self) -> str:
        return "session.expired"


@dataclass
class LoginAttemptFailed(DomainEvent):
    """Event raised when a login attempt fails"""
    
    email: str
    ip_address: str
    reason: str  # "invalid_credentials", "account_locked", etc.
    attempt_count: int
    
    @property
    def event_name(self) -> str:
        return "auth.login_attempt_failed"