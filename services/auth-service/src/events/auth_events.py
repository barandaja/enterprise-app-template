"""
Authentication-related events for audit logging and system integration.
These events decouple business logic from audit logging concerns.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass

from .base_event import BaseEvent


@dataclass
class UserAuthenticatedEvent(BaseEvent):
    """Event published when a user successfully authenticates."""
    
    user_id: int
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None
    location_data: Optional[Dict[str, Any]] = None


@dataclass
class UserLoggedOutEvent(BaseEvent):
    """Event published when a user logs out."""
    
    user_id: int
    session_id: Optional[str] = None
    session_count: Optional[int] = None
    logout_all: bool = False


@dataclass
class LoginFailedEvent(BaseEvent):
    """Event published when login attempt fails."""
    
    email: str
    reason: str
    ip_address: Optional[str] = None
    user_id: Optional[int] = None


@dataclass
class TokenCreatedEvent(BaseEvent):
    """Event published when a JWT token is created."""
    
    user_id: int
    token_type: str  # "access" or "refresh"
    session_id: Optional[str] = None


@dataclass
class TokenRefreshedEvent(BaseEvent):
    """Event published when tokens are refreshed."""
    
    user_id: int
    session_id: Optional[str] = None
    old_token_id: Optional[str] = None


@dataclass
class PasswordResetInitiatedEvent(BaseEvent):
    """Event published when password reset is initiated."""
    
    user_id: int
    email: str
    reset_token: str
    ip_address: Optional[str] = None


@dataclass
class PasswordResetCompletedEvent(BaseEvent):
    """Event published when password reset is completed."""
    
    user_id: int
    ip_address: Optional[str] = None


@dataclass
class PasswordResetFailedEvent(BaseEvent):
    """Event published when password reset fails."""
    
    email: str
    reason: str
    ip_address: Optional[str] = None


@dataclass
class PasswordChangedEvent(BaseEvent):
    """Event published when password is changed."""
    
    user_id: int
    changed_by_user_id: int
    is_admin_change: bool = False


@dataclass
class EmailVerificationRequestedEvent(BaseEvent):
    """Event published when email verification is requested."""
    
    user_id: int
    email: str
    verification_token: str
    is_resend: bool = False


@dataclass
class EmailVerifiedEvent(BaseEvent):
    """Event published when email is successfully verified."""
    
    user_id: int
    email: str


@dataclass
class UserCreatedEvent(BaseEvent):
    """Event published when a new user is created."""
    
    user_id: int
    email: str
    created_by_user_id: Optional[int] = None
    registration_source: Optional[str] = None


@dataclass
class UserUpdatedEvent(BaseEvent):
    """Event published when user data is updated."""
    
    user_id: int
    updated_fields: list
    updated_by_user_id: Optional[int] = None


@dataclass
class UserDeactivatedEvent(BaseEvent):
    """Event published when user is deactivated."""
    
    user_id: int
    reason: Optional[str] = None
    deactivated_by_user_id: Optional[int] = None


@dataclass
class UserDeletedEvent(BaseEvent):
    """Event published when user is deleted."""
    
    user_id: int
    hard_delete: bool = False
    deleted_by_user_id: Optional[int] = None


@dataclass
class RoleAssignedEvent(BaseEvent):
    """Event published when role is assigned to user."""
    
    user_id: int
    role_name: str
    assigned_by_user_id: Optional[int] = None


@dataclass
class RoleRevokedEvent(BaseEvent):
    """Event published when role is revoked from user."""
    
    user_id: int
    role_name: str
    revoked_by_user_id: Optional[int] = None


@dataclass
class SessionCreatedEvent(BaseEvent):
    """Event published when user session is created."""
    
    user_id: int
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    remember_me: bool = False


@dataclass
class SessionEndedEvent(BaseEvent):
    """Event published when user session ends."""
    
    user_id: int
    session_id: str
    reason: str
    ip_address: Optional[str] = None