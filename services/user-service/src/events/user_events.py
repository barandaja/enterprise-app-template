"""
Domain events for user service
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import uuid4

from ..interfaces.event_interface import IEvent


@dataclass
class BaseUserEvent(IEvent):
    """Base class for user domain events"""
    
    event_id: str
    event_type: str
    occurred_at: datetime
    correlation_id: str
    user_id: str
    
    def __init__(self, user_id: str, correlation_id: Optional[str] = None):
        self.event_id = str(uuid4())
        self.occurred_at = datetime.utcnow()
        self.correlation_id = correlation_id or str(uuid4())
        self.user_id = user_id


@dataclass
class UserCreatedEvent(BaseUserEvent):
    """Event emitted when a new user is created"""
    
    email: str
    username: str
    created_by: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str, 
        email: str, 
        username: str,
        created_by: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserCreated"
        self.email = email
        self.username = username
        self.created_by = created_by


@dataclass
class UserUpdatedEvent(BaseUserEvent):
    """Event emitted when user profile is updated"""
    
    changes: Dict[str, Any]
    updated_by: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str, 
        changes: Dict[str, Any],
        updated_by: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserUpdated"
        self.changes = changes
        self.updated_by = updated_by


@dataclass
class UserDeletedEvent(BaseUserEvent):
    """Event emitted when a user is deleted"""
    
    deleted_by: Optional[str] = None
    reason: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str,
        deleted_by: Optional[str] = None,
        reason: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserDeleted"
        self.deleted_by = deleted_by
        self.reason = reason


@dataclass
class UserActivatedEvent(BaseUserEvent):
    """Event emitted when a user account is activated"""
    
    activated_by: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str,
        activated_by: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserActivated"
        self.activated_by = activated_by


@dataclass
class UserDeactivatedEvent(BaseUserEvent):
    """Event emitted when a user account is deactivated"""
    
    deactivated_by: Optional[str] = None
    reason: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str,
        deactivated_by: Optional[str] = None,
        reason: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserDeactivated"
        self.deactivated_by = deactivated_by
        self.reason = reason


@dataclass
class UserRoleChangedEvent(BaseUserEvent):
    """Event emitted when user role is changed"""
    
    old_role: str
    new_role: str
    changed_by: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str,
        old_role: str,
        new_role: str,
        changed_by: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserRoleChanged"
        self.old_role = old_role
        self.new_role = new_role
        self.changed_by = changed_by


@dataclass
class UserEmailVerifiedEvent(BaseUserEvent):
    """Event emitted when user email is verified"""
    
    email: str
    verification_token: Optional[str] = None
    
    def __init__(
        self, 
        user_id: str,
        email: str,
        verification_token: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserEmailVerified"
        self.email = email
        self.verification_token = verification_token


@dataclass
class UserPasswordChangedEvent(BaseUserEvent):
    """Event emitted when user password is changed"""
    
    changed_by: Optional[str] = None
    reset_token_used: bool = False
    
    def __init__(
        self, 
        user_id: str,
        changed_by: Optional[str] = None,
        reset_token_used: bool = False,
        correlation_id: Optional[str] = None
    ):
        super().__init__(user_id, correlation_id)
        self.event_type = "UserPasswordChanged"
        self.changed_by = changed_by
        self.reset_token_used = reset_token_used