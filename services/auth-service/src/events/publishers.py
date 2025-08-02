"""
Event publishers for auth service
Publishes domain events when significant actions occur
"""

import logging
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from shared.events.base import EventBus
from shared.events.auth_events import (
    UserRegistered, UserLoggedIn, UserLoggedOut,
    UserPasswordChanged, UserEmailVerified,
    UserAccountLocked, UserAccountUnlocked,
    UserRoleAssigned, UserRoleRevoked,
    UserDeleted, PasswordResetRequested,
    PasswordResetCompleted, LoginAttemptFailed,
    SessionExpired
)

from ..models import User


logger = logging.getLogger(__name__)


class AuthEventPublisher:
    """Publishes authentication domain events"""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
    
    async def publish_user_registered(
        self,
        user: User,
        roles: List[str]
    ) -> None:
        """Publish user registration event"""
        event = UserRegistered(
            user_id=user.id,
            email=user.email,
            username=user.username,
            roles=roles
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserRegistered event for user {user.id}")
    
    async def publish_user_logged_in(
        self,
        user_id: UUID,
        session_id: UUID,
        ip_address: str,
        user_agent: str
    ) -> None:
        """Publish user login event"""
        event = UserLoggedIn(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserLoggedIn event for user {user_id}")
    
    async def publish_user_logged_out(
        self,
        user_id: UUID,
        session_id: UUID
    ) -> None:
        """Publish user logout event"""
        event = UserLoggedOut(
            user_id=user_id,
            session_id=session_id
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserLoggedOut event for user {user_id}")
    
    async def publish_password_changed(
        self,
        user_id: UUID,
        changed_by: UUID
    ) -> None:
        """Publish password change event"""
        event = UserPasswordChanged(
            user_id=user_id,
            changed_by=changed_by
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserPasswordChanged event for user {user_id}")
    
    async def publish_email_verified(
        self,
        user: User
    ) -> None:
        """Publish email verification event"""
        event = UserEmailVerified(
            user_id=user.id,
            email=user.email,
            verified_at=datetime.utcnow()
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserEmailVerified event for user {user.id}")
    
    async def publish_account_locked(
        self,
        user_id: UUID,
        reason: str,
        locked_until: Optional[datetime] = None,
        locked_by: Optional[UUID] = None
    ) -> None:
        """Publish account lock event"""
        event = UserAccountLocked(
            user_id=user_id,
            reason=reason,
            locked_until=locked_until,
            locked_by=locked_by
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserAccountLocked event for user {user_id}")
    
    async def publish_account_unlocked(
        self,
        user_id: UUID,
        unlocked_by: Optional[UUID] = None
    ) -> None:
        """Publish account unlock event"""
        event = UserAccountUnlocked(
            user_id=user_id,
            unlocked_by=unlocked_by
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserAccountUnlocked event for user {user_id}")
    
    async def publish_role_assigned(
        self,
        user_id: UUID,
        role_name: str,
        assigned_by: UUID
    ) -> None:
        """Publish role assignment event"""
        event = UserRoleAssigned(
            user_id=user_id,
            role_name=role_name,
            assigned_by=assigned_by
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserRoleAssigned event for user {user_id}, role {role_name}")
    
    async def publish_role_revoked(
        self,
        user_id: UUID,
        role_name: str,
        revoked_by: UUID
    ) -> None:
        """Publish role revocation event"""
        event = UserRoleRevoked(
            user_id=user_id,
            role_name=role_name,
            revoked_by=revoked_by
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserRoleRevoked event for user {user_id}, role {role_name}")
    
    async def publish_user_deleted(
        self,
        user_id: UUID,
        deleted_by: UUID,
        deletion_reason: str
    ) -> None:
        """Publish user deletion event"""
        event = UserDeleted(
            user_id=user_id,
            deleted_by=deleted_by,
            deletion_reason=deletion_reason
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published UserDeleted event for user {user_id}")
    
    async def publish_password_reset_requested(
        self,
        user_id: UUID,
        email: str,
        reset_token_id: UUID,
        expires_at: datetime
    ) -> None:
        """Publish password reset request event"""
        event = PasswordResetRequested(
            user_id=user_id,
            email=email,
            reset_token_id=reset_token_id,
            expires_at=expires_at
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published PasswordResetRequested event for user {user_id}")
    
    async def publish_password_reset_completed(
        self,
        user_id: UUID,
        reset_token_id: UUID
    ) -> None:
        """Publish password reset completion event"""
        event = PasswordResetCompleted(
            user_id=user_id,
            reset_token_id=reset_token_id
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published PasswordResetCompleted event for user {user_id}")
    
    async def publish_login_attempt_failed(
        self,
        email: str,
        ip_address: str,
        reason: str,
        attempt_count: int
    ) -> None:
        """Publish failed login attempt event"""
        event = LoginAttemptFailed(
            email=email,
            ip_address=ip_address,
            reason=reason,
            attempt_count=attempt_count
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published LoginAttemptFailed event for email {email}")
    
    async def publish_session_expired(
        self,
        user_id: UUID,
        session_id: UUID,
        expired_at: datetime
    ) -> None:
        """Publish session expiration event"""
        event = SessionExpired(
            user_id=user_id,
            session_id=session_id,
            expired_at=expired_at
        )
        
        await self.event_bus.publish(event)
        logger.info(f"Published SessionExpired event for user {user_id}, session {session_id}")