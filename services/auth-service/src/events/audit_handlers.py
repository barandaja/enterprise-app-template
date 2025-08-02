"""
Event handlers for audit logging.
Decouples audit logging from business logic through event-driven architecture.
"""

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from ..interfaces.event_interface import IEvent
from ..models.audit import AuditLogger, AuditEventType, AuditSeverity
from ..core.database import get_db
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
    EmailVerifiedEvent,
    UserCreatedEvent,
    UserUpdatedEvent,
    UserDeactivatedEvent,
    UserDeletedEvent,
    RoleAssignedEvent,
    RoleRevokedEvent,
    SessionCreatedEvent,
    SessionEndedEvent
)

logger = structlog.get_logger()


class AuditEventHandler:
    """Handler for audit logging events."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
    
    async def handle_event(self, event: IEvent) -> None:
        """
        Main event handler that routes events to specific audit methods.
        
        Args:
            event: Event to handle
        """
        try:
            # Get database session
            db = next(get_db())
            
            try:
                # Route event to appropriate handler
                if isinstance(event, UserAuthenticatedEvent):
                    await self._handle_user_authenticated(db, event)
                elif isinstance(event, UserLoggedOutEvent):
                    await self._handle_user_logged_out(db, event)
                elif isinstance(event, LoginFailedEvent):
                    await self._handle_login_failed(db, event)
                elif isinstance(event, TokenCreatedEvent):
                    await self._handle_token_created(db, event)
                elif isinstance(event, TokenRefreshedEvent):
                    await self._handle_token_refreshed(db, event)
                elif isinstance(event, PasswordResetInitiatedEvent):
                    await self._handle_password_reset_initiated(db, event)
                elif isinstance(event, PasswordResetCompletedEvent):
                    await self._handle_password_reset_completed(db, event)
                elif isinstance(event, PasswordResetFailedEvent):
                    await self._handle_password_reset_failed(db, event)
                elif isinstance(event, PasswordChangedEvent):
                    await self._handle_password_changed(db, event)
                elif isinstance(event, EmailVerificationRequestedEvent):
                    await self._handle_email_verification_requested(db, event)
                elif isinstance(event, EmailVerifiedEvent):
                    await self._handle_email_verified(db, event)
                elif isinstance(event, UserCreatedEvent):
                    await self._handle_user_created(db, event)
                elif isinstance(event, UserUpdatedEvent):
                    await self._handle_user_updated(db, event)
                elif isinstance(event, UserDeactivatedEvent):
                    await self._handle_user_deactivated(db, event)
                elif isinstance(event, UserDeletedEvent):
                    await self._handle_user_deleted(db, event)
                elif isinstance(event, RoleAssignedEvent):
                    await self._handle_role_assigned(db, event)
                elif isinstance(event, RoleRevokedEvent):
                    await self._handle_role_revoked(db, event)
                elif isinstance(event, SessionCreatedEvent):
                    await self._handle_session_created(db, event)
                elif isinstance(event, SessionEndedEvent):
                    await self._handle_session_ended(db, event)
                else:
                    logger.debug("No audit handler for event type", event_type=event.event_type)
            
            finally:
                await db.close()
        
        except Exception as e:
            logger.error(
                "Audit event handling failed",
                event_type=event.event_type,
                correlation_id=event.correlation_id,
                error=str(e)
            )
    
    async def _handle_user_authenticated(
        self, 
        db: AsyncSession, 
        event: UserAuthenticatedEvent
    ) -> None:
        """Handle user authentication event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=True,
            description="User authenticated successfully",
            event_data={
                "session_id": event.session_id,
                "user_agent": event.user_agent,
                "device_info": event.device_info,
                "location_data": event.location_data,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_user_logged_out(
        self, 
        db: AsyncSession, 
        event: UserLoggedOutEvent
    ) -> None:
        """Handle user logout event."""
        description = "User logged out"
        if event.logout_all:
            description += f" (all {event.session_count} sessions)"
        
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.LOGOUT,
            user_id=event.user_id,
            success=True,
            description=description,
            event_data={
                "session_id": event.session_id,
                "session_count": event.session_count,
                "logout_all": event.logout_all,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_login_failed(
        self, 
        db: AsyncSession, 
        event: LoginFailedEvent
    ) -> None:
        """Handle login failure event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILURE,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=False,
            description=f"Login failed: {event.reason}",
            event_data={
                "reason": event.reason,
                "correlation_id": event.correlation_id
            },
            severity=AuditSeverity.MEDIUM
        )
    
    async def _handle_token_created(
        self, 
        db: AsyncSession, 
        event: TokenCreatedEvent
    ) -> None:
        """Handle token creation event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.TOKEN_CREATED,
            user_id=event.user_id,
            success=True,
            description=f"{event.token_type.title()} token created",
            event_data={
                "token_type": event.token_type,
                "session_id": event.session_id,
                "correlation_id": event.correlation_id
            },
            severity=AuditSeverity.LOW
        )
    
    async def _handle_token_refreshed(
        self, 
        db: AsyncSession, 
        event: TokenRefreshedEvent
    ) -> None:
        """Handle token refresh event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.TOKEN_REFRESHED,
            user_id=event.user_id,
            success=True,
            description="Tokens refreshed",
            event_data={
                "session_id": event.session_id,
                "old_token_id": event.old_token_id,
                "correlation_id": event.correlation_id
            },
            severity=AuditSeverity.LOW
        )
    
    async def _handle_password_reset_initiated(
        self, 
        db: AsyncSession, 
        event: PasswordResetInitiatedEvent
    ) -> None:
        """Handle password reset initiation event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.PASSWORD_RESET,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=True,
            description="Password reset requested",
            event_data={
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_password_reset_completed(
        self, 
        db: AsyncSession, 
        event: PasswordResetCompletedEvent
    ) -> None:
        """Handle password reset completion event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.PASSWORD_CHANGE,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=True,
            description="Password reset completed",
            event_data={
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_password_reset_failed(
        self, 
        db: AsyncSession, 
        event: PasswordResetFailedEvent
    ) -> None:
        """Handle password reset failure event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.PASSWORD_RESET,
            ip_address=event.ip_address,
            success=False,
            description=f"Password reset failed: {event.reason}",
            event_data={
                "reason": event.reason,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_password_changed(
        self, 
        db: AsyncSession, 
        event: PasswordChangedEvent
    ) -> None:
        """Handle password change event."""
        description = "Password changed"
        if event.is_admin_change:
            description += " by administrator"
        
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.PASSWORD_CHANGE,
            user_id=event.user_id,
            success=True,
            description=description,
            event_data={
                "changed_by_user_id": event.changed_by_user_id,
                "is_admin_change": event.is_admin_change,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_email_verification_requested(
        self, 
        db: AsyncSession, 
        event: EmailVerificationRequestedEvent
    ) -> None:
        """Handle email verification request event."""
        description = "Email verification requested"
        if event.is_resend:
            description += " (resend)"
        
        await self.audit_logger.log_data_access(
            db=db,
            action="verify_email_request",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.user_id,
            success=True,
            description=description,
            event_data={
                "is_resend": event.is_resend,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_email_verified(
        self, 
        db: AsyncSession, 
        event: EmailVerifiedEvent
    ) -> None:
        """Handle email verification completion event."""
        await self.audit_logger.log_data_access(
            db=db,
            action="verify_email",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.user_id,
            success=True,
            description="Email address verified",
            event_data={
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_user_created(
        self, 
        db: AsyncSession, 
        event: UserCreatedEvent
    ) -> None:
        """Handle user creation event."""
        await self.audit_logger.log_data_access(
            db=db,
            action="create",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.created_by_user_id,
            success=True,
            description="User created",
            event_data={
                "registration_source": event.registration_source,
                "correlation_id": event.correlation_id
            },
            pii_accessed=True
        )
    
    async def _handle_user_updated(
        self, 
        db: AsyncSession, 
        event: UserUpdatedEvent
    ) -> None:
        """Handle user update event."""
        pii_fields = {"first_name", "last_name", "phone_number", "email"}
        has_pii = any(field in pii_fields for field in event.updated_fields)
        
        await self.audit_logger.log_data_access(
            db=db,
            action="update",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.updated_by_user_id,
            success=True,
            description="User updated",
            event_data={
                "updated_fields": event.updated_fields,
                "correlation_id": event.correlation_id
            },
            pii_accessed=has_pii
        )
    
    async def _handle_user_deactivated(
        self, 
        db: AsyncSession, 
        event: UserDeactivatedEvent
    ) -> None:
        """Handle user deactivation event."""
        await self.audit_logger.log_data_access(
            db=db,
            action="deactivate",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.deactivated_by_user_id,
            success=True,
            description=f"User deactivated: {event.reason or 'No reason provided'}",
            event_data={
                "reason": event.reason,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_user_deleted(
        self, 
        db: AsyncSession, 
        event: UserDeletedEvent
    ) -> None:
        """Handle user deletion event."""
        event_type = AuditEventType.GDPR_DATA_DELETE if event.hard_delete else AuditEventType.USER_DELETED
        
        await self.audit_logger.log_data_access(
            db=db,
            action="delete",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.deleted_by_user_id,
            success=True,
            description=f"User {'permanently ' if event.hard_delete else ''}deleted",
            event_data={
                "hard_delete": event.hard_delete,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_role_assigned(
        self, 
        db: AsyncSession, 
        event: RoleAssignedEvent
    ) -> None:
        """Handle role assignment event."""
        await self.audit_logger.log_data_access(
            db=db,
            action="assign_role",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.assigned_by_user_id,
            success=True,
            description=f"Role '{event.role_name}' assigned to user",
            event_data={
                "role": event.role_name,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_role_revoked(
        self, 
        db: AsyncSession, 
        event: RoleRevokedEvent
    ) -> None:
        """Handle role revocation event."""
        await self.audit_logger.log_data_access(
            db=db,
            action="revoke_role",
            resource_type="user",
            resource_id=str(event.user_id),
            user_id=event.revoked_by_user_id,
            success=True,
            description=f"Role '{event.role_name}' revoked from user",
            event_data={
                "role": event.role_name,
                "correlation_id": event.correlation_id
            }
        )
    
    async def _handle_session_created(
        self, 
        db: AsyncSession, 
        event: SessionCreatedEvent
    ) -> None:
        """Handle session creation event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.SESSION_CREATED,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=True,
            description="User session created",
            event_data={
                "session_id": event.session_id,
                "user_agent": event.user_agent,
                "remember_me": event.remember_me,
                "correlation_id": event.correlation_id
            },
            severity=AuditSeverity.LOW
        )
    
    async def _handle_session_ended(
        self, 
        db: AsyncSession, 
        event: SessionEndedEvent
    ) -> None:
        """Handle session end event."""
        await self.audit_logger.log_auth_event(
            db=db,
            event_type=AuditEventType.SESSION_ENDED,
            user_id=event.user_id,
            ip_address=event.ip_address,
            success=True,
            description=f"User session ended: {event.reason}",
            event_data={
                "session_id": event.session_id,
                "reason": event.reason,
                "correlation_id": event.correlation_id
            },
            severity=AuditSeverity.LOW
        )