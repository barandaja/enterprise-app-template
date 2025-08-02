"""
Event handlers for auth service
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from shared.events.base import EventHandler, DomainEvent
from shared.events.user_events import (
    UserProfileCreated, UserDeleted as UserDeletedEvent,
    UserDataExportRequested, UserVerificationCompleted
)
from shared.events.auth_events import UserDeleted, UserAccountLocked

from ..models import User
from ..database import get_session
from ..services.audit_service import AuditService


logger = logging.getLogger(__name__)


class UserProfileCreatedHandler(EventHandler):
    """Handle user profile creation events from user service"""
    
    def __init__(self, session_factory=None):
        self.session_factory = session_factory or get_session
    
    @property
    def event_type(self):
        return UserProfileCreated
    
    async def handle(self, event: UserProfileCreated) -> None:
        """Update auth service when user profile is created"""
        logger.info(f"Handling UserProfileCreated event for user {event.user_id}")
        
        async with self.session_factory() as session:
            # Update user record with profile creation status
            user = await session.get(User, event.user_id)
            if user:
                user.profile_created = True
                user.display_name = event.display_name
                
                await session.commit()
                
                # Log audit event
                audit_service = AuditService(session)
                await audit_service.log_event(
                    user_id=event.user_id,
                    event_type="profile_created",
                    event_data={
                        "display_name": event.display_name,
                        "triggered_by_event": event.event_id
                    }
                )


class UserVerificationCompletedHandler(EventHandler):
    """Handle user verification completion from user service"""
    
    def __init__(self, session_factory=None):
        self.session_factory = session_factory or get_session
    
    @property
    def event_type(self):
        return UserVerificationCompleted
    
    async def handle(self, event: UserVerificationCompleted) -> None:
        """Update user verification status"""
        logger.info(f"Handling UserVerificationCompleted for user {event.user_id}")
        
        async with self.session_factory() as session:
            user = await session.get(User, event.user_id)
            if user:
                # Update verification status based on type
                if event.verification_type == "identity":
                    user.identity_verified = True
                    user.verification_level = event.verification_level
                elif event.verification_type == "email":
                    user.email_verified = True
                
                await session.commit()
                
                # Log audit event
                audit_service = AuditService(session)
                await audit_service.log_event(
                    user_id=event.user_id,
                    event_type="verification_completed",
                    event_data={
                        "verification_type": event.verification_type,
                        "verification_level": event.verification_level
                    }
                )


class UserDataExportRequestedHandler(EventHandler):
    """Handle GDPR data export requests"""
    
    def __init__(self, session_factory=None, export_service=None):
        self.session_factory = session_factory or get_session
        self.export_service = export_service
    
    @property
    def event_type(self):
        return UserDataExportRequested
    
    async def handle(self, event: UserDataExportRequested) -> None:
        """Export auth service data for user"""
        logger.info(f"Handling data export request for user {event.user_id}")
        
        async with self.session_factory() as session:
            user = await session.get(User, event.user_id)
            if not user:
                logger.warning(f"User {event.user_id} not found for data export")
                return
            
            # Collect auth service data
            auth_data = {
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "username": user.username,
                    "created_at": user.created_at.isoformat(),
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "email_verified": user.email_verified,
                    "is_active": user.is_active,
                    "roles": [role.name for role in user.roles]
                },
                "sessions": [],
                "audit_logs": []
            }
            
            # Get user sessions
            for session in user.sessions:
                auth_data["sessions"].append({
                    "id": str(session.id),
                    "created_at": session.created_at.isoformat(),
                    "last_activity": session.last_activity.isoformat(),
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent
                })
            
            # Get audit logs (limited to last 90 days for performance)
            audit_service = AuditService(session)
            audit_logs = await audit_service.get_user_audit_logs(
                user_id=event.user_id,
                days=90
            )
            
            for log in audit_logs:
                auth_data["audit_logs"].append({
                    "timestamp": log.timestamp.isoformat(),
                    "event_type": log.event_type,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent
                })
            
            # Send data to export service
            if self.export_service:
                await self.export_service.add_service_data(
                    export_id=event.export_id,
                    service_name="auth",
                    data=auth_data
                )


class UserDeletedFromOtherServiceHandler(EventHandler):
    """Handle user deletion events from other services"""
    
    def __init__(self, session_factory=None, event_bus=None):
        self.session_factory = session_factory or get_session
        self.event_bus = event_bus
    
    @property
    def event_type(self):
        return UserDeletedEvent  # From user service
    
    async def handle(self, event: UserDeletedEvent) -> None:
        """Handle cascading user deletion"""
        logger.info(f"Handling user deletion cascade for user {event.user_id}")
        
        async with self.session_factory() as session:
            user = await session.get(User, event.user_id)
            if not user:
                logger.warning(f"User {event.user_id} not found, may already be deleted")
                return
            
            # Mark user as deleted (soft delete)
            user.is_deleted = True
            user.is_active = False
            user.deleted_at = event.occurred_at
            
            # Invalidate all sessions
            for user_session in user.sessions:
                user_session.is_active = False
                user_session.invalidated_at = event.occurred_at
            
            await session.commit()
            
            # Publish auth service deletion event
            if self.event_bus:
                auth_deleted_event = UserDeleted(
                    user_id=event.user_id,
                    deleted_by=event.deleted_by,
                    deletion_reason=f"Cascade from user service: {event.deletion_reason}",
                    metadata={
                        "triggered_by_event": str(event.event_id),
                        "cascade_deletion": True
                    }
                )
                await self.event_bus.publish(auth_deleted_event)
            
            # Log audit event
            audit_service = AuditService(session)
            await audit_service.log_event(
                user_id=event.user_id,
                event_type="user_deleted",
                event_data={
                    "deletion_type": "cascade",
                    "triggered_by": str(event.event_id),
                    "deleted_by": str(event.deleted_by)
                }
            )