"""
User Registration Saga
Orchestrates the user registration process across multiple services
"""

import logging
from typing import Optional
from uuid import UUID

from ..base import Saga, DomainEvent, EventBus
from ..auth_events import (
    UserRegistered, UserDeleted, UserEmailVerified,
    UserAccountLocked
)
from ..user_events import (
    UserProfileCreated, UserPreferencesUpdated,
    UserNotificationPreferencesUpdated
)


logger = logging.getLogger(__name__)


class UserRegistrationSaga(Saga):
    """
    Orchestrates user registration across services:
    1. User registered in auth service
    2. User profile created in user service
    3. Default preferences set
    4. Welcome email sent
    5. Analytics updated
    """
    
    def __init__(self, saga_id: Optional[UUID] = None, event_bus: Optional[EventBus] = None):
        super().__init__(saga_id)
        self.event_bus = event_bus
        self.user_id: Optional[UUID] = None
        self.email: Optional[str] = None
        self.username: Optional[str] = None
        
        # Define saga steps
        self.steps = [
            "auth_service.user_registered",
            "user_service.profile_created",
            "user_service.preferences_set",
            "notification_service.welcome_email_sent",
            "analytics_service.user_tracked"
        ]
    
    async def handle(self, event: DomainEvent) -> None:
        """Handle events and orchestrate the saga"""
        
        if isinstance(event, UserRegistered):
            await self._handle_user_registered(event)
            
        elif isinstance(event, UserProfileCreated):
            await self._handle_profile_created(event)
            
        elif isinstance(event, UserPreferencesUpdated):
            await self._handle_preferences_updated(event)
            
        else:
            logger.warning(f"Saga {self.saga_id} received unexpected event: {event.event_name}")
    
    async def _handle_user_registered(self, event: UserRegistered):
        """Handle the initial user registration event"""
        logger.info(f"Starting user registration saga for user {event.user_id}")
        
        self.user_id = event.user_id
        self.email = event.email
        self.username = event.username
        
        self.mark_step_completed("auth_service.user_registered")
        
        # Trigger profile creation in user service
        profile_created_event = UserProfileCreated(
            user_id=event.user_id,
            first_name="",  # To be updated by user
            last_name="",
            display_name=event.username,
            metadata={
                "saga_id": str(self.saga_id),
                "triggered_by": "registration_saga"
            }
        )
        
        if self.event_bus:
            await self.event_bus.publish(profile_created_event)
    
    async def _handle_profile_created(self, event: UserProfileCreated):
        """Handle profile creation completion"""
        if event.user_id != self.user_id:
            return
        
        logger.info(f"Profile created for user {event.user_id}")
        self.mark_step_completed("user_service.profile_created")
        
        # Set default preferences
        preferences_event = UserPreferencesUpdated(
            user_id=event.user_id,
            preferences={
                "theme": "light",
                "language": "en",
                "timezone": "UTC",
                "email_notifications": True,
                "marketing_emails": False
            },
            metadata={
                "saga_id": str(self.saga_id),
                "triggered_by": "registration_saga"
            }
        )
        
        if self.event_bus:
            await self.event_bus.publish(preferences_event)
    
    async def _handle_preferences_updated(self, event: UserPreferencesUpdated):
        """Handle preferences update completion"""
        if event.user_id != self.user_id:
            return
        
        logger.info(f"Preferences set for user {event.user_id}")
        self.mark_step_completed("user_service.preferences_set")
        
        # Set notification preferences
        notification_prefs_event = UserNotificationPreferencesUpdated(
            user_id=event.user_id,
            email_notifications=True,
            sms_notifications=False,
            push_notifications=True,
            notification_categories={
                "security": True,
                "updates": True,
                "marketing": False,
                "social": True
            },
            metadata={
                "saga_id": str(self.saga_id),
                "triggered_by": "registration_saga"
            }
        )
        
        if self.event_bus:
            await self.event_bus.publish(notification_prefs_event)
        
        # In a real implementation, we would also:
        # - Send welcome email via notification service
        # - Track user in analytics service
        # For now, we'll mark these as completed
        self.mark_step_completed("notification_service.welcome_email_sent")
        self.mark_step_completed("analytics_service.user_tracked")
        
        # Mark saga as completed
        self.mark_completed()
        logger.info(f"User registration saga completed for user {event.user_id}")
    
    async def compensate(self) -> None:
        """Compensate (rollback) the saga in case of failure"""
        logger.warning(f"Compensating user registration saga for user {self.user_id}")
        
        if not self.user_id or not self.event_bus:
            return
        
        # Compensate in reverse order
        compensations = []
        
        # If profile was created, delete it
        if "user_service.profile_created" in self.completed_steps:
            # In a real implementation, we'd have a UserProfileDeleted event
            # For now, we'll just log it
            logger.info(f"Would delete profile for user {self.user_id}")
        
        # If user was registered, delete the user
        if "auth_service.user_registered" in self.completed_steps:
            user_deleted_event = UserDeleted(
                user_id=self.user_id,
                deleted_by=self.user_id,  # Self-deletion due to failed registration
                deletion_reason="Registration saga failed",
                metadata={
                    "saga_id": str(self.saga_id),
                    "compensation": True
                }
            )
            compensations.append(user_deleted_event)
        
        # Publish compensation events
        for event in compensations:
            await self.event_bus.publish(event)
        
        logger.info(f"Compensation completed for user registration saga")


class UserDeletionSaga(Saga):
    """
    Orchestrates user deletion across services (GDPR compliance):
    1. Archive user data
    2. Delete user profile
    3. Delete user authentication
    4. Remove from analytics
    5. Notify user of deletion
    """
    
    def __init__(self, saga_id: Optional[UUID] = None, event_bus: Optional[EventBus] = None):
        super().__init__(saga_id)
        self.event_bus = event_bus
        self.user_id: Optional[UUID] = None
        self.deletion_reason: Optional[str] = None
        
        self.steps = [
            "archive_service.user_data_archived",
            "user_service.profile_deleted",
            "auth_service.user_deleted",
            "analytics_service.user_removed",
            "notification_service.deletion_confirmed"
        ]
    
    async def handle(self, event: DomainEvent) -> None:
        """Handle events for user deletion saga"""
        # Implementation would follow similar pattern to registration saga
        pass
    
    async def compensate(self) -> None:
        """Compensate user deletion - restore user data"""
        # This would restore user data from archives
        pass


class PasswordResetSaga(Saga):
    """
    Orchestrates password reset process:
    1. Generate reset token
    2. Send reset email
    3. Validate token
    4. Update password
    5. Notify user of change
    6. Invalidate all sessions
    """
    
    def __init__(self, saga_id: Optional[UUID] = None, event_bus: Optional[EventBus] = None):
        super().__init__(saga_id)
        self.event_bus = event_bus
        self.user_id: Optional[UUID] = None
        self.reset_token_id: Optional[UUID] = None
        
        self.steps = [
            "auth_service.reset_token_generated",
            "notification_service.reset_email_sent",
            "auth_service.token_validated",
            "auth_service.password_updated",
            "notification_service.change_confirmed",
            "auth_service.sessions_invalidated"
        ]
    
    async def handle(self, event: DomainEvent) -> None:
        """Handle events for password reset saga"""
        # Implementation would follow similar pattern
        pass
    
    async def compensate(self) -> None:
        """Compensate password reset - restore original password"""
        # This would restore the original password if possible
        pass