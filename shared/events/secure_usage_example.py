"""
Example of how to use the secure event bus in services
"""

import asyncio
import os
from datetime import datetime
from uuid import uuid4

from .secure_config import create_secure_event_bus, create_service_token
from .auth_events import UserRegistered
from .user_events import UserProfileCreated
from .base import EventHandler


# Example: Auth Service startup
async def auth_service_example():
    """Example of auth service using secure event bus"""
    
    # Create service token (in production, this would be provided by a secure token service)
    service_token = create_service_token(
        service_name="auth_service",
        roles={"auth-service"}
    )
    
    # Create secure event bus
    event_bus = await create_secure_event_bus(service_token)
    
    # Example: Publish user registered event
    user_registered_event = UserRegistered(
        event_id=uuid4(),
        occurred_at=datetime.utcnow(),
        user_id=uuid4(),
        email="user@example.com",
        username="johndoe",
        roles=["user"]
    )
    
    try:
        await event_bus.publish(user_registered_event)
        print("Successfully published UserRegistered event")
    except PermissionError as e:
        print(f"Permission denied: {e}")
    
    # Example: Subscribe to user profile created events
    class ProfileCreatedHandler(EventHandler):
        @property
        def event_type(self):
            return UserProfileCreated
        
        async def handle(self, event: UserProfileCreated):
            print(f"Auth service received UserProfileCreated for user {event.user_id}")
            # Update user status in auth database
    
    try:
        await event_bus.subscribe(UserProfileCreated, ProfileCreatedHandler())
        print("Successfully subscribed to UserProfileCreated events")
    except PermissionError as e:
        print(f"Permission denied: {e}")


# Example: User Service startup
async def user_service_example():
    """Example of user service using secure event bus"""
    
    # Create service token
    service_token = create_service_token(
        service_name="user_service",
        roles={"user-service"}
    )
    
    # Create secure event bus
    event_bus = await create_secure_event_bus(service_token)
    
    # Subscribe to user registered events
    class UserRegisteredHandler(EventHandler):
        @property
        def event_type(self):
            return UserRegistered
        
        async def handle(self, event: UserRegistered):
            print(f"User service received UserRegistered for {event.email}")
            
            # Create user profile
            profile_created_event = UserProfileCreated(
                event_id=uuid4(),
                occurred_at=datetime.utcnow(),
                user_id=event.user_id,
                profile_data={
                    "display_name": event.username,
                    "email": event.email,
                    "created_at": datetime.utcnow().isoformat()
                }
            )
            
            # Publish profile created event
            await event_bus.publish(profile_created_event)
    
    try:
        await event_bus.subscribe(UserRegistered, UserRegisteredHandler())
        print("User service subscribed to UserRegistered events")
    except PermissionError as e:
        print(f"Permission denied: {e}")


# Example: Unauthorized service trying to access events
async def unauthorized_service_example():
    """Example of unauthorized access attempts"""
    
    # Create token for a service without proper permissions
    service_token = create_service_token(
        service_name="analytics_service",
        roles={"analytics"}  # This role doesn't have permissions for auth events
    )
    
    # Create secure event bus
    event_bus = await create_secure_event_bus(service_token)
    
    # Try to publish auth event (should fail)
    try:
        user_registered_event = UserRegistered(
            event_id=uuid4(),
            occurred_at=datetime.utcnow(),
            user_id=uuid4(),
            email="hacker@example.com",
            username="hacker",
            roles=["admin"]  # Trying to escalate privileges
        )
        await event_bus.publish(user_registered_event)
        print("ERROR: Unauthorized publish succeeded!")
    except PermissionError as e:
        print(f"Good: Permission correctly denied - {e}")


# Example: Rate limiting in action
async def rate_limiting_example():
    """Example of rate limiting"""
    
    # Create service token
    service_token = create_service_token(
        service_name="notification_service",
        roles={"notification-service"}
    )
    
    # Create secure event bus
    event_bus = await create_secure_event_bus(service_token)
    
    # Try to exceed rate limit
    for i in range(1100):  # Default limit is 1000/minute
        try:
            # Notification services can publish notification events
            from .base import DomainEvent
            
            class NotificationSent(DomainEvent):
                @property
                def event_name(self):
                    return "notification.sent"
                
                def to_dict(self):
                    return {"notification_id": str(self.event_id)}
            
            await event_bus.publish(NotificationSent(
                event_id=uuid4(),
                occurred_at=datetime.utcnow()
            ))
            
            if i % 100 == 0:
                print(f"Published {i} events")
                
        except PermissionError as e:
            print(f"Rate limit hit at event {i}: {e}")
            break


# Example: Running all examples
async def main():
    """Run all examples"""
    print("=== Auth Service Example ===")
    await auth_service_example()
    
    print("\n=== User Service Example ===")
    await user_service_example()
    
    print("\n=== Unauthorized Access Example ===")
    await unauthorized_service_example()
    
    print("\n=== Rate Limiting Example ===")
    await rate_limiting_example()


if __name__ == "__main__":
    # Set up environment variables for demo
    os.environ["EVENT_JWT_SECRET"] = "demo_jwt_secret_key_32_bytes_long!"
    os.environ["EVENT_ENCRYPTION_KEY"] = "demo_encryption_key_32_bytes_ok!"
    os.environ["EVENT_HMAC_SECRET"] = "demo_hmac_secret"
    
    asyncio.run(main())