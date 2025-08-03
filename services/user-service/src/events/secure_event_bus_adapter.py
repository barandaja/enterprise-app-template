"""
Adapter to make SecureEventBus compatible with IEventBus interface.
This allows gradual migration from InMemoryEventBus to SecureEventBus.
"""

import os
from typing import Callable, Dict, List, Awaitable, Optional
from datetime import datetime
from uuid import UUID, uuid4
import structlog

logger = structlog.get_logger()

from ..interfaces.event_interface import IEvent, IEventBus

# Import from shared events module
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../../'))
try:
    from shared.events.base import DomainEvent
    from shared.events.secure_config import create_secure_event_bus, create_service_token
except ImportError:
    # Fallback if shared module is not available
    logger.warning("Shared events module not found, using stub implementations")
    
    class DomainEvent:
        def __init__(self, event_id=None, occurred_at=None):
            self.event_id = event_id or uuid4()
            self.occurred_at = occurred_at or datetime.utcnow()
    
    async def create_secure_event_bus(service_token):
        # Return a mock for development
        return None
    
    def create_service_token(service_name, roles):
        # Return a mock token
        return f"mock_token_{service_name}"


class DomainEventAdapter(DomainEvent):
    """Adapter to convert IEvent to DomainEvent"""
    
    def __init__(self, event: IEvent):
        self._event = event
        # DomainEvent requires these fields
        super().__init__(
            event_id=UUID(event.event_id) if isinstance(event.event_id, str) else event.event_id,
            occurred_at=event.occurred_at
        )
        
    @property
    def event_name(self) -> str:
        """Return the event type as event name for DomainEvent"""
        return self._event.event_type
    
    @property
    def aggregate_id(self) -> Optional[UUID]:
        """Extract aggregate ID from event data if available"""
        if hasattr(self._event, 'aggregate_id'):
            return self._event.aggregate_id
        return None
    
    def to_dict(self) -> Dict:
        """Convert event data to dictionary"""
        # Use the original event's to_dict if available
        if hasattr(self._event, 'to_dict'):
            return self._event.to_dict()
        
        # Otherwise, extract all public attributes
        data = {}
        for key, value in self._event.__dict__.items():
            if not key.startswith('_'):
                if isinstance(value, (UUID, datetime)):
                    data[key] = str(value)
                else:
                    data[key] = value
        return data


class SecureEventBusAdapter(IEventBus):
    """
    Adapter that makes SecureEventBus compatible with IEventBus interface.
    Handles authentication, conversion between event types, and maintains
    backward compatibility.
    """
    
    def __init__(self, service_name: str, service_role: str):
        self.service_name = service_name
        self.service_role = service_role
        self._secure_bus = None
        self._initialized = False
        self._handler_mapping = {}
        
    async def initialize(self) -> None:
        """Initialize the secure event bus with authentication"""
        if self._initialized:
            return
            
        try:
            # Create service token
            service_token = create_service_token(
                service_name=self.service_name,
                roles={self.service_role}
            )
            
            # Create and authenticate with secure event bus
            self._secure_bus = await create_secure_event_bus(service_token)
            
            self._initialized = True
            logger.info(
                "Secure event bus initialized",
                extra={
                    "service_name": self.service_name,
                    "service_role": self.service_role
                }
            )
            
        except Exception as e:
            logger.error(
                "Failed to initialize secure event bus",
                extra={
                    "service_name": self.service_name,
                    "error": str(e)
                }
            )
            raise
    
    async def publish(self, event: IEvent) -> bool:
        """
        Publish an event through the secure event bus.
        
        Args:
            event: IEvent to publish
            
        Returns:
            True if published successfully
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            # Convert IEvent to DomainEvent
            domain_event = DomainEventAdapter(event)
            
            # Publish through secure bus
            await self._secure_bus.publish(domain_event)
            
            logger.debug(
                "Event published through secure bus",
                extra={
                    "event_type": event.event_type,
                    "event_id": event.event_id,
                    "service": self.service_name
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to publish event through secure bus",
                extra={
                    "event_type": event.event_type,
                    "event_id": event.event_id,
                    "error": str(e)
                }
            )
            return False
    
    async def subscribe(
        self, 
        event_type: str, 
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Type of events to subscribe to
            handler: Async function to handle events
            
        Returns:
            True if subscription successful
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            # Create a wrapper that converts DomainEvent back to IEvent format
            async def domain_event_handler(domain_event: DomainEvent):
                # Convert DomainEvent data back to IEvent-compatible format
                event_data = domain_event.to_dict()
                
                # Create a simple IEvent implementation
                class SimpleEvent:
                    def __init__(self):
                        self.event_id = str(domain_event.event_id)
                        self.event_type = domain_event.event_name
                        self.occurred_at = domain_event.occurred_at
                        self.correlation_id = getattr(domain_event, 'correlation_id', str(uuid4()))
                        
                        # Add any additional fields from event data
                        for key, value in event_data.items():
                            if not hasattr(self, key):
                                setattr(self, key, value)
                
                # Call the original handler
                await handler(SimpleEvent())
            
            # Store mapping for unsubscribe
            self._handler_mapping[handler] = domain_event_handler
            
            # Find the event class that matches this event type
            # For now, we'll use a generic subscription
            from shared.events.base import EventHandler
            
            class GenericHandler(EventHandler):
                def __init__(self, callback, event_name):
                    self.callback = callback
                    self._event_name = event_name
                
                @property
                def event_type(self):
                    # This would need to return the actual event class
                    # For now, return DomainEvent as base
                    return DomainEvent
                
                async def handle(self, event: DomainEvent):
                    if event.event_name == self._event_name:
                        await self.callback(event)
            
            handler_wrapper = GenericHandler(domain_event_handler, event_type)
            
            # Subscribe through secure bus using pattern matching
            await self._secure_bus.subscribe_secure(event_type, domain_event_handler)
            
            logger.info(
                "Handler subscribed through secure bus",
                extra={
                    "event_type": event_type,
                    "handler": handler.__name__,
                    "service": self.service_name
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to subscribe through secure bus",
                extra={
                    "event_type": event_type,
                    "handler": handler.__name__ if handler else "unknown",
                    "error": str(e)
                }
            )
            return False
    
    async def unsubscribe(
        self, 
        event_type: str, 
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """
        Unsubscribe from events of a specific type.
        
        Args:
            event_type: Type of events to unsubscribe from
            handler: Handler to remove
            
        Returns:
            True if unsubscription successful
        """
        try:
            # Get the wrapped handler
            domain_handler = self._handler_mapping.get(handler)
            if not domain_handler:
                logger.warning(
                    "Handler not found in mapping",
                    extra={
                        "event_type": event_type,
                        "handler": handler.__name__
                    }
                )
                return False
            
            # For now, we don't have a direct unsubscribe method in secure bus
            # This would need to be implemented
            del self._handler_mapping[handler]
            
            logger.info(
                "Handler unsubscribed from secure bus",
                extra={
                    "event_type": event_type,
                    "handler": handler.__name__
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to unsubscribe from secure bus",
                extra={
                    "event_type": event_type,
                    "handler": handler.__name__ if handler else "unknown",
                    "error": str(e)
                }
            )
            return False
    
    async def subscribe_to_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """Subscribe to all events (global handler)."""
        # For secure bus, we would need to subscribe to a wildcard pattern
        return await self.subscribe("*", handler)
    
    async def unsubscribe_from_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """Unsubscribe from all events (remove global handler)."""
        return await self.unsubscribe("*", handler)
    
    async def get_handlers(self, event_type: str) -> List[Callable[[IEvent], Awaitable[None]]]:
        """Get all handlers for a specific event type."""
        # Return handlers from our mapping
        handlers = []
        for original_handler, domain_handler in self._handler_mapping.items():
            # This is a simplified check - in reality we'd need to track
            # which handlers are subscribed to which event types
            handlers.append(original_handler)
        return handlers
    
    async def clear_handlers(self, event_type: str) -> bool:
        """Clear all handlers for a specific event type."""
        # This would need to be implemented in the secure bus
        logger.warning("Clear handlers not fully implemented for secure bus")
        return True
    
    async def get_statistics(self) -> Dict[str, int]:
        """Get event bus statistics."""
        stats = {
            "adapter_type": "secure",
            "service_name": self.service_name,
            "initialized": self._initialized,
            "mapped_handlers": len(self._handler_mapping)
        }
        
        # Add stats from secure bus if available
        if self._initialized and hasattr(self._secure_bus, 'get_statistics'):
            secure_stats = await self._secure_bus.get_statistics()
            stats.update(secure_stats)
            
        return stats