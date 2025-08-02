"""
Event interface for user service.
Defines contracts for event publishing and handling in the domain.
"""

from abc import ABC, abstractmethod
from typing import Callable, List, Dict, Awaitable
from datetime import datetime
from uuid import UUID


class IEvent(ABC):
    """Base interface for all domain events"""
    
    @property
    @abstractmethod
    def event_id(self) -> str:
        """Unique identifier for the event"""
        pass
    
    @property
    @abstractmethod
    def event_type(self) -> str:
        """Type of the event (e.g., 'UserCreated', 'UserUpdated')"""
        pass
    
    @property
    @abstractmethod
    def occurred_at(self) -> datetime:
        """When the event occurred"""
        pass
    
    @property
    @abstractmethod
    def correlation_id(self) -> str:
        """ID for tracking related events"""
        pass


class IEventBus(ABC):
    """Interface for event bus implementations"""
    
    @abstractmethod
    async def publish(self, event: IEvent) -> bool:
        """
        Publish an event to the bus.
        
        Args:
            event: Event to publish
            
        Returns:
            True if published successfully
        """
        pass
    
    @abstractmethod
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
        pass
    
    @abstractmethod
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
        pass
    
    @abstractmethod
    async def subscribe_to_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """Subscribe to all events (global handler)."""
        pass
    
    @abstractmethod
    async def unsubscribe_from_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """Unsubscribe from all events (remove global handler)."""
        pass
    
    @abstractmethod
    async def get_handlers(self, event_type: str) -> List[Callable[[IEvent], Awaitable[None]]]:
        """Get all handlers for a specific event type."""
        pass
    
    @abstractmethod
    async def clear_handlers(self, event_type: str) -> bool:
        """Clear all handlers for a specific event type."""
        pass
    
    @abstractmethod
    async def get_statistics(self) -> Dict[str, int]:
        """Get event bus statistics."""
        pass