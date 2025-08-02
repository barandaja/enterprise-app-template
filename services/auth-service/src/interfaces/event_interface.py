"""
Event system interfaces for dependency abstraction.
Defines contracts for event-driven architecture to enable dependency injection
and improve testability.
"""

from typing import Any, Dict, List, Protocol, runtime_checkable, Callable, Awaitable
from datetime import datetime
from abc import ABC, abstractmethod


class IEvent(ABC):
    """Base interface for all events."""
    
    @property
    @abstractmethod
    def event_type(self) -> str:
        """Event type identifier."""
        ...
    
    @property
    @abstractmethod
    def timestamp(self) -> datetime:
        """When the event occurred."""
        ...
    
    @property
    @abstractmethod
    def data(self) -> Dict[str, Any]:
        """Event data payload."""
        ...
    
    @property
    @abstractmethod
    def correlation_id(self) -> str:
        """Correlation ID for tracing."""
        ...


@runtime_checkable
class IEventBus(Protocol):
    """Protocol for event bus operations."""
    
    async def publish(self, event: IEvent) -> bool:
        """
        Publish an event to the event bus.
        
        Args:
            event: Event to publish
            
        Returns:
            True if published successfully, False otherwise
        """
        ...
    
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
            True if subscription successful, False otherwise
        """
        ...
    
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
            True if unsubscription successful, False otherwise
        """
        ...
    
    async def get_handlers(self, event_type: str) -> List[Callable[[IEvent], Awaitable[None]]]:
        """
        Get all handlers for a specific event type.
        
        Args:
            event_type: Event type to get handlers for
            
        Returns:
            List of handlers for the event type
        """
        ...
    
    async def clear_handlers(self, event_type: str) -> bool:
        """
        Clear all handlers for a specific event type.
        
        Args:
            event_type: Event type to clear handlers for
            
        Returns:
            True if cleared successfully, False otherwise
        """
        ...