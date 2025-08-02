"""
Event bus implementation for publishing and subscribing to events.
Provides decoupled communication between services through events.
"""

import asyncio
from typing import Callable, Dict, List, Set, Awaitable
from collections import defaultdict
import structlog

from ..interfaces.event_interface import IEvent, IEventBus

logger = structlog.get_logger()


class InMemoryEventBus(IEventBus):
    """In-memory event bus implementation for single-instance deployments."""
    
    def __init__(self):
        self._handlers: Dict[str, Set[Callable[[IEvent], Awaitable[None]]]] = defaultdict(set)
        self._global_handlers: Set[Callable[[IEvent], Awaitable[None]]] = set()
        self._lock = asyncio.Lock()
    
    async def publish(self, event: IEvent) -> bool:
        """
        Publish an event to all registered handlers.
        
        Args:
            event: Event to publish
            
        Returns:
            True if published successfully (always True for in-memory)
        """
        try:
            event_type = event.event_type
            
            # Get handlers for this event type
            type_handlers = self._handlers.get(event_type, set())
            all_handlers = type_handlers.union(self._global_handlers)
            
            if not all_handlers:
                logger.debug("No handlers registered for event", event_type=event_type)
                return True
            
            # Call all handlers concurrently
            tasks = []
            for handler in all_handlers:
                try:
                    task = asyncio.create_task(handler(event))
                    tasks.append(task)
                except Exception as e:
                    logger.error(
                        "Failed to create handler task",
                        event_type=event_type,
                        handler=handler.__name__,
                        error=str(e)
                    )
            
            if tasks:
                # Wait for all handlers to complete
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Log any handler exceptions
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        handler_name = list(all_handlers)[i].__name__
                        logger.error(
                            "Event handler failed",
                            event_type=event_type,
                            handler=handler_name,
                            error=str(result)
                        )
            
            logger.debug(
                "Event published successfully",
                event_type=event_type,
                handler_count=len(all_handlers),
                correlation_id=event.correlation_id
            )
            
            return True
        
        except Exception as e:
            logger.error(
                "Failed to publish event",
                event_type=event.event_type,
                error=str(e)
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
        try:
            async with self._lock:
                self._handlers[event_type].add(handler)
            
            logger.info(
                "Handler subscribed to event type",
                event_type=event_type,
                handler=handler.__name__
            )
            return True
        
        except Exception as e:
            logger.error(
                "Failed to subscribe handler",
                event_type=event_type,
                handler=handler.__name__ if handler else "unknown",
                error=str(e)
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
            async with self._lock:
                if event_type in self._handlers:
                    self._handlers[event_type].discard(handler)
                    
                    # Clean up empty handler sets
                    if not self._handlers[event_type]:
                        del self._handlers[event_type]
            
            logger.info(
                "Handler unsubscribed from event type",
                event_type=event_type,
                handler=handler.__name__
            )
            return True
        
        except Exception as e:
            logger.error(
                "Failed to unsubscribe handler",
                event_type=event_type,
                handler=handler.__name__ if handler else "unknown",
                error=str(e)
            )
            return False
    
    async def subscribe_to_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """
        Subscribe to all events (global handler).
        
        Args:
            handler: Handler to receive all events
            
        Returns:
            True if subscription successful
        """
        try:
            async with self._lock:
                self._global_handlers.add(handler)
            
            logger.info("Global handler subscribed", handler=handler.__name__)
            return True
        
        except Exception as e:
            logger.error(
                "Failed to subscribe global handler",
                handler=handler.__name__ if handler else "unknown",
                error=str(e)
            )
            return False
    
    async def unsubscribe_from_all(
        self,
        handler: Callable[[IEvent], Awaitable[None]]
    ) -> bool:
        """
        Unsubscribe from all events (remove global handler).
        
        Args:
            handler: Handler to remove
            
        Returns:
            True if unsubscription successful
        """
        try:
            async with self._lock:
                self._global_handlers.discard(handler)
            
            logger.info("Global handler unsubscribed", handler=handler.__name__)
            return True
        
        except Exception as e:
            logger.error(
                "Failed to unsubscribe global handler",
                handler=handler.__name__ if handler else "unknown",
                error=str(e)
            )
            return False
    
    async def get_handlers(self, event_type: str) -> List[Callable[[IEvent], Awaitable[None]]]:
        """
        Get all handlers for a specific event type.
        
        Args:
            event_type: Event type to get handlers for
            
        Returns:
            List of handlers for the event type
        """
        try:
            type_handlers = self._handlers.get(event_type, set())
            return list(type_handlers.union(self._global_handlers))
        
        except Exception as e:
            logger.error(
                "Failed to get handlers",
                event_type=event_type,
                error=str(e)
            )
            return []
    
    async def clear_handlers(self, event_type: str) -> bool:
        """
        Clear all handlers for a specific event type.
        
        Args:
            event_type: Event type to clear handlers for
            
        Returns:
            True if cleared successfully
        """
        try:
            async with self._lock:
                if event_type in self._handlers:
                    handler_count = len(self._handlers[event_type])
                    del self._handlers[event_type]
                    
                    logger.info(
                        "Handlers cleared for event type",
                        event_type=event_type,
                        handler_count=handler_count
                    )
            
            return True
        
        except Exception as e:
            logger.error(
                "Failed to clear handlers",
                event_type=event_type,
                error=str(e)
            )
            return False
    
    async def get_statistics(self) -> Dict[str, int]:
        """Get event bus statistics."""
        try:
            stats = {
                "total_event_types": len(self._handlers),
                "total_handlers": sum(len(handlers) for handlers in self._handlers.values()),
                "global_handlers": len(self._global_handlers)
            }
            
            # Add per-event-type statistics
            for event_type, handlers in self._handlers.items():
                stats[f"handlers_{event_type}"] = len(handlers)
            
            return stats
        
        except Exception as e:
            logger.error("Failed to get event bus statistics", error=str(e))
            return {}


# Alias for the main event bus implementation
EventBus = InMemoryEventBus