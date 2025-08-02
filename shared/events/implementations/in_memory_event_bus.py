"""
In-memory implementation of EventBus for testing
"""

import asyncio
import logging
from collections import defaultdict
from typing import Dict, List, Type

from ..base import EventBus, DomainEvent, EventHandler


logger = logging.getLogger(__name__)


class InMemoryEventBus(EventBus):
    """In-memory event bus for testing and development"""
    
    def __init__(self):
        self._handlers: Dict[Type[DomainEvent], List[EventHandler]] = defaultdict(list)
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the event processor"""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("In-memory event bus started")
    
    async def stop(self):
        """Stop the event processor"""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel processor task
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("In-memory event bus stopped")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event to the bus"""
        await self._event_queue.put(event)
        logger.debug(f"Published event {event.event_name}")
    
    async def subscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe a handler to an event type"""
        self._handlers[event_type].append(handler)
        logger.debug(f"Subscribed handler {handler.__class__.__name__} to {event_type.__name__}")
    
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type"""
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            logger.debug(f"Unsubscribed handler {handler.__class__.__name__} from {event_type.__name__}")
    
    async def _process_events(self):
        """Process events from the queue"""
        while self._running:
            try:
                # Wait for event with timeout to allow checking _running flag
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                
                # Get handlers for this event type
                handlers = self._handlers.get(type(event), [])
                
                # Call each handler
                for handler in handlers:
                    try:
                        await handler.handle(event)
                    except Exception as e:
                        logger.error(
                            f"Handler {handler.__class__.__name__} failed for event "
                            f"{event.event_name}: {e}"
                        )
                        
            except asyncio.TimeoutError:
                # Continue checking if still running
                continue
            except asyncio.CancelledError:
                logger.debug("Event processor cancelled")
                break
            except Exception as e:
                logger.error(f"Event processing error: {e}")
    
    async def wait_for_events(self, timeout: float = 0.1):
        """Wait for all queued events to be processed (for testing)"""
        # Wait for queue to be empty
        while not self._event_queue.empty():
            await asyncio.sleep(0.01)
        
        # Give handlers a bit more time to complete
        await asyncio.sleep(timeout)