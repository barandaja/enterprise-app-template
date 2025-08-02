"""
Redis implementation of EventBus for local development
Uses Redis Pub/Sub for event distribution
"""

import asyncio
import json
import logging
from typing import Dict, List, Type, Optional, Set
from uuid import UUID

import aioredis
from aioredis.client import PubSub

from ..base import EventBus, DomainEvent, EventHandler


logger = logging.getLogger(__name__)


class RedisEventBus(EventBus):
    """Redis-based event bus implementation using Pub/Sub"""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        channel_prefix: str = "events",
        connection_pool_size: int = 10
    ):
        self.redis_url = redis_url
        self.channel_prefix = channel_prefix
        self.connection_pool_size = connection_pool_size
        
        self._redis: Optional[aioredis.Redis] = None
        self._pubsub: Optional[PubSub] = None
        self._handlers: Dict[Type[DomainEvent], List[EventHandler]] = {}
        self._subscribed_channels: Set[str] = set()
        self._listener_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the event bus"""
        if self._running:
            return
        
        # Create Redis connection
        self._redis = await aioredis.from_url(
            self.redis_url,
            max_connections=self.connection_pool_size,
            decode_responses=True
        )
        
        # Create pubsub instance
        self._pubsub = self._redis.pubsub()
        
        # Start listener task
        self._listener_task = asyncio.create_task(self._listen_for_events())
        
        self._running = True
        logger.info("Redis event bus started")
    
    async def stop(self):
        """Stop the event bus"""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel listener task
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        
        # Unsubscribe from all channels
        if self._pubsub and self._subscribed_channels:
            await self._pubsub.unsubscribe(*self._subscribed_channels)
            await self._pubsub.close()
        
        # Close Redis connection
        if self._redis:
            await self._redis.close()
        
        logger.info("Redis event bus stopped")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event to Redis"""
        if not self._redis:
            raise RuntimeError("Event bus not started")
        
        channel = self._get_channel_name(event.event_name)
        
        try:
            # Publish event to Redis channel
            await self._redis.publish(
                channel=channel,
                message=event.to_json()
            )
            
            logger.info(f"Published event {event.event_name} to channel {channel}")
            
        except Exception as e:
            logger.error(f"Failed to publish event {event.event_name}: {e}")
            raise
    
    async def subscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe a handler to an event type"""
        # Register handler
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        
        # Get event name from a dummy instance
        dummy_event = event_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
        event_name = dummy_event.event_name
        channel = self._get_channel_name(event_name)
        
        # Subscribe to channel if not already subscribed
        if channel not in self._subscribed_channels:
            if self._pubsub:
                await self._pubsub.subscribe(channel)
                self._subscribed_channels.add(channel)
        
        logger.info(f"Subscribed handler {handler.__class__.__name__} to {event_name}")
    
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type"""
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            
            # If no more handlers for this event type, unsubscribe from channel
            if not self._handlers[event_type]:
                del self._handlers[event_type]
                
                dummy_event = event_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
                event_name = dummy_event.event_name
                channel = self._get_channel_name(event_name)
                
                if channel in self._subscribed_channels and self._pubsub:
                    await self._pubsub.unsubscribe(channel)
                    self._subscribed_channels.remove(channel)
        
        logger.info(f"Unsubscribed handler {handler.__class__.__name__}")
    
    def _get_channel_name(self, event_name: str) -> str:
        """Get Redis channel name for an event"""
        return f"{self.channel_prefix}:{event_name}"
    
    def _get_event_name_from_channel(self, channel: str) -> str:
        """Extract event name from channel name"""
        prefix = f"{self.channel_prefix}:"
        if channel.startswith(prefix):
            return channel[len(prefix):]
        return channel
    
    async def _listen_for_events(self):
        """Listen for events from Redis pubsub"""
        if not self._pubsub:
            return
        
        try:
            async for message in self._pubsub.listen():
                if not self._running:
                    break
                
                # Skip non-message types
                if message['type'] not in ('message', 'pmessage'):
                    continue
                
                try:
                    # Get event name from channel
                    channel = message['channel']
                    event_name = self._get_event_name_from_channel(channel)
                    
                    # Parse event data
                    event_data = json.loads(message['data'])
                    
                    # Find the event type based on event name
                    event_type = None
                    for evt_type in self._handlers.keys():
                        dummy = evt_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
                        if dummy.event_name == event_name:
                            event_type = evt_type
                            break
                    
                    if not event_type:
                        logger.debug(f"No handler registered for event {event_name}")
                        continue
                    
                    # Create event instance
                    event = event_type.from_dict(event_data)
                    
                    # Call handlers
                    handlers = self._handlers.get(event_type, [])
                    for handler in handlers:
                        try:
                            await handler.handle(event)
                        except Exception as e:
                            logger.error(
                                f"Handler {handler.__class__.__name__} failed for event {event_name}: {e}"
                            )
                            # Continue with other handlers
                
                except Exception as e:
                    logger.error(f"Failed to process message: {e}")
                    
        except asyncio.CancelledError:
            logger.info("Event listener task cancelled")
            raise
        except Exception as e:
            logger.error(f"Event listener error: {e}")
            raise


class RedisEventStore:
    """Simple event store implementation using Redis"""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        events_key_prefix: str = "event_store",
        ttl_seconds: Optional[int] = None  # Optional TTL for events
    ):
        self.redis_url = redis_url
        self.events_key_prefix = events_key_prefix
        self.ttl_seconds = ttl_seconds
        self._redis: Optional[aioredis.Redis] = None
    
    async def connect(self):
        """Connect to Redis"""
        self._redis = await aioredis.from_url(
            self.redis_url,
            decode_responses=True
        )
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self._redis:
            await self._redis.close()
    
    async def append(self, event: DomainEvent) -> None:
        """Append an event to the store"""
        if not self._redis:
            raise RuntimeError("Not connected to Redis")
        
        # Store event in aggregate's event list
        if event.aggregate_id:
            key = f"{self.events_key_prefix}:aggregate:{event.aggregate_id}"
            await self._redis.rpush(key, event.to_json())
            
            if self.ttl_seconds:
                await self._redis.expire(key, self.ttl_seconds)
        
        # Store event in global event stream
        global_key = f"{self.events_key_prefix}:global"
        await self._redis.rpush(global_key, event.to_json())
        
        if self.ttl_seconds:
            await self._redis.expire(global_key, self.ttl_seconds)
        
        # Store event by type
        type_key = f"{self.events_key_prefix}:type:{event.event_name}"
        await self._redis.rpush(type_key, event.to_json())
        
        if self.ttl_seconds:
            await self._redis.expire(type_key, self.ttl_seconds)
    
    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: Optional[int] = None,
        to_version: Optional[int] = None
    ) -> List[DomainEvent]:
        """Get events for an aggregate"""
        if not self._redis:
            raise RuntimeError("Not connected to Redis")
        
        key = f"{self.events_key_prefix}:aggregate:{aggregate_id}"
        
        # Get all events for the aggregate
        event_jsons = await self._redis.lrange(key, 0, -1)
        
        events = []
        for event_json in event_jsons:
            event_data = json.loads(event_json)
            event = self._deserialize_event(event_data)
            
            # Filter by version if specified
            if from_version and event.version < from_version:
                continue
            if to_version and event.version > to_version:
                continue
                
            events.append(event)
        
        return events
    
    def _deserialize_event(self, event_data: Dict) -> DomainEvent:
        """Deserialize event from dict"""
        # This is a simplified version - in production you'd need a registry
        # of event types to properly deserialize
        from ..auth_events import (
            UserRegistered, UserLoggedIn, UserLoggedOut
        )
        from ..user_events import (
            UserProfileCreated, UserProfileUpdated
        )
        
        event_name = event_data.get('event_name')
        
        # Map event names to classes
        event_classes = {
            'user.registered': UserRegistered,
            'user.logged_in': UserLoggedIn,
            'user.logged_out': UserLoggedOut,
            'user_profile.created': UserProfileCreated,
            'user_profile.updated': UserProfileUpdated,
        }
        
        event_class = event_classes.get(event_name)
        if event_class:
            return event_class.from_dict(event_data)
        
        raise ValueError(f"Unknown event type: {event_name}")