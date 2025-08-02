"""
Secure Redis implementation of EventBus with authentication and encryption
"""

import asyncio
import json
import logging
from typing import Dict, List, Type, Optional, Any
from uuid import UUID

import aioredis
from redis.asyncio import Redis

from ..base import EventBus, DomainEvent, EventHandler
from ..security import SecureEventBusBase, EventSecurityConfig, ServiceIdentity, EventSecurityManager
from .redis_event_bus import RedisEventStore

logger = logging.getLogger(__name__)


class SecureRedisEventBus(SecureEventBusBase, EventBus):
    """Secure Redis event bus with authentication, encryption, and rate limiting"""
    
    def __init__(
        self,
        redis_url: str,
        security_config: EventSecurityConfig,
        channel_prefix: str = "secure_events"
    ):
        super().__init__(security_config)
        self.redis_url = redis_url
        self.channel_prefix = channel_prefix
        self._redis: Optional[Redis] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None
        self._running = False
        self._handlers: Dict[Type[DomainEvent], List[EventHandler]] = {}
        self._subscription_patterns: Dict[str, List[EventHandler]] = {}
        self._listener_task: Optional[asyncio.Task] = None
        
        # Audit logging
        self._audit_logger = logging.getLogger("event_security_audit")
    
    async def start(self):
        """Start the secure event bus"""
        if self._running:
            return
        
        # Connect to Redis
        self._redis = await aioredis.from_url(self.redis_url, decode_responses=False)
        self._pubsub = self._redis.pubsub()
        
        # Start listener
        self._running = True
        self._listener_task = asyncio.create_task(self._listen_for_events())
        
        logger.info("Secure Redis event bus started")
    
    async def stop(self):
        """Stop the secure event bus"""
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
        
        # Close connections
        if self._pubsub:
            await self._pubsub.close()
        
        if self._redis:
            await self._redis.close()
        
        logger.info("Secure Redis event bus stopped")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event with security checks"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        event_name = event.event_name
        
        # Check permissions
        if not self._check_publish_permission(event_name):
            self._audit_logger.warning(
                f"Publish denied - Service: {self._service_identity.service_name}, "
                f"Event: {event_name}"
            )
            raise PermissionError(f"Not authorized to publish {event_name}")
        
        # Prepare event with encryption and signing
        event_data = self.security_manager.prepare_event_for_publish(
            str(event.event_id),
            event_name,
            event.to_dict()
        )
        
        # Add publisher information
        event_data["publisher"] = {
            "service_name": self._service_identity.service_name,
            "published_at": event.occurred_at.isoformat()
        }
        
        # Publish to Redis
        channel = f"{self.channel_prefix}:{event_name}"
        await self._redis.publish(channel, json.dumps(event_data))
        
        # Log successful publish
        self._audit_logger.info(
            f"Event published - Service: {self._service_identity.service_name}, "
            f"Event: {event_name}, ID: {event.event_id}"
        )
        
        logger.debug(f"Published secure event {event_name} to channel {channel}")
    
    async def subscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe to an event type with security checks"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        # Get event name from the event type
        event_instance = event_type()
        event_pattern = event_instance.event_name
        
        # Check permissions
        if not self._check_subscribe_permission(event_pattern):
            self._audit_logger.warning(
                f"Subscribe denied - Service: {self._service_identity.service_name}, "
                f"Pattern: {event_pattern}"
            )
            raise PermissionError(f"Not authorized to subscribe to {event_pattern}")
        
        # Store handler
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        
        # Subscribe to Redis channel
        channel_pattern = f"{self.channel_prefix}:{event_pattern}"
        
        if channel_pattern not in self._subscription_patterns:
            self._subscription_patterns[channel_pattern] = []
            await self._pubsub.psubscribe(channel_pattern)
        
        self._subscription_patterns[channel_pattern].append(handler)
        
        # Log subscription
        self._audit_logger.info(
            f"Subscribed - Service: {self._service_identity.service_name}, "
            f"Pattern: {event_pattern}, Handler: {handler.__class__.__name__}"
        )
        
        logger.debug(f"Subscribed to secure pattern {channel_pattern}")
    
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe from an event type"""
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            
            if not self._handlers[event_type]:
                del self._handlers[event_type]
                
                # Unsubscribe from Redis if no more handlers
                event_instance = event_type()
                channel_pattern = f"{self.channel_prefix}:{event_instance.event_name}"
                
                if channel_pattern in self._subscription_patterns:
                    del self._subscription_patterns[channel_pattern]
                    await self._pubsub.punsubscribe(channel_pattern)
    
    async def _listen_for_events(self):
        """Listen for events from Redis"""
        while self._running:
            try:
                async for message in self._pubsub.listen():
                    if message["type"] in ("pmessage", "message"):
                        await self._handle_message(message)
            except asyncio.CancelledError:
                logger.debug("Event listener cancelled")
                break
            except Exception as e:
                logger.error(f"Error in event listener: {e}")
                await asyncio.sleep(1)  # Brief pause before retrying
    
    async def _handle_message(self, message: Dict[str, Any]):
        """Handle incoming Redis message"""
        try:
            # Parse message
            channel = message.get("channel", b"").decode() if isinstance(message.get("channel"), bytes) else message.get("channel", "")
            data = message["data"]
            
            if isinstance(data, bytes):
                data = data.decode()
            
            event_data = json.loads(data)
            
            # Verify and decrypt event
            decrypted_data = self.security_manager.verify_and_decrypt_event(event_data)
            if not decrypted_data:
                self._audit_logger.error(
                    f"Event verification failed - Channel: {channel}, "
                    f"Event ID: {event_data.get('event_id')}"
                )
                return
            
            # Extract event name from channel
            event_name = channel.replace(f"{self.channel_prefix}:", "")
            
            # Find matching handlers
            handlers = []
            for pattern, pattern_handlers in self._subscription_patterns.items():
                if self._pattern_matches(pattern, channel):
                    handlers.extend(pattern_handlers)
            
            # Call handlers
            for handler in handlers:
                try:
                    # Reconstruct domain event
                    event = self._reconstruct_event(event_name, decrypted_data["payload"])
                    if event:
                        await handler.handle(event)
                except Exception as e:
                    logger.error(
                        f"Handler {handler.__class__.__name__} failed for event "
                        f"{event_name}: {e}"
                    )
                    self._audit_logger.error(
                        f"Handler failed - Service: {self._service_identity.service_name}, "
                        f"Handler: {handler.__class__.__name__}, Event: {event_name}, "
                        f"Error: {str(e)}"
                    )
        
        except Exception as e:
            logger.error(f"Error handling message: {e}")
    
    def _pattern_matches(self, pattern: str, channel: str) -> bool:
        """Check if channel matches subscription pattern"""
        # Simple pattern matching - could be enhanced with wildcards
        return pattern == channel
    
    def _reconstruct_event(self, event_name: str, payload: Dict[str, Any]) -> Optional[DomainEvent]:
        """Reconstruct domain event from payload"""
        # Find event type by name
        for event_type in self._handlers.keys():
            event_instance = event_type()
            if event_instance.event_name == event_name:
                try:
                    # Create new instance with payload data
                    return event_type(**payload)
                except Exception as e:
                    logger.error(f"Failed to reconstruct event {event_name}: {e}")
                    return None
        
        return None
    
    async def publish_secure(self, event_id: str, event_name: str, payload: Dict[str, Any]) -> None:
        """Secure publish method from base class"""
        # Create a minimal DomainEvent for publishing
        from datetime import datetime
        
        class GenericEvent(DomainEvent):
            @property
            def event_name(self) -> str:
                return event_name
            
            def to_dict(self) -> Dict[str, Any]:
                return payload
        
        event = GenericEvent(
            event_id=UUID(event_id),
            occurred_at=datetime.utcnow()
        )
        
        await self.publish(event)
    
    async def subscribe_secure(self, event_pattern: str, handler: callable) -> None:
        """Secure subscribe method from base class"""
        # Create a generic handler wrapper
        class GenericHandler(EventHandler):
            def __init__(self, callback):
                self.callback = callback
            
            @property
            def event_type(self) -> Type[DomainEvent]:
                return DomainEvent
            
            async def handle(self, event: DomainEvent) -> None:
                await self.callback(event)
        
        # For pattern-based subscriptions
        if not self._check_subscribe_permission(event_pattern):
            raise PermissionError(f"Not authorized to subscribe to {event_pattern}")
        
        handler_wrapper = GenericHandler(handler)
        
        # Subscribe to pattern
        channel_pattern = f"{self.channel_prefix}:{event_pattern}"
        
        if channel_pattern not in self._subscription_patterns:
            self._subscription_patterns[channel_pattern] = []
            await self._pubsub.psubscribe(channel_pattern)
        
        self._subscription_patterns[channel_pattern].append(handler_wrapper)


class SecureRedisEventStore(RedisEventStore):
    """Secure Redis event store with encryption support"""
    
    def __init__(
        self,
        redis_url: str,
        security_config: EventSecurityConfig,
        ttl_seconds: Optional[int] = None
    ):
        super().__init__(redis_url, ttl_seconds)
        self.security_manager = EventSecurityManager(security_config)
        self._service_identity: Optional[ServiceIdentity] = None
    
    def authenticate(self, token: str) -> bool:
        """Authenticate service with token"""
        identity = self.security_manager.verify_service_token(token)
        if identity:
            self._service_identity = identity
            return True
        return False
    
    async def append(self, event: DomainEvent) -> None:
        """Append event with encryption"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        # Prepare event with encryption
        event_data = self.security_manager.prepare_event_for_publish(
            str(event.event_id),
            event.event_name,
            event.to_dict()
        )
        
        # Store in Redis
        key = self._get_event_key(event.event_id)
        
        await self._redis.hset(
            key,
            mapping={
                "event_id": str(event.event_id),
                "event_name": event.event_name,
                "aggregate_id": str(event.aggregate_id) if event.aggregate_id else "",
                "occurred_at": event.occurred_at.isoformat(),
                "payload": json.dumps(event_data["payload"]),
                "encrypted_fields": json.dumps(event_data["encrypted_fields"]),
                "signature": event_data.get("signature", ""),
                "publisher": self._service_identity.service_name
            }
        )
        
        # Set TTL if configured
        if self.ttl_seconds:
            await self._redis.expire(key, self.ttl_seconds)
        
        # Add to aggregate events
        if event.aggregate_id:
            await self._add_to_aggregate(event.aggregate_id, event.event_id)
    
    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: Optional[int] = None,
        to_version: Optional[int] = None
    ) -> List[DomainEvent]:
        """Get events with decryption"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        events = await super().get_events(aggregate_id, from_version, to_version)
        
        # Decrypt events
        decrypted_events = []
        for event in events:
            event_dict = event.to_dict()
            
            # Get stored event data
            key = self._get_event_key(event.event_id)
            event_data = await self._redis.hgetall(key)
            
            if event_data:
                # Verify and decrypt
                secure_data = {
                    "event_id": str(event.event_id),
                    "event_name": event.event_name,
                    "payload": json.loads(event_data.get("payload", "{}")),
                    "encrypted_fields": json.loads(event_data.get("encrypted_fields", "[]")),
                    "signature": event_data.get("signature")
                }
                
                decrypted = self.security_manager.verify_and_decrypt_event(secure_data)
                if decrypted:
                    # Update event with decrypted payload
                    event_dict.update(decrypted["payload"])
                    
                    # Recreate event with decrypted data
                    event_class = type(event)
                    decrypted_event = event_class(**event_dict)
                    decrypted_events.append(decrypted_event)
        
        return decrypted_events