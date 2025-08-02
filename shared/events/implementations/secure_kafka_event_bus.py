"""
Secure Kafka implementation of EventBus with authentication, encryption, and rate limiting
"""

import asyncio
import json
import logging
import ssl
from datetime import datetime
from typing import Dict, List, Type, Optional, Any, Set
from uuid import UUID

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError
from kafka.errors import KafkaTimeoutError

from ..base import EventBus, DomainEvent, EventHandler
from ..security import SecureEventBusBase, EventSecurityConfig, ServiceIdentity

logger = logging.getLogger(__name__)


class SecureKafkaEventBus(SecureEventBusBase, EventBus):
    """Secure Kafka event bus with SASL authentication, TLS, encryption, and rate limiting"""
    
    def __init__(
        self,
        bootstrap_servers: str,
        security_config: EventSecurityConfig,
        topic_prefix: str = "secure_events",
        consumer_group: str = "secure_event_handlers",
        # Kafka security settings
        security_protocol: str = "SASL_SSL",
        sasl_mechanism: str = "PLAIN",
        sasl_username: Optional[str] = None,
        sasl_password: Optional[str] = None,
        ssl_cafile: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
    ):
        super().__init__(security_config)
        self.bootstrap_servers = bootstrap_servers
        self.topic_prefix = topic_prefix
        self.consumer_group = consumer_group
        
        # Kafka security settings
        self.security_protocol = security_protocol
        self.sasl_mechanism = sasl_mechanism
        self.sasl_username = sasl_username
        self.sasl_password = sasl_password
        
        # SSL settings
        self.ssl_context = None
        if security_protocol in ["SSL", "SASL_SSL"]:
            self.ssl_context = ssl.create_default_context()
            if ssl_cafile:
                self.ssl_context.load_verify_locations(cafile=ssl_cafile)
            if ssl_certfile and ssl_keyfile:
                self.ssl_context.load_cert_chain(
                    certfile=ssl_certfile,
                    keyfile=ssl_keyfile
                )
        
        # Kafka clients
        self._producer: Optional[AIOKafkaProducer] = None
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._running = False
        
        # Event handling
        self._handlers: Dict[Type[DomainEvent], List[EventHandler]] = {}
        self._topic_handlers: Dict[str, List[EventHandler]] = {}
        self._consumer_task: Optional[asyncio.Task] = None
        
        # Audit logging
        self._audit_logger = logging.getLogger("event_security_audit")
        
        # Dead letter queue
        self.dlq_topic = f"{topic_prefix}.dlq"
    
    async def start(self):
        """Start the secure Kafka event bus"""
        if self._running:
            return
        
        # Create producer with security settings
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_username,
            sasl_plain_password=self.sasl_password,
            ssl_context=self.ssl_context,
            value_serializer=lambda v: json.dumps(v).encode(),
            key_serializer=lambda k: k.encode() if k else None,
            compression_type="gzip",
            acks="all",  # Wait for all replicas
            retries=3,
            retry_backoff_ms=100,
        )
        
        await self._producer.start()
        
        # Create consumer with security settings
        self._consumer = AIOKafkaConsumer(
            bootstrap_servers=self.bootstrap_servers,
            group_id=f"{self.consumer_group}_{self._service_identity.service_name if self._service_identity else 'unknown'}",
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_username,
            sasl_plain_password=self.sasl_password,
            ssl_context=self.ssl_context,
            value_deserializer=lambda v: json.loads(v.decode()),
            key_deserializer=lambda k: k.decode() if k else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False,  # Manual commit for reliability
            max_poll_records=100,
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
        )
        
        self._running = True
        self._consumer_task = asyncio.create_task(self._consume_events())
        
        logger.info("Secure Kafka event bus started")
    
    async def stop(self):
        """Stop the secure Kafka event bus"""
        if not self._running:
            return
        
        self._running = False
        
        # Stop consumer
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        
        # Close Kafka clients
        if self._consumer:
            await self._consumer.stop()
        
        if self._producer:
            await self._producer.stop()
        
        logger.info("Secure Kafka event bus stopped")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event with security checks"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        event_name = event.event_name
        
        # Check permissions and rate limit
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
        
        # Add metadata
        event_data["metadata"] = {
            "publisher": self._service_identity.service_name,
            "published_at": event.occurred_at.isoformat(),
            "correlation_id": str(event.correlation_id) if hasattr(event, "correlation_id") else None,
        }
        
        # Determine topic and key
        topic = self._get_topic_name(event_name)
        key = str(event.aggregate_id) if event.aggregate_id else str(event.event_id)
        
        try:
            # Send to Kafka with timeout
            await asyncio.wait_for(
                self._producer.send(
                    topic=topic,
                    key=key,
                    value=event_data,
                    headers=[
                        ("event_id", str(event.event_id).encode()),
                        ("event_name", event_name.encode()),
                        ("publisher", self._service_identity.service_name.encode()),
                    ]
                ),
                timeout=10.0
            )
            
            # Log successful publish
            self._audit_logger.info(
                f"Event published - Service: {self._service_identity.service_name}, "
                f"Event: {event_name}, ID: {event.event_id}, Topic: {topic}"
            )
            
        except asyncio.TimeoutError:
            logger.error(f"Timeout publishing event {event_name}")
            # Send to DLQ
            await self._send_to_dlq(event_data, "publish_timeout")
            raise
        except Exception as e:
            logger.error(f"Error publishing event {event_name}: {e}")
            # Send to DLQ
            await self._send_to_dlq(event_data, str(e))
            raise
    
    async def subscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe to an event type with security checks"""
        if not self._service_identity:
            raise PermissionError("Not authenticated")
        
        # Get event name
        event_instance = event_type()
        event_name = event_instance.event_name
        
        # Check permissions
        if not self._check_subscribe_permission(event_name):
            self._audit_logger.warning(
                f"Subscribe denied - Service: {self._service_identity.service_name}, "
                f"Event: {event_name}"
            )
            raise PermissionError(f"Not authorized to subscribe to {event_name}")
        
        # Store handler
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        
        # Subscribe to Kafka topic
        topic = self._get_topic_name(event_name)
        
        if topic not in self._topic_handlers:
            self._topic_handlers[topic] = []
            # Subscribe consumer to new topic
            self._consumer.subscribe(list(self._topic_handlers.keys()))
        
        self._topic_handlers[topic].append(handler)
        
        # Log subscription
        self._audit_logger.info(
            f"Subscribed - Service: {self._service_identity.service_name}, "
            f"Event: {event_name}, Topic: {topic}, Handler: {handler.__class__.__name__}"
        )
    
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe from an event type"""
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            
            if not self._handlers[event_type]:
                del self._handlers[event_type]
                
                # Update topic subscriptions
                event_instance = event_type()
                topic = self._get_topic_name(event_instance.event_name)
                
                if topic in self._topic_handlers:
                    self._topic_handlers[topic] = [
                        h for h in self._topic_handlers[topic] 
                        if h != handler
                    ]
                    
                    if not self._topic_handlers[topic]:
                        del self._topic_handlers[topic]
                        # Re-subscribe to remaining topics
                        if self._topic_handlers:
                            self._consumer.subscribe(list(self._topic_handlers.keys()))
                        else:
                            self._consumer.unsubscribe()
    
    async def _consume_events(self):
        """Consume events from Kafka"""
        while self._running:
            try:
                # Poll for messages
                async for msg in self._consumer:
                    if not self._running:
                        break
                    
                    try:
                        await self._handle_message(msg)
                        
                        # Commit offset after successful processing
                        await self._consumer.commit()
                        
                    except Exception as e:
                        logger.error(f"Error handling message: {e}")
                        # Send to DLQ
                        await self._send_to_dlq(
                            msg.value,
                            f"handler_error: {str(e)}",
                            original_topic=msg.topic
                        )
                        
                        # Still commit to avoid reprocessing
                        await self._consumer.commit()
                        
            except asyncio.CancelledError:
                logger.debug("Event consumer cancelled")
                break
            except Exception as e:
                logger.error(f"Error in event consumer: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _handle_message(self, message):
        """Handle incoming Kafka message"""
        try:
            event_data = message.value
            
            # Verify and decrypt event
            decrypted_data = self.security_manager.verify_and_decrypt_event(event_data)
            if not decrypted_data:
                self._audit_logger.error(
                    f"Event verification failed - Topic: {message.topic}, "
                    f"Event ID: {event_data.get('event_id')}"
                )
                return
            
            # Get event name
            event_name = decrypted_data["event_name"]
            
            # Find handlers for this topic
            handlers = self._topic_handlers.get(message.topic, [])
            
            # Execute handlers with timeout
            for handler in handlers:
                try:
                    # Reconstruct domain event
                    event = self._reconstruct_event(event_name, decrypted_data["payload"])
                    if event:
                        await asyncio.wait_for(
                            handler.handle(event),
                            timeout=30.0  # 30 second timeout for handlers
                        )
                except asyncio.TimeoutError:
                    logger.error(
                        f"Handler {handler.__class__.__name__} timed out for event {event_name}"
                    )
                    raise
                except Exception as e:
                    logger.error(
                        f"Handler {handler.__class__.__name__} failed for event "
                        f"{event_name}: {e}"
                    )
                    raise
                    
        except Exception as e:
            logger.error(f"Error processing message from topic {message.topic}: {e}")
            raise
    
    def _get_topic_name(self, event_name: str) -> str:
        """Get Kafka topic name for event"""
        # Replace dots with dashes for Kafka topic naming
        safe_name = event_name.replace(".", "-")
        return f"{self.topic_prefix}.{safe_name}"
    
    def _reconstruct_event(self, event_name: str, payload: Dict[str, Any]) -> Optional[DomainEvent]:
        """Reconstruct domain event from payload"""
        # Find event type by name
        for event_type in self._handlers.keys():
            event_instance = event_type()
            if event_instance.event_name == event_name:
                try:
                    return event_type(**payload)
                except Exception as e:
                    logger.error(f"Failed to reconstruct event {event_name}: {e}")
                    return None
        return None
    
    async def _send_to_dlq(self, event_data: Dict[str, Any], error: str, original_topic: Optional[str] = None):
        """Send failed event to dead letter queue"""
        try:
            dlq_record = {
                "event_data": event_data,
                "error": error,
                "failed_at": datetime.utcnow().isoformat(),
                "original_topic": original_topic,
                "service": self._service_identity.service_name if self._service_identity else "unknown"
            }
            
            await self._producer.send(
                topic=self.dlq_topic,
                value=dlq_record,
                headers=[
                    ("error_type", error.encode()),
                    ("failed_service", (self._service_identity.service_name if self._service_identity else "unknown").encode()),
                ]
            )
            
            self._audit_logger.error(
                f"Event sent to DLQ - Topic: {original_topic}, "
                f"Error: {error}, Event ID: {event_data.get('event_id')}"
            )
            
        except Exception as e:
            logger.error(f"Failed to send to DLQ: {e}")
    
    async def publish_secure(self, event_id: str, event_name: str, payload: Dict[str, Any]) -> None:
        """Secure publish method from base class"""
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
        class GenericHandler(EventHandler):
            def __init__(self, callback):
                self.callback = callback
            
            @property
            def event_type(self) -> Type[DomainEvent]:
                return DomainEvent
            
            async def handle(self, event: DomainEvent) -> None:
                await self.callback(event)
        
        if not self._check_subscribe_permission(event_pattern):
            raise PermissionError(f"Not authorized to subscribe to {event_pattern}")
        
        # For Kafka, we need to determine the topic from the pattern
        topic = self._get_topic_name(event_pattern)
        handler_wrapper = GenericHandler(handler)
        
        if topic not in self._topic_handlers:
            self._topic_handlers[topic] = []
            self._consumer.subscribe(list(self._topic_handlers.keys()))
        
        self._topic_handlers[topic].append(handler_wrapper)