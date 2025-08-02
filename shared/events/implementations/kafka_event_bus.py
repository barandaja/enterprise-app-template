"""
Kafka implementation of EventBus
"""

import asyncio
import json
import logging
from typing import Dict, List, Type, Optional
from uuid import UUID

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError

from ..base import EventBus, DomainEvent, EventHandler


logger = logging.getLogger(__name__)


class KafkaEventBus(EventBus):
    """Kafka-based event bus implementation"""
    
    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic_prefix: str = "events",
        consumer_group: str = "event-handlers",
        producer_config: Optional[Dict] = None,
        consumer_config: Optional[Dict] = None
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic_prefix = topic_prefix
        self.consumer_group = consumer_group
        self.producer_config = producer_config or {}
        self.consumer_config = consumer_config or {}
        
        self._producer: Optional[AIOKafkaProducer] = None
        self._consumers: Dict[str, AIOKafkaConsumer] = {}
        self._handlers: Dict[Type[DomainEvent], List[EventHandler]] = {}
        self._consumer_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
    
    async def start(self):
        """Start the event bus"""
        if self._running:
            return
            
        # Start producer
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None,
            **self.producer_config
        )
        await self._producer.start()
        
        self._running = True
        logger.info("Kafka event bus started")
    
    async def stop(self):
        """Stop the event bus"""
        if not self._running:
            return
            
        self._running = False
        
        # Cancel consumer tasks
        for task in self._consumer_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks.values(), return_exceptions=True)
        
        # Stop consumers
        for consumer in self._consumers.values():
            await consumer.stop()
        
        # Stop producer
        if self._producer:
            await self._producer.stop()
        
        logger.info("Kafka event bus stopped")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event to Kafka"""
        if not self._producer:
            raise RuntimeError("Event bus not started")
        
        topic = self._get_topic_name(event.event_name)
        key = str(event.aggregate_id) if event.aggregate_id else None
        
        try:
            # Send event to Kafka
            await self._producer.send(
                topic=topic,
                key=key,
                value=event.to_dict()
            )
            
            logger.info(f"Published event {event.event_name} to topic {topic}")
            
        except KafkaError as e:
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
        topic = self._get_topic_name(event_name)
        
        # Start consumer if not already running
        if topic not in self._consumers:
            await self._start_consumer(topic, event_name)
        
        logger.info(f"Subscribed handler {handler.__class__.__name__} to {event_name}")
    
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type"""
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            
            # If no more handlers for this event type, stop the consumer
            if not self._handlers[event_type]:
                del self._handlers[event_type]
                
                dummy_event = event_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
                event_name = dummy_event.event_name
                topic = self._get_topic_name(event_name)
                
                if topic in self._consumers:
                    # Cancel consumer task
                    if topic in self._consumer_tasks:
                        self._consumer_tasks[topic].cancel()
                        del self._consumer_tasks[topic]
                    
                    # Stop consumer
                    await self._consumers[topic].stop()
                    del self._consumers[topic]
        
        logger.info(f"Unsubscribed handler {handler.__class__.__name__}")
    
    def _get_topic_name(self, event_name: str) -> str:
        """Get Kafka topic name for an event"""
        # Replace dots with hyphens for Kafka topic naming
        safe_event_name = event_name.replace('.', '-')
        return f"{self.topic_prefix}-{safe_event_name}"
    
    async def _start_consumer(self, topic: str, event_name: str):
        """Start a consumer for a topic"""
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.consumer_group,
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            key_deserializer=lambda k: k.decode('utf-8') if k else None,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            **self.consumer_config
        )
        
        await consumer.start()
        self._consumers[topic] = consumer
        
        # Start consumer task
        task = asyncio.create_task(self._consume_events(consumer, event_name))
        self._consumer_tasks[topic] = task
        
        logger.info(f"Started consumer for topic {topic}")
    
    async def _consume_events(self, consumer: AIOKafkaConsumer, event_name: str):
        """Consume events from Kafka"""
        try:
            async for msg in consumer:
                if not self._running:
                    break
                
                try:
                    # Deserialize event
                    event_data = msg.value
                    
                    # Find the event type based on event name
                    event_type = None
                    for evt_type in self._handlers.keys():
                        dummy = evt_type(aggregate_id=UUID('00000000-0000-0000-0000-000000000000'))
                        if dummy.event_name == event_name:
                            event_type = evt_type
                            break
                    
                    if not event_type:
                        logger.warning(f"No handler registered for event {event_name}")
                        continue
                    
                    # Create event instance
                    event = event_type.from_dict(event_data)
                    
                    # Call handlers
                    handlers = self._handlers.get(event_type, [])
                    for handler in handlers:
                        try:
                            await handler.handle(event)
                        except Exception as e:
                            logger.error(f"Handler {handler.__class__.__name__} failed: {e}")
                            # Continue with other handlers
                
                except Exception as e:
                    logger.error(f"Failed to process message: {e}")
                    
        except asyncio.CancelledError:
            logger.info(f"Consumer task cancelled for {event_name}")
            raise
        except Exception as e:
            logger.error(f"Consumer error for {event_name}: {e}")
            raise