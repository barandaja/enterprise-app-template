"""
Event-driven architecture configuration
"""

import os
from enum import Enum
from typing import Optional, Dict, Any

from pydantic import BaseSettings, Field


class EventBusType(str, Enum):
    """Supported event bus types"""
    REDIS = "redis"
    KAFKA = "kafka"
    RABBITMQ = "rabbitmq"
    IN_MEMORY = "in_memory"  # For testing


class EventConfig(BaseSettings):
    """Event system configuration"""
    
    # Event bus type
    event_bus_type: EventBusType = Field(
        default=EventBusType.REDIS,
        env="EVENT_BUS_TYPE",
        description="Type of event bus to use"
    )
    
    # Redis configuration
    redis_url: str = Field(
        default="redis://localhost:6379",
        env="REDIS_EVENT_URL",
        description="Redis URL for event bus"
    )
    redis_channel_prefix: str = Field(
        default="events",
        env="REDIS_CHANNEL_PREFIX",
        description="Prefix for Redis pub/sub channels"
    )
    
    # Kafka configuration
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        env="KAFKA_BOOTSTRAP_SERVERS",
        description="Kafka bootstrap servers"
    )
    kafka_topic_prefix: str = Field(
        default="events",
        env="KAFKA_TOPIC_PREFIX",
        description="Prefix for Kafka topics"
    )
    kafka_consumer_group: str = Field(
        default="event-handlers",
        env="KAFKA_CONSUMER_GROUP",
        description="Kafka consumer group name"
    )
    
    # RabbitMQ configuration
    rabbitmq_url: str = Field(
        default="amqp://guest:guest@localhost:5672/",
        env="RABBITMQ_URL",
        description="RabbitMQ connection URL"
    )
    rabbitmq_exchange: str = Field(
        default="events",
        env="RABBITMQ_EXCHANGE",
        description="RabbitMQ exchange name"
    )
    
    # Event store configuration
    enable_event_store: bool = Field(
        default=True,
        env="ENABLE_EVENT_STORE",
        description="Enable event store for event sourcing"
    )
    event_store_ttl_days: Optional[int] = Field(
        default=90,
        env="EVENT_STORE_TTL_DAYS",
        description="TTL for events in days (None for no expiry)"
    )
    
    # Saga configuration
    enable_sagas: bool = Field(
        default=True,
        env="ENABLE_SAGAS",
        description="Enable saga orchestration"
    )
    saga_timeout_seconds: int = Field(
        default=3600,
        env="SAGA_TIMEOUT_SECONDS",
        description="Default saga timeout in seconds"
    )
    
    # Performance configuration
    event_batch_size: int = Field(
        default=100,
        env="EVENT_BATCH_SIZE",
        description="Batch size for event processing"
    )
    event_processing_threads: int = Field(
        default=4,
        env="EVENT_PROCESSING_THREADS",
        description="Number of threads for event processing"
    )
    
    # Monitoring configuration
    enable_event_monitoring: bool = Field(
        default=True,
        env="ENABLE_EVENT_MONITORING",
        description="Enable event monitoring and metrics"
    )
    event_dead_letter_queue: bool = Field(
        default=True,
        env="EVENT_DEAD_LETTER_QUEUE",
        description="Enable dead letter queue for failed events"
    )
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global configuration instance
event_config = EventConfig()


def get_event_bus_config() -> Dict[str, Any]:
    """Get event bus configuration based on type"""
    
    if event_config.event_bus_type == EventBusType.REDIS:
        return {
            "redis_url": event_config.redis_url,
            "channel_prefix": event_config.redis_channel_prefix,
        }
    
    elif event_config.event_bus_type == EventBusType.KAFKA:
        return {
            "bootstrap_servers": event_config.kafka_bootstrap_servers,
            "topic_prefix": event_config.kafka_topic_prefix,
            "consumer_group": event_config.kafka_consumer_group,
        }
    
    elif event_config.event_bus_type == EventBusType.RABBITMQ:
        return {
            "url": event_config.rabbitmq_url,
            "exchange": event_config.rabbitmq_exchange,
        }
    
    else:  # IN_MEMORY
        return {}


async def create_event_bus():
    """Factory function to create event bus based on configuration"""
    
    if event_config.event_bus_type == EventBusType.REDIS:
        from .implementations.redis_event_bus import RedisEventBus
        config = get_event_bus_config()
        event_bus = RedisEventBus(**config)
        await event_bus.start()
        return event_bus
    
    elif event_config.event_bus_type == EventBusType.KAFKA:
        from .implementations.kafka_event_bus import KafkaEventBus
        config = get_event_bus_config()
        event_bus = KafkaEventBus(**config)
        await event_bus.start()
        return event_bus
    
    elif event_config.event_bus_type == EventBusType.RABBITMQ:
        # RabbitMQ implementation would go here
        raise NotImplementedError("RabbitMQ event bus not yet implemented")
    
    else:  # IN_MEMORY
        from .implementations.in_memory_event_bus import InMemoryEventBus
        return InMemoryEventBus()


async def create_event_store():
    """Factory function to create event store based on configuration"""
    
    if not event_config.enable_event_store:
        return None
    
    if event_config.event_bus_type == EventBusType.REDIS:
        from .implementations.redis_event_bus import RedisEventStore
        
        ttl_seconds = None
        if event_config.event_store_ttl_days:
            ttl_seconds = event_config.event_store_ttl_days * 24 * 60 * 60
        
        event_store = RedisEventStore(
            redis_url=event_config.redis_url,
            ttl_seconds=ttl_seconds
        )
        await event_store.connect()
        return event_store
    
    else:
        # Other event store implementations would go here
        raise NotImplementedError(
            f"Event store not implemented for {event_config.event_bus_type}"
        )