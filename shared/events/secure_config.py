"""
Secure event system configuration and factory
"""

import os
from typing import Optional, Dict, Any

from .config import EventBusType, EventConfig, event_config
from .security import EventSecurityConfig


def get_event_security_config() -> EventSecurityConfig:
    """Get event security configuration from environment"""
    return EventSecurityConfig(
        # JWT Configuration
        jwt_secret=os.getenv("EVENT_JWT_SECRET", "CHANGE_ME_event_jwt_secret"),
        jwt_algorithm=os.getenv("EVENT_JWT_ALGORITHM", "HS256"),
        jwt_expiry_seconds=int(os.getenv("EVENT_JWT_EXPIRY_SECONDS", "3600")),
        
        # Encryption Configuration
        encryption_key=os.getenv("EVENT_ENCRYPTION_KEY", "CHANGE_ME_32_byte_encryption_key_here_please!"),
        encrypt_sensitive_fields=os.getenv("EVENT_ENCRYPT_SENSITIVE_FIELDS", "true").lower() == "true",
        sensitive_field_patterns=os.getenv(
            "EVENT_SENSITIVE_PATTERNS",
            "password,secret,token,key,ssn,credit_card,email,phone"
        ).split(","),
        
        # HMAC Configuration
        hmac_secret=os.getenv("EVENT_HMAC_SECRET", "CHANGE_ME_event_hmac_secret"),
        require_event_signing=os.getenv("EVENT_REQUIRE_SIGNING", "true").lower() == "true",
        
        # Rate Limiting
        enable_rate_limiting=os.getenv("EVENT_ENABLE_RATE_LIMITING", "true").lower() == "true",
        default_rate_limit_per_minute=int(os.getenv("EVENT_RATE_LIMIT_PER_MINUTE", "1000")),
        
        # Access Control
        enable_rbac=os.getenv("EVENT_ENABLE_RBAC", "true").lower() == "true",
    )


def get_secure_event_bus_config() -> Dict[str, Any]:
    """Get secure event bus configuration based on type"""
    
    base_config = {
        "security_config": get_event_security_config()
    }
    
    if event_config.event_bus_type == EventBusType.REDIS:
        return {
            **base_config,
            "redis_url": event_config.redis_url,
            "channel_prefix": event_config.redis_channel_prefix,
        }
    
    elif event_config.event_bus_type == EventBusType.KAFKA:
        return {
            **base_config,
            "bootstrap_servers": event_config.kafka_bootstrap_servers,
            "topic_prefix": event_config.kafka_topic_prefix,
            "consumer_group": event_config.kafka_consumer_group,
            # Kafka security
            "security_protocol": os.getenv("KAFKA_SECURITY_PROTOCOL", "SASL_SSL"),
            "sasl_mechanism": os.getenv("KAFKA_SASL_MECHANISM", "PLAIN"),
            "sasl_username": os.getenv("KAFKA_SASL_USERNAME"),
            "sasl_password": os.getenv("KAFKA_SASL_PASSWORD"),
            "ssl_cafile": os.getenv("KAFKA_SSL_CAFILE"),
            "ssl_certfile": os.getenv("KAFKA_SSL_CERTFILE"),
            "ssl_keyfile": os.getenv("KAFKA_SSL_KEYFILE"),
        }
    
    else:
        return base_config


async def create_secure_event_bus(service_token: Optional[str] = None):
    """Factory function to create secure event bus based on configuration"""
    
    security_config = get_event_security_config()
    
    if event_config.event_bus_type == EventBusType.REDIS:
        from .implementations.secure_redis_event_bus import SecureRedisEventBus
        config = get_secure_event_bus_config()
        event_bus = SecureRedisEventBus(**config)
        
        # Authenticate if token provided
        if service_token:
            if not event_bus.authenticate(service_token):
                raise PermissionError("Invalid service token")
        
        await event_bus.start()
        return event_bus
    
    elif event_config.event_bus_type == EventBusType.KAFKA:
        from .implementations.secure_kafka_event_bus import SecureKafkaEventBus
        config = get_secure_event_bus_config()
        event_bus = SecureKafkaEventBus(**config)
        
        # Authenticate if token provided
        if service_token:
            if not event_bus.authenticate(service_token):
                raise PermissionError("Invalid service token")
        
        await event_bus.start()
        return event_bus
    
    elif event_config.event_bus_type == EventBusType.RABBITMQ:
        # RabbitMQ implementation would go here
        raise NotImplementedError("Secure RabbitMQ event bus not yet implemented")
    
    else:  # IN_MEMORY
        from .implementations.in_memory_event_bus import InMemoryEventBus
        # For testing, use regular in-memory bus
        event_bus = InMemoryEventBus()
        await event_bus.start()
        return event_bus


def create_service_token(service_name: str, roles: set[str]) -> str:
    """Create a JWT token for a service"""
    from .security import EventSecurityManager
    
    security_config = get_event_security_config()
    security_manager = EventSecurityManager(security_config)
    
    return security_manager.create_service_token(service_name, roles)