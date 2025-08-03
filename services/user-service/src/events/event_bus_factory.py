"""
Factory for creating event bus instances based on configuration.
Supports both in-memory and secure event bus implementations.
"""

import os
from typing import Optional
import structlog

from ..interfaces.event_interface import IEventBus
from .event_bus import InMemoryEventBus
from .secure_event_bus_adapter import SecureEventBusAdapter

logger = structlog.get_logger()


class EventBusFactory:
    """Factory for creating appropriate event bus implementation"""
    
    @staticmethod
    async def create_event_bus(
        service_name: str,
        service_role: str,
        event_bus_type: Optional[str] = None
    ) -> IEventBus:
        """
        Create an event bus instance based on configuration.
        
        Args:
            service_name: Name of the service
            service_role: Role/permission set for the service
            event_bus_type: Type of event bus to create (in_memory, redis, kafka)
                          If None, reads from EVENT_BUS_TYPE env var
        
        Returns:
            IEventBus implementation
        """
        # Get event bus type from env if not provided
        if event_bus_type is None:
            event_bus_type = os.getenv("EVENT_BUS_TYPE", "in_memory").lower()
        
        logger.info(
            "Creating event bus",
            extra={
                "event_bus_type": event_bus_type,
                "service_name": service_name,
                "service_role": service_role
            }
        )
        
        # Create appropriate implementation
        if event_bus_type == "in_memory":
            # Use in-memory bus for development/testing
            return InMemoryEventBus()
            
        elif event_bus_type in ["redis", "kafka", "secure"]:
            # Use secure event bus adapter for production
            adapter = SecureEventBusAdapter(
                service_name=service_name,
                service_role=service_role
            )
            
            # Initialize the adapter
            await adapter.initialize()
            
            return adapter
            
        else:
            raise ValueError(f"Unknown event bus type: {event_bus_type}")
    
    @staticmethod
    def get_event_bus_info() -> dict:
        """Get information about current event bus configuration"""
        event_bus_type = os.getenv("EVENT_BUS_TYPE", "in_memory").lower()
        
        info = {
            "type": event_bus_type,
            "secure": event_bus_type != "in_memory",
            "redis_url": os.getenv("REDIS_EVENT_URL", "Not configured"),
            "kafka_servers": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "Not configured"),
            "service_name": os.getenv("SERVICE_NAME", "Not configured"),
            "service_role": os.getenv("SERVICE_ROLE", "Not configured")
        }
        
        # Mask sensitive information
        if info["redis_url"] != "Not configured":
            # Hide password in Redis URL
            import re
            info["redis_url"] = re.sub(r':([^@]+)@', ':****@', info["redis_url"])
        
        return info