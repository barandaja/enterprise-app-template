"""
Base event implementation for the event system.
Provides common functionality for all events in the system.
"""

import uuid
from typing import Any, Dict
from datetime import datetime
from dataclasses import dataclass, field

from ..interfaces.event_interface import IEvent


class BaseEvent(IEvent):
    """Base implementation for all events."""
    
    def __init__(self):
        self.correlation_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
    
    @property
    def event_type(self) -> str:
        """Event type identifier based on class name."""
        return self.__class__.__name__
    
    @property
    def data(self) -> Dict[str, Any]:
        """Event data payload excluding system fields."""
        # Get all fields except system fields
        system_fields = {"correlation_id", "timestamp"}
        return {
            key: value for key, value in self.__dict__.items()
            if key not in system_fields and not key.startswith("_")
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_type": self.event_type,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data
        }
    
    def __str__(self) -> str:
        """String representation of the event."""
        return f"{self.event_type}(correlation_id={self.correlation_id}, timestamp={self.timestamp})"