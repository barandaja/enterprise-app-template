"""
Base classes for event-driven architecture
Provides foundation for domain events and event handling
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Type
from uuid import UUID, uuid4
import json


@dataclass
class DomainEvent(ABC):
    """Base class for all domain events"""
    
    event_id: UUID = field(default_factory=uuid4)
    aggregate_id: UUID = field(default=None)
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    version: int = field(default=1)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    @abstractmethod
    def event_name(self) -> str:
        """Return the name of the event"""
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        return {
            "event_id": str(self.event_id),
            "event_name": self.event_name,
            "aggregate_id": str(self.aggregate_id) if self.aggregate_id else None,
            "occurred_at": self.occurred_at.isoformat(),
            "version": self.version,
            "metadata": self.metadata,
            "payload": self._get_payload()
        }
    
    def _get_payload(self) -> Dict[str, Any]:
        """Get event-specific payload"""
        payload = {}
        for key, value in self.__dict__.items():
            if key not in ["event_id", "aggregate_id", "occurred_at", "version", "metadata"]:
                if isinstance(value, UUID):
                    payload[key] = str(value)
                elif isinstance(value, datetime):
                    payload[key] = value.isoformat()
                else:
                    payload[key] = value
        return payload
    
    def to_json(self) -> str:
        """Convert event to JSON string"""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainEvent":
        """Create event from dictionary"""
        event_data = data.copy()
        
        # Extract standard fields
        event_id = UUID(event_data.pop("event_id"))
        aggregate_id = UUID(event_data.pop("aggregate_id")) if event_data.get("aggregate_id") else None
        occurred_at = datetime.fromisoformat(event_data.pop("occurred_at"))
        version = event_data.pop("version", 1)
        metadata = event_data.pop("metadata", {})
        payload = event_data.pop("payload", {})
        
        # Create event with payload
        return cls(
            event_id=event_id,
            aggregate_id=aggregate_id,
            occurred_at=occurred_at,
            version=version,
            metadata=metadata,
            **payload
        )


class EventHandler(ABC):
    """Base class for event handlers"""
    
    @abstractmethod
    async def handle(self, event: DomainEvent) -> None:
        """Handle the event"""
        pass
    
    @property
    @abstractmethod
    def event_type(self) -> Type[DomainEvent]:
        """Return the event type this handler processes"""
        pass


class EventBus(ABC):
    """Abstract base class for event bus implementations"""
    
    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish an event to the bus"""
        pass
    
    @abstractmethod
    async def subscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe a handler to an event type"""
        pass
    
    @abstractmethod
    async def unsubscribe(self, event_type: Type[DomainEvent], handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type"""
        pass


class EventStore(ABC):
    """Abstract base class for event store implementations"""
    
    @abstractmethod
    async def append(self, event: DomainEvent) -> None:
        """Append an event to the store"""
        pass
    
    @abstractmethod
    async def get_events(
        self, 
        aggregate_id: UUID, 
        from_version: Optional[int] = None,
        to_version: Optional[int] = None
    ) -> list[DomainEvent]:
        """Get events for an aggregate"""
        pass
    
    @abstractmethod
    async def get_all_events(
        self,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        limit: Optional[int] = None
    ) -> list[DomainEvent]:
        """Get all events within a time range"""
        pass


class AggregateRoot(ABC):
    """Base class for aggregate roots that produce events"""
    
    def __init__(self, aggregate_id: Optional[UUID] = None):
        self.aggregate_id = aggregate_id or uuid4()
        self._version = 0
        self._pending_events: list[DomainEvent] = []
    
    def add_event(self, event: DomainEvent) -> None:
        """Add a new event to pending events"""
        event.aggregate_id = self.aggregate_id
        event.version = self._version + 1
        self._pending_events.append(event)
        self._version += 1
        
        # Apply event to update state
        self._apply_event(event)
    
    def get_pending_events(self) -> list[DomainEvent]:
        """Get and clear pending events"""
        events = self._pending_events.copy()
        self._pending_events.clear()
        return events
    
    @abstractmethod
    def _apply_event(self, event: DomainEvent) -> None:
        """Apply event to update aggregate state"""
        pass
    
    def replay_events(self, events: list[DomainEvent]) -> None:
        """Replay events to rebuild aggregate state"""
        for event in events:
            self._version = event.version
            self._apply_event(event)


class Saga(ABC):
    """Base class for saga implementations"""
    
    def __init__(self, saga_id: Optional[UUID] = None):
        self.saga_id = saga_id or uuid4()
        self.state = "STARTED"
        self.completed_steps: list[str] = []
        self.failed_step: Optional[str] = None
        self.error: Optional[str] = None
    
    @abstractmethod
    async def handle(self, event: DomainEvent) -> None:
        """Handle an event and potentially trigger next steps"""
        pass
    
    @abstractmethod
    async def compensate(self) -> None:
        """Run compensation logic to rollback saga"""
        pass
    
    def mark_step_completed(self, step: str) -> None:
        """Mark a step as completed"""
        self.completed_steps.append(step)
    
    def mark_failed(self, step: str, error: str) -> None:
        """Mark saga as failed"""
        self.state = "FAILED"
        self.failed_step = step
        self.error = error
    
    def mark_completed(self) -> None:
        """Mark saga as completed"""
        self.state = "COMPLETED"