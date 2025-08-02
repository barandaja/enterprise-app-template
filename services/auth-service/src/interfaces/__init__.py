"""
Interface definitions for dependency abstractions following SOLID principles.
These Protocol classes define contracts for services to enable dependency injection
and improve testability.
"""

from .cache_interface import ICacheService
from .encryption_interface import IEncryptionService
from .event_interface import IEventBus, IEvent
from .repository_interface import IUserRepository
from .middleware_interface import IMiddleware, IMiddlewareFactory

__all__ = [
    "ICacheService",
    "IEncryptionService", 
    "IEventBus",
    "IEvent",
    "IUserRepository",
    "IMiddleware",
    "IMiddlewareFactory"
]