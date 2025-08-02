"""
Compatibility layer for maintaining backward compatibility with existing code.
Provides adapters and facades to bridge old and new architectures.
"""

from .legacy_auth_service import LegacyAuthServiceAdapter
from .middleware_adapter import MiddlewareAdapter

__all__ = [
    "LegacyAuthServiceAdapter",
    "MiddlewareAdapter"
]