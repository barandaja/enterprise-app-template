"""
Configurable middleware system for FastAPI.
Provides extensible and configurable middleware components following
the Open/Closed Principle.
"""

from .middleware_factory import MiddlewareFactory
from .configurable_middleware import (
    ConfigurableSecurityHeadersMiddleware,
    ConfigurableRateLimitMiddleware,
    ConfigurableAuthenticationMiddleware,
    ConfigurableCORSMiddleware,
    ConfigurableRequestTrackingMiddleware,
    ConfigurablePerformanceMonitoringMiddleware
)
from .middleware_config import MiddlewareConfig, MiddlewareType

__all__ = [
    "MiddlewareFactory",
    "ConfigurableSecurityHeadersMiddleware",
    "ConfigurableRateLimitMiddleware", 
    "ConfigurableAuthenticationMiddleware",
    "ConfigurableCORSMiddleware",
    "ConfigurableRequestTrackingMiddleware",
    "ConfigurablePerformanceMonitoringMiddleware",
    "MiddlewareConfig",
    "MiddlewareType"
]