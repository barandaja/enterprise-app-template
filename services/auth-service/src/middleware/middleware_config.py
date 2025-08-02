"""
Configuration classes for middleware system.
Defines configuration options and types for all middleware components.
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class MiddlewareType(str, Enum):
    """Enumeration of available middleware types."""
    
    SECURITY_HEADERS = "security_headers"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION = "authentication"
    CORS = "cors"
    REQUEST_TRACKING = "request_tracking"
    PERFORMANCE_MONITORING = "performance_monitoring"
    ERROR_HANDLING = "error_handling"
    COMPRESSION = "compression"
    LOGGING = "logging"


@dataclass
class MiddlewareConfig:
    """Base configuration for middleware."""
    
    enabled: bool = True
    priority: int = 50  # Lower number = higher priority
    name: Optional[str] = None
    
    def __post_init__(self):
        if self.name is None:
            self.name = self.__class__.__name__.replace("Config", "")


@dataclass
class SecurityHeadersConfig(MiddlewareConfig):
    """Configuration for security headers middleware."""
    
    priority: int = 10  # High priority
    headers: Dict[str, str] = field(default_factory=lambda: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    })
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def get_all_headers(self) -> Dict[str, str]:
        """Get all headers including custom ones."""
        all_headers = self.headers.copy()
        all_headers.update(self.custom_headers)
        return all_headers


@dataclass
class RateLimitConfig(MiddlewareConfig):
    """Configuration for rate limiting middleware."""
    
    priority: int = 20  # High priority
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    window_size: int = 60  # seconds
    
    # Paths to exclude from rate limiting
    excluded_paths: Set[str] = field(default_factory=lambda: {
        "/health", "/ready", "/metrics"
    })
    
    # Different limits for different endpoints
    endpoint_limits: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Custom rate limit keys (e.g., by user, IP, etc.)
    rate_limit_key_generator: Optional[str] = None
    
    # Response when rate limit exceeded
    rate_limit_response: Dict[str, Any] = field(default_factory=lambda: {
        "detail": "Rate limit exceeded",
        "error_code": "RATE_LIMIT_EXCEEDED"
    })


@dataclass
class AuthenticationConfig(MiddlewareConfig):
    """Configuration for authentication middleware."""
    
    priority: int = 30  # Medium-high priority
    
    # Paths that don't require authentication
    public_paths: Set[str] = field(default_factory=lambda: {
        "/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json",
        "/api/v1/auth/login", "/api/v1/auth/refresh",
        "/api/v1/auth/password-reset", "/api/v1/auth/password-reset/confirm",
        "/api/v1/auth/verify-email"
    })
    
    # Paths that require specific roles
    role_protected_paths: Dict[str, List[str]] = field(default_factory=dict)
    
    # Token extraction settings
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "
    cookie_name: Optional[str] = None
    
    # Authentication failure responses
    auth_required_response: Dict[str, Any] = field(default_factory=lambda: {
        "detail": "Authentication required",
        "error_code": "AUTH_REQUIRED"
    })
    
    invalid_token_response: Dict[str, Any] = field(default_factory=lambda: {
        "detail": "Invalid or expired token",
        "error_code": "INVALID_TOKEN"
    })
    
    insufficient_permissions_response: Dict[str, Any] = field(default_factory=lambda: {
        "detail": "Insufficient permissions",
        "error_code": "INSUFFICIENT_PERMISSIONS"
    })


@dataclass
class CORSConfig(MiddlewareConfig):
    """Configuration for CORS middleware."""
    
    priority: int = 15  # High priority, before auth
    
    allowed_origins: Set[str] = field(default_factory=lambda: {"*"})
    allowed_methods: Set[str] = field(default_factory=lambda: {
        "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
    })
    allowed_headers: Set[str] = field(default_factory=lambda: {
        "Accept", "Accept-Language", "Content-Language",
        "Content-Type", "Authorization"
    })
    exposed_headers: Set[str] = field(default_factory=set)
    allow_credentials: bool = True
    max_age: int = 3600
    
    # Whether to allow all origins in development
    allow_all_origins: bool = False


@dataclass
class RequestTrackingConfig(MiddlewareConfig):
    """Configuration for request tracking middleware."""
    
    priority: int = 5  # Very high priority
    
    # Request ID settings
    request_id_header: str = "X-Request-ID"
    generate_request_id: bool = True
    
    # Logging settings
    log_requests: bool = True
    log_responses: bool = True
    log_request_body: bool = False
    log_response_body: bool = False
    
    # Performance tracking
    track_performance: bool = True
    slow_request_threshold: float = 1.0  # seconds
    
    # Fields to include in logs
    log_fields: Set[str] = field(default_factory=lambda: {
        "method", "path", "status_code", "process_time", "client_ip"
    })
    
    # Paths to exclude from logging
    excluded_paths: Set[str] = field(default_factory=lambda: {
        "/health", "/ready"
    })


@dataclass
class PerformanceMonitoringConfig(MiddlewareConfig):
    """Configuration for performance monitoring middleware."""
    
    priority: int = 90  # Low priority, after processing
    
    # Performance thresholds
    slow_request_threshold: float = 1.0  # seconds
    very_slow_request_threshold: float = 5.0  # seconds
    
    # Metrics collection
    collect_metrics: bool = True
    metrics_prefix: str = "auth_service"
    
    # Response headers
    add_timing_header: bool = True
    timing_header_name: str = "X-Process-Time"
    
    # Memory tracking
    track_memory_usage: bool = False
    memory_threshold_mb: int = 100
    
    # Database query tracking
    track_db_queries: bool = True
    db_query_threshold: float = 0.1  # seconds


@dataclass
class ErrorHandlingConfig(MiddlewareConfig):
    """Configuration for error handling middleware."""
    
    priority: int = 95  # Very low priority, catch-all
    
    # Whether to include stack traces in responses
    include_stack_trace: bool = False
    
    # Custom error responses
    default_error_response: Dict[str, Any] = field(default_factory=lambda: {
        "detail": "Internal server error",
        "error_code": "INTERNAL_ERROR"
    })
    
    # Error notification settings
    notify_on_errors: bool = True
    notification_threshold: int = 5  # errors per minute
    
    # Error logging
    log_errors: bool = True
    log_stack_traces: bool = True


@dataclass
class CompressionConfig(MiddlewareConfig):
    """Configuration for response compression middleware."""
    
    priority: int = 85  # Low priority, before response
    
    # Compression settings
    minimum_size: int = 1000  # bytes
    compression_level: int = 6  # 1-9, higher = more compression
    
    # Content types to compress
    compressible_types: Set[str] = field(default_factory=lambda: {
        "application/json", "application/javascript",
        "text/html", "text/css", "text/plain", "text/xml"
    })
    
    # Exclude paths from compression
    excluded_paths: Set[str] = field(default_factory=set)


@dataclass
class LoggingConfig(MiddlewareConfig):
    """Configuration for logging middleware."""
    
    priority: int = 8  # High priority
    
    # Logging levels
    request_log_level: str = "INFO"
    error_log_level: str = "ERROR"
    
    # What to log
    log_request_headers: bool = False
    log_response_headers: bool = False
    log_request_body: bool = False
    log_response_body: bool = False
    
    # Sensitive data filtering
    sensitive_headers: Set[str] = field(default_factory=lambda: {
        "authorization", "cookie", "x-api-key"
    })
    
    sensitive_fields: Set[str] = field(default_factory=lambda: {
        "password", "token", "secret", "key"
    })
    
    # Log format
    structured_logging: bool = True
    include_correlation_id: bool = True