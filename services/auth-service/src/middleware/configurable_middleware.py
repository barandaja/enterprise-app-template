"""
Configurable middleware implementations.
Each middleware can be configured through configuration objects,
making them extensible and maintainable.
"""

import time
import uuid
import gzip
from typing import Dict, Any
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from fastapi import HTTPException, status
import structlog

from ..interfaces.middleware_interface import IMiddleware
from .middleware_config import (
    SecurityHeadersConfig,
    RateLimitConfig,
    AuthenticationConfig,
    CORSConfig,
    RequestTrackingConfig,
    PerformanceMonitoringConfig,
    ErrorHandlingConfig,
    CompressionConfig,
    LoggingConfig
)

logger = structlog.get_logger()


class ConfigurableSecurityHeadersMiddleware(IMiddleware):
    """Configurable security headers middleware."""
    
    def __init__(self, config: SecurityHeadersConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "SecurityHeaders"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Process incoming request (no modifications needed)."""
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Add security headers to response."""
        if not self.config.enabled:
            return response
        
        try:
            headers = self.config.get_all_headers()
            for header, value in headers.items():
                response.headers[header] = value
            
            return response
        
        except Exception as e:
            logger.error("Security headers middleware failed", error=str(e))
            return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """No exception handling needed."""
        return None


class ConfigurableRateLimitMiddleware(IMiddleware):
    """Configurable rate limiting middleware."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._cache_service = None
    
    @property
    def name(self) -> str:
        return self.config.name or "RateLimit"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Check rate limits before processing request."""
        if not self.config.enabled:
            return request
        
        # Skip rate limiting for excluded paths
        if request.url.path in self.config.excluded_paths:
            return request
        
        try:
            # Get cache service
            if not self._cache_service:
                from ..core.redis import get_cache_service
                self._cache_service = get_cache_service()
            
            # Generate rate limit key
            client_ip = request.client.host
            rate_limit_key = f"rate_limit:{client_ip}:{request.url.path}"
            
            # Check current request count
            current_requests = await self._cache_service.increment(rate_limit_key)
            
            if current_requests == 1:
                # First request in window, set expiration
                await self._cache_service.expire(rate_limit_key, self.config.window_size)
            
            # Check if limit exceeded
            limit = self._get_limit_for_path(request.url.path)
            if current_requests > limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=self.config.rate_limit_response,
                    headers={"Retry-After": str(self.config.window_size)}
                )
            
            # Add rate limit info to request state
            request.state.rate_limit_remaining = max(0, limit - current_requests)
            request.state.rate_limit_limit = limit
            
            return request
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Rate limit middleware failed", error=str(e))
            return request  # Fail open
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Add rate limit headers to response."""
        if hasattr(request.state, 'rate_limit_remaining'):
            response.headers["X-RateLimit-Limit"] = str(request.state.rate_limit_limit)
            response.headers["X-RateLimit-Remaining"] = str(request.state.rate_limit_remaining)
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.config.window_size)
        
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """Handle rate limit exceptions."""
        if isinstance(exception, HTTPException) and exception.status_code == 429:
            return JSONResponse(
                status_code=exception.status_code,
                content=exception.detail,
                headers=exception.headers
            )
        return None
    
    def _get_limit_for_path(self, path: str) -> int:
        """Get rate limit for specific path."""
        for pattern, limits in self.config.endpoint_limits.items():
            if path.startswith(pattern):
                return limits.get("requests_per_minute", self.config.requests_per_minute)
        return self.config.requests_per_minute


class ConfigurableAuthenticationMiddleware(IMiddleware):
    """Configurable authentication middleware."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "Authentication"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Authenticate request if required."""
        if not self.config.enabled:
            return request
        
        # Skip authentication for public paths
        if request.url.path in self.config.public_paths:
            return request
        
        try:
            # Extract token
            token = self._extract_token(request)
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=self.config.auth_required_response,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            # Validate token using auth service
            from ..container import get_container
            from ..services.auth.authentication_service import AuthenticationService
            from ..core.database import get_db
            
            container = get_container()
            auth_service = container.get(AuthenticationService)
            db = next(get_db())
            
            try:
                user = await auth_service.validate_token(
                    db=db,
                    token=token,
                    ip_address=request.client.host
                )
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=self.config.invalid_token_response,
                        headers={"WWW-Authenticate": "Bearer"}
                    )
                
                # Check role requirements
                required_roles = self._get_required_roles(request.url.path)
                if required_roles and not self._user_has_roles(user, required_roles):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=self.config.insufficient_permissions_response
                    )
                
                # Add user to request state
                request.state.current_user = user
                
                # Add user context to logging
                structlog.contextvars.bind_contextvars(
                    user_id=user.id,
                    user_email="***MASKED***"
                )
            
            finally:
                await db.close()
            
            return request
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Authentication middleware failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"detail": "Authentication failed", "error_code": "AUTH_ERROR"}
            )
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """No response processing needed."""
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """Handle authentication exceptions."""
        if isinstance(exception, HTTPException) and exception.status_code in [401, 403]:
            return JSONResponse(
                status_code=exception.status_code,
                content=exception.detail,
                headers=getattr(exception, 'headers', {})
            )
        return None
    
    def _extract_token(self, request: Request) -> str:
        """Extract token from request."""
        # Check Authorization header
        auth_header = request.headers.get(self.config.token_header)
        if auth_header and auth_header.startswith(self.config.token_prefix):
            return auth_header[len(self.config.token_prefix):]
        
        # Check cookie if configured
        if self.config.cookie_name:
            return request.cookies.get(self.config.cookie_name)
        
        return None
    
    def _get_required_roles(self, path: str) -> list:
        """Get required roles for path."""
        for pattern, roles in self.config.role_protected_paths.items():
            if path.startswith(pattern):
                return roles
        return []
    
    def _user_has_roles(self, user, required_roles: list) -> bool:
        """Check if user has required roles."""
        if not required_roles:
            return True
        
        user_roles = {role.name for role in getattr(user, 'roles', [])}
        return any(role in user_roles for role in required_roles)


class ConfigurableCORSMiddleware(IMiddleware):
    """Configurable CORS middleware."""
    
    def __init__(self, config: CORSConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "CORS"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Handle CORS preflight requests."""
        if not self.config.enabled:
            return request
        
        if request.method == "OPTIONS":
            # Handle preflight request
            origin = request.headers.get("origin")
            if self._is_origin_allowed(origin):
                response = Response()
                self._add_cors_headers(response, origin)
                request.state.cors_preflight_response = response
        
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Add CORS headers to response."""
        if not self.config.enabled:
            return response
        
        # Return preflight response if available
        if hasattr(request.state, 'cors_preflight_response'):
            return request.state.cors_preflight_response
        
        # Add CORS headers to regular response
        origin = request.headers.get("origin")
        if self._is_origin_allowed(origin):
            self._add_cors_headers(response, origin)
        
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """No exception handling needed."""
        return None
    
    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed."""
        if not origin:
            return False
        
        if self.config.allow_all_origins or "*" in self.config.allowed_origins:
            return True
        
        return origin in self.config.allowed_origins
    
    def _add_cors_headers(self, response: Response, origin: str):
        """Add CORS headers to response."""
        response.headers["Access-Control-Allow-Origin"] = origin
        
        if self.config.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.config.allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.config.allowed_headers)
        
        if self.config.exposed_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self.config.exposed_headers)
        
        response.headers["Access-Control-Max-Age"] = str(self.config.max_age)


class ConfigurableRequestTrackingMiddleware(IMiddleware):
    """Configurable request tracking middleware."""
    
    def __init__(self, config: RequestTrackingConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "RequestTracking"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Add request tracking."""
        if not self.config.enabled:
            return request
        
        try:
            # Generate request ID
            if self.config.generate_request_id:
                request_id = str(uuid.uuid4())
                request.state.request_id = request_id
                
                # Add to structured logging context
                structlog.contextvars.clear_contextvars()
                structlog.contextvars.bind_contextvars(
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    client_ip=request.client.host
                )
            
            # Start timing
            if self.config.track_performance:
                request.state.start_time = time.time()
            
            # Log request if enabled
            if (self.config.log_requests and 
                request.url.path not in self.config.excluded_paths):
                
                log_data = {}
                for field in self.config.log_fields:
                    if field == "method":
                        log_data["method"] = request.method
                    elif field == "path":
                        log_data["path"] = request.url.path
                    elif field == "client_ip":
                        log_data["client_ip"] = request.client.host
                
                logger.info("Request started", **log_data)
            
            return request
        
        except Exception as e:
            logger.error("Request tracking middleware failed", error=str(e))
            return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Add response tracking."""
        try:
            # Add request ID to response headers
            if hasattr(request.state, 'request_id'):
                response.headers[self.config.request_id_header] = request.state.request_id
            
            # Calculate processing time
            if hasattr(request.state, 'start_time'):
                process_time = time.time() - request.state.start_time
                
                # Log slow requests
                if process_time > self.config.slow_request_threshold:
                    logger.warning(
                        "Slow request detected",
                        path=request.url.path,
                        method=request.method,
                        process_time=f"{process_time:.3f}s",
                        status_code=response.status_code
                    )
                
                # Log response if enabled
                if (self.config.log_responses and 
                    request.url.path not in self.config.excluded_paths):
                    
                    logger.info(
                        "Request completed",
                        status_code=response.status_code,
                        process_time=f"{process_time:.3f}s"
                    )
            
            return response
        
        except Exception as e:
            logger.error("Response tracking failed", error=str(e))
            return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """Handle request tracking exceptions."""
        if hasattr(request.state, 'start_time'):
            process_time = time.time() - request.state.start_time
            logger.error(
                "Request failed",
                error=str(exception),
                process_time=f"{process_time:.3f}s"
            )
        return None


class ConfigurablePerformanceMonitoringMiddleware(IMiddleware):
    """Configurable performance monitoring middleware."""
    
    def __init__(self, config: PerformanceMonitoringConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "PerformanceMonitoring"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        """Start performance monitoring."""
        if self.config.enabled:
            request.state.start_time = time.time()
            
            if self.config.track_memory_usage:
                import psutil
                request.state.start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Add performance monitoring to response."""
        if not self.config.enabled or not hasattr(request.state, 'start_time'):
            return response
        
        try:
            process_time = time.time() - request.state.start_time
            
            # Add timing header
            if self.config.add_timing_header:
                response.headers[self.config.timing_header_name] = f"{process_time:.3f}"
            
            # Log performance metrics
            if process_time > self.config.very_slow_request_threshold:
                logger.error(
                    "Very slow request detected",
                    path=request.url.path,
                    method=request.method,
                    process_time=f"{process_time:.3f}s",
                    status_code=response.status_code
                )
            elif process_time > self.config.slow_request_threshold:
                logger.warning(
                    "Slow request detected",
                    path=request.url.path,
                    method=request.method,
                    process_time=f"{process_time:.3f}s",
                    status_code=response.status_code
                )
            
            # Collect metrics if enabled
            if self.config.collect_metrics:
                self._collect_metrics(request, response, process_time)
            
            return response
        
        except Exception as e:
            logger.error("Performance monitoring failed", error=str(e))
            return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        """No exception handling needed."""
        return None
    
    def _collect_metrics(self, request: Request, response: Response, process_time: float):
        """Collect performance metrics."""
        try:
            # This would integrate with a metrics system like Prometheus
            # For now, just log the metrics
            logger.debug(
                "Performance metrics",
                endpoint=request.url.path,
                method=request.method,
                status_code=response.status_code,
                process_time=process_time,
                metrics_prefix=self.config.metrics_prefix
            )
        except Exception as e:
            logger.debug("Metrics collection failed", error=str(e))


# Placeholder implementations for remaining middleware
class ConfigurableErrorHandlingMiddleware(IMiddleware):
    """Configurable error handling middleware."""
    
    def __init__(self, config: ErrorHandlingConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "ErrorHandling"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        if self.config.enabled:
            logger.error("Unhandled exception", error=str(exception))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=self.config.default_error_response
            )
        return None


class ConfigurableCompressionMiddleware(IMiddleware):
    """Configurable compression middleware."""
    
    def __init__(self, config: CompressionConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "Compression"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        # Simplified compression implementation
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        return None


class ConfigurableLoggingMiddleware(IMiddleware):
    """Configurable logging middleware."""
    
    def __init__(self, config: LoggingConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name or "Logging"
    
    @property
    def priority(self) -> int:
        return self.config.priority
    
    async def process_request(self, request: Request) -> Request:
        if self.config.enabled:
            logger.info("Request received", method=request.method, path=request.url.path)
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        if self.config.enabled:
            logger.info("Response sent", status_code=response.status_code)
        return response
    
    async def handle_exception(self, request: Request, exception: Exception) -> Response:
        if self.config.enabled:
            logger.error("Request exception", error=str(exception))
        return None