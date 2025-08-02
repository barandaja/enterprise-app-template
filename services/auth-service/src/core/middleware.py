"""
Security middleware for FastAPI with comprehensive error handling and monitoring.
Implements request/response logging, security headers, and performance tracking.
"""
import time
import uuid
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
import structlog

from .config import settings
from .redis import get_cache_service

logger = structlog.get_logger()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware for request tracking and correlation."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID for tracing
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Extract and store client IP
        client_ip = request.client.host if request.client else None
        request.state.client_ip = client_ip
        
        # Add request ID to structured logging context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip
        )
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            # Log successful request
            process_time = time.time() - start_time
            logger.info(
                "Request completed",
                status_code=response.status_code,
                process_time=f"{process_time:.3f}s"
            )
            
            return response
        
        except Exception as e:
            # Log failed request
            process_time = time.time() - start_time
            logger.error(
                "Request failed",
                error=str(e),
                process_time=f"{process_time:.3f}s"
            )
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global rate limiting middleware."""
    
    def __init__(self, app, requests_per_minute: int = None):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute or settings.RATE_LIMIT_PER_MINUTE
        self.cache_service = get_cache_service()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting if disabled
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/ready", "/metrics"]:
            return await call_next(request)
        
        client_ip = getattr(request.state, 'client_ip', None) or (
            request.client.host if request.client else None
        )
        rate_limit_key = f"global_rate_limit:{client_ip}"
        
        try:
            # Use Redis for distributed rate limiting
            current_requests = await self.cache_service.increment(rate_limit_key)
            
            if current_requests == 1:
                # First request in window, set expiration
                await self.cache_service.expire(rate_limit_key, 60)
            
            if current_requests > self.requests_per_minute:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Rate limit exceeded",
                        "error_code": "RATE_LIMIT_EXCEEDED"
                    },
                    headers={"Retry-After": "60"}
                )
            
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
            response.headers["X-RateLimit-Remaining"] = str(
                max(0, self.requests_per_minute - current_requests)
            )
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
            
            return response
        
        except Exception as e:
            logger.error("Rate limiting failed", error=str(e))
            # Fail open - don't block requests if rate limiting fails
            return await call_next(request)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware for token-based authentication."""
    
    def __init__(self, app):
        super().__init__(app)
        # Paths that don't require authentication
        self.public_paths = {
            "/health",
            "/ready", 
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/password-reset",
            "/api/v1/auth/password-reset/confirm",
            "/api/v1/auth/verify-email"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for public paths
        if request.url.path in self.public_paths:
            return await call_next(request)
        
        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Authentication required",
                    "error_code": "AUTH_REQUIRED"
                },
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        try:
            # Extract token
            token = auth_header.split(" ")[1]
            
            # Validate token using auth service
            from ..services.auth_service import AuthService
            from ..core.database import get_db
            
            auth_service = AuthService()
            db = next(get_db())
            
            try:
                client_ip = getattr(request.state, 'client_ip', None) or (
                    request.client.host if request.client else None
                )
                
                user = await auth_service.validate_token(
                    db=db,
                    token=token,
                    ip_address=client_ip
                )
                
                if not user:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={
                            "detail": "Invalid or expired token",
                            "error_code": "INVALID_TOKEN"
                        },
                        headers={"WWW-Authenticate": "Bearer"}
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
            
            return await call_next(request)
        
        except Exception as e:
            logger.error("Authentication middleware failed", error=str(e))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": "Authentication failed",
                    "error_code": "AUTH_ERROR"
                }
            )


class CORSSecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced CORS middleware with security considerations."""
    
    def __init__(self, app):
        super().__init__(app)
        self.allowed_origins = set(settings.BACKEND_CORS_ORIGINS)
        self.allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
        self.allowed_headers = {
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        origin = request.headers.get("origin")
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            return self._create_cors_response(origin)
        
        response = await call_next(request)
        
        # Add CORS headers
        if origin and (origin in self.allowed_origins or "*" in self.allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
            response.headers["Access-Control-Max-Age"] = "3600"
        
        return response
    
    def _create_cors_response(self, origin: str) -> Response:
        """Create CORS preflight response."""
        response = Response()
        
        if origin and (origin in self.allowed_origins or "*" in self.allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
            response.headers["Access-Control-Max-Age"] = "3600"
        
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Global error handling middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        
        except HTTPException as e:
            # HTTP exceptions are handled by FastAPI
            raise
        
        except Exception as e:
            # Log unexpected errors
            request_id = getattr(request.state, 'request_id', 'unknown')
            logger.error(
                "Unexpected error in request",
                request_id=request_id,
                error=str(e),
                path=request.url.path,
                method=request.method
            )
            
            # Return generic error response
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": "Internal server error",
                    "error_code": "INTERNAL_ERROR",
                    "request_id": request_id
                }
            )


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for performance monitoring and metrics collection."""
    
    def __init__(self, app):
        super().__init__(app)
        self.slow_request_threshold = 1.0  # 1 second
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        
        # Add performance headers
        response.headers["X-Process-Time"] = f"{process_time:.3f}"
        
        # Log slow requests
        if process_time > self.slow_request_threshold:
            logger.warning(
                "Slow request detected",
                path=request.url.path,
                method=request.method,
                process_time=f"{process_time:.3f}s",
                status_code=response.status_code
            )
        
        # Collect metrics (would integrate with Prometheus in production)
        try:
            from prometheus_client import Counter, Histogram
            
            REQUEST_COUNT = Counter(
                'http_requests_total',
                'Total HTTP requests',
                ['method', 'endpoint', 'status']
            )
            
            REQUEST_DURATION = Histogram(
                'http_request_duration_seconds',
                'HTTP request duration',
                ['method', 'endpoint']
            )
            
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).inc()
            
            REQUEST_DURATION.labels(
                method=request.method,
                endpoint=request.url.path
            ).observe(process_time)
        
        except ImportError:
            # Prometheus not available
            pass
        except Exception as e:
            logger.debug("Metrics collection failed", error=str(e))
        
        return response


class ComplianceMiddleware(BaseHTTPMiddleware):
    """Middleware for compliance-related headers and logging."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check for Do Not Track header (privacy compliance)
        dnt_header = request.headers.get("dnt")
        if dnt_header == "1":
            request.state.do_not_track = True
        
        # GDPR compliance headers
        response = await call_next(request)
        
        # Add privacy policy and terms of service headers
        response.headers["X-Privacy-Policy"] = "https://example.com/privacy"
        response.headers["X-Terms-Of-Service"] = "https://example.com/terms"
        
        # Add data retention policy header
        if settings.GDPR_DATA_RETENTION_DAYS:
            response.headers["X-Data-Retention-Days"] = str(settings.GDPR_DATA_RETENTION_DAYS)
        
        return response