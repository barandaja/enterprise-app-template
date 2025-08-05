"""
Comprehensive middleware stack for the API Gateway.
Handles security, rate limiting, circuit breaking, transformation, and monitoring.
"""
import asyncio
import time
import uuid
import json
from typing import Dict, Any, Optional, Callable, Awaitable
import httpx
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager
from ..services.rate_limiter import RateLimiterManager, RateLimitType, RateLimitResult
from ..services.circuit_breaker import CircuitBreakerManager, CircuitBreakerError

logger = structlog.get_logger()
settings = get_settings()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Request logging and tracing middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Log request
        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params),
            user_agent=request.headers.get("user-agent"),
            ip=request.client.host if request.client else None
        )
        
        try:
            # Add request ID to headers for downstream services
            request.headers.__dict__["_list"].append(
                (b"x-request-id", request_id.encode())
            )
            
            response = await call_next(request)
            
            # Log response
            duration = time.time() - start_time
            logger.info(
                "Request completed",
                request_id=request_id,
                status_code=response.status_code,
                duration=duration
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Request failed",
                request_id=request_id,
                error=str(e),
                duration=duration,
                exc_info=True
            )
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "Internal server error",
                    "request_id": request_id
                },
                headers={"X-Request-ID": request_id}
            )


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security headers and basic security checks."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Security headers to add to all responses
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
        }
        
        # Basic security checks
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.max_request_size:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"error": "Request too large"},
                headers=security_headers
            )
        
        # Check for suspicious headers
        suspicious_headers = ["x-forwarded-host", "x-real-ip"]
        for header in suspicious_headers:
            if header in request.headers:
                logger.warning(
                    "Suspicious header detected",
                    request_id=getattr(request.state, 'request_id', 'unknown'),
                    header=header,
                    value=request.headers[header]
                )
        
        response = await call_next(request)
        
        # Add security headers
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware with multiple strategies."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.rate_limiter = RateLimiterManager()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        # Skip rate limiting for health checks and docs
        if request.url.path in ["/health", "/ready", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        try:
            # Get identifiers for rate limiting
            ip_address = request.client.host if request.client else "unknown"
            user_id = getattr(request.state, 'user_id', None)
            api_key = request.headers.get("x-api-key")
            
            logger.debug(
                "Rate limiting check started",
                request_id=request_id,
                path=request.url.path,
                ip_address=ip_address,
                user_id=user_id,
                has_api_key=bool(api_key)
            )
            
            # Check global rate limit
            global_result = await self.rate_limiter.check_rate_limit(
                "global",
                RateLimitType.GLOBAL
            )
            
            if not global_result.allowed:
                logger.warning(
                    "Global rate limit exceeded",
                    request_id=request_id,
                    path=request.url.path,
                    reset_time=global_result.reset_time
                )
                return self._create_rate_limit_response(global_result)
            
            # Check IP rate limit
            ip_result = await self.rate_limiter.check_rate_limit(
                ip_address,
                RateLimitType.IP
            )
            
            if not ip_result.allowed:
                logger.warning(
                    "IP rate limit exceeded",
                    request_id=request_id,
                    path=request.url.path,
                    ip_address=ip_address,
                    reset_time=ip_result.reset_time
                )
                return self._create_rate_limit_response(ip_result)
            
            # Check user rate limit if authenticated
            if user_id:
                user_result = await self.rate_limiter.check_rate_limit(
                    str(user_id),
                    RateLimitType.USER
                )
                
                if not user_result.allowed:
                    logger.warning(
                        "User rate limit exceeded",
                        request_id=request_id,
                        path=request.url.path,
                        user_id=user_id,
                        reset_time=user_result.reset_time
                    )
                    return self._create_rate_limit_response(user_result)
            
            # Check API key rate limit if present
            if api_key:
                api_result = await self.rate_limiter.check_rate_limit(
                    api_key,
                    RateLimitType.API_KEY
                )
                
                if not api_result.allowed:
                    logger.warning(
                        "API key rate limit exceeded",
                        request_id=request_id,
                        path=request.url.path,
                        api_key_prefix=api_key[:8] + "..." if len(api_key) > 8 else "short_key",
                        reset_time=api_result.reset_time
                    )
                    return self._create_rate_limit_response(api_result)
            
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(settings.user_rate_limit_requests)
            response.headers["X-RateLimit-Remaining"] = str(max(0, global_result.remaining))
            response.headers["X-RateLimit-Reset"] = str(int(global_result.reset_time))
            
            return response
            
        except Exception as e:
            logger.error(
                "Rate limiting middleware error",
                request_id=request_id,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                exc_info=True
            )
            
            # On rate limiter failure, allow the request but log the error
            response = await call_next(request)
            response.headers["X-RateLimit-Error"] = "Rate limiter unavailable"
            return response
    
    def _create_rate_limit_response(self, result: RateLimitResult) -> JSONResponse:
        """Create rate limit exceeded response."""
        headers = {
            "X-RateLimit-Limit": "0",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(result.reset_time)),
        }
        
        if result.retry_after:
            headers["Retry-After"] = str(result.retry_after)
        
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Rate limit exceeded",
                "type": result.limit_type,
                "retry_after": result.retry_after
            },
            headers=headers
        )


class CircuitBreakerMiddleware(BaseHTTPMiddleware):
    """Circuit breaker middleware for backend service calls."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.circuit_breaker_manager = CircuitBreakerManager()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Attach circuit breaker manager to request state
        request.state.circuit_breaker_manager = self.circuit_breaker_manager
        
        try:
            response = await call_next(request)
            return response
        except CircuitBreakerError as e:
            logger.warning(
                "Circuit breaker triggered",
                request_id=getattr(request.state, 'request_id', 'unknown'),
                error=str(e)
            )
            
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "error": "Service temporarily unavailable",
                    "message": "Backend service is experiencing issues"
                },
                headers={"Retry-After": "60"}
            )


class RequestTransformMiddleware(BaseHTTPMiddleware):
    """Request transformation and validation middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Parse API version
        api_version = (
            request.headers.get(settings.api_version_header) or
            request.query_params.get("version") or
            settings.default_api_version
        )
        
        if api_version not in settings.supported_api_versions:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "Unsupported API version",
                    "supported_versions": settings.supported_api_versions
                }
            )
        
        request.state.api_version = api_version
        
        # Add correlation headers for downstream services
        request.headers.__dict__["_list"].extend([
            (b"x-api-version", api_version.encode()),
            (b"x-gateway-timestamp", str(int(time.time())).encode()),
        ])
        
        response = await call_next(request)
        return response


class ResponseTransformMiddleware(BaseHTTPMiddleware):
    """Response transformation middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add common headers
        response.headers["X-API-Version"] = getattr(request.state, 'api_version', settings.default_api_version)
        response.headers["X-Gateway"] = "Enterprise-API-Gateway"
        response.headers["X-Timestamp"] = str(int(time.time()))
        
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Metrics collection middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Record metrics
            duration = time.time() - start_time
            await self._record_metrics(
                request,
                response.status_code,
                duration,
                success=True
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            await self._record_metrics(
                request,
                500,
                duration,
                success=False,
                error=str(e)
            )
            raise
    
    async def _record_metrics(
        self,
        request: Request,
        status_code: int,
        duration: float,
        success: bool,
        error: Optional[str] = None
    ):
        """Record request metrics to Redis."""
        try:
            metrics_key = f"metrics:{int(time.time() // 60)}"  # Per-minute buckets
            
            metrics_data = {
                "timestamp": time.time(),
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration": duration,
                "success": success,
                "user_agent": request.headers.get("user-agent", "unknown"),
                "ip": request.client.host if request.client else "unknown"
            }
            
            if error:
                metrics_data["error"] = error
            
            # Store in Redis with TTL
            await redis_manager.set_json(
                f"{metrics_key}:{uuid.uuid4()}",
                metrics_data,
                ttl=3600  # Keep for 1 hour
            )
            
        except Exception as e:
            logger.error("Failed to record metrics", error=str(e))


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Authentication middleware that integrates with auth service."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.http_client = httpx.AsyncClient(timeout=5.0)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for public endpoints
        # Get dynamic auth paths from settings
        auth_paths = settings.get_auth_paths()
        
        public_paths = [
            "/health", "/ready", "/docs", "/redoc", "/openapi.json",
            "/auth/login", "/auth/register", "/auth/password-reset", "/auth/csrf",
            "/auth/refresh", "/api/v1/auth/refresh",  # Add refresh to public paths
            "/security/events", "/api/security/events", 
            settings.get_api_path("security", "events")
        ]
        
        # Add dynamic auth paths
        public_paths.extend(auth_paths)
        
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)
        
        # Extract token
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Missing or invalid authorization header"}
            )
        
        token = auth_header.split(" ")[1]
        
        # Validate token with auth service
        try:
            user_info = await self._validate_token(token, request)
            if not user_info:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"error": "Invalid or expired token"}
                )
            
            # Add user info to request state
            request.state.user_id = user_info.get("user_id")
            request.state.user_info = user_info
            
            # Add user headers for downstream services
            request.headers.__dict__["_list"].extend([
                (b"x-user-id", str(user_info["user_id"]).encode()),
                (b"x-user-email", user_info.get("email", "").encode()),
            ])
            
            return await call_next(request)
            
        except Exception as e:
            logger.error("Authentication failed", error=str(e))
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Authentication failed"}
            )
    
    async def _validate_token(self, token: str, request: Request) -> Optional[Dict[str, Any]]:
        """Validate token using authentication service with enhanced error handling."""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        try:
            auth_service = request.app.state.auth_service
            if not auth_service:
                logger.error(
                    "Authentication service not available",
                    request_id=request_id,
                    path=request.url.path
                )
                return None
                
            user_info = await auth_service.validate_token(token)
            
            if user_info:
                logger.debug(
                    "Token validation successful",
                    request_id=request_id,
                    user_id=user_info.user_id,
                    path=request.url.path
                )
                
                return {
                    "user_id": user_info.user_id,
                    "email": user_info.email,
                    "roles": user_info.roles,
                    "permissions": user_info.permissions,
                    "is_active": user_info.is_active,
                    "is_verified": user_info.is_verified,
                    "metadata": user_info.metadata
                }
            
            logger.warning(
                "Token validation failed - invalid token",
                request_id=request_id,
                path=request.url.path,
                token_prefix=token[:8] + "..." if len(token) > 8 else "short_token"
            )
            return None
            
        except httpx.TimeoutException as e:
            logger.error(
                "Token validation timeout",
                request_id=request_id,
                path=request.url.path,
                error=str(e),
                timeout_duration="5s"
            )
            return None
        except httpx.ConnectError as e:
            logger.error(
                "Authentication service connection failed",
                request_id=request_id,
                path=request.url.path,
                error=str(e),
                service_url=getattr(request.app.state, 'auth_service_url', 'unknown')
            )
            return None
        except Exception as e:
            logger.error(
                "Token validation unexpected error",
                request_id=request_id,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                exc_info=True
            )
            return None