"""
Enterprise API Gateway Service

Central entry point for all microservices with comprehensive security,
routing, monitoring, and compliance features.
"""
import asyncio
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import structlog
import uvicorn

from .core.config import get_settings
from .core.database import init_db
from .core.redis import init_redis, get_redis
from .middleware.gateway_middleware import (
    RequestLoggingMiddleware,
    SecurityMiddleware, 
    RateLimitMiddleware,
    CircuitBreakerMiddleware,
    RequestTransformMiddleware,
    ResponseTransformMiddleware,
    MetricsMiddleware,
    AuthenticationMiddleware
)
from .api.gateway import router as gateway_router
from .api.health import router as health_router
from .api.metrics import router as metrics_router
from .services.service_registry import ServiceRegistry
from .services.circuit_breaker import CircuitBreakerManager
from .services.rate_limiter import RateLimiterManager
from .services.auth_service import auth_service


logger = structlog.get_logger()
settings = get_settings()


async def _validate_architectural_setup(app: FastAPI):
    """Validate that all architectural improvements are properly configured."""
    validation_errors = []
    warnings = []
    
    try:
        # 1. Validate middleware ordering
        middleware_stack = [m.__class__.__name__ for m in app.user_middleware]
        expected_order = [
            "MetricsMiddleware",
            "RequestLoggingMiddleware", 
            "SecurityMiddleware",
            "AuthenticationMiddleware",  # Should be before RateLimitMiddleware
            "RateLimitMiddleware",
            "CircuitBreakerMiddleware",
            "RequestTransformMiddleware",
            "ResponseTransformMiddleware"
        ]
        
        if middleware_stack != expected_order:
            validation_errors.append(
                f"Middleware ordering incorrect. Expected: {expected_order}, Got: {middleware_stack}"
            )
        
        # 2. Validate service discovery configuration
        if not settings.k8s_namespace:
            warnings.append("Kubernetes namespace not configured, using default")
        
        if settings.environment != "development":
            # Check if using Kubernetes DNS patterns
            if not settings.auth_service_url.endswith(".svc.cluster.local:8000"):
                warnings.append("Auth service URL doesn't follow Kubernetes DNS pattern")
            
            if not settings.user_service_url.endswith(".svc.cluster.local:8000"):
                warnings.append("User service URL doesn't follow Kubernetes DNS pattern")
        
        # 3. Validate WebSocket configuration
        # This is validated at runtime when connections are made
        
        # 4. Validate service registry
        service_registry = app.state.service_registry
        registered_services = len(service_registry.services)
        if registered_services == 0:
            validation_errors.append("No services registered in service registry")
        
        # 5. Validate authentication service
        auth_service = app.state.auth_service
        if not auth_service:
            validation_errors.append("Authentication service not initialized")
        
        # Log results
        if validation_errors:
            logger.error(
                "Architectural validation failed",
                errors=validation_errors,
                warnings=warnings
            )
            raise RuntimeError(f"Architectural validation failed: {validation_errors}")
        
        if warnings:
            logger.warning(
                "Architectural validation completed with warnings",
                warnings=warnings
            )
        else:
            logger.info(
                "Architectural validation passed",
                middleware_order="correct",
                k8s_dns="configured" if settings.environment != "development" else "development_mode",
                websocket_auth="message_based_with_legacy_support",
                registered_services=registered_services
            )
            
    except Exception as e:
        logger.error("Error during architectural validation", error=str(e))
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    
    # Startup
    logger.info("Starting API Gateway service")
    
    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized")
        
        # Initialize Redis
        await init_redis()
        logger.info("Redis initialized")
        
        # Initialize service registry
        service_registry = ServiceRegistry()
        await service_registry.initialize()
        app.state.service_registry = service_registry
        logger.info("Service registry initialized")
        
        # Initialize circuit breaker manager
        circuit_breaker_manager = CircuitBreakerManager()
        app.state.circuit_breaker_manager = circuit_breaker_manager
        logger.info("Circuit breaker manager initialized")
        
        # Initialize rate limiter manager  
        rate_limiter_manager = RateLimiterManager()
        app.state.rate_limiter_manager = rate_limiter_manager
        logger.info("Rate limiter manager initialized")
        
        # Initialize authentication service
        await auth_service.initialize()
        app.state.auth_service = auth_service
        logger.info("Authentication service initialized")
        
        # Health check for backend services
        await service_registry.health_check_all_services()
        logger.info("Backend service health checks completed")
        
        # Validate architectural configuration
        await _validate_architectural_setup(app)
        
        logger.info("API Gateway service started successfully")
        
    except Exception as e:
        logger.error("Failed to start API Gateway service", error=str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down API Gateway service")
    
    try:
        # Cleanup service registry
        if hasattr(app.state, 'service_registry'):
            await app.state.service_registry.cleanup()
        
        # Cleanup authentication service
        if hasattr(app.state, 'auth_service'):
            await app.state.auth_service.cleanup()
        
        # Close Redis connections
        redis = await get_redis()
        if redis:
            await redis.close()
        
        logger.info("API Gateway service shutdown completed")
        
    except Exception as e:
        logger.error("Error during service shutdown", error=str(e))


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title="Enterprise API Gateway",
        description="Central API gateway for enterprise microservices architecture",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        openapi_url="/openapi.json" if settings.environment != "production" else None,
    )
    
    # Security middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts
    )
    
    # CORS middleware with explicit domain whitelist
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,  # Now uses explicit domains from config
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining", "X-RateLimit-Limit", "X-RateLimit-Reset"]
    )
    
    # Compression middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Custom middleware stack (order matters - authentication before rate limiting)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(AuthenticationMiddleware)  # Auth first to identify users
    app.add_middleware(RateLimitMiddleware)       # Then rate limit based on user identity
    app.add_middleware(CircuitBreakerMiddleware)
    app.add_middleware(RequestTransformMiddleware)
    app.add_middleware(ResponseTransformMiddleware)
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Global exception handler with proper logging and compliance."""
        
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.error(
            "Unhandled exception in API Gateway",
            request_id=request_id,
            path=request.url.path,
            method=request.method,
            error=str(exc),
            exc_info=True
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "request_id": request_id,
                "timestamp": int(time.time())
            },
            headers={"X-Request-ID": request_id}
        )
    
    # HTTP exception handler
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """HTTP exception handler with proper logging."""
        
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.warning(
            "HTTP exception in API Gateway",
            request_id=request_id,
            path=request.url.path,
            method=request.method,
            status_code=exc.status_code,
            detail=exc.detail
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "request_id": request_id,
                "timestamp": int(time.time())
            },
            headers={"X-Request-ID": request_id}
        )
    
    # Include routers
    app.include_router(health_router)
    app.include_router(metrics_router)
    app.include_router(gateway_router)
    
    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "development",
        workers=1 if settings.environment == "development" else 4,
        log_config=None,  # Use structlog configuration
        access_log=False   # Handle access logging in middleware
    )