"""
Updated FastAPI application entry point using the new SOLID architecture.
Maintains backward compatibility while using the new decomposed services
and configurable middleware system.
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, List
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import structlog
import uvicorn

from .core.config import settings
from .core.database import close_db_connections
from .core.redis import initialize_redis, close_redis
from .container import initialize_container, cleanup_container, get_container
from .compatibility.middleware_adapter import MiddlewareAdapter
from .middleware.middleware_config import MiddlewareType
from .api.auth import router as auth_router

# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer() if settings.DEBUG else structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO level
    logger_factory=structlog.WriteLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager with new architecture initialization.
    Handles startup and shutdown events for both legacy and new systems.
    """
    # Startup
    logger.info(
        "Starting auth service with new architecture", 
        version=settings.VERSION, 
        environment=settings.ENVIRONMENT
    )
    
    try:
        # Initialize Redis connection
        await initialize_redis()
        logger.info("Redis connection initialized")
        
        # Initialize dependency injection container
        container = await initialize_container()
        logger.info("Dependency injection container initialized")
        
        # Initialize event system
        from .interfaces.event_interface import IEventBus
        event_bus = container.get(IEventBus)
        logger.info("Event bus initialized")
        
        # Store container in app state for access in routes
        app.state.container = container
        
        yield
        
    finally:
        # Shutdown
        logger.info("Shutting down auth service")
        
        # Close connections and cleanup
        await cleanup_container()
        await close_redis()
        await close_db_connections()
        
        logger.info("Auth service shutdown complete")


def create_middleware_config() -> List[Dict[str, Any]]:
    """Create middleware configuration based on environment settings."""
    config = [
        {
            "type": MiddlewareType.REQUEST_TRACKING,
            "enabled": True,
            "priority": 5,
            "generate_request_id": True,
            "log_requests": settings.DEBUG,
            "track_performance": True,
            "slow_request_threshold": 1.0
        },
        {
            "type": MiddlewareType.SECURITY_HEADERS,
            "enabled": True,
            "priority": 10,
            "custom_headers": {
                "X-Service-Name": settings.PROJECT_NAME,
                "X-Service-Version": settings.VERSION
            }
        },
        {
            "type": MiddlewareType.CORS,
            "enabled": True,
            "priority": 15,
            "allowed_origins": set(settings.BACKEND_CORS_ORIGINS),
            "allow_credentials": True,
            "allow_all_origins": settings.DEBUG
        },
        {
            "type": MiddlewareType.RATE_LIMIT,
            "enabled": settings.RATE_LIMIT_ENABLED,
            "priority": 20,
            "requests_per_minute": settings.RATE_LIMIT_PER_MINUTE,
            "requests_per_hour": settings.RATE_LIMIT_PER_MINUTE * 60,
            "excluded_paths": {"/health", "/ready", "/metrics"}
        },
        {
            "type": MiddlewareType.AUTHENTICATION,
            "enabled": True,
            "priority": 30,
            "public_paths": {
                "/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json",
                "/api/v1/auth/login", "/api/v1/auth/refresh",
                "/api/v1/auth/password-reset", "/api/v1/auth/password-reset/confirm",
                "/api/v1/auth/verify-email", "/"
            }
        },
        {
            "type": MiddlewareType.PERFORMANCE_MONITORING,
            "enabled": True,
            "priority": 90,
            "slow_request_threshold": 1.0,
            "very_slow_request_threshold": 5.0,
            "add_timing_header": True,
            "collect_metrics": True
        },
        {
            "type": MiddlewareType.LOGGING,
            "enabled": settings.DEBUG,
            "priority": 8,
            "log_request_headers": False,
            "log_response_headers": False,
            "structured_logging": True
        }
    ]
    
    return config


# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Authentication Service with GDPR, HIPAA, and SOC2 compliance - New Architecture",
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan
)

# Add trusted hosts middleware (if not in debug mode)
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1"] + settings.BACKEND_CORS_ORIGINS
    )

# Add the new configurable middleware adapter
middleware_config = create_middleware_config()
app.add_middleware(MiddlewareAdapter, middleware_config=middleware_config)


# Custom exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors."""
    logger.warning("Validation error", errors=exc.errors(), path=request.url.path)
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "error_code": "VALIDATION_ERROR",
            "service": "auth-service-v2"
        }
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": f"HTTP_{exc.status_code}",
            "service": "auth-service-v2"
        }
    )


# Health check endpoints with container integration
@app.get("/health", tags=["health"])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy", 
        "service": "auth-service-v2", 
        "version": settings.VERSION,
        "architecture": "SOLID"
    }


@app.get("/ready", tags=["health"])
async def readiness_check():
    """Readiness check with dependency validation and new architecture."""
    checks = {
        "database": False, 
        "redis": False, 
        "container": False,
        "event_bus": False
    }
    
    try:
        # Check database connection
        from .core.database import DatabaseHealthCheck
        checks["database"] = await DatabaseHealthCheck.check_connection()
        
        # Check Redis connection
        from .core.redis import redis_manager
        checks["redis"] = await redis_manager.health_check()
        
        # Check dependency injection container
        try:
            container = get_container()
            checks["container"] = container is not None
        except Exception:
            checks["container"] = False
        
        # Check event bus
        try:
            if checks["container"]:
                from .interfaces.event_interface import IEventBus
                event_bus = container.get(IEventBus)
                checks["event_bus"] = event_bus is not None
        except Exception:
            checks["event_bus"] = False
        
        all_ready = all(checks.values())
        
        return {
            "status": "ready" if all_ready else "not_ready",
            "checks": checks,
            "service": "auth-service-v2",
            "version": settings.VERSION,
            "architecture": "SOLID"
        }
    
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "error": str(e),
                "service": "auth-service-v2",
                "version": settings.VERSION
            }
        )


@app.get("/metrics", tags=["monitoring"])
async def metrics_endpoint():
    """Prometheus metrics endpoint with additional service metrics."""
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        # Generate Prometheus metrics
        metrics_data = generate_latest()
        
        return Response(
            content=metrics_data,
            media_type=CONTENT_TYPE_LATEST
        )
    
    except ImportError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Metrics not available"}
        )
    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Failed to generate metrics"}
        )


@app.get("/architecture", tags=["info"])
async def architecture_info():
    """Get information about the new architecture."""
    try:
        container = get_container()
        
        # Get service registration info
        service_info = container.get_registration_info()
        
        return {
            "architecture": "SOLID Principles Implementation",
            "version": "2.0",
            "principles": [
                "Single Responsibility Principle",
                "Open/Closed Principle", 
                "Liskov Substitution Principle",
                "Interface Segregation Principle",
                "Dependency Inversion Principle"
            ],
            "patterns": [
                "Service Layer Decomposition",
                "Repository Pattern",
                "Event-Driven Architecture",
                "Dependency Injection",
                "Configurable Middleware"
            ],
            "services": list(service_info.keys()),
            "container_info": service_info
        }
    
    except Exception as e:
        logger.error("Failed to get architecture info", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Failed to get architecture information"}
        )


# Include API routers (these can be updated to use new services gradually)
app.include_router(auth_router, prefix=settings.API_V1_STR)


# Root endpoint
@app.get("/", tags=["root"])
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Enterprise Authentication Service",
        "version": settings.VERSION + "-SOLID",
        "environment": settings.ENVIRONMENT,
        "architecture": "SOLID Principles Implementation",
        "docs_url": "/docs" if settings.DEBUG else "Not available in production",
        "health_check": "/health",
        "readiness_check": "/ready",
        "architecture_info": "/architecture"
    }


# Factory function for the app
def create_app() -> FastAPI:
    """Factory function to create the FastAPI app with new architecture."""
    return app


def run_dev():
    """Run development server with new architecture."""
    logger.info("Starting development server with SOLID architecture")
    uvicorn.run(
        "src.main_updated:app",
        host="0.0.0.0",
        port=8001,  # Different port to avoid conflicts
        reload=True,
        log_level="debug" if settings.DEBUG else "info"
    )


def run_prod():
    """Run production server with new architecture."""
    logger.info("Starting production server with SOLID architecture")
    uvicorn.run(
        "src.main_updated:app",
        host="0.0.0.0",
        port=8001,  # Different port to avoid conflicts
        reload=False,
        log_level="info",
        workers=1,  # Use gunicorn for multiple workers in production
        access_log=False  # Use structured logging instead
    )


if __name__ == "__main__":
    if settings.DEBUG:
        run_dev()
    else:
        run_prod()