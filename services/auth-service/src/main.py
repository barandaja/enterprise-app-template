"""
FastAPI application entry point for the enterprise authentication service.
Production-ready with comprehensive security, monitoring, and error handling.
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any
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
from .core.middleware import (
    SecurityHeadersMiddleware,
    RequestTrackingMiddleware, 
    RateLimitMiddleware,
    CORSSecurityMiddleware,
    ErrorHandlingMiddleware,
    PerformanceMonitoringMiddleware,
    ComplianceMiddleware
)
from .api.auth import router as auth_router
from .container.container import initialize_container, cleanup_container


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
    Application lifespan context manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting auth service", version=settings.VERSION, environment=settings.ENVIRONMENT)
    
    try:
        # Initialize Redis connection
        await initialize_redis()
        logger.info("Redis connection initialized")
        
        # Initialize dependency injection container
        await initialize_container()
        logger.info("Dependency injection container initialized")
        
        yield
        
    finally:
        # Shutdown
        logger.info("Shutting down auth service")
        
        # Cleanup container
        await cleanup_container()
        
        # Close connections
        await close_redis()
        await close_db_connections()
        
        logger.info("Auth service shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Authentication Service with GDPR, HIPAA, and SOC2 compliance",
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan
)

# Add security middleware (order matters!)
# Trusted hosts (outermost)
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "auth-service", "auth-service:8000"] + settings.BACKEND_CORS_ORIGINS
    )

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# CORS handling
app.add_middleware(CORSSecurityMiddleware)

# Compliance middleware
app.add_middleware(ComplianceMiddleware)

# Performance monitoring
app.add_middleware(PerformanceMonitoringMiddleware)

# Error handling
app.add_middleware(ErrorHandlingMiddleware)

# Rate limiting
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.RATE_LIMIT_GLOBAL_PER_MINUTE)

# Request tracking (innermost)
app.add_middleware(RequestTrackingMiddleware)


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
            "error_code": "VALIDATION_ERROR"
        }
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": f"HTTP_{exc.status_code}"
        }
    )


# Health check endpoints
@app.get("/health", tags=["health"])
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "auth-service", "version": settings.VERSION}


@app.get("/ready", tags=["health"])
async def readiness_check():
    """Readiness check with dependency validation."""
    checks = {"database": False, "redis": False}
    
    try:
        # Check database connection
        from .core.database import DatabaseHealthCheck
        checks["database"] = await DatabaseHealthCheck.check_connection()
        
        # Check Redis connection
        from .core.redis import redis_manager
        checks["redis"] = await redis_manager.health_check()
        
        all_ready = all(checks.values())
        
        return {
            "status": "ready" if all_ready else "not_ready",
            "checks": checks,
            "service": "auth-service",
            "version": settings.VERSION
        }
    
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "error": str(e),
                "service": "auth-service",
                "version": settings.VERSION
            }
        )


@app.get("/metrics", tags=["monitoring"])
async def metrics_endpoint():
    """Prometheus metrics endpoint."""
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


# Include API routers
app.include_router(auth_router, prefix=settings.API_V1_STR)


# Root endpoint
@app.get("/", tags=["root"])
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Enterprise Authentication Service",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "docs_url": "/docs" if settings.DEBUG else "Not available in production",
        "health_check": "/health",
        "readiness_check": "/ready"
    }


# CLI commands
def create_app() -> FastAPI:
    """Factory function to create the FastAPI app."""
    return app


def run_dev():
    """Run development server."""
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug" if settings.DEBUG else "info"
    )


def run_prod():
    """Run production server."""
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
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