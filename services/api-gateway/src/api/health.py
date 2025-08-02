"""
Health check endpoints for the API Gateway.
Provides detailed health status of the gateway and backend services.
"""
import asyncio
import time
from typing import Dict, Any
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
import structlog

from ..core.config import get_settings
from ..core.database import DatabaseManager
from ..core.redis import redis_manager
from ..services.service_registry import ServiceRegistry

logger = structlog.get_logger()
settings = get_settings()

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "api-gateway",
        "version": "1.0.0",
        "timestamp": int(time.time())
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """Readiness check for Kubernetes."""
    try:
        # Check Redis connectivity
        redis_healthy = await redis_manager.health_check()
        
        # Check service registry
        service_registry: ServiceRegistry = request.app.state.service_registry
        healthy_services = await service_registry.get_healthy_services()
        
        if redis_healthy and len(healthy_services) > 0:
            return {
                "status": "ready",
                "redis": "healthy",
                "services": len(healthy_services),
                "timestamp": int(time.time())
            }
        else:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "redis": "healthy" if redis_healthy else "unhealthy",
                    "services": len(healthy_services),
                    "timestamp": int(time.time())
                }
            )
    
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "error": str(e),
                "timestamp": int(time.time())
            }
        )


@router.get("/health/detailed")
async def detailed_health_check(request: Request):
    """Detailed health check with component status."""
    
    health_data = {
        "status": "healthy",
        "service": "api-gateway",
        "version": "1.0.0",
        "timestamp": int(time.time()),
        "components": {}
    }
    
    overall_healthy = True
    
    # Check Redis
    try:
        redis_healthy = await redis_manager.health_check()
        redis_stats = await redis_manager.get_connection_stats()
        
        health_data["components"]["redis"] = {
            "status": "healthy" if redis_healthy else "unhealthy",
            "stats": redis_stats
        }
        
        if not redis_healthy:
            overall_healthy = False
    
    except Exception as e:
        health_data["components"]["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_healthy = False
    
    # Check database
    try:
        db_manager = DatabaseManager()
        db_healthy = await db_manager.health_check()
        db_stats = await db_manager.get_connection_stats()
        
        health_data["components"]["database"] = {
            "status": "healthy" if db_healthy else "unhealthy",
            "stats": db_stats
        }
        
        if not db_healthy:
            overall_healthy = False
    
    except Exception as e:
        health_data["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_healthy = False
    
    # Check service registry
    try:
        service_registry: ServiceRegistry = request.app.state.service_registry
        services_status = await service_registry.get_all_services_status()
        
        healthy_count = len([s for s in services_status.values() if s["status"] == "healthy"])
        total_count = len(services_status)
        
        health_data["components"]["service_registry"] = {
            "status": "healthy" if healthy_count > 0 else "unhealthy",
            "healthy_services": healthy_count,
            "total_services": total_count,
            "services": services_status
        }
        
        if healthy_count == 0:
            overall_healthy = False
    
    except Exception as e:
        health_data["components"]["service_registry"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_healthy = False
    
    # Check circuit breakers
    try:
        circuit_breaker_manager = request.app.state.circuit_breaker_manager
        cb_health = await circuit_breaker_manager.health_check()
        cb_states = await circuit_breaker_manager.get_all_states()
        
        health_data["components"]["circuit_breakers"] = {
            "status": cb_health["health"],
            "stats": cb_health,
            "states": cb_states
        }
        
        if cb_health["health"] != "healthy":
            overall_healthy = False
    
    except Exception as e:
        health_data["components"]["circuit_breakers"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        overall_healthy = False
    
    # Update overall status
    health_data["status"] = "healthy" if overall_healthy else "unhealthy"
    
    # Return appropriate HTTP status
    status_code = status.HTTP_200_OK if overall_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return JSONResponse(
        status_code=status_code,
        content=health_data
    )


@router.get("/health/services")
async def services_health_check(request: Request):
    """Health check specifically for backend services."""
    
    try:
        service_registry: ServiceRegistry = request.app.state.service_registry
        
        # Force fresh health check
        await service_registry.health_check_all_services()
        
        # Get current status
        services_status = await service_registry.get_all_services_status()
        
        healthy_count = len([s for s in services_status.values() if s["status"] == "healthy"])
        unhealthy_count = len([s for s in services_status.values() if s["status"] == "unhealthy"])
        total_count = len(services_status)
        
        health_data = {
            "status": "healthy" if healthy_count > 0 else "unhealthy",
            "summary": {
                "total": total_count,
                "healthy": healthy_count,
                "unhealthy": unhealthy_count,
                "health_percentage": (healthy_count / total_count * 100) if total_count > 0 else 0
            },
            "services": services_status,
            "timestamp": int(time.time())
        }
        
        status_code = status.HTTP_200_OK if healthy_count > 0 else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return JSONResponse(
            status_code=status_code,
            content=health_data
        )
    
    except Exception as e:
        logger.error("Services health check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": int(time.time())
            }
        )


@router.get("/health/startup")
async def startup_health_check(request: Request):
    """Startup health check for initialization verification."""
    
    startup_checks = {
        "database_initialized": False,
        "redis_initialized": False,
        "service_registry_initialized": False,
        "circuit_breaker_initialized": False,
        "rate_limiter_initialized": False
    }
    
    all_initialized = True
    
    # Check database initialization
    try:
        db_manager = DatabaseManager()
        startup_checks["database_initialized"] = await db_manager.health_check()
    except:
        startup_checks["database_initialized"] = False
        all_initialized = False
    
    # Check Redis initialization
    try:
        startup_checks["redis_initialized"] = await redis_manager.health_check()
    except:
        startup_checks["redis_initialized"] = False
        all_initialized = False
    
    # Check service registry
    try:
        service_registry: ServiceRegistry = request.app.state.service_registry
        services = await service_registry.get_all_services_status()
        startup_checks["service_registry_initialized"] = len(services) > 0
    except:
        startup_checks["service_registry_initialized"] = False
        all_initialized = False
    
    # Check circuit breaker manager
    try:
        circuit_breaker_manager = request.app.state.circuit_breaker_manager
        startup_checks["circuit_breaker_initialized"] = True
    except:
        startup_checks["circuit_breaker_initialized"] = False
        all_initialized = False
    
    # Check rate limiter manager
    try:
        rate_limiter_manager = request.app.state.rate_limiter_manager
        startup_checks["rate_limiter_initialized"] = True
    except:
        startup_checks["rate_limiter_initialized"] = False
        all_initialized = False
    
    health_data = {
        "status": "initialized" if all_initialized else "initializing",
        "checks": startup_checks,
        "timestamp": int(time.time())
    }
    
    status_code = status.HTTP_200_OK if all_initialized else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return JSONResponse(
        status_code=status_code,
        content=health_data
    )