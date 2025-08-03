"""
Service registry for backend service discovery and health monitoring.
"""
import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import httpx
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager

logger = structlog.get_logger()


class ServiceStatus(Enum):
    """Service health status."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ServiceEndpoint:
    """Service endpoint configuration."""
    name: str
    url: str
    health_check_path: str = "/health"
    timeout: int = 5
    retries: int = 3
    circuit_breaker_enabled: bool = True
    rate_limit_enabled: bool = True
    authentication_required: bool = True
    version: str = "v1"
    priority: int = 100  # Lower number = higher priority
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class ServiceHealth:
    """Service health information."""
    status: ServiceStatus
    last_check: float
    response_time: Optional[float]
    error_message: Optional[str] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class ServiceRegistry:
    """Service registry with health monitoring and load balancing."""
    
    def __init__(self):
        self.services: Dict[str, ServiceEndpoint] = {}
        self.health_status: Dict[str, ServiceHealth] = {}
        self.health_check_task: Optional[asyncio.Task] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        
    async def initialize(self):
        """Initialize service registry."""
        
        # Initialize HTTP client
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
        )
        
        # Register backend services
        await self._register_backend_services()
        
        # Start health monitoring
        self.health_check_task = asyncio.create_task(self._health_monitor_loop())
        
        logger.info("Service registry initialized", services=list(self.services.keys()))
    
    async def cleanup(self):
        """Cleanup service registry."""
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
        
        if self.http_client:
            await self.http_client.aclose()
        
        logger.info("Service registry cleanup completed")
    
    async def _register_backend_services(self):
        """Register known backend services using Kubernetes DNS and Istio conventions."""
        
        # Get settings dynamically
        settings = get_settings()
        
        # Use the new service registry builder from settings
        service_registry = settings.build_service_registry()
        
        # Auth service
        self.services["auth"] = ServiceEndpoint(
            name="auth",
            url=service_registry.get("auth", settings.auth_service_url),
            health_check_path="/health",
            authentication_required=False,  # Auth service handles its own auth
            tags=["authentication", "security"]
        )
        
        # User service  
        self.services["user"] = ServiceEndpoint(
            name="user",
            url=service_registry.get("user", settings.user_service_url),
            health_check_path="/health",
            tags=["user-management", "profile"]
        )
        
        # Business and auto-discovered services
        for service_name, service_url in service_registry.items():
            if service_name not in ["auth", "user"]:  # Skip already registered services
                self.services[service_name] = ServiceEndpoint(
                    name=service_name,
                    url=service_url,
                    health_check_path="/health",
                    tags=["business-logic", "auto-discovered"] if service_name not in settings.business_service_urls else ["business-logic"]
                )
        
        # Initialize health status
        for service_name in self.services.keys():
            self.health_status[service_name] = ServiceHealth(
                status=ServiceStatus.UNKNOWN,
                last_check=0,
                response_time=None
            )
        
        logger.info(
            "Backend services registered",
            total_services=len(self.services),
            service_names=list(self.services.keys()),
            k8s_namespace=settings.k8s_namespace,
            istio_enabled=settings.istio_enabled
        )
    
    async def get_service_endpoint(self, service_name: str) -> Optional[ServiceEndpoint]:
        """Get service endpoint by name."""
        return self.services.get(service_name)
    
    async def register_dynamic_service(
        self, 
        service_name: str, 
        service_url: Optional[str] = None,
        port: int = 8000,
        tags: List[str] = None
    ) -> bool:
        """
        Dynamically register a new service, optionally using Kubernetes DNS.
        
        Args:
            service_name: Name of the service
            service_url: Full URL, or None to auto-generate K8s DNS
            port: Port number for auto-generated URLs
            tags: Service tags
            
        Returns:
            True if service was registered successfully
        """
        try:
            if service_name in self.services:
                logger.warning("Service already registered", service=service_name)
                return False
            
            # Generate URL if not provided
            if not service_url:
                settings = get_settings()
                service_url = settings.get_k8s_service_url(f"{service_name}-service", port)
            
            # Create service endpoint
            endpoint = ServiceEndpoint(
                name=service_name,
                url=service_url,
                health_check_path="/health",
                tags=tags or ["dynamic", "auto-registered"]
            )
            
            # Register service
            self.services[service_name] = endpoint
            self.health_status[service_name] = ServiceHealth(
                status=ServiceStatus.UNKNOWN,
                last_check=0,
                response_time=None
            )
            
            # Perform initial health check
            await self.health_check_service(service_name)
            
            logger.info(
                "Dynamic service registered",
                service=service_name,
                url=service_url,
                tags=tags
            )
            
            return True
            
        except Exception as e:
            logger.error("Failed to register dynamic service", service=service_name, error=str(e))
            return False
    
    async def unregister_service(self, service_name: str) -> bool:
        """
        Unregister a service from the registry.
        
        Args:
            service_name: Name of the service to unregister
            
        Returns:
            True if service was unregistered successfully
        """
        try:
            if service_name not in self.services:
                logger.warning("Service not found for unregistration", service=service_name)
                return False
            
            # Remove from registries
            del self.services[service_name]
            del self.health_status[service_name]
            
            logger.info("Service unregistered", service=service_name)
            return True
            
        except Exception as e:
            logger.error("Failed to unregister service", service=service_name, error=str(e))
            return False
    
    async def get_healthy_services(self) -> List[str]:
        """Get list of healthy service names."""
        healthy = []
        for service_name, health in self.health_status.items():
            if health.status == ServiceStatus.HEALTHY:
                healthy.append(service_name)
        return healthy
    
    async def is_service_healthy(self, service_name: str) -> bool:
        """Check if a specific service is healthy."""
        health = self.health_status.get(service_name)
        return health and health.status == ServiceStatus.HEALTHY
    
    async def get_service_url(self, service_name: str) -> Optional[str]:
        """Get service URL if service is healthy."""
        if await self.is_service_healthy(service_name):
            service = self.services.get(service_name)
            return service.url if service else None
        return None
    
    async def get_all_services_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered services."""
        status = {}
        for service_name in self.services.keys():
            service = self.services[service_name]
            health = self.health_status[service_name]
            
            status[service_name] = {
                "url": service.url,
                "status": health.status.value,
                "last_check": health.last_check,
                "response_time": health.response_time,
                "error_message": health.error_message,
                "consecutive_failures": health.consecutive_failures,
                "consecutive_successes": health.consecutive_successes,
                "tags": service.tags
            }
        
        return status
    
    async def health_check_service(self, service_name: str) -> bool:
        """Perform health check for a specific service."""
        service = self.services.get(service_name)
        if not service:
            logger.warning("Service not found for health check", service=service_name)
            return False
        
        health = self.health_status[service_name]
        start_time = time.time()
        
        try:
            # Make health check request
            url = f"{service.url.rstrip('/')}{service.health_check_path}"
            response = await self.http_client.get(
                url,
                timeout=service.timeout
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Health check successful
                health.status = ServiceStatus.HEALTHY
                health.response_time = response_time
                health.error_message = None
                health.consecutive_failures = 0
                health.consecutive_successes += 1
                health.last_check = time.time()
                
                # Cache healthy status in Redis
                settings = get_settings()
                await redis_manager.set_json(
                    f"service_health:{service_name}",
                    {
                        "status": "healthy",
                        "last_check": health.last_check,
                        "response_time": response_time
                    },
                    ttl=settings.service_registry_ttl * 2
                )
                
                logger.debug(
                    "Service health check passed",
                    service=service_name,
                    response_time=response_time
                )
                return True
            else:
                raise httpx.HTTPStatusError(
                    f"Health check failed with status {response.status_code}",
                    request=response.request,
                    response=response
                )
        
        except Exception as e:
            # Health check failed
            response_time = time.time() - start_time
            health.status = ServiceStatus.UNHEALTHY
            health.response_time = response_time
            health.error_message = str(e)
            health.consecutive_successes = 0
            health.consecutive_failures += 1
            health.last_check = time.time()
            
            # Cache unhealthy status in Redis
            settings = get_settings()
            await redis_manager.set_json(
                f"service_health:{service_name}",
                {
                    "status": "unhealthy",
                    "last_check": health.last_check,
                    "error": str(e)
                },
                ttl=settings.service_registry_ttl
            )
            
            logger.warning(
                "Service health check failed",
                service=service_name,
                error=str(e),
                consecutive_failures=health.consecutive_failures
            )
            return False
    
    async def health_check_all_services(self):
        """Perform health check for all registered services."""
        tasks = []
        for service_name in self.services.keys():
            task = asyncio.create_task(
                self.health_check_service(service_name)
            )
            tasks.append(task)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            healthy_count = sum(1 for result in results if result is True)
            total_count = len(tasks)
            
            logger.info(
                "Service health check completed",
                healthy=healthy_count,
                total=total_count
            )
    
    async def _health_monitor_loop(self):
        """Background task for continuous health monitoring."""
        while True:
            try:
                settings = get_settings()
                await asyncio.sleep(settings.service_health_check_interval)
                await self.health_check_all_services()
                
            except asyncio.CancelledError:
                logger.info("Health monitor loop cancelled")
                break
            except Exception as e:
                logger.error("Error in health monitor loop", error=str(e))
                await asyncio.sleep(5)  # Wait before retrying