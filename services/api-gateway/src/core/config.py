"""
Configuration settings for the API Gateway service.
"""
from functools import lru_cache
from typing import List, Dict, Any, Optional
from pydantic import field_validator, Field
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    """API Gateway configuration settings."""
    
    # Application settings
    app_name: str = "Enterprise API Gateway"
    environment: str = "development" 
    debug: bool = False
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Security settings
    secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    allowed_hosts: List[str] = ["localhost", "127.0.0.1", "app.example.com", "www.example.com"]
    cors_origins_str: str = Field(default="http://localhost:3000,http://localhost:8080", env="CORS_ORIGINS")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire: int = 1800  # 30 minutes
    
    # Database settings
    database_url: str = os.getenv("DATABASE_URL", "")
    database_pool_size: int = 50  # Increased for 1000 concurrent users
    database_max_overflow: int = 150  # Allow up to 200 total connections
    database_pool_timeout: int = 30
    
    # Redis settings
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis_pool_size: int = 50  # Increased for 1000 concurrent users
    redis_timeout: int = 5
    
    # Service discovery
    service_registry_ttl: int = 30
    service_health_check_interval: int = 10
    
    # Backend services configuration (Kubernetes DNS + Istio service mesh)
    auth_service_url: str = os.getenv("AUTH_SERVICE_URL", "http://auth-service.default.svc.cluster.local:8000")
    user_service_url: str = os.getenv("USER_SERVICE_URL", "http://user-service.default.svc.cluster.local:8000")
    business_service_urls: Dict[str, str] = {}
    
    # Kubernetes namespace for service discovery
    k8s_namespace: str = os.getenv("K8S_NAMESPACE", "default")
    k8s_cluster_domain: str = os.getenv("K8S_CLUSTER_DOMAIN", "cluster.local")
    
    # Istio service mesh settings
    istio_enabled: bool = os.getenv("ISTIO_ENABLED", "false").lower() == "true"
    istio_mesh_gateway: str = os.getenv("ISTIO_MESH_GATEWAY", "istio-system/gateway")
    
    # Rate limiting settings
    global_rate_limit_requests: int = 1000
    global_rate_limit_window: int = 60  # seconds
    user_rate_limit_requests: int = 100
    user_rate_limit_window: int = 60    # seconds
    
    # Circuit breaker settings
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_timeout: int = 60
    circuit_breaker_reset_timeout: int = 300
    
    # Request/Response transformation
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    request_timeout: int = 30
    
    # WebSocket settings
    websocket_ping_interval: int = 20
    websocket_ping_timeout: int = 10
    websocket_max_connections: int = 1000
    
    # Monitoring and observability
    metrics_enabled: bool = True
    tracing_enabled: bool = True
    jaeger_endpoint: Optional[str] = None
    prometheus_multiproc_dir: Optional[str] = None
    
    # Logging settings
    log_level: str = "INFO"
    log_format: str = "json"
    access_log_enabled: bool = True
    
    # Compliance settings
    gdpr_enabled: bool = True
    hipaa_enabled: bool = True
    soc2_enabled: bool = True
    audit_log_retention_days: int = 2555  # 7 years
    
    # Caching settings
    cache_default_ttl: int = 300  # 5 minutes
    cache_auth_ttl: int = 120     # 2 minutes - reduced for security
    cache_max_size: int = 10000
    
    # API versioning
    api_version_header: str = "X-API-Version"
    default_api_version: str = "v1"
    supported_api_versions: List[str] = ["v1"]
    
    # Documentation aggregation
    docs_aggregation_enabled: bool = True
    docs_cache_ttl: int = 3600  # 1 hour
    
    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v):
        if not v:
            raise ValueError("JWT_SECRET_KEY environment variable must be set")
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        return v
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v):
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v
    
    @property
    def cors_origins(self) -> List[str]:
        """Parse CORS origins from string."""
        return [origin.strip() for origin in self.cors_origins_str.split(",")]
    
    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    @field_validator("business_service_urls", mode="before")
    @classmethod
    def parse_business_service_urls(cls, v):
        if isinstance(v, str):
            services = {}
            for service_config in v.split(","):
                if "=" in service_config:
                    name, url = service_config.strip().split("=", 1)
                    services[name] = url
            return services
        return v or {}
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        return self.environment == "development"
    
    def get_service_url(self, service_name: str) -> Optional[str]:
        """Get URL for a backend service."""
        service_urls = {
            "auth": self.auth_service_url,
            "user": self.user_service_url,
            **self.business_service_urls
        }
        return service_urls.get(service_name)
    
    def get_k8s_service_url(self, service_name: str, port: int = 8000, protocol: str = "http") -> str:
        """
        Generate Kubernetes DNS service URL following best practices.
        
        Args:
            service_name: Name of the Kubernetes service
            port: Service port (default: 8000)
            protocol: Protocol (http/https, default: http)
            
        Returns:
            Full service URL in Kubernetes DNS format
        """
        if self.istio_enabled:
            # Use Istio service mesh naming conventions
            return f"{protocol}://{service_name}.{self.k8s_namespace}.svc.{self.k8s_cluster_domain}:{port}"
        else:
            # Standard Kubernetes DNS
            return f"{protocol}://{service_name}.{self.k8s_namespace}.svc.{self.k8s_cluster_domain}:{port}"
    
    def build_service_registry(self) -> Dict[str, str]:
        """Build service registry with Kubernetes DNS names."""
        registry = {}
        
        # Core services
        registry["auth"] = self.auth_service_url
        registry["user"] = self.user_service_url
        
        # Business services
        registry.update(self.business_service_urls)
        
        # Auto-discover additional services based on environment
        if self.environment != "development":
            # In K8s environments, auto-generate common service URLs
            common_services = ["notification", "payment", "analytics", "reporting"]
            for service in common_services:
                if service not in registry:
                    registry[service] = self.get_k8s_service_url(f"{service}-service")
        
        return registry
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore"
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()