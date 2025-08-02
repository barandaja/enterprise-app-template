"""
Factory for creating configured middleware instances.
Implements the Factory pattern to create middleware with proper configuration.
"""

from typing import Dict, List, Type, Any
import structlog

from ..interfaces.middleware_interface import IMiddleware, IMiddlewareFactory
from .middleware_config import (
    MiddlewareConfig,
    MiddlewareType,
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
from .configurable_middleware import (
    ConfigurableSecurityHeadersMiddleware,
    ConfigurableRateLimitMiddleware,
    ConfigurableAuthenticationMiddleware,
    ConfigurableCORSMiddleware,
    ConfigurableRequestTrackingMiddleware,
    ConfigurablePerformanceMonitoringMiddleware,
    ConfigurableErrorHandlingMiddleware,
    ConfigurableCompressionMiddleware,
    ConfigurableLoggingMiddleware
)

logger = structlog.get_logger()


class MiddlewareFactory(IMiddlewareFactory):
    """Factory for creating configured middleware instances."""
    
    def __init__(self):
        self._middleware_registry: Dict[str, Type[IMiddleware]] = {}
        self._config_registry: Dict[str, Type[MiddlewareConfig]] = {}
        self._register_default_middleware()
    
    def _register_default_middleware(self):
        """Register default middleware types and their configurations."""
        # Register middleware implementations
        self._middleware_registry[MiddlewareType.SECURITY_HEADERS] = ConfigurableSecurityHeadersMiddleware
        self._middleware_registry[MiddlewareType.RATE_LIMIT] = ConfigurableRateLimitMiddleware
        self._middleware_registry[MiddlewareType.AUTHENTICATION] = ConfigurableAuthenticationMiddleware
        self._middleware_registry[MiddlewareType.CORS] = ConfigurableCORSMiddleware
        self._middleware_registry[MiddlewareType.REQUEST_TRACKING] = ConfigurableRequestTrackingMiddleware
        self._middleware_registry[MiddlewareType.PERFORMANCE_MONITORING] = ConfigurablePerformanceMonitoringMiddleware
        self._middleware_registry[MiddlewareType.ERROR_HANDLING] = ConfigurableErrorHandlingMiddleware
        self._middleware_registry[MiddlewareType.COMPRESSION] = ConfigurableCompressionMiddleware
        self._middleware_registry[MiddlewareType.LOGGING] = ConfigurableLoggingMiddleware
        
        # Register configuration classes
        self._config_registry[MiddlewareType.SECURITY_HEADERS] = SecurityHeadersConfig
        self._config_registry[MiddlewareType.RATE_LIMIT] = RateLimitConfig
        self._config_registry[MiddlewareType.AUTHENTICATION] = AuthenticationConfig
        self._config_registry[MiddlewareType.CORS] = CORSConfig
        self._config_registry[MiddlewareType.REQUEST_TRACKING] = RequestTrackingConfig
        self._config_registry[MiddlewareType.PERFORMANCE_MONITORING] = PerformanceMonitoringConfig
        self._config_registry[MiddlewareType.ERROR_HANDLING] = ErrorHandlingConfig
        self._config_registry[MiddlewareType.COMPRESSION] = CompressionConfig
        self._config_registry[MiddlewareType.LOGGING] = LoggingConfig
        
        logger.info("Middleware factory initialized with default middleware")
    
    def create_middleware(
        self, 
        middleware_type: str, 
        config: Dict[str, Any]
    ) -> IMiddleware:
        """
        Create middleware instance with configuration.
        
        Args:
            middleware_type: Type of middleware to create
            config: Configuration parameters
            
        Returns:
            Configured middleware instance
            
        Raises:
            ValueError: If middleware type is not registered
        """
        if middleware_type not in self._middleware_registry:
            raise ValueError(f"Unknown middleware type: {middleware_type}")
        
        try:
            # Get middleware class and config class
            middleware_class = self._middleware_registry[middleware_type]
            config_class = self._config_registry[middleware_type]
            
            # Create configuration instance
            middleware_config = self._create_config(config_class, config)
            
            # Create middleware instance
            middleware_instance = middleware_class(middleware_config)
            
            logger.info(
                "Created middleware instance",
                middleware_type=middleware_type,
                enabled=middleware_config.enabled,
                priority=middleware_config.priority
            )
            
            return middleware_instance
        
        except Exception as e:
            logger.error(
                "Failed to create middleware",
                middleware_type=middleware_type,
                error=str(e)
            )
            raise
    
    def create_middleware_stack(
        self, 
        middleware_configs: List[Dict[str, Any]]
    ) -> List[IMiddleware]:
        """
        Create a stack of middleware instances from configuration.
        
        Args:
            middleware_configs: List of middleware configurations
            
        Returns:
            List of middleware instances sorted by priority
        """
        middleware_instances = []
        
        for config in middleware_configs:
            try:
                middleware_type = config.get("type")
                if not middleware_type:
                    logger.warning("Middleware configuration missing type", config=config)
                    continue
                
                # Extract configuration (excluding 'type' field)
                middleware_config = {k: v for k, v in config.items() if k != "type"}
                
                # Create middleware instance
                instance = self.create_middleware(middleware_type, middleware_config)
                
                # Only add if enabled
                if hasattr(instance, 'config') and instance.config.enabled:
                    middleware_instances.append(instance)
                elif not hasattr(instance, 'config'):
                    # Fallback for middleware without config attribute
                    middleware_instances.append(instance)
            
            except Exception as e:
                logger.error(
                    "Failed to create middleware from config",
                    config=config,
                    error=str(e)
                )
                continue
        
        # Sort by priority (lower number = higher priority)
        middleware_instances.sort(key=lambda m: getattr(m, 'priority', 50))
        
        logger.info(
            "Created middleware stack",
            count=len(middleware_instances),
            middleware=[m.name for m in middleware_instances]
        )
        
        return middleware_instances
    
    def get_available_middleware(self) -> List[str]:
        """
        Get list of available middleware types.
        
        Returns:
            List of middleware type names
        """
        return list(self._middleware_registry.keys())
    
    def register_middleware_type(
        self, 
        middleware_type: str, 
        middleware_class: Type[IMiddleware],
        config_class: Type[MiddlewareConfig] = None
    ) -> bool:
        """
        Register a new middleware type.
        
        Args:
            middleware_type: Type name for the middleware
            middleware_class: Middleware class to register
            config_class: Configuration class for the middleware
            
        Returns:
            True if registration successful, False otherwise
        """
        try:
            if middleware_type in self._middleware_registry:
                logger.warning(
                    "Middleware type already registered, overwriting",
                    middleware_type=middleware_type
                )
            
            self._middleware_registry[middleware_type] = middleware_class
            
            if config_class:
                self._config_registry[middleware_type] = config_class
            else:
                # Use base MiddlewareConfig if no specific config provided
                self._config_registry[middleware_type] = MiddlewareConfig
            
            logger.info(
                "Registered middleware type",
                middleware_type=middleware_type,
                middleware_class=middleware_class.__name__
            )
            
            return True
        
        except Exception as e:
            logger.error(
                "Failed to register middleware type",
                middleware_type=middleware_type,
                error=str(e)
            )
            return False
    
    def unregister_middleware_type(self, middleware_type: str) -> bool:
        """
        Unregister a middleware type.
        
        Args:
            middleware_type: Type name to unregister
            
        Returns:
            True if unregistration successful, False otherwise
        """
        try:
            if middleware_type not in self._middleware_registry:
                logger.warning("Middleware type not registered", middleware_type=middleware_type)
                return False
            
            del self._middleware_registry[middleware_type]
            if middleware_type in self._config_registry:
                del self._config_registry[middleware_type]
            
            logger.info("Unregistered middleware type", middleware_type=middleware_type)
            return True
        
        except Exception as e:
            logger.error(
                "Failed to unregister middleware type",
                middleware_type=middleware_type,
                error=str(e)
            )
            return False
    
    def get_default_config(self, middleware_type: str) -> Dict[str, Any]:
        """
        Get default configuration for a middleware type.
        
        Args:
            middleware_type: Middleware type
            
        Returns:
            Default configuration dictionary
        """
        if middleware_type not in self._config_registry:
            return {}
        
        config_class = self._config_registry[middleware_type]
        default_config = config_class()
        
        # Convert to dictionary (simplified)
        return {
            field.name: getattr(default_config, field.name)
            for field in config_class.__dataclass_fields__.values()
        }
    
    def _create_config(
        self, 
        config_class: Type[MiddlewareConfig], 
        config_data: Dict[str, Any]
    ) -> MiddlewareConfig:
        """
        Create configuration instance from data.
        
        Args:
            config_class: Configuration class
            config_data: Configuration data
            
        Returns:
            Configuration instance
        """
        try:
            # Filter config data to only include valid fields
            valid_fields = set(config_class.__dataclass_fields__.keys())
            filtered_config = {
                k: v for k, v in config_data.items() 
                if k in valid_fields
            }
            
            # Create configuration instance
            return config_class(**filtered_config)
        
        except Exception as e:
            logger.error(
                "Failed to create configuration",
                config_class=config_class.__name__,
                error=str(e)
            )
            # Return default configuration on error
            return config_class()
    
    def validate_config(
        self, 
        middleware_type: str, 
        config: Dict[str, Any]
    ) -> tuple[bool, List[str]]:
        """
        Validate middleware configuration.
        
        Args:
            middleware_type: Middleware type
            config: Configuration to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if middleware_type not in self._config_registry:
            errors.append(f"Unknown middleware type: {middleware_type}")
            return False, errors
        
        try:
            config_class = self._config_registry[middleware_type]
            self._create_config(config_class, config)
            return True, []
        
        except Exception as e:
            errors.append(f"Configuration validation failed: {str(e)}")
            return False, errors