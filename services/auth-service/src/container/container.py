"""
Dependency injection container implementation.
Manages service instances and their dependencies following SOLID principles.
"""

from typing import Dict, Any, TypeVar, Type, Optional, Callable
import structlog
from functools import singledispatch

from ..interfaces.cache_interface import ICacheService
from ..interfaces.encryption_interface import IEncryptionService
from ..interfaces.event_interface import IEventBus
from ..interfaces.repository_interface import IUserRepository
from ..services.auth.authentication_service import AuthenticationService
from ..services.auth.token_service import TokenService
from ..services.auth.password_service import PasswordService
from ..services.auth.email_verification_service import EmailVerificationService
from ..services.session_service import SessionService
from ..repositories.user_repository import UserRepository
from ..events.event_bus import InMemoryEventBus
from ..events.event_bus_factory import EventBusFactory
from ..events.audit_handlers import AuditEventHandler
from ..core.config import settings

logger = structlog.get_logger()

T = TypeVar('T')


class Container:
    """Dependency injection container."""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._singletons: Dict[str, Any] = {}
        self._factories: Dict[str, Callable[[], Any]] = {}
        self._initialized = False
    
    def register_singleton(self, interface: Type[T], implementation: Type[T]) -> None:
        """
        Register a singleton service implementation.
        
        Args:
            interface: Interface type
            implementation: Implementation type
        """
        key = interface.__name__
        self._singletons[key] = implementation
        logger.debug("Registered singleton", interface=key, implementation=implementation.__name__)
    
    def register_transient(self, interface: Type[T], implementation: Type[T]) -> None:
        """
        Register a transient service implementation.
        
        Args:
            interface: Interface type
            implementation: Implementation type
        """
        key = interface.__name__
        self._services[key] = implementation
        logger.debug("Registered transient", interface=key, implementation=implementation.__name__)
    
    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """
        Register a factory function for creating service instances.
        
        Args:
            interface: Interface type
            factory: Factory function
        """
        key = interface.__name__
        self._factories[key] = factory
        logger.debug("Registered factory", interface=key, factory=factory.__name__)
    
    def register_instance(self, interface: Type[T], instance: T) -> None:
        """
        Register a specific instance for an interface.
        
        Args:
            interface: Interface type
            instance: Instance to register
        """
        key = interface.__name__
        self._singletons[key] = instance
        logger.debug("Registered instance", interface=key, instance=type(instance).__name__)
    
    def get(self, interface: Type[T]) -> T:
        """
        Get service instance by interface type.
        
        Args:
            interface: Interface type to resolve
            
        Returns:
            Service instance
            
        Raises:
            ValueError: If service is not registered
        """
        key = interface.__name__
        
        # Check if we have a factory
        if key in self._factories:
            return self._factories[key]()
        
        # Check if it's a singleton and already instantiated
        if key in self._singletons:
            singleton = self._singletons[key]
            if not isinstance(singleton, type):
                # Already instantiated
                return singleton
            
            # Need to instantiate singleton
            instance = self._create_instance(singleton)
            self._singletons[key] = instance
            return instance
        
        # Check if it's a transient service
        if key in self._services:
            return self._create_instance(self._services[key])
        
        raise ValueError(f"Service not registered: {key}")
    
    def _create_instance(self, implementation_class: Type[T]) -> T:
        """
        Create instance with dependency injection.
        
        Args:
            implementation_class: Class to instantiate
            
        Returns:
            Instantiated object with dependencies resolved
        """
        # Get constructor parameters
        import inspect
        signature = inspect.signature(implementation_class.__init__)
        
        # Skip 'self' parameter
        parameters = list(signature.parameters.values())[1:]
        
        # Resolve dependencies
        dependencies = {}
        for param in parameters:
            if param.annotation and param.annotation != inspect.Parameter.empty:
                try:
                    dependency = self.get(param.annotation)
                    dependencies[param.name] = dependency
                except ValueError as e:
                    if param.default != inspect.Parameter.empty:
                        # Use default value if available
                        dependencies[param.name] = param.default
                    else:
                        logger.error(
                            "Failed to resolve dependency",
                            class_name=implementation_class.__name__,
                            parameter=param.name,
                            annotation=param.annotation,
                            error=str(e)
                        )
                        raise
        
        # Create instance with resolved dependencies
        try:
            instance = implementation_class(**dependencies)
            logger.debug(
                "Created instance with dependencies",
                class_name=implementation_class.__name__,
                dependencies=list(dependencies.keys())
            )
            return instance
        except Exception as e:
            logger.error(
                "Failed to create instance",
                class_name=implementation_class.__name__,
                error=str(e)
            )
            raise
    
    async def initialize(self) -> None:
        """Initialize the container and configure default services."""
        if self._initialized:
            return
        
        try:
            # Import service implementations
            from .service_implementations import (
                RedisCacheService,
                FernetEncryptionService
            )
            
            # Register cache service as singleton
            self.register_singleton(ICacheService, RedisCacheService)
            
            # Register encryption service as singleton
            self.register_singleton(IEncryptionService, FernetEncryptionService)
            
            # Register event bus as singleton using factory
            event_bus = await EventBusFactory.create_event_bus(
                service_name=settings.SERVICE_NAME,
                service_role=settings.SERVICE_ROLE
            )
            self.register_instance(IEventBus, event_bus)
            
            # Register audit event handler
            audit_handler = AuditEventHandler()
            await event_bus.subscribe_to_all(audit_handler.handle_event)
            
            # Register repository as singleton
            self.register_singleton(IUserRepository, UserRepository)
            
            # Register services as transients (new instance per request)
            self.register_transient(AuthenticationService, AuthenticationService)
            self.register_transient(TokenService, TokenService)
            self.register_transient(PasswordService, PasswordService)
            self.register_transient(EmailVerificationService, EmailVerificationService)
            self.register_transient(SessionService, SessionService)
            
            self._initialized = True
            logger.info("Dependency injection container initialized successfully")
        
        except Exception as e:
            logger.error("Failed to initialize container", error=str(e))
            raise
    
    async def cleanup(self) -> None:
        """Cleanup container resources."""
        try:
            # Cleanup singletons that might need cleanup
            for key, instance in self._singletons.items():
                if hasattr(instance, 'cleanup'):
                    try:
                        await instance.cleanup()
                    except Exception as e:
                        logger.error(f"Failed to cleanup {key}", error=str(e))
            
            logger.info("Container cleanup completed")
        
        except Exception as e:
            logger.error("Container cleanup failed", error=str(e))
    
    def get_registration_info(self) -> Dict[str, str]:
        """Get information about registered services."""
        info = {}
        
        for key, impl in self._singletons.items():
            if isinstance(impl, type):
                info[key] = f"Singleton: {impl.__name__}"
            else:
                info[key] = f"Instance: {type(impl).__name__}"
        
        for key, impl in self._services.items():
            info[key] = f"Transient: {impl.__name__}"
        
        for key, factory in self._factories.items():
            info[key] = f"Factory: {factory.__name__}"
        
        return info


# Global container instance
_container: Optional[Container] = None


def get_container() -> Container:
    """Get the global container instance."""
    global _container
    if _container is None:
        _container = Container()
    return _container


async def initialize_container() -> Container:
    """Initialize and return the global container."""
    container = get_container()
    await container.initialize()
    return container


async def cleanup_container() -> None:
    """Cleanup the global container."""
    global _container
    if _container:
        await _container.cleanup()
        _container = None