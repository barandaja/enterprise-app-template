"""
Middleware interfaces for dependency abstraction.
Defines contracts for configurable middleware to enable dependency injection
and improve extensibility.
"""

from typing import Callable, Dict, List, Protocol, runtime_checkable, Any
from starlette.requests import Request
from starlette.responses import Response


@runtime_checkable
class IMiddleware(Protocol):
    """Protocol for middleware components."""
    
    @property
    def name(self) -> str:
        """Middleware name identifier."""
        ...
    
    @property
    def priority(self) -> int:
        """Middleware execution priority (lower number = higher priority)."""
        ...
    
    async def process_request(self, request: Request) -> Request:
        """
        Process incoming request before routing.
        
        Args:
            request: Incoming HTTP request
            
        Returns:
            Modified request or original request
        """
        ...
    
    async def process_response(
        self, 
        request: Request, 
        response: Response
    ) -> Response:
        """
        Process outgoing response after routing.
        
        Args:
            request: HTTP request
            response: HTTP response
            
        Returns:
            Modified response or original response
        """
        ...
    
    async def handle_exception(
        self, 
        request: Request, 
        exception: Exception
    ) -> Response:
        """
        Handle exceptions that occur during request processing.
        
        Args:
            request: HTTP request
            exception: Exception that occurred
            
        Returns:
            Error response or None to let other handlers process
        """
        ...


@runtime_checkable
class IMiddlewareFactory(Protocol):
    """Protocol for middleware factory that creates configured middleware instances."""
    
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
        """
        ...
    
    def get_available_middleware(self) -> List[str]:
        """
        Get list of available middleware types.
        
        Returns:
            List of middleware type names
        """
        ...
    
    def register_middleware_type(
        self, 
        middleware_type: str, 
        middleware_class: type
    ) -> bool:
        """
        Register a new middleware type.
        
        Args:
            middleware_type: Type name for the middleware
            middleware_class: Middleware class to register
            
        Returns:
            True if registration successful, False otherwise
        """
        ...