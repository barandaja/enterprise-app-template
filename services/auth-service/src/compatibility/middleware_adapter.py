"""
Middleware adapter for backward compatibility with existing middleware.
Provides a bridge between old middleware classes and new configurable middleware.
"""

from typing import List, Dict, Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import structlog

from ..interfaces.middleware_interface import IMiddleware
from ..middleware.middleware_factory import MiddlewareFactory
from ..middleware.middleware_config import MiddlewareType

logger = structlog.get_logger()


class MiddlewareAdapter(BaseHTTPMiddleware):
    """
    Adapter that bridges new configurable middleware with FastAPI's middleware system.
    Allows new middleware to work within the existing FastAPI middleware pipeline.
    """
    
    def __init__(self, app, middleware_config: List[Dict[str, Any]] = None):
        super().__init__(app)
        self.middleware_factory = MiddlewareFactory()
        self.middleware_stack = []
        
        if middleware_config:
            self._initialize_middleware_stack(middleware_config)
        else:
            self._initialize_default_middleware_stack()
    
    def _initialize_default_middleware_stack(self):
        """Initialize with default middleware configuration."""
        default_config = [
            {
                "type": MiddlewareType.REQUEST_TRACKING,
                "enabled": True,
                "priority": 5
            },
            {
                "type": MiddlewareType.SECURITY_HEADERS,
                "enabled": True,
                "priority": 10
            },
            {
                "type": MiddlewareType.CORS,
                "enabled": True,
                "priority": 15
            },
            {
                "type": MiddlewareType.RATE_LIMIT,
                "enabled": True,
                "priority": 20,
                "requests_per_minute": 60
            },
            {
                "type": MiddlewareType.AUTHENTICATION,
                "enabled": True,
                "priority": 30
            },
            {
                "type": MiddlewareType.PERFORMANCE_MONITORING,
                "enabled": True,
                "priority": 90
            }
        ]
        
        self._initialize_middleware_stack(default_config)
    
    def _initialize_middleware_stack(self, middleware_config: List[Dict[str, Any]]):
        """Initialize middleware stack from configuration."""
        try:
            self.middleware_stack = self.middleware_factory.create_middleware_stack(
                middleware_config
            )
            
            logger.info(
                "Middleware stack initialized",
                middleware_count=len(self.middleware_stack),
                middleware_names=[m.name for m in self.middleware_stack]
            )
        
        except Exception as e:
            logger.error("Failed to initialize middleware stack", error=str(e))
            self.middleware_stack = []
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request through the middleware stack.
        
        This method integrates the new middleware system with FastAPI's
        existing middleware pipeline.
        """
        try:
            # Process request through all middleware
            processed_request = request
            for middleware in self.middleware_stack:
                try:
                    processed_request = await middleware.process_request(processed_request)
                except Exception as e:
                    # Handle exceptions through middleware
                    error_response = await middleware.handle_exception(processed_request, e)
                    if error_response:
                        return error_response
                    # If middleware doesn't handle the exception, re-raise
                    raise
            
            # Call the next middleware or route handler
            try:
                response = await call_next(processed_request)
            except Exception as e:
                # Handle exceptions from downstream middleware/handlers
                for middleware in reversed(self.middleware_stack):
                    try:
                        error_response = await middleware.handle_exception(processed_request, e)
                        if error_response:
                            response = error_response
                            break
                    except Exception as middleware_error:
                        logger.error(
                            "Middleware exception handler failed",
                            middleware=middleware.name,
                            error=str(middleware_error)
                        )
                else:
                    # No middleware handled the exception, re-raise
                    raise
            
            # Process response through all middleware (in reverse order)
            processed_response = response
            for middleware in reversed(self.middleware_stack):
                try:
                    processed_response = await middleware.process_response(
                        processed_request, 
                        processed_response
                    )
                except Exception as e:
                    logger.error(
                        "Middleware response processing failed",
                        middleware=middleware.name,
                        error=str(e)
                    )
                    # Continue with current response on error
            
            return processed_response
        
        except Exception as e:
            logger.error("Middleware adapter dispatch failed", error=str(e))
            # Fallback: try to call next middleware directly
            try:
                return await call_next(request)
            except Exception as fallback_error:
                logger.error("Fallback dispatch failed", error=str(fallback_error))
                raise
    
    def add_middleware(self, middleware: IMiddleware):
        """
        Add a middleware to the stack dynamically.
        
        Args:
            middleware: Middleware instance to add
        """
        try:
            self.middleware_stack.append(middleware)
            # Re-sort by priority
            self.middleware_stack.sort(key=lambda m: m.priority)
            
            logger.info(
                "Middleware added to stack",
                middleware_name=middleware.name,
                priority=middleware.priority,
                total_middleware=len(self.middleware_stack)
            )
        
        except Exception as e:
            logger.error(
                "Failed to add middleware",
                middleware_name=getattr(middleware, 'name', 'unknown'),
                error=str(e)
            )
    
    def remove_middleware(self, middleware_name: str) -> bool:
        """
        Remove middleware from the stack by name.
        
        Args:
            middleware_name: Name of middleware to remove
            
        Returns:
            True if middleware was removed, False if not found
        """
        try:
            original_count = len(self.middleware_stack)
            self.middleware_stack = [
                m for m in self.middleware_stack 
                if m.name != middleware_name
            ]
            
            removed = len(self.middleware_stack) < original_count
            if removed:
                logger.info(
                    "Middleware removed from stack",
                    middleware_name=middleware_name,
                    remaining_middleware=len(self.middleware_stack)
                )
            else:
                logger.warning(
                    "Middleware not found for removal",
                    middleware_name=middleware_name
                )
            
            return removed
        
        except Exception as e:
            logger.error(
                "Failed to remove middleware",
                middleware_name=middleware_name,
                error=str(e)
            )
            return False
    
    def get_middleware_info(self) -> List[Dict[str, Any]]:
        """
        Get information about current middleware stack.
        
        Returns:
            List of middleware information
        """
        try:
            return [
                {
                    "name": middleware.name,
                    "priority": middleware.priority,
                    "enabled": getattr(middleware, 'config', {}).get('enabled', True)
                }
                for middleware in self.middleware_stack
            ]
        
        except Exception as e:
            logger.error("Failed to get middleware info", error=str(e))
            return []
    
    def reload_middleware(self, middleware_config: List[Dict[str, Any]]):
        """
        Reload middleware stack with new configuration.
        
        Args:
            middleware_config: New middleware configuration
        """
        try:
            logger.info("Reloading middleware stack")
            old_count = len(self.middleware_stack)
            
            self._initialize_middleware_stack(middleware_config)
            
            logger.info(
                "Middleware stack reloaded",
                old_count=old_count,
                new_count=len(self.middleware_stack)
            )
        
        except Exception as e:
            logger.error("Failed to reload middleware stack", error=str(e))


class LegacyMiddlewareWrapper:
    """
    Wrapper to make new configurable middleware compatible with old middleware system.
    This allows gradual adoption of the new middleware system.
    """
    
    def __init__(self, middleware: IMiddleware):
        self.middleware = middleware
    
    async def __call__(self, request: Request, call_next):
        """Make the wrapper callable like traditional middleware."""
        try:
            # Process request
            processed_request = await self.middleware.process_request(request)
            
            # Call next middleware
            try:
                response = await call_next(processed_request)
            except Exception as e:
                # Handle exception
                error_response = await self.middleware.handle_exception(processed_request, e)
                if error_response:
                    return error_response
                raise
            
            # Process response
            return await self.middleware.process_response(processed_request, response)
        
        except Exception as e:
            logger.error(
                "Legacy middleware wrapper failed",
                middleware_name=self.middleware.name,
                error=str(e)
            )
            raise