"""
Advanced decorators for cross-cutting concerns in the auth service.
Implements rate limiting, audit logging, permission checking, and performance monitoring.
"""
import time
import asyncio
import functools
from typing import Callable, Optional, List, Any, Dict
from datetime import datetime
from fastapi import HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from .database import get_db
from .redis import get_cache_service, get_rate_limit_service
from .config import settings
from ..models.user import User
from ..models.session import UserSession
from ..models.audit import AuditLog, AuditEventType, AuditSeverity, AuditLogger

logger = structlog.get_logger()
security = HTTPBearer()


def rate_limit(
    requests_per_minute: int = None,
    requests_per_hour: int = None,
    key_func: Callable = None,
    error_message: str = "Rate limit exceeded"
):
    """
    Rate limiting decorator with Redis backend.
    
    Args:
        requests_per_minute: Maximum requests per minute
        requests_per_hour: Maximum requests per hour  
        key_func: Function to generate rate limit key
        error_message: Custom error message
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Skip rate limiting if disabled
            if not settings.RATE_LIMIT_ENABLED:
                return await func(*args, **kwargs)
            
            # Get request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # No request object found, skip rate limiting
                return await func(*args, **kwargs)
            
            rate_limit_service = get_rate_limit_service()
            
            # Generate rate limit key
            if key_func:
                rate_key = key_func(request, *args, **kwargs)
            else:
                # Default key based on IP and endpoint
                rate_key = f"rate_limit:{request.client.host}:{request.url.path}"
            
            # Check minute-based rate limit
            if requests_per_minute:
                is_limited, current_count, reset_time = await rate_limit_service.is_rate_limited(
                    f"{rate_key}:minute", 
                    requests_per_minute, 
                    60
                )
                
                if is_limited:
                    # Log rate limit violation
                    db = kwargs.get('db') or next(get_db())
                    audit_logger = AuditLogger()
                    await audit_logger.log_security_event(
                        db=db,
                        event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
                        description=f"Rate limit exceeded: {current_count}/{requests_per_minute} per minute",
                        ip_address=request.client.host,
                        severity=AuditSeverity.MEDIUM
                    )
                    
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=error_message,
                        headers={"Retry-After": str(reset_time)}
                    )
            
            # Check hour-based rate limit
            if requests_per_hour:
                is_limited, current_count, reset_time = await rate_limit_service.is_rate_limited(
                    f"{rate_key}:hour", 
                    requests_per_hour, 
                    3600
                )
                
                if is_limited:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=error_message,
                        headers={"Retry-After": str(reset_time)}
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def audit_log(
    event_type: AuditEventType,
    action: str = None,
    resource_type: str = None,
    include_request_data: bool = False,
    include_response_data: bool = False,
    pii_accessed: bool = False,
    severity: AuditSeverity = AuditSeverity.LOW
):
    """
    Audit logging decorator for comprehensive compliance tracking.
    
    Args:
        event_type: Type of audit event
        action: Action being performed
        resource_type: Type of resource being accessed
        include_request_data: Whether to include request data in audit log
        include_response_data: Whether to include response data in audit log
        pii_accessed: Whether PII data is being accessed
        severity: Severity level of the event
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if not settings.ENABLE_AUDIT_LOGGING:
                return await func(*args, **kwargs)
            
            start_time = time.time()
            request = None
            db = None
            user = None
            session_id = None
            
            # Extract context from args/kwargs
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    db = arg
                elif isinstance(arg, User):
                    user = arg
            
            # Extract from kwargs
            db = db or kwargs.get('db')
            user = user or kwargs.get('current_user')
            
            # Get session from request headers if available
            if request and hasattr(request.state, 'session_id'):
                session_id = request.state.session_id
            
            success = True
            error_code = None
            error_message = None
            result = None
            
            try:
                result = await func(*args, **kwargs)
                return result
            
            except HTTPException as e:
                success = False
                error_code = str(e.status_code)
                error_message = e.detail
                raise
            
            except Exception as e:
                success = False
                error_code = "INTERNAL_ERROR"
                error_message = str(e)
                raise
            
            finally:
                if db:
                    try:
                        execution_time = int((time.time() - start_time) * 1000)
                        
                        # Prepare event data
                        event_data = {}
                        
                        if include_request_data and request:
                            event_data['request'] = {
                                'method': request.method,
                                'path': str(request.url.path),
                                'query_params': dict(request.query_params),
                                'headers': dict(request.headers) if not pii_accessed else "***REDACTED***"
                            }
                        
                        if include_response_data and result:
                            # Only include non-sensitive response data
                            if not pii_accessed and hasattr(result, 'dict'):
                                event_data['response'] = result.dict()
                        
                        # Create audit log entry
                        await AuditLog.create_audit_log(
                            db=db,
                            event_type=event_type,
                            action=action or func.__name__,
                            description=f"API call: {func.__name__}",
                            user_id=user.id if user else None,
                            session_id=session_id,
                            ip_address=request.client.host if request else None,
                            user_agent=request.headers.get('User-Agent') if request else None,
                            resource_type=resource_type,
                            success=success,
                            severity=severity,
                            error_code=error_code,
                            error_message=error_message,
                            event_data=event_data,
                            execution_time_ms=execution_time,
                            pii_accessed=pii_accessed,
                            request_method=request.method if request else None,
                            request_path=str(request.url.path) if request else None
                        )
                    
                    except Exception as audit_error:
                        logger.error("Audit logging failed", error=str(audit_error))
        
        return wrapper
    return decorator


def require_permissions(
    resource: str,
    action: str,
    allow_superuser: bool = True
):
    """
    Permission checking decorator for RBAC authorization.
    
    Args:
        resource: Resource being accessed (e.g., 'users', 'roles')
        action: Action being performed (e.g., 'read', 'write', 'delete')
        allow_superuser: Whether superusers bypass permission checks
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            user = None
            request = None
            
            # Extract user and request from args/kwargs
            for arg in args:
                if isinstance(arg, User):
                    user = arg
                elif isinstance(arg, Request):
                    request = arg
            
            user = user or kwargs.get('current_user')
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user has required permission
            if allow_superuser and user.is_superuser:
                return await func(*args, **kwargs)
            
            if not user.has_permission(resource, action):
                # Log permission denial
                if 'db' in kwargs:
                    audit_logger = AuditLogger()
                    await audit_logger.log_security_event(
                        db=kwargs['db'],
                        event_type=AuditEventType.PERMISSION_DENIED,
                        description=f"Permission denied for {resource}:{action}",
                        user_id=user.id,
                        ip_address=request.client.host if request else None,
                        severity=AuditSeverity.MEDIUM
                    )
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions for {resource}:{action}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def cache_result(
    ttl: int = 300,  # 5 minutes default
    key_func: Callable = None,
    vary_by_user: bool = False
):
    """
    Caching decorator with Redis backend.
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key
        vary_by_user: Whether to include user ID in cache key
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            cache_service = get_cache_service()
            
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default cache key based on function name and args
                key_parts = [func.__name__]
                
                # Add user ID if vary_by_user is True
                if vary_by_user:
                    user = kwargs.get('current_user')
                    if user:
                        key_parts.append(f"user_{user.id}")
                
                # Add string representation of args (excluding sensitive data)
                safe_args = []
                for arg in args:
                    if isinstance(arg, (str, int, float, bool)):
                        safe_args.append(str(arg))
                    elif hasattr(arg, 'id'):
                        safe_args.append(f"{arg.__class__.__name__}_{arg.id}")
                
                if safe_args:
                    key_parts.extend(safe_args)
                
                cache_key = ":".join(key_parts)
            
            # Try to get from cache
            cached_result = await cache_service.get(cache_key)
            if cached_result is not None:
                logger.debug("Cache hit", key=cache_key)
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            
            # Cache the result (only if it's serializable)
            try:
                await cache_service.set(cache_key, result, ttl)
                logger.debug("Cache set", key=cache_key, ttl=ttl)
            except Exception as e:
                logger.warning("Cache set failed", key=cache_key, error=str(e))
            
            return result
        
        return wrapper
    return decorator


def performance_monitor(
    slow_query_threshold_ms: int = 1000,
    log_performance: bool = True
):
    """
    Performance monitoring decorator.
    
    Args:
        slow_query_threshold_ms: Threshold for logging slow queries
        log_performance: Whether to log performance metrics
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                return result
            
            finally:
                if log_performance:
                    execution_time = int((time.time() - start_time) * 1000)
                    
                    log_data = {
                        "function": func.__name__,
                        "execution_time_ms": execution_time,
                        "slow_query": execution_time > slow_query_threshold_ms
                    }
                    
                    if execution_time > slow_query_threshold_ms:
                        logger.warning("Slow query detected", **log_data)
                    else:
                        logger.debug("Performance metric", **log_data)
        
        return wrapper
    return decorator


def validate_session(require_active: bool = True):
    """
    Session validation decorator.
    
    Args:
        require_active: Whether to require an active session
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            db = None
            
            # Extract request and db from args/kwargs
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, AsyncSession):
                    db = arg
            
            db = db or kwargs.get('db')
            
            if not request or not db:
                return await func(*args, **kwargs)
            
            # Get session ID from headers or cookies
            session_id = None
            
            # Try Authorization header first
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                # Extract session ID from token (implementation depends on token format)
                # For now, assume token contains session info
                pass
            
            # Try session cookie
            if not session_id:
                session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
            
            if require_active and session_id:
                # Validate session
                session = await UserSession.get_by_session_id(db, session_id)
                if session and session.is_valid():
                    # Update last activity
                    await session.update_activity(db)
                    # Store session in request state
                    request.state.session_id = session_id
                    request.state.session = session
                elif require_active:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired session"
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_mfa(allow_trusted_devices: bool = True):
    """
    Multi-factor authentication requirement decorator.
    
    Args:
        allow_trusted_devices: Whether to skip MFA for trusted devices
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            user = None
            
            # Extract request and user from args/kwargs
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, User):
                    user = arg
            
            user = user or kwargs.get('current_user')
            
            if not user or not request:
                return await func(*args, **kwargs)
            
            # Check if session exists and requires MFA
            session = getattr(request.state, 'session', None)
            
            if session:
                # Skip MFA for trusted devices if allowed
                if allow_trusted_devices and session.is_trusted_device:
                    return await func(*args, **kwargs)
                
                # Check if MFA is required and completed
                if session.requires_mfa and not session.mfa_completed:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Multi-factor authentication required",
                        headers={"X-MFA-Required": "true"}
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Combine multiple decorators for common use cases
def secure_endpoint(
    rate_limit_per_minute: int = 60,
    event_type: AuditEventType = AuditEventType.DATA_READ,
    resource: str = None,
    action: str = "read",
    cache_ttl: int = None,
    require_mfa_check: bool = False
):
    """
    Combined decorator for secure endpoints with common security measures.
    
    Args:
        rate_limit_per_minute: Rate limit per minute
        event_type: Audit event type
        resource: Resource type for permission check
        action: Action for permission check
        cache_ttl: Cache TTL in seconds (if caching is desired)
        require_mfa_check: Whether to require MFA
    """
    def decorator(func: Callable) -> Callable:
        # Apply decorators in reverse order (inside-out)
        decorated_func = func
        
        # Performance monitoring (innermost)
        decorated_func = performance_monitor()(decorated_func)
        
        # Caching (if enabled)
        if cache_ttl:
            decorated_func = cache_result(ttl=cache_ttl)(decorated_func)
        
        # Permission checking
        if resource and action:
            decorated_func = require_permissions(resource, action)(decorated_func)
        
        # MFA requirement
        if require_mfa_check:
            decorated_func = require_mfa()(decorated_func)
        
        # Session validation
        decorated_func = validate_session()(decorated_func)
        
        # Audit logging
        decorated_func = audit_log(
            event_type=event_type,
            action=action,
            resource_type=resource
        )(decorated_func)
        
        # Rate limiting (outermost)
        decorated_func = rate_limit(
            requests_per_minute=rate_limit_per_minute
        )(decorated_func)
        
        return decorated_func
    
    return decorator