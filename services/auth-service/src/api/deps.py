"""
Dependency injection for FastAPI endpoints.
Provides common dependencies like database sessions, current user, etc.
"""
from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from ..core.database import get_db
from ..core.security import SecurityService
from ..models.user import User
from ..services.auth_service import AuthService

logger = structlog.get_logger()
security = HTTPBearer()


async def get_current_user(
    request: Request,
    token: str = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user from token.
    
    Args:
        request: FastAPI request object
        token: Bearer token from Authorization header
        db: Database session
    
    Returns:
        Current user object
    
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Check if user is already in request state (from middleware)
        if hasattr(request.state, 'current_user'):
            return request.state.current_user
        
        # Validate token
        auth_service = AuthService()
        
        # Extract client IP address from request
        # Priority: request.state.client_ip (set by middleware) > request.client.host
        client_ip = getattr(request.state, 'client_ip', None) or (
            request.client.host if request.client else None
        )
        
        user = await auth_service.validate_token(
            db=db,
            token=token.credentials,
            ip_address=client_ip
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get current user", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user.
    
    Args:
        current_user: Current user from token
    
    Returns:
        Active user object
    
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current verified user.
    
    Args:
        current_user: Current active user
    
    Returns:
        Verified user object
    
    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current superuser.
    
    Args:
        current_user: Current active user
    
    Returns:
        Superuser object
    
    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def require_permissions(*required_permissions: str):
    """
    Dependency factory for requiring specific permissions.
    
    Args:
        *required_permissions: Required permission strings (e.g., 'users:read')
    
    Returns:
        Dependency function that checks permissions
    """
    async def permission_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Check if user has required permissions."""
        if current_user.is_superuser:
            return current_user
        
        user_permissions = set(current_user.get_permissions())
        
        for permission in required_permissions:
            if permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission required: {permission}"
                )
        
        return current_user
    
    return permission_checker


def require_roles(*required_roles: str):
    """
    Dependency factory for requiring specific roles.
    
    Args:
        *required_roles: Required role names
    
    Returns:
        Dependency function that checks roles
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Check if user has required roles."""
        if current_user.is_superuser:
            return current_user
        
        user_roles = {role.name for role in current_user.roles}
        
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {' or '.join(required_roles)}"
            )
        
        return current_user
    
    return role_checker


async def get_session_id(request: Request) -> Optional[str]:
    """
    Get session ID from request.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Session ID if available
    """
    # Try to get from request state (set by middleware)
    if hasattr(request.state, 'session_id'):
        return request.state.session_id
    
    # Try to get from Authorization header token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = SecurityService.decode_token(token)
            return payload.get("session_id")
        except Exception:
            pass
    
    # Try to get from cookies
    return request.cookies.get("session_id")


async def get_client_info(request: Request) -> dict:
    """
    Get client information from request.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Client information dictionary
    """
    # Extract client IP address from request
    # Priority: request.state.client_ip (set by middleware) > request.client.host
    client_ip = getattr(request.state, 'client_ip', None) or (
        request.client.host if request.client else None
    )
    
    return {
        "ip_address": client_ip,
        "user_agent": request.headers.get("User-Agent"),
        "origin": request.headers.get("Origin"),
        "referer": request.headers.get("Referer"),
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP")
    }


class CommonQueryParams:
    """Common query parameters for list endpoints."""
    
    def __init__(
        self,
        page: int = 1,
        page_size: int = 50,
        include_inactive: bool = False,
        sort_by: str = "id",
        sort_order: str = "asc"
    ):
        self.page = max(1, page)
        self.page_size = min(100, max(1, page_size))  # Max 100 items per page
        self.skip = (self.page - 1) * self.page_size
        self.limit = self.page_size
        self.include_inactive = include_inactive
        self.sort_by = sort_by
        self.sort_order = sort_order.lower()
        
        if self.sort_order not in ["asc", "desc"]:
            self.sort_order = "asc"


async def get_common_params(
    page: int = 1,
    page_size: int = 50,
    include_inactive: bool = False,
    sort_by: str = "id",
    sort_order: str = "asc"
) -> CommonQueryParams:
    """Dependency for common query parameters."""
    return CommonQueryParams(
        page=page,
        page_size=page_size,
        include_inactive=include_inactive,
        sort_by=sort_by,
        sort_order=sort_order
    )