"""
Enhanced authentication service for the API Gateway.
Integrates with backend auth service for JWT validation and user management.
"""
import asyncio
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import httpx
from jose import JWTError, jwt
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager

logger = structlog.get_logger()
settings = get_settings()


@dataclass
class UserInfo:
    """User information from authentication."""
    user_id: str
    email: str
    roles: List[str]
    permissions: List[str]
    is_active: bool
    is_verified: bool
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class TokenInfo:
    """JWT token information."""
    token: str
    token_type: str = "Bearer"
    expires_at: Optional[float] = None
    issued_at: Optional[float] = None
    user_id: Optional[str] = None
    scopes: List[str] = None
    
    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        return time.time() > self.expires_at


class AuthenticationService:
    """Authentication service for JWT validation and user management."""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=10)
        )
        self._jwt_secret_key: Optional[str] = None
        self._jwt_public_key: Optional[str] = None
    
    async def initialize(self):
        """Initialize authentication service."""
        try:
            # Fetch JWT configuration from auth service
            await self._fetch_jwt_config()
            logger.info("Authentication service initialized")
        except Exception as e:
            logger.error("Failed to initialize authentication service", error=str(e))
            raise
    
    async def cleanup(self):
        """Cleanup authentication service."""
        await self.http_client.aclose()
        logger.info("Authentication service cleanup completed")
    
    async def _fetch_jwt_config(self):
        """Fetch JWT configuration from auth service."""
        try:
            # Try to get JWT public key from auth service
            config_url = f"{settings.auth_service_url}/auth/config/jwt"
            response = await self.http_client.get(config_url)
            
            if response.status_code == 200:
                config = response.json()
                self._jwt_public_key = config.get("public_key")
                self._jwt_secret_key = config.get("secret_key") if settings.environment == "development" else None
                logger.info("JWT configuration fetched from auth service")
            else:
                # Fallback to settings
                self._jwt_secret_key = settings.secret_key
                logger.warning("Using fallback JWT configuration from settings")
        
        except Exception as e:
            logger.warning("Failed to fetch JWT config from auth service", error=str(e))
            self._jwt_secret_key = settings.secret_key
    
    async def validate_token(self, token: str) -> Optional[UserInfo]:
        """
        Validate JWT token and return user information.
        
        Args:
            token: JWT token to validate
            
        Returns:
            UserInfo if token is valid, None otherwise
        """
        try:
            # Check cache first
            cache_key = f"token_validation:{self._get_token_hash(token)}"
            cached_result = await redis_manager.get_json(cache_key)
            if cached_result:
                logger.debug("Token validation cache hit")
                return UserInfo(**cached_result)
            
            # Try local JWT validation first (faster)
            user_info = await self._validate_token_locally(token)
            if user_info:
                # Cache successful validation
                await redis_manager.set_json(
                    cache_key,
                    user_info.__dict__,
                    ttl=settings.cache_auth_ttl
                )
                return user_info
            
            # Fallback to auth service validation
            user_info = await self._validate_token_remote(token)
            if user_info:
                # Cache successful validation
                await redis_manager.set_json(
                    cache_key,
                    user_info.__dict__,
                    ttl=settings.cache_auth_ttl
                )
                return user_info
            
            return None
            
        except Exception as e:
            logger.error("Token validation failed", error=str(e))
            return None
    
    async def _validate_token_locally(self, token: str) -> Optional[UserInfo]:
        """Validate JWT token locally using secret key."""
        try:
            if not self._jwt_secret_key and not self._jwt_public_key:
                return None
            
            # Decode JWT token
            key = self._jwt_public_key or self._jwt_secret_key
            algorithm = "RS256" if self._jwt_public_key else "HS256"
            
            payload = jwt.decode(
                token,
                key,
                algorithms=[algorithm]
            )
            
            # Extract user information
            user_id = payload.get("sub")
            if not user_id:
                return None
            
            # Check expiration
            exp = payload.get("exp")
            if exp and time.time() > exp:
                logger.debug("Token expired", user_id=user_id)
                return None
            
            # Extract user details
            user_info = UserInfo(
                user_id=user_id,
                email=payload.get("email", ""),
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                is_active=payload.get("is_active", True),
                is_verified=payload.get("is_verified", True),
                metadata=payload.get("metadata", {})
            )
            
            logger.debug("Token validated locally", user_id=user_id)
            return user_info
            
        except JWTError as e:
            logger.debug("Local JWT validation failed", error=str(e))
            return None
        except Exception as e:
            logger.error("Local token validation error", error=str(e))
            return None
    
    async def _validate_token_remote(self, token: str) -> Optional[UserInfo]:
        """Validate token with remote auth service."""
        try:
            # Call auth service validation endpoint
            validation_url = f"{settings.auth_service_url}/auth/validate"
            response = await self.http_client.post(
                validation_url,
                json={"token": token},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                user_info = UserInfo(
                    user_id=data["user_id"],
                    email=data.get("email", ""),
                    roles=data.get("roles", []),
                    permissions=data.get("permissions", []),
                    is_active=data.get("is_active", True),
                    is_verified=data.get("is_verified", True),
                    metadata=data.get("metadata", {})
                )
                
                logger.debug("Token validated remotely", user_id=user_info.user_id)
                return user_info
            
            elif response.status_code == 401:
                logger.debug("Token validation failed - invalid or expired")
                return None
            
            else:
                logger.warning(
                    "Unexpected response from auth service",
                    status_code=response.status_code
                )
                return None
            
        except httpx.TimeoutException:
            logger.warning("Auth service timeout during token validation")
            return None
        except Exception as e:
            logger.error("Remote token validation error", error=str(e))
            return None
    
    def _get_token_hash(self, token: str) -> str:
        """Get a hash of the token for caching."""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()[:16]
    
    async def check_permissions(
        self,
        user_info: UserInfo,
        required_permissions: List[str],
        operation: str = "AND"
    ) -> bool:
        """
        Check if user has required permissions.
        
        Args:
            user_info: User information
            required_permissions: List of required permissions
            operation: "AND" (all required) or "OR" (any required)
            
        Returns:
            True if user has required permissions
        """
        if not required_permissions:
            return True
        
        user_permissions = set(user_info.permissions)
        required_set = set(required_permissions)
        
        if operation == "AND":
            return required_set.issubset(user_permissions)
        else:  # OR
            return bool(required_set.intersection(user_permissions))
    
    async def check_roles(
        self,
        user_info: UserInfo,
        required_roles: List[str],
        operation: str = "OR"
    ) -> bool:
        """
        Check if user has required roles.
        
        Args:
            user_info: User information
            required_roles: List of required roles
            operation: "AND" (all required) or "OR" (any required)
            
        Returns:
            True if user has required roles
        """
        if not required_roles:
            return True
        
        user_roles = set(user_info.roles)
        required_set = set(required_roles)
        
        if operation == "AND":
            return required_set.issubset(user_roles)
        else:  # OR
            return bool(required_set.intersection(user_roles))
    
    async def invalidate_token_cache(self, token: str):
        """Invalidate cached token validation."""
        try:
            cache_key = f"token_validation:{self._get_token_hash(token)}"
            await redis_manager.delete(cache_key)
            logger.debug("Token cache invalidated")
        except Exception as e:
            logger.error("Failed to invalidate token cache", error=str(e))
    
    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active sessions for a user."""
        try:
            sessions_url = f"{settings.auth_service_url}/auth/users/{user_id}/sessions"
            response = await self.http_client.get(sessions_url)
            
            if response.status_code == 200:
                return response.json().get("sessions", [])
            
            return []
            
        except Exception as e:
            logger.error("Failed to get user sessions", user_id=user_id, error=str(e))
            return []
    
    async def revoke_user_sessions(self, user_id: str, session_ids: Optional[List[str]] = None) -> bool:
        """Revoke user sessions."""
        try:
            revoke_url = f"{settings.auth_service_url}/auth/users/{user_id}/sessions/revoke"
            payload = {"session_ids": session_ids} if session_ids else {"all": True}
            
            response = await self.http_client.post(
                revoke_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info("User sessions revoked", user_id=user_id)
                return True
            
            return False
            
        except Exception as e:
            logger.error("Failed to revoke user sessions", user_id=user_id, error=str(e))
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for authentication service."""
        try:
            health_url = f"{settings.auth_service_url}/health"
            response = await self.http_client.get(health_url, timeout=5.0)
            
            auth_service_healthy = response.status_code == 200
            
            return {
                "auth_service": "healthy" if auth_service_healthy else "unhealthy",
                "jwt_config": "configured" if (self._jwt_secret_key or self._jwt_public_key) else "missing",
                "cache_enabled": True,
                "status": "healthy" if auth_service_healthy else "degraded"
            }
            
        except Exception as e:
            logger.error("Authentication service health check failed", error=str(e))
            return {
                "auth_service": "unhealthy",
                "error": str(e),
                "status": "unhealthy"
            }


# Global authentication service instance
auth_service = AuthenticationService()