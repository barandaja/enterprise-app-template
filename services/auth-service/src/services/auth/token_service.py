"""
Token service focused solely on JWT token operations.
Follows Single Responsibility Principle by handling only token creation,
validation, and refresh logic.
"""

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from ...interfaces.cache_interface import ICacheService
from ...interfaces.event_interface import IEventBus
from ...core.security import SecurityService
from ...core.config import settings
from ..session_service import SessionService

logger = structlog.get_logger()


class TokenService:
    """Service responsible for JWT token operations."""
    
    def __init__(
        self,
        cache_service: ICacheService,
        event_bus: IEventBus,
        session_service: SessionService
    ):
        self.cache_service = cache_service
        self.event_bus = event_bus
        self.session_service = session_service
    
    async def create_access_token(
        self,
        user_id: int,
        session_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
        Args:
            user_id: User ID
            session_id: Session ID (optional)
            expires_delta: Custom expiration time
        
        Returns:
            JWT access token
        """
        try:
            data = {"sub": str(user_id)}
            if session_id:
                data["session_id"] = session_id
            
            token = SecurityService.create_access_token(
                data=data,
                expires_delta=expires_delta
            )
            
            # Publish token created event
            from ...events.auth_events import TokenCreatedEvent
            token_event = TokenCreatedEvent(
                user_id=user_id,
                token_type="access",
                session_id=session_id
            )
            await self.event_bus.publish(token_event)
            
            logger.debug("Access token created", user_id=user_id, session_id=session_id)
            return token
        
        except Exception as e:
            logger.error("Access token creation failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token creation failed"
            )
    
    async def create_refresh_token(
        self,
        user_id: int,
        session_id: Optional[str] = None,
        jti: Optional[str] = None
    ) -> str:
        """
        Create JWT refresh token.
        
        Args:
            user_id: User ID
            session_id: Session ID (optional)
            jti: JWT ID to use for token (optional, will generate if not provided)
        
        Returns:
            JWT refresh token
        """
        try:
            data = {"sub": str(user_id)}
            if session_id:
                data["session_id"] = session_id
            
            token = SecurityService.create_refresh_token(data=data, jti=jti)
            
            # Publish token created event
            from ...events.auth_events import TokenCreatedEvent
            token_event = TokenCreatedEvent(
                user_id=user_id,
                token_type="refresh",
                session_id=session_id
            )
            await self.event_bus.publish(token_event)
            
            logger.debug("Refresh token created", user_id=user_id, session_id=session_id)
            return token
        
        except Exception as e:
            logger.error("Refresh token creation failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token creation failed"
            )
    
    async def validate_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate access token and return payload.
        
        Args:
            token: JWT access token
        
        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = SecurityService.decode_token(token)
            
            if payload.get("type") != "access":
                return None
            
            # Check if token is blacklisted
            token_id = payload.get("jti")
            if token_id:
                blacklisted = await self.cache_service.exists(f"blacklist:token:{token_id}")
                if blacklisted:
                    return None
            
            return payload
        
        except Exception as e:
            logger.debug("Access token validation failed", error=str(e))
            return None
    
    async def validate_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate refresh token and return payload.
        
        Args:
            token: JWT refresh token
        
        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = SecurityService.decode_token(token)
            
            if payload.get("type") != "refresh":
                return None
            
            # Check if token is blacklisted
            token_id = payload.get("jti")
            if token_id:
                blacklisted = await self.cache_service.exists(f"blacklist:token:{token_id}")
                if blacklisted:
                    return None
            
            return payload
        
        except Exception as e:
            logger.debug("Refresh token validation failed", error=str(e))
            return None
    
    async def refresh_tokens(
        self,
        db: AsyncSession,
        refresh_token: str,
        ip_address: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Refresh access token using refresh token.
        
        Args:
            db: Database session
            refresh_token: Refresh token
            ip_address: Client IP address
        
        Returns:
            Tuple of (new_access_token, new_refresh_token)
        """
        try:
            # Validate refresh token
            payload = await self.validate_refresh_token(refresh_token)
            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            user_id = payload.get("sub")
            refresh_token_id = payload.get("jti")
            session_id = payload.get("session_id")
            
            if not user_id or not refresh_token_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token format"
                )
            
            # Refresh session if session_id is provided
            if session_id:
                session = await self.session_service.refresh_session(
                    db=db,
                    refresh_token_id=refresh_token_id,
                    ip_address=ip_address
                )
                
                if not session:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired refresh token"
                    )
            
            # Blacklist old refresh token
            await self.blacklist_token(refresh_token_id)
            
            # Generate new tokens
            access_token = await self.create_access_token(
                user_id=int(user_id),
                session_id=session_id
            )
            
            new_refresh_token = await self.create_refresh_token(
                user_id=int(user_id),
                session_id=session_id,
                jti=session.refresh_token_id if session else None
            )
            
            # Publish token refreshed event
            from ...events.auth_events import TokenRefreshedEvent
            refresh_event = TokenRefreshedEvent(
                user_id=int(user_id),
                session_id=session_id,
                old_token_id=refresh_token_id
            )
            await self.event_bus.publish(refresh_event)
            
            logger.info(
                "Token refreshed successfully",
                user_id=user_id,
                session_id=session_id
            )
            
            return access_token, new_refresh_token
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Token refresh failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    
    async def blacklist_token(self, token_id: str) -> bool:
        """
        Blacklist a token by its ID.
        
        Args:
            token_id: Token ID to blacklist
        
        Returns:
            True if blacklisted successfully
        """
        try:
            # Store in cache with TTL equal to token expiration
            return await self.cache_service.set(
                f"blacklist:token:{token_id}",
                True,
                ttl=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
            )
        except Exception as e:
            logger.error("Token blacklisting failed", token_id=token_id, error=str(e))
            return False
    
    async def revoke_user_tokens(self, user_id: int) -> bool:
        """
        Revoke all tokens for a user.
        
        Args:
            user_id: User ID
        
        Returns:
            True if revocation successful
        """
        try:
            # In a production system, you'd maintain a list of active tokens
            # For now, we'll use a simple cache key to invalidate user tokens
            revocation_key = f"token_revocation:{user_id}"
            timestamp = datetime.utcnow().timestamp()
            
            return await self.cache_service.set(
                revocation_key,
                timestamp,
                ttl=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
            )
        
        except Exception as e:
            logger.error("Token revocation failed", user_id=user_id, error=str(e))
            return False
    
    async def is_token_revoked(self, user_id: int, token_issued_at: int) -> bool:
        """
        Check if token was revoked after it was issued.
        
        Args:
            user_id: User ID
            token_issued_at: Token issued at timestamp
        
        Returns:
            True if token is revoked
        """
        try:
            revocation_key = f"token_revocation:{user_id}"
            revocation_time = await self.cache_service.get(revocation_key)
            
            if revocation_time and revocation_time > token_issued_at:
                return True
            
            return False
        
        except Exception as e:
            logger.error("Token revocation check failed", user_id=user_id, error=str(e))
            return False