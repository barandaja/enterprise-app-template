"""
Authentication service focused solely on login/logout operations.
Follows Single Responsibility Principle by handling only authentication logic.
"""

from typing import Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from ...interfaces.cache_interface import ICacheService
from ...interfaces.repository_interface import IUserRepository
from ...interfaces.event_interface import IEventBus
from ...models.user import User
from ...models.session import UserSession
from ...models.audit import AuditEventType, AuditSeverity
from ..session_service import SessionService
from .token_service import TokenService

logger = structlog.get_logger()


class AuthenticationService:
    """Service responsible for user authentication operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        cache_service: ICacheService,
        event_bus: IEventBus,
        session_service: SessionService,
        token_service: TokenService
    ):
        self.user_repository = user_repository
        self.cache_service = cache_service
        self.event_bus = event_bus
        self.session_service = session_service
        self.token_service = token_service
    
    async def authenticate_user(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        location_data: Optional[Dict[str, Any]] = None,
        remember_me: bool = False
    ) -> Tuple[User, UserSession, str, str]:
        """
        Authenticate user and create session with tokens.
        
        Args:
            db: Database session
            email: User email
            password: User password
            ip_address: Client IP address
            user_agent: User agent string
            device_info: Device fingerprint
            location_data: GeoIP location data
            remember_me: Whether to extend session lifetime
        
        Returns:
            Tuple of (user, session, access_token, refresh_token)
        
        Raises:
            HTTPException: If authentication fails
        """
        try:
            # Get user by email
            user = await self.user_repository.get_by_email(db, email)
            
            # Check if user exists
            if not user:
                await self._log_failed_login(db, email, "user_not_found", ip_address)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            
            # Check if account is locked
            if user.is_locked():
                await self._log_failed_login(db, email, "account_locked", ip_address, user.id)
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked"
                )
            
            # Check if user is active
            if not user.is_active:
                await self._log_failed_login(db, email, "account_inactive", ip_address, user.id)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is not active"
                )
            
            # Verify password
            if not await self.user_repository.verify_password(db, user.id, password):
                await user.record_login_attempt(db, success=False, ip_address=ip_address)
                await self._log_failed_login(db, email, "invalid_password", ip_address, user.id)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            
            # Password is correct - record successful login
            await user.record_login_attempt(db, success=True, ip_address=ip_address)
            
            # Create session
            session = await self.session_service.create_session(
                db=db,
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                location_data=location_data,
                remember_me=remember_me
            )
            
            # Generate tokens
            access_token = await self.token_service.create_access_token(
                user_id=user.id,
                session_id=session.session_id
            )
            
            refresh_token = await self.token_service.create_refresh_token(
                user_id=user.id,
                session_id=session.session_id
            )
            
            # Publish authentication event
            from ...events.auth_events import UserAuthenticatedEvent
            auth_event = UserAuthenticatedEvent(
                user_id=user.id,
                session_id=session.session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info
            )
            await self.event_bus.publish(auth_event)
            
            logger.info(
                "User authenticated successfully",
                user_id=user.id,
                session_id=session.session_id,
                ip_address=ip_address
            )
            
            return user, session, access_token, refresh_token
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Authentication failed", email="***MASKED***", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication failed"
            )
    
    async def logout(
        self,
        db: AsyncSession,
        session_id: str,
        user_id: Optional[int] = None,
        logout_all_sessions: bool = False
    ) -> bool:
        """
        Logout user and end session(s).
        
        Args:
            db: Database session
            session_id: Session identifier
            user_id: User ID (for logging out all sessions)
            logout_all_sessions: Whether to logout all user sessions
        
        Returns:
            True if logout successful
        """
        try:
            if logout_all_sessions and user_id:
                # End all user sessions
                count = await self.session_service.end_all_user_sessions(
                    db=db,
                    user_id=user_id,
                    reason="logout_all"
                )
                
                # Publish logout event
                from ...events.auth_events import UserLoggedOutEvent
                logout_event = UserLoggedOutEvent(
                    user_id=user_id,
                    session_count=count,
                    logout_all=True
                )
                await self.event_bus.publish(logout_event)
                
                logger.info("All user sessions ended", user_id=user_id, count=count)
                return count > 0
            else:
                # End specific session
                result = await self.session_service.end_session(
                    db=db,
                    session_id=session_id,
                    reason="logout"
                )
                
                if result and user_id:
                    # Publish logout event
                    from ...events.auth_events import UserLoggedOutEvent
                    logout_event = UserLoggedOutEvent(
                        user_id=user_id,
                        session_id=session_id,
                        logout_all=False
                    )
                    await self.event_bus.publish(logout_event)
                
                return result
        
        except Exception as e:
            logger.error("Logout failed", session_id=session_id, error=str(e))
            return False
    
    async def validate_token(
        self,
        db: AsyncSession,
        token: str,
        ip_address: Optional[str] = None
    ) -> Optional[User]:
        """
        Validate access token and return user.
        
        Args:
            db: Database session
            token: Access token
            ip_address: Client IP address
        
        Returns:
            User object if token is valid
        """
        try:
            # Validate token and get payload
            payload = await self.token_service.validate_access_token(token)
            if not payload:
                return None
            
            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            
            if not user_id:
                return None
            
            # Get user
            user = await self.user_repository.get_by_id(db, int(user_id))
            if not user or not user.is_active:
                return None
            
            # Validate session if provided
            if session_id:
                session = await self.session_service.validate_session(
                    db=db,
                    session_id=session_id,
                    ip_address=ip_address
                )
                
                if not session or session.user_id != user.id:
                    return None
            
            return user
        
        except Exception as e:
            logger.debug("Token validation failed", error=str(e))
            return None
    
    async def _log_failed_login(
        self,
        db: AsyncSession,
        email: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> None:
        """Log failed login attempt."""
        try:
            # Publish failed login event
            from ...events.auth_events import LoginFailedEvent
            failed_event = LoginFailedEvent(
                email=email,
                reason=reason,
                ip_address=ip_address,
                user_id=user_id
            )
            await self.event_bus.publish(failed_event)
        
        except Exception as e:
            logger.error("Failed to log failed login", error=str(e))