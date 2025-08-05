"""
Authentication service with comprehensive security features.
Implements login, logout, password reset, and token management.
"""
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import secrets
import structlog

from ..models.user import User
from ..models.session import UserSession
from ..models.audit import AuditEventType, AuditSeverity, AuditLogger
from ..core.security import SecurityService
from ..core.redis import get_cache_service
from ..core.config import settings
from .user_service import UserService
from .session_service import SessionService

logger = structlog.get_logger()


class AuthService:
    """Comprehensive authentication service."""
    
    def __init__(self):
        self.user_service = UserService()
        self.session_service = SessionService()
        self.cache_service = get_cache_service()
        self.audit_logger = AuditLogger()
    
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
        Authenticate user and create session.
        
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
            # Get user by email with roles and permissions eagerly loaded
            logger.info("AuthService.authenticate_user starting", email="***MASKED***")
            user = await self.user_service.get_user_by_email_with_roles(db, email)
            logger.info("AuthService user lookup result", 
                       user_found=user is not None,
                       user_id=user.id if user else None,
                       user_active=user.is_active if user else None,
                       user_verified=user.is_verified if user else None)
            
            # Check if user exists
            if not user:
                await self._log_failed_login(db, email, "user_not_found", ip_address)
                logger.warning("Authentication failed: user not found", email="***MASKED***")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            
            # Check if account is locked
            if user.is_locked():
                await self._log_failed_login(db, email, "account_locked", ip_address)
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked"
                )
            
            # Check if user is active
            if not user.is_active:
                await self._log_failed_login(db, email, "account_inactive", ip_address)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is not active"
                )
            
            # Verify password
            logger.info("AuthService verifying password", user_id=user.id)
            try:
                password_valid = await user.verify_password(password)
                logger.info("AuthService password verification result", 
                           user_id=user.id, 
                           password_valid=password_valid)
                
                if not password_valid:
                    await user.record_login_attempt(db, success=False, ip_address=ip_address)
                    await self._log_failed_login(db, email, "invalid_password", ip_address, user.id)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid credentials"
                    )
            except Exception as e:
                logger.error("AuthService password verification failed", 
                            user_id=user.id, 
                            error=str(e), 
                            error_type=type(e).__name__)
                await self._log_failed_login(db, email, "password_verification_error", ip_address, user.id)
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
            access_token = SecurityService.create_access_token(
                data={"sub": str(user.id), "session_id": session.session_id}
            )
            
            refresh_token = SecurityService.create_refresh_token(
                data={"sub": str(user.id), "session_id": session.session_id},
                jti=session.refresh_token_id
            )
            
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
    
    async def refresh_token(
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
            # Decode refresh token
            payload = SecurityService.decode_token(refresh_token)
            
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            user_id = payload.get("sub")
            refresh_token_id = payload.get("jti")
            
            if not user_id or not refresh_token_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token format"
                )
            
            # Refresh session
            logger.info("Attempting to refresh session", refresh_token_id=refresh_token_id[:8] + "...")
            try:
                session = await self.session_service.refresh_session(
                    db=db,
                    refresh_token_id=refresh_token_id,
                    ip_address=ip_address
                )
                
                if not session:
                    logger.warning("Session refresh returned None - invalid or expired token")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired refresh token"
                    )
                
                logger.info("Session refreshed successfully in AuthService", session_id=session.session_id)
                
            except HTTPException:
                # Re-raise HTTP exceptions as-is
                raise
            except Exception as session_error:
                logger.error(
                    "Session refresh failed in AuthService",
                    refresh_token_id=refresh_token_id[:8] + "...",
                    error=str(session_error),
                    error_type=type(session_error).__name__
                )
                # Re-raise to surface the real database error
                raise
            
            # Generate new tokens
            access_token = SecurityService.create_access_token(
                data={"sub": str(user_id), "session_id": session.session_id}
            )
            
            new_refresh_token = SecurityService.create_refresh_token(
                data={"sub": str(user_id), "session_id": session.session_id},
                jti=session.refresh_token_id
            )
            
            logger.info(
                "Token refreshed successfully",
                user_id=user_id,
                session_id=session.session_id
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
                
                logger.info("All user sessions ended", user_id=user_id, count=count)
                return count > 0
            else:
                # End specific session
                return await self.session_service.end_session(
                    db=db,
                    session_id=session_id,
                    reason="logout"
                )
        
        except Exception as e:
            logger.error("Logout failed", session_id=session_id, error=str(e))
            return False
    
    async def initiate_password_reset(
        self,
        db: AsyncSession,
        email: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Initiate password reset process.
        
        Args:
            db: Database session
            email: User email
            ip_address: Client IP address
        
        Returns:
            True if reset initiated (always returns True for security)
        """
        try:
            # Always return True for security (don't reveal if email exists)
            user = await self.user_service.get_user_by_email(db, email)
            
            if user and user.is_active:
                # Generate reset token
                reset_token = SecurityService.generate_password_reset_token(email)
                
                # Cache reset token with short TTL
                reset_key = f"password_reset:{user.id}"
                await self.cache_service.set(
                    reset_key, 
                    {"token": reset_token, "email": email}, 
                    ttl=3600  # 1 hour
                )
                
                # Log password reset request
                await self.audit_logger.log_auth_event(
                    db=db,
                    event_type=AuditEventType.PASSWORD_RESET,
                    user_id=user.id,
                    ip_address=ip_address,
                    success=True,
                    description="Password reset requested"
                )
                
                # In production, send reset email here
                logger.info("Password reset initiated", user_id=user.id)
            else:
                # Log attempt for non-existent or inactive user
                await self.audit_logger.log_auth_event(
                    db=db,
                    event_type=AuditEventType.PASSWORD_RESET,
                    ip_address=ip_address,
                    success=False,
                    description=f"Password reset requested for non-existent/inactive user"
                )
            
            # Always return True for security
            return True
        
        except Exception as e:
            logger.error("Password reset initiation failed", error=str(e))
            # Still return True for security
            return True
    
    async def complete_password_reset(
        self,
        db: AsyncSession,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Complete password reset with token.
        
        Args:
            db: Database session
            token: Password reset token
            new_password: New password
            ip_address: Client IP address
        
        Returns:
            True if password reset successful
        """
        try:
            # Verify reset token
            email = SecurityService.verify_password_reset_token(token)
            if not email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired reset token"
                )
            
            # Get user
            user = await self.user_service.get_user_by_email(db, email)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid reset token"
                )
            
            # Check if token exists in cache
            reset_key = f"password_reset:{user.id}"
            cached_reset = await self.cache_service.get(reset_key)
            if not cached_reset or cached_reset.get("token") != token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired reset token"
                )
            
            # Update password
            await user.update_password(db, new_password)
            
            # Remove reset token from cache
            await self.cache_service.delete(reset_key)
            
            # End all user sessions (force re-login)
            await self.session_service.end_all_user_sessions(
                db=db,
                user_id=user.id,
                reason="password_reset"
            )
            
            # Log successful password reset
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.PASSWORD_CHANGE,
                user_id=user.id,
                ip_address=ip_address,
                success=True,
                description="Password reset completed"
            )
            
            logger.info("Password reset completed successfully", user_id=user.id)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Password reset completion failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Password reset failed"
            )
    
    async def verify_email(
        self,
        db: AsyncSession,
        token: str
    ) -> bool:
        """
        Verify user email with token.
        
        Args:
            db: Database session
            token: Email verification token
        
        Returns:
            True if email verified successfully
        """
        try:
            # Verify token
            email = SecurityService.verify_email_verification_token(token)
            if not email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired verification token"
                )
            
            # Get user
            user = await self.user_service.get_user_by_email(db, email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid verification token"
                )
            
            # Mark email as verified
            user.is_verified = True
            user.email_verified_at = datetime.utcnow()
            await user.save(db)
            
            # Log email verification
            await self.audit_logger.log_data_access(
                db=db,
                action="verify_email",
                resource_type="user",
                resource_id=str(user.id),
                user_id=user.id,
                success=True,
                description="Email address verified"
            )
            
            logger.info("Email verified successfully", user_id=user.id)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Email verification failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Email verification failed"
            )
    
    async def change_password(
        self,
        db: AsyncSession,
        user_id: int,
        current_password: str,
        new_password: str,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Change user password with current password verification.
        
        Args:
            db: Database session
            user_id: User ID
            current_password: Current password
            new_password: New password  
            session_id: Current session ID (to preserve)
        
        Returns:
            True if password changed successfully
        """
        try:
            # Change password using user service
            await self.user_service.change_password(
                db=db,
                user_id=user_id,
                current_password=current_password,
                new_password=new_password,
                changed_by_user_id=user_id
            )
            
            # End all other sessions except current one
            await self.session_service.end_all_user_sessions(
                db=db,
                user_id=user_id,
                except_session_id=session_id,
                reason="password_change"
            )
            
            logger.info("Password changed successfully", user_id=user_id)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Password change failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Password change failed"
            )
    
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
            # Decode token
            payload = SecurityService.decode_token(token)
            
            if payload.get("type") != "access":
                return None
            
            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            
            if not user_id:
                return None
            
            # Get user
            user = await self.user_service.get_user_by_id(db, int(user_id))
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
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.LOGIN_FAILURE,
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                description=f"Login failed: {reason}",
                event_data={"reason": reason},
                severity=AuditSeverity.MEDIUM
            )
        except Exception as e:
            logger.error("Failed to log failed login", error=str(e))