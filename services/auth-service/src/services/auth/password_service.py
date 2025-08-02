"""
Password service focused solely on password operations.
Follows Single Responsibility Principle by handling only password reset,
change, and validation logic.
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from ...interfaces.cache_interface import ICacheService
from ...interfaces.repository_interface import IUserRepository
from ...interfaces.event_interface import IEventBus
from ...core.security import SecurityService
from ..session_service import SessionService

logger = structlog.get_logger()


class PasswordService:
    """Service responsible for password operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        cache_service: ICacheService,
        event_bus: IEventBus,
        session_service: SessionService
    ):
        self.user_repository = user_repository
        self.cache_service = cache_service
        self.event_bus = event_bus
        self.session_service = session_service
    
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
            user = await self.user_repository.get_by_email(db, email)
            
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
                
                # Publish password reset initiated event
                from ...events.auth_events import PasswordResetInitiatedEvent
                reset_event = PasswordResetInitiatedEvent(
                    user_id=user.id,
                    email=email,
                    reset_token=reset_token,
                    ip_address=ip_address
                )
                await self.event_bus.publish(reset_event)
                
                logger.info("Password reset initiated", user_id=user.id)
            else:
                # Publish failed password reset event for non-existent user
                from ...events.auth_events import PasswordResetFailedEvent
                failed_event = PasswordResetFailedEvent(
                    email=email,
                    reason="user_not_found",
                    ip_address=ip_address
                )
                await self.event_bus.publish(failed_event)
            
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
            user = await self.user_repository.get_by_email(db, email)
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
            await self.user_repository.update_password(db, user.id, new_password)
            
            # Remove reset token from cache
            await self.cache_service.delete(reset_key)
            
            # End all user sessions (force re-login)
            await self.session_service.end_all_user_sessions(
                db=db,
                user_id=user.id,
                reason="password_reset"
            )
            
            # Publish password reset completed event
            from ...events.auth_events import PasswordResetCompletedEvent
            completed_event = PasswordResetCompletedEvent(
                user_id=user.id,
                ip_address=ip_address
            )
            await self.event_bus.publish(completed_event)
            
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
    
    async def change_password(
        self,
        db: AsyncSession,
        user_id: int,
        current_password: str,
        new_password: str,
        session_id: Optional[str] = None,
        changed_by_user_id: Optional[int] = None
    ) -> bool:
        """
        Change user password with current password verification.
        
        Args:
            db: Database session
            user_id: User ID
            current_password: Current password
            new_password: New password  
            session_id: Current session ID (to preserve)
            changed_by_user_id: ID of user performing the change
        
        Returns:
            True if password changed successfully
        """
        try:
            user = await self.user_repository.get_by_id(db, user_id, include_roles=False)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Verify current password (unless changed by admin)
            is_admin_change = changed_by_user_id and changed_by_user_id != user_id
            if not is_admin_change:
                if not await self.user_repository.verify_password(db, user_id, current_password):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Current password is incorrect"
                    )
            
            # Update password
            await self.user_repository.update_password(db, user_id, new_password)
            
            # End all other sessions except current one
            await self.session_service.end_all_user_sessions(
                db=db,
                user_id=user_id,
                except_session_id=session_id,
                reason="password_change"
            )
            
            # Publish password changed event
            from ...events.auth_events import PasswordChangedEvent
            changed_event = PasswordChangedEvent(
                user_id=user_id,
                changed_by_user_id=changed_by_user_id or user_id,
                is_admin_change=is_admin_change
            )
            await self.event_bus.publish(changed_event)
            
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
    
    async def validate_password_strength(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate password meets security requirements.
        
        Args:
            password: Password to validate
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        try:
            return SecurityService.validate_password_strength(password)
        except Exception as e:
            logger.error("Password validation failed", error=str(e))
            return False, ["Password validation failed"]
    
    async def generate_temporary_password(self) -> str:
        """
        Generate a temporary password for user accounts.
        
        Returns:
            Temporary password string
        """
        try:
            import secrets
            import string
            
            # Generate a secure temporary password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))
            
            # Ensure it meets requirements
            is_valid, errors = await self.validate_password_strength(temp_password)
            if not is_valid:
                # Fallback to a known good pattern
                temp_password = f"Temp{secrets.randbelow(1000):03d}!{secrets.token_hex(4)}"
            
            return temp_password
        
        except Exception as e:
            logger.error("Temporary password generation failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate temporary password"
            )