"""
Email verification service focused solely on email verification operations.
Follows Single Responsibility Principle by handling only email verification logic.
"""

from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from ...interfaces.cache_interface import ICacheService
from ...interfaces.repository_interface import IUserRepository
from ...interfaces.event_interface import IEventBus
from ...core.security import SecurityService

logger = structlog.get_logger()


class EmailVerificationService:
    """Service responsible for email verification operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        cache_service: ICacheService,
        event_bus: IEventBus
    ):
        self.user_repository = user_repository
        self.cache_service = cache_service
        self.event_bus = event_bus
    
    async def send_verification_email(
        self,
        db: AsyncSession,
        user_id: int,
        email: str,
        resend: bool = False
    ) -> bool:
        """
        Send email verification token to user.
        
        Args:
            db: Database session
            user_id: User ID
            email: Email address to verify
            resend: Whether this is a resend request
        
        Returns:
            True if verification email sent successfully
        """
        try:
            # Check if user exists and is active
            user = await self.user_repository.get_by_id(db, user_id)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Check if already verified (unless resending)
            if user.is_verified and not resend:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already verified"
                )
            
            # Check rate limiting for verification emails
            rate_limit_key = f"email_verification_rate:{user_id}"
            rate_limited = await self.cache_service.exists(rate_limit_key)
            if rate_limited:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Please wait before requesting another verification email"
                )
            
            # Generate verification token
            verification_token = SecurityService.generate_email_verification_token(email)
            
            # Cache the verification token
            verification_key = f"email_verification:{user_id}"
            await self.cache_service.set(
                verification_key,
                {"token": verification_token, "email": email},
                ttl=7 * 24 * 3600  # 7 days
            )
            
            # Set rate limit (1 verification email per 5 minutes)
            await self.cache_service.set(rate_limit_key, True, ttl=300)
            
            # Publish email verification requested event
            from ...events.auth_events import EmailVerificationRequestedEvent
            verification_event = EmailVerificationRequestedEvent(
                user_id=user_id,
                email=email,
                verification_token=verification_token,
                is_resend=resend
            )
            await self.event_bus.publish(verification_event)
            
            logger.info(
                "Email verification requested",
                user_id=user_id,
                is_resend=resend
            )
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Email verification send failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email"
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
            
            # Get user by email
            user = await self.user_repository.get_by_email(db, email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid verification token"
                )
            
            # Check if token exists in cache
            verification_key = f"email_verification:{user.id}"
            cached_verification = await self.cache_service.get(verification_key)
            if not cached_verification or cached_verification.get("token") != token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired verification token"
                )
            
            # Mark email as verified
            await self.user_repository.update(
                db=db,
                user_id=user.id,
                update_data={
                    "is_verified": True,
                    "email_verified_at": datetime.utcnow()
                }
            )
            
            # Remove verification token from cache
            await self.cache_service.delete(verification_key)
            
            # Publish email verified event
            from ...events.auth_events import EmailVerifiedEvent
            verified_event = EmailVerifiedEvent(
                user_id=user.id,
                email=email
            )
            await self.event_bus.publish(verified_event)
            
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
    
    async def resend_verification_email(
        self,
        db: AsyncSession,
        user_id: int
    ) -> bool:
        """
        Resend email verification to user.
        
        Args:
            db: Database session
            user_id: User ID
        
        Returns:
            True if verification email resent successfully
        """
        try:
            user = await self.user_repository.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Get user's email (this would need to be decrypted)
            user_email = user.email  # Assuming email is accessible
            
            return await self.send_verification_email(
                db=db,
                user_id=user_id,
                email=user_email,
                resend=True
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Email verification resend failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to resend verification email"
            )
    
    async def check_verification_status(
        self,
        db: AsyncSession,
        user_id: int
    ) -> dict:
        """
        Check email verification status for user.
        
        Args:
            db: Database session
            user_id: User ID
        
        Returns:
            Dictionary with verification status information
        """
        try:
            user = await self.user_repository.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Check if there's a pending verification
            verification_key = f"email_verification:{user_id}"
            pending_verification = await self.cache_service.exists(verification_key)
            
            # Check rate limiting
            rate_limit_key = f"email_verification_rate:{user_id}"
            rate_limited = await self.cache_service.exists(rate_limit_key)
            
            return {
                "is_verified": user.is_verified,
                "email_verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,
                "has_pending_verification": pending_verification,
                "can_resend": not rate_limited,
                "user_id": user_id
            }
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Verification status check failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to check verification status"
            )