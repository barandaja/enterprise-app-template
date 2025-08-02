"""
Legacy AuthService adapter for backward compatibility.
Maintains the original AuthService interface while delegating to new services.
"""

from typing import Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from ..models.user import User
from ..models.session import UserSession
from ..container import get_container
from ..services.auth.authentication_service import AuthenticationService
from ..services.auth.token_service import TokenService
from ..services.auth.password_service import PasswordService
from ..services.auth.email_verification_service import EmailVerificationService

logger = structlog.get_logger()


class LegacyAuthServiceAdapter:
    """
    Adapter class that maintains the original AuthService interface
    while delegating to the new decomposed services.
    
    This allows existing code to continue working without changes
    while benefiting from the new architecture.
    """
    
    def __init__(self):
        self._container = get_container()
        logger.info("Legacy AuthService adapter initialized")
    
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
        
        Delegates to AuthenticationService while maintaining original interface.
        """
        try:
            auth_service = self._container.get(AuthenticationService)
            return await auth_service.authenticate_user(
                db=db,
                email=email,
                password=password,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                location_data=location_data,
                remember_me=remember_me
            )
        except Exception as e:
            logger.error("Legacy authenticate_user failed", error=str(e))
            raise
    
    async def refresh_token(
        self,
        db: AsyncSession,
        refresh_token: str,
        ip_address: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Refresh access token using refresh token.
        
        Delegates to TokenService while maintaining original interface.
        """
        try:
            token_service = self._container.get(TokenService)
            return await token_service.refresh_tokens(
                db=db,
                refresh_token=refresh_token,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error("Legacy refresh_token failed", error=str(e))
            raise
    
    async def logout(
        self,
        db: AsyncSession,
        session_id: str,
        user_id: Optional[int] = None,
        logout_all_sessions: bool = False
    ) -> bool:
        """
        Logout user and end session(s).
        
        Delegates to AuthenticationService while maintaining original interface.
        """
        try:
            auth_service = self._container.get(AuthenticationService)
            return await auth_service.logout(
                db=db,
                session_id=session_id,
                user_id=user_id,
                logout_all_sessions=logout_all_sessions
            )
        except Exception as e:
            logger.error("Legacy logout failed", error=str(e))
            return False
    
    async def initiate_password_reset(
        self,
        db: AsyncSession,
        email: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Initiate password reset process.
        
        Delegates to PasswordService while maintaining original interface.
        """
        try:
            password_service = self._container.get(PasswordService)
            return await password_service.initiate_password_reset(
                db=db,
                email=email,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error("Legacy initiate_password_reset failed", error=str(e))
            return True  # Return True for security as in original
    
    async def complete_password_reset(
        self,
        db: AsyncSession,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Complete password reset with token.
        
        Delegates to PasswordService while maintaining original interface.
        """
        try:
            password_service = self._container.get(PasswordService)
            return await password_service.complete_password_reset(
                db=db,
                token=token,
                new_password=new_password,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error("Legacy complete_password_reset failed", error=str(e))
            raise
    
    async def verify_email(
        self,
        db: AsyncSession,
        token: str
    ) -> bool:
        """
        Verify user email with token.
        
        Delegates to EmailVerificationService while maintaining original interface.
        """
        try:
            email_service = self._container.get(EmailVerificationService)
            return await email_service.verify_email(
                db=db,
                token=token
            )
        except Exception as e:
            logger.error("Legacy verify_email failed", error=str(e))
            raise
    
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
        
        Delegates to PasswordService while maintaining original interface.
        """
        try:
            password_service = self._container.get(PasswordService)
            return await password_service.change_password(
                db=db,
                user_id=user_id,
                current_password=current_password,
                new_password=new_password,
                session_id=session_id,
                changed_by_user_id=user_id
            )
        except Exception as e:
            logger.error("Legacy change_password failed", error=str(e))
            raise
    
    async def validate_token(
        self,
        db: AsyncSession,
        token: str,
        ip_address: Optional[str] = None
    ) -> Optional[User]:
        """
        Validate access token and return user.
        
        Delegates to AuthenticationService while maintaining original interface.
        """
        try:
            auth_service = self._container.get(AuthenticationService)
            return await auth_service.validate_token(
                db=db,
                token=token,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error("Legacy validate_token failed", error=str(e))
            return None
    
    # Additional methods for extended compatibility
    async def send_verification_email(
        self,
        db: AsyncSession,
        user_id: int,
        email: str,
        resend: bool = False
    ) -> bool:
        """
        Send email verification (new method exposed through legacy interface).
        """
        try:
            email_service = self._container.get(EmailVerificationService)
            return await email_service.send_verification_email(
                db=db,
                user_id=user_id,
                email=email,
                resend=resend
            )
        except Exception as e:
            logger.error("Legacy send_verification_email failed", error=str(e))
            return False
    
    async def create_access_token(
        self,
        user_id: int,
        session_id: Optional[str] = None
    ) -> str:
        """
        Create access token (new method exposed through legacy interface).
        """
        try:
            token_service = self._container.get(TokenService)
            return await token_service.create_access_token(
                user_id=user_id,
                session_id=session_id
            )
        except Exception as e:
            logger.error("Legacy create_access_token failed", error=str(e))
            raise
    
    async def create_refresh_token(
        self,
        user_id: int,
        session_id: Optional[str] = None
    ) -> str:
        """
        Create refresh token (new method exposed through legacy interface).
        """
        try:
            token_service = self._container.get(TokenService)
            return await token_service.create_refresh_token(
                user_id=user_id,
                session_id=session_id
            )
        except Exception as e:
            logger.error("Legacy create_refresh_token failed", error=str(e))
            raise