"""
Authentication endpoints for the auth service.
Implements login, logout, token refresh, password reset, and email verification.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from ..core.database import get_db
from ..core.decorators import (
    rate_limit, audit_log, performance_monitor, secure_endpoint
)
from ..models.audit import AuditEventType, AuditSeverity
from ..schemas.auth_schemas import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    LogoutRequest, LogoutResponse, PasswordResetRequest, PasswordResetResponse,
    PasswordResetConfirmRequest, PasswordResetConfirmResponse,
    PasswordChangeRequest, PasswordChangeResponse,
    EmailVerificationRequest, EmailVerificationResponse,
    SessionListResponse, ErrorResponse, UserResponse
)
from ..services.auth_service import AuthService
from ..services.session_service import SessionService
from ..api.deps import get_current_active_user, get_session_id, get_client_info

logger = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        423: {"model": ErrorResponse},
        429: {"model": ErrorResponse}
    }
)
@rate_limit(requests_per_minute=10, requests_per_hour=50)
@audit_log(
    event_type=AuditEventType.LOGIN_SUCCESS,
    action="login",
    include_request_data=False,  # Don't log password
    severity=AuditSeverity.MEDIUM
)
@performance_monitor()
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and create session.
    
    - **email**: User's email address
    - **password**: User's password
    - **remember_me**: Whether to extend session lifetime
    - **device_info**: Optional device fingerprint information
    
    Returns access token, refresh token, user info, and session details.
    """
    try:
        auth_service = AuthService()
        client_info = await get_client_info(request)
        
        # Authenticate user
        user, session, access_token, refresh_token = await auth_service.authenticate_user(
            db=db,
            email=login_data.email,
            password=login_data.password,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            device_info=login_data.device_info,
            remember_me=login_data.remember_me
        )
        
        # Prepare response
        user_response = UserResponse.from_user_model(user, include_pii=True)
        session_info = session.get_session_info()
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800,  # 30 minutes
            user=user_response,
            session_info=session_info
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    responses={
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse}
    }
)
@rate_limit(requests_per_minute=20)
@audit_log(
    event_type=AuditEventType.LOGIN_SUCCESS,
    action="token_refresh",
    severity=AuditSeverity.LOW
)
@performance_monitor()
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    
    - **refresh_token**: Valid JWT refresh token
    
    Returns new access token and refresh token.
    """
    try:
        auth_service = AuthService()
        client_info = await get_client_info(request)
        
        access_token, new_refresh_token = await auth_service.refresh_token(
            db=db,
            refresh_token=refresh_data.refresh_token,
            ip_address=client_info["ip_address"]
        )
        
        return RefreshTokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=1800  # 30 minutes
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    responses={
        401: {"model": ErrorResponse}
    }
)
@audit_log(
    event_type=AuditEventType.LOGOUT,
    action="logout",
    severity=AuditSeverity.LOW
)
@performance_monitor()
async def logout(
    request: Request,
    logout_data: LogoutRequest = LogoutRequest(),
    current_user = Depends(get_current_active_user),
    session_id: Optional[str] = Depends(get_session_id), 
    db: AsyncSession = Depends(get_db)
):
    """
    Logout user and end session(s).
    
    - **logout_all_sessions**: Whether to logout from all user sessions
    
    Requires authentication. Returns logout status.
    """
    try:
        auth_service = AuthService()
        
        if logout_data.logout_all_sessions:
            # Logout from all sessions
            sessions_ended = await auth_service.logout(
                db=db,
                session_id=session_id,
                user_id=current_user.id,
                logout_all_sessions=True
            )
            message = f"Logged out from all sessions"
        else:
            # Logout from current session only
            success = await auth_service.logout(
                db=db,
                session_id=session_id,
                user_id=current_user.id,
                logout_all_sessions=False
            )
            sessions_ended = 1 if success else 0
            message = "Logged out successfully"
        
        return LogoutResponse(
            message=message,
            sessions_ended=sessions_ended
        )
    
    except Exception as e:
        logger.error("Logout failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post(
    "/password-reset",
    response_model=PasswordResetResponse,
    responses={
        429: {"model": ErrorResponse}
    }
)
@rate_limit(requests_per_minute=5, requests_per_hour=10)
@audit_log(
    event_type=AuditEventType.PASSWORD_RESET,
    action="password_reset_request",
    severity=AuditSeverity.MEDIUM
)
@performance_monitor()
async def request_password_reset(
    request: Request,
    reset_data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Request password reset for user account.
    
    - **email**: User's email address
    
    Always returns success for security reasons (doesn't reveal if email exists).
    If email exists, a password reset link will be sent.
    """
    try:
        auth_service = AuthService()
        client_info = await get_client_info(request)
        
        await auth_service.initiate_password_reset(
            db=db,
            email=reset_data.email,
            ip_address=client_info["ip_address"]
        )
        
        return PasswordResetResponse(
            message="If the email exists, a password reset link has been sent"
        )
    
    except Exception as e:
        logger.error("Password reset request failed", error=str(e))
        # Always return success for security
        return PasswordResetResponse(
            message="If the email exists, a password reset link has been sent"
        )


@router.post(
    "/password-reset/confirm",
    response_model=PasswordResetConfirmResponse,
    responses={
        400: {"model": ErrorResponse},
        429: {"model": ErrorResponse}
    }
)
@rate_limit(requests_per_minute=5)
@audit_log(
    event_type=AuditEventType.PASSWORD_CHANGE,
    action="password_reset_confirm",
    severity=AuditSeverity.HIGH
)
@performance_monitor()
async def confirm_password_reset(
    request: Request,
    confirm_data: PasswordResetConfirmRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Confirm password reset with token and set new password.
    
    - **token**: Password reset token from email
    - **new_password**: New password (must meet strength requirements)
    - **confirm_password**: Password confirmation (must match new_password)
    
    Returns success message if password reset is completed.
    """
    try:
        auth_service = AuthService()
        client_info = await get_client_info(request)
        
        success = await auth_service.complete_password_reset(
            db=db,
            token=confirm_data.token,
            new_password=confirm_data.new_password,
            ip_address=client_info["ip_address"]
        )
        
        if success:
            return PasswordResetConfirmResponse(
                message="Password has been reset successfully"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset failed"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Password reset confirmation failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )


@router.post(
    "/change-password",
    response_model=PasswordChangeResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse}
    }
)
@audit_log(
    event_type=AuditEventType.PASSWORD_CHANGE,
    action="password_change",
    severity=AuditSeverity.HIGH
)
@performance_monitor()
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user = Depends(get_current_active_user),
    session_id: Optional[str] = Depends(get_session_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Change user password (requires current password).
    
    - **current_password**: Current password for verification
    - **new_password**: New password (must meet strength requirements)
    - **confirm_password**: Password confirmation (must match new_password)
    
    Requires authentication. Returns success message if password is changed.
    All other sessions will be terminated for security.
    """
    try:
        auth_service = AuthService()
        
        success = await auth_service.change_password(
            db=db,
            user_id=current_user.id,
            current_password=password_data.current_password,
            new_password=password_data.new_password,
            session_id=session_id
        )
        
        if success:
            return PasswordChangeResponse(
                message="Password changed successfully"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change failed"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Password change failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.post(
    "/verify-email",
    response_model=EmailVerificationResponse,
    responses={
        400: {"model": ErrorResponse}
    }
)
@rate_limit(requests_per_minute=10)
@audit_log(
    event_type=AuditEventType.DATA_UPDATE,
    action="email_verification",
    resource_type="user",
    severity=AuditSeverity.MEDIUM
)
@performance_monitor()
async def verify_email(
    verification_data: EmailVerificationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify user email address with token.
    
    - **token**: Email verification token from registration email
    
    Returns success message if email is verified.
    """
    try:
        auth_service = AuthService()
        
        success = await auth_service.verify_email(
            db=db,
            token=verification_data.token
        )
        
        if success:
            return EmailVerificationResponse(
                message="Email verified successfully"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification failed"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Email verification failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email verification failed"
        )


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    responses={
        401: {"model": ErrorResponse}
    }
)
@secure_endpoint(
    event_type=AuditEventType.DATA_READ,
    resource="session",
    action="read",
    cache_ttl=60
)
async def get_user_sessions(
    current_user = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's active sessions.
    
    Requires authentication. Returns list of user's active sessions with details.
    """
    try:
        session_service = SessionService()
        
        sessions = await session_service.get_user_sessions(
            db=db,
            user_id=current_user.id,
            active_only=True,
            limit=20
        )
        
        session_info_list = [session.get_session_info() for session in sessions]
        
        return SessionListResponse(
            sessions=session_info_list,
            total=len(session_info_list)
        )
    
    except Exception as e:
        logger.error("Failed to get user sessions", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get sessions"
        )


@router.delete(
    "/sessions/{session_id}",
    response_model=LogoutResponse,
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse}
    }
)
@audit_log(
    event_type=AuditEventType.LOGOUT,
    action="end_session",
    resource_type="session",
    severity=AuditSeverity.MEDIUM
)
@performance_monitor()
async def end_session(
    session_id: str,
    current_user = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    End a specific user session.
    
    - **session_id**: ID of session to end
    
    Requires authentication. User can only end their own sessions.
    """
    try:
        session_service = SessionService()
        
        # Verify session belongs to current user
        session = await session_service.get_session(db, session_id, validate=False)
        if not session or session.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        success = await session_service.end_session(
            db=db,
            session_id=session_id,
            reason="user_requested",
            ended_by_user_id=current_user.id
        )
        
        if success:
            return LogoutResponse(
                message="Session ended successfully",
                sessions_ended=1
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to end session"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to end session", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to end session"
        )