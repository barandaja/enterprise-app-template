"""
Authentication-related Pydantic schemas for request/response validation.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator
from ..core.config import settings


class LoginRequest(BaseModel):
    """Login request schema."""
    
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=1, description="User's password")
    remember_me: bool = Field(False, description="Whether to extend session lifetime")
    device_info: Optional[Dict[str, Any]] = Field(None, description="Device fingerprint information")
    
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123",
                "remember_me": False,
                "device_info": {
                    "browser": "Chrome",
                    "os": "Windows 10",
                    "device_type": "desktop"
                }
            }
        }


class LoginResponse(BaseModel):
    """Login response schema."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: 'UserResponse' = Field(..., description="User information")
    session_info: Dict[str, Any] = Field(..., description="Session information")
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": 1,
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "is_active": True,
                    "is_verified": True
                },
                "session_info": {
                    "session_id": "session_123",
                    "expires_at": "2023-01-01T12:00:00Z",
                    "is_mobile": False
                }
            }
        }


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    
    refresh_token: str = Field(..., description="JWT refresh token")
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }


class RefreshTokenResponse(BaseModel):
    """Refresh token response schema."""
    
    access_token: str = Field(..., description="New JWT access token")
    refresh_token: str = Field(..., description="New JWT refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }


class LogoutRequest(BaseModel):
    """Logout request schema."""
    
    logout_all_sessions: bool = Field(False, description="Whether to logout from all sessions")
    
    class Config:
        schema_extra = {
            "example": {
                "logout_all_sessions": False
            }
        }


class LogoutResponse(BaseModel):
    """Logout response schema."""
    
    message: str = Field(..., description="Logout status message")
    sessions_ended: int = Field(..., description="Number of sessions ended")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Successfully logged out",
                "sessions_ended": 1
            }
        }


class PasswordResetRequest(BaseModel):
    """Password reset request schema."""
    
    email: EmailStr = Field(..., description="User's email address")
    
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetResponse(BaseModel):
    """Password reset response schema."""
    
    message: str = Field(..., description="Reset status message")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "If the email exists, a password reset link has been sent"
            }
        }


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation request schema."""
    
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ..., 
        min_length=settings.PASSWORD_MIN_LENGTH,
        description="New password"
    )
    confirm_password: str = Field(..., description="Password confirmation")
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        from ..core.security import SecurityService
        is_valid, errors = SecurityService.validate_password_strength(v)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "token": "reset_token_123",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }


class PasswordResetConfirmResponse(BaseModel):
    """Password reset confirmation response schema."""
    
    message: str = Field(..., description="Reset confirmation status message")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Password has been reset successfully"
            }
        }


class PasswordChangeRequest(BaseModel):
    """Password change request schema."""
    
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ..., 
        min_length=settings.PASSWORD_MIN_LENGTH,
        description="New password"
    )
    confirm_password: str = Field(..., description="Password confirmation")
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        from ..core.security import SecurityService
        is_valid, errors = SecurityService.validate_password_strength(v)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "current_password": "CurrentPassword123!",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }


class PasswordChangeResponse(BaseModel):
    """Password change response schema."""
    
    message: str = Field(..., description="Password change status message")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Password changed successfully"
            }
        }


class EmailVerificationRequest(BaseModel):
    """Email verification request schema."""
    
    token: str = Field(..., description="Email verification token")
    
    class Config:
        schema_extra = {
            "example": {
                "token": "verification_token_123"
            }
        }


class EmailVerificationResponse(BaseModel):
    """Email verification response schema."""
    
    message: str = Field(..., description="Verification status message")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Email verified successfully"
            }
        }


# User response schema (referenced in LoginResponse)
class UserResponse(BaseModel):
    """User response schema for API responses."""
    
    id: int = Field(..., description="User ID")
    email: str = Field(..., description="User's email address")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")
    is_active: bool = Field(..., description="Whether user is active")
    is_verified: bool = Field(..., description="Whether user's email is verified")
    is_superuser: bool = Field(..., description="Whether user is a superuser")
    roles: List[str] = Field([], description="User's roles")
    permissions: List[str] = Field([], description="User's permissions")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "id": 1,
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "is_active": True,
                "is_verified": True,
                "is_superuser": False,
                "roles": ["user"],
                "permissions": ["users:read"],
                "last_login_at": "2023-01-01T12:00:00Z",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            }
        }


class SessionInfo(BaseModel):
    """Session information schema."""
    
    session_id: str = Field(..., description="Session identifier")
    started_at: datetime = Field(..., description="Session start timestamp")
    last_activity_at: datetime = Field(..., description="Last activity timestamp")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    is_mobile: bool = Field(..., description="Whether session is from mobile device")
    is_trusted_device: bool = Field(..., description="Whether device is trusted")
    location: Dict[str, Any] = Field({}, description="Location information")
    device_info: Dict[str, Any] = Field({}, description="Device information")
    
    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "session_id": "session_123",
                "started_at": "2023-01-01T10:00:00Z",
                "last_activity_at": "2023-01-01T12:00:00Z",
                "expires_at": "2023-01-01T22:00:00Z",
                "ip_address": "192.168.1.100",
                "is_mobile": False,
                "is_trusted_device": True,
                "location": {"country": "US", "city": "San Francisco"},
                "device_info": {"browser": "Chrome", "os": "Windows 10"}
            }
        }


class SessionListResponse(BaseModel):
    """Session list response schema."""
    
    sessions: List[SessionInfo] = Field(..., description="List of user sessions")
    total: int = Field(..., description="Total number of sessions")
    
    class Config:
        schema_extra = {
            "example": {
                "sessions": [
                    {
                        "session_id": "session_123",
                        "started_at": "2023-01-01T10:00:00Z",
                        "last_activity_at": "2023-01-01T12:00:00Z",
                        "expires_at": "2023-01-01T22:00:00Z",
                        "ip_address": "192.168.1.100",
                        "is_mobile": False,
                        "is_trusted_device": False,
                        "location": {},
                        "device_info": {}
                    }
                ],
                "total": 1
            }
        }


class ErrorResponse(BaseModel):
    """Error response schema."""
    
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "detail": "Invalid credentials",
                "error_code": "AUTH_001",
                "timestamp": "2023-01-01T12:00:00Z"
            }
        }


# Update forward references
LoginResponse.model_rebuild()