"""
User-related Pydantic schemas for request/response validation.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator
from ..core.config import settings


class UserCreate(BaseModel):
    """User creation request schema."""
    
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(
        ..., 
        min_length=settings.PASSWORD_MIN_LENGTH,
        description="User's password"
    )
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    phone_number: Optional[str] = Field(None, max_length=20, description="User's phone number")
    roles: Optional[List[str]] = Field([], description="Roles to assign to user")
    is_active: bool = Field(True, description="Whether user is active")
    
    @validator('password')
    def validate_password_strength(cls, v):
        from ..core.security import SecurityService
        is_valid, errors = SecurityService.validate_password_strength(v)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "email": "newuser@example.com",
                "password": "SecurePassword123!",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1-555-123-4567",
                "roles": ["user"],
                "is_active": True
            }
        }


class UserUpdate(BaseModel):
    """User update request schema."""
    
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    phone_number: Optional[str] = Field(None, max_length=20, description="User's phone number")
    is_active: Optional[bool] = Field(None, description="Whether user is active")
    is_verified: Optional[bool] = Field(None, description="Whether user's email is verified")
    data_processing_consent: Optional[bool] = Field(None, description="GDPR data processing consent")
    marketing_consent: Optional[bool] = Field(None, description="Marketing consent")
    profile_data: Optional[Dict[str, Any]] = Field(None, description="Additional profile data")
    preferences: Optional[Dict[str, Any]] = Field(None, description="User preferences")
    
    class Config:
        schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Smith",
                "phone_number": "+1-555-987-6543",
                "is_active": True,
                "is_verified": True,
                "data_processing_consent": True,
                "marketing_consent": False,
                "profile_data": {
                    "department": "Engineering",
                    "title": "Software Engineer"
                },
                "preferences": {
                    "theme": "dark",
                    "notifications": True
                }
            }
        }


class UserResponse(BaseModel):
    """User response schema for API responses."""
    
    id: int = Field(..., description="User ID")
    email: str = Field(..., description="User's email address")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")
    phone_number: Optional[str] = Field(None, description="User's phone number")
    is_active: bool = Field(..., description="Whether user is active")
    is_verified: bool = Field(..., description="Whether user's email is verified")
    is_superuser: bool = Field(..., description="Whether user is a superuser")
    roles: List[str] = Field([], description="User's roles")
    permissions: List[str] = Field([], description="User's permissions")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    email_verified_at: Optional[datetime] = Field(None, description="Email verification timestamp")
    password_changed_at: Optional[datetime] = Field(None, description="Last password change timestamp")
    data_processing_consent: bool = Field(..., description="GDPR data processing consent")
    marketing_consent: bool = Field(..., description="Marketing consent")
    profile_data: Optional[Dict[str, Any]] = Field(None, description="Additional profile data")
    preferences: Optional[Dict[str, Any]] = Field(None, description="User preferences")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    @classmethod
    async def from_user_model(cls, user, db, include_pii: bool = True):
        """Create UserResponse from User model."""
        permissions = await user.get_permissions(db)
        
        # Get roles safely - after get_permissions, roles should be loaded
        roles = []
        try:
            roles = [role.name for role in user.roles] if hasattr(user, 'roles') and user.roles else []
        except Exception:
            # If roles access fails, return empty list
            roles = []
        
        return cls(
            id=user.id,
            email=user.email if include_pii else "***MASKED***",
            first_name=user.first_name if include_pii else None,
            last_name=user.last_name if include_pii else None,
            phone_number=user.phone_number if include_pii else None,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_superuser=user.is_superuser,
            roles=roles,
            permissions=permissions,
            last_login_at=user.last_login_at,
            email_verified_at=user.email_verified_at,
            password_changed_at=user.password_changed_at,
            data_processing_consent=user.data_processing_consent,
            marketing_consent=user.marketing_consent,
            profile_data=user.profile_data if include_pii else None,
            preferences=user.preferences if include_pii else None,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    
    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "id": 1,
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1-555-123-4567",
                "is_active": True,
                "is_verified": True,
                "is_superuser": False,
                "roles": ["user"],
                "permissions": ["users:read"],
                "last_login_at": "2023-01-01T12:00:00Z",
                "email_verified_at": "2023-01-01T01:00:00Z",
                "password_changed_at": "2023-01-01T00:00:00Z",
                "data_processing_consent": True,
                "marketing_consent": False,
                "profile_data": {
                    "department": "Engineering"
                },
                "preferences": {
                    "theme": "dark"
                },
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            }
        }


class UserList(BaseModel):
    """User list response schema."""
    
    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of users per page")
    
    class Config:
        schema_extra = {
            "example": {
                "users": [
                    {
                        "id": 1,
                        "email": "user1@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "is_active": True,
                        "is_verified": True,
                        "is_superuser": False,
                        "roles": ["user"],
                        "permissions": ["users:read"],
                        "created_at": "2023-01-01T00:00:00Z"
                    }
                ],
                "total": 1,
                "page": 1,
                "page_size": 50
            }
        }


class RoleAssignRequest(BaseModel):
    """Role assignment request schema."""
    
    role_name: str = Field(..., description="Name of role to assign")
    
    class Config:
        schema_extra = {
            "example": {
                "role_name": "admin"
            }
        }


class RoleAssignResponse(BaseModel):
    """Role assignment response schema."""
    
    message: str = Field(..., description="Assignment status message")
    user_id: int = Field(..., description="User ID")
    role_name: str = Field(..., description="Role name")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Role assigned successfully",
                "user_id": 1,
                "role_name": "admin"
            }
        }


class UserSearchRequest(BaseModel):
    """User search request schema."""
    
    query: Optional[str] = Field(None, description="Search query")
    include_inactive: bool = Field(False, description="Include inactive users")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(50, ge=1, le=100, description="Page size")
    
    class Config:
        schema_extra = {
            "example": {
                "query": "john",
                "include_inactive": False,
                "page": 1,
                "page_size": 50
            }
        }


class UserStats(BaseModel):
    """User statistics schema."""
    
    total_users: int = Field(..., description="Total number of users")
    active_users: int = Field(..., description="Number of active users")
    verified_users: int = Field(..., description="Number of verified users")
    new_users_today: int = Field(..., description="New users registered today")
    new_users_this_week: int = Field(..., description="New users registered this week")
    new_users_this_month: int = Field(..., description="New users registered this month")
    
    class Config:
        schema_extra = {
            "example": {
                "total_users": 1000,
                "active_users": 950,
                "verified_users": 900,
                "new_users_today": 5,
                "new_users_this_week": 25,
                "new_users_this_month": 100
            }
        }


class AuditLogEntry(BaseModel):
    """Audit log entry schema."""
    
    id: int = Field(..., description="Audit log ID")
    event_type: str = Field(..., description="Type of event")
    action: str = Field(..., description="Action performed")
    description: str = Field(..., description="Event description")
    timestamp: datetime = Field(..., description="Event timestamp")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="User agent")
    success: bool = Field(..., description="Whether the action was successful")
    resource_type: Optional[str] = Field(None, description="Type of resource accessed")
    resource_id: Optional[str] = Field(None, description="ID of resource accessed")
    
    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "id": 1,
                "event_type": "login_success",
                "action": "authentication",
                "description": "User login successful",
                "timestamp": "2023-01-01T12:00:00Z",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
                "success": True,
                "resource_type": "user",
                "resource_id": "1"
            }
        }


class AuditLogList(BaseModel):
    """Audit log list response schema."""
    
    logs: List[AuditLogEntry] = Field(..., description="List of audit log entries")
    total: int = Field(..., description="Total number of log entries")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of entries per page")
    
    class Config:
        schema_extra = {
            "example": {
                "logs": [
                    {
                        "id": 1,
                        "event_type": "login_success",
                        "action": "authentication",
                        "description": "User login successful",
                        "timestamp": "2023-01-01T12:00:00Z",
                        "success": True
                    }
                ],
                "total": 1,
                "page": 1,
                "page_size": 50
            }
        }