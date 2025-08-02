"""
User, Role, and Permission models with comprehensive RBAC implementation.
Includes field-level encryption for PII data and audit trail support.
"""
from datetime import datetime
import hashlib
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, 
    ForeignKey, Table, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
import structlog

from .base import BaseModel
from .encryption import EncryptedField, PIIFieldMixin
from ..core.security import SecurityService

logger = structlog.get_logger()

# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    BaseModel.metadata,
    Column('user_id', Integer, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    Column('role_id', Integer, ForeignKey('role.id', ondelete='CASCADE'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow),
    Column('assigned_by', Integer, ForeignKey('user.id')),
    Index('idx_user_roles_user_id', 'user_id'),
    Index('idx_user_roles_role_id', 'role_id')
)

role_permissions = Table(
    'role_permissions',
    BaseModel.metadata,
    Column('role_id', Integer, ForeignKey('role.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permission.id', ondelete='CASCADE'), primary_key=True),
    Column('granted_at', DateTime, default=datetime.utcnow),
    Column('granted_by', Integer, ForeignKey('user.id')),
    Index('idx_role_permissions_role_id', 'role_id'),
    Index('idx_role_permissions_permission_id', 'permission_id')
)


class Permission(BaseModel):
    """Permission model for fine-grained access control."""
    
    __tablename__ = 'permission'
    
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource = Column(String(100), nullable=False, index=True)  # e.g., 'users', 'roles'
    action = Column(String(50), nullable=False, index=True)     # e.g., 'create', 'read', 'update', 'delete'
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
    
    __table_args__ = (
        UniqueConstraint('resource', 'action', name='uq_permission_resource_action'),
        Index('idx_permission_resource_action', 'resource', 'action')
    )
    
    @classmethod
    async def get_by_name(cls, db: AsyncSession, name: str) -> Optional['Permission']:
        """Get permission by name."""
        query = select(cls).where(cls.name == name, cls.is_deleted == False)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def create_permission(
        cls, 
        db: AsyncSession, 
        name: str, 
        resource: str, 
        action: str,
        description: Optional[str] = None
    ) -> 'Permission':
        """Create a new permission."""
        permission = cls(
            name=name,
            resource=resource,
            action=action,
            description=description
        )
        return await permission.save(db)
    
    def __repr__(self) -> str:
        return f"<Permission(name={self.name}, resource={self.resource}, action={self.action})>"


class Role(BaseModel):
    """Role model for role-based access control."""
    
    __tablename__ = 'role'
    
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_system_role = Column(Boolean, default=False, nullable=False)  # System roles cannot be deleted
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    
    @classmethod
    async def get_by_name(cls, db: AsyncSession, name: str) -> Optional['Role']:
        """Get role by name with permissions."""
        query = select(cls).options(
            selectinload(cls.permissions)
        ).where(cls.name == name, cls.is_deleted == False)
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def create_role(
        cls, 
        db: AsyncSession, 
        name: str, 
        description: Optional[str] = None,
        is_system_role: bool = False
    ) -> 'Role':
        """Create a new role."""
        role = cls(
            name=name,
            description=description,
            is_system_role=is_system_role
        )
        return await role.save(db)
    
    async def add_permission(self, db: AsyncSession, permission: Permission) -> None:
        """Add permission to role."""
        if permission not in self.permissions:
            self.permissions.append(permission)
            await self.save(db)
    
    async def remove_permission(self, db: AsyncSession, permission: Permission) -> None:
        """Remove permission from role."""
        if permission in self.permissions:
            self.permissions.remove(permission)
            await self.save(db)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has specific permission."""
        return any(
            perm.resource == resource and perm.action == action
            for perm in self.permissions
        )
    
    def __repr__(self) -> str:
        return f"<Role(name={self.name})>"


class User(BaseModel, PIIFieldMixin):
    """User model with encrypted PII fields and comprehensive security features."""
    
    __tablename__ = 'user'
    
    # Basic user information (encrypted PII)
    email = EncryptedField("string", nullable=False, index=True)
    email_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA256 hash for lookups
    first_name = EncryptedField("string", nullable=True)
    last_name = EncryptedField("string", nullable=True)
    phone_number = EncryptedField("string", nullable=True)
    
    # Authentication
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Security tracking
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 support
    password_changed_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Account management
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    terms_accepted_at = Column(DateTime(timezone=True), nullable=True)
    privacy_policy_accepted_at = Column(DateTime(timezone=True), nullable=True)
    
    # GDPR compliance
    data_processing_consent = Column(Boolean, default=False, nullable=False)
    marketing_consent = Column(Boolean, default=False, nullable=False)
    data_retention_until = Column(DateTime(timezone=True), nullable=True)
    
    # Additional metadata (encrypted)
    profile_data = EncryptedField("json", nullable=True)  # Additional user data
    preferences = EncryptedField("json", nullable=True)   # User preferences
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_user_email_hash', 'email_hash'),
        Index('idx_user_active_verified', 'is_active', 'is_verified'),
        Index('idx_user_last_login', 'last_login_at'),
    )
    
    @staticmethod
    def _hash_email(email: str) -> str:
        """Generate SHA256 hash of email for efficient lookups."""
        return hashlib.sha256(email.lower().encode('utf-8')).hexdigest()
    
    @classmethod
    async def get_by_email(cls, db: AsyncSession, email: str) -> Optional['User']:
        """Get user by email using hash index for efficient lookup."""
        email_hash = cls._hash_email(email)
        
        query = select(cls).options(
            selectinload(cls.roles).selectinload(Role.permissions)
        ).where(
            cls.email_hash == email_hash,
            cls.is_deleted == False
        )
        
        result = await db.execute(query)
        user = result.scalar_one_or_none()
        
        # Verify email matches (defense in depth against hash collisions)
        if user and user.email.lower() != email.lower():
            logger.warning(
                "Email hash collision detected",
                email_hash=email_hash,
                user_id=user.id
            )
            return None
        
        return user
    
    @classmethod
    async def create_user(
        cls,
        db: AsyncSession,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        is_active: bool = True,
        is_verified: bool = False
    ) -> 'User':
        """Create a new user with encrypted PII and email hash."""
        # Validate password strength
        is_valid, errors = SecurityService.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        
        # Check if user already exists
        existing_user = await cls.get_by_email(db, email)
        if existing_user:
            raise ValueError("User with this email already exists")
        
        # Hash password
        hashed_password = SecurityService.get_password_hash(password)
        
        # Generate email hash for efficient lookups
        email_hash = cls._hash_email(email)
        
        user = cls(
            email=email,
            email_hash=email_hash,
            first_name=first_name,
            last_name=last_name,
            hashed_password=hashed_password,
            is_active=is_active,
            is_verified=is_verified,
            password_changed_at=datetime.utcnow()
        )
        
        return await user.save(db)
    
    async def verify_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        return SecurityService.verify_password(password, self.hashed_password)
    
    async def update_password(self, db: AsyncSession, new_password: str) -> None:
        """Update user password with validation."""
        is_valid, errors = SecurityService.validate_password_strength(new_password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        
        self.hashed_password = SecurityService.get_password_hash(new_password)
        self.password_changed_at = datetime.utcnow()
        self.failed_login_attempts = 0  # Reset failed attempts
        self.locked_until = None
        
        await self.save(db)
    
    async def add_role(self, db: AsyncSession, role: Role) -> None:
        """Add role to user."""
        if role not in self.roles:
            self.roles.append(role)
            await self.save(db)
    
    async def remove_role(self, db: AsyncSession, role: Role) -> None:
        """Remove role from user."""
        if role in self.roles:
            self.roles.remove(role)
            await self.save(db)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if user has specific permission through roles."""
        if self.is_superuser:
            return True
        
        return any(
            role.has_permission(resource, action)
            for role in self.roles
        )
    
    def get_permissions(self) -> List[str]:
        """Get all permissions for user."""
        if self.is_superuser:
            return ["*"]  # Superuser has all permissions
        
        permissions = set()
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(f"{perm.resource}:{perm.action}")
        
        return list(permissions)
    
    async def lock_account(self, db: AsyncSession, duration_minutes: int = 30) -> None:
        """Lock user account for specified duration."""
        self.locked_until = datetime.utcnow() + datetime.timedelta(minutes=duration_minutes)
        await self.save(db)
    
    async def unlock_account(self, db: AsyncSession) -> None:
        """Unlock user account."""
        self.locked_until = None
        self.failed_login_attempts = 0
        await self.save(db)
    
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    async def record_login_attempt(
        self, 
        db: AsyncSession, 
        success: bool, 
        ip_address: Optional[str] = None
    ) -> None:
        """Record login attempt for security tracking."""
        if success:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.last_login_at = datetime.utcnow()
            self.last_login_ip = ip_address
        else:
            self.failed_login_attempts += 1
            # Lock account after 5 failed attempts
            if self.failed_login_attempts >= 5:
                await self.lock_account(db, duration_minutes=30)
        
        await self.save(db)
    
    def to_dict(self, exclude: Optional[set] = None) -> dict:
        """Convert to dict with PII masking for logging."""
        data = super().to_dict(exclude)
        return self.mask_pii_for_logging(data)
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email=***MASKED***)>"


# Convenience classes for association table records
class UserRole(BaseModel):
    """User-Role association with metadata."""
    
    __tablename__ = 'user_role'
    
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role_id = Column(Integer, ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    assigned_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    assigned_by = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Relationships
    user = relationship("User")
    role = relationship("Role")
    assigned_by_user = relationship("User", foreign_keys=[assigned_by])


class RolePermission(BaseModel):
    """Role-Permission association with metadata."""
    
    __tablename__ = 'role_permission'
    
    role_id = Column(Integer, ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permission.id', ondelete='CASCADE'), nullable=False)
    granted_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    granted_by = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Relationships
    role = relationship("Role")
    permission = relationship("Permission")
    granted_by_user = relationship("User")