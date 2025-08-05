"""
User management service with comprehensive CRUD operations and security features.
Implements async patterns with proper error handling and audit logging.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
import structlog

from ..models.user import User, Role, Permission
from ..models.audit import AuditLog, AuditEventType, AuditSeverity, AuditLogger
from ..core.security import SecurityService
from ..core.redis import get_cache_service
from ..core.config import settings

logger = structlog.get_logger()


class UserService:
    """Comprehensive user management service."""
    
    def __init__(self):
        self.cache_service = get_cache_service()
        self.audit_logger = AuditLogger()
    
    async def create_user(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        roles: Optional[List[str]] = None,
        is_active: bool = True,
        created_by_user_id: Optional[int] = None
    ) -> User:
        """
        Create a new user with proper validation and audit logging.
        
        Args:
            db: Database session
            email: User email address
            password: Plain text password
            first_name: User's first name
            last_name: User's last name
            roles: List of role names to assign
            is_active: Whether user is active
            created_by_user_id: ID of user creating this user
        
        Returns:
            Created user instance
        
        Raises:
            HTTPException: If user creation fails
        """
        try:
            # Check if user already exists
            existing_user = await self.get_user_by_email(db, email)
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            
            # Create user
            user = await User.create_user(
                db=db,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                is_active=is_active
            )
            
            # Assign roles if provided
            if roles:
                await self._assign_roles_to_user(db, user, roles)
            
            # Log user creation
            await self.audit_logger.log_data_access(
                db=db,
                action="create",
                resource_type="user",
                resource_id=str(user.id),
                user_id=created_by_user_id,
                success=True,
                description=f"User created: {email}",
                pii_accessed=True
            )
            
            logger.info("User created successfully", user_id=user.id, email="***MASKED***")
            return user
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("User creation failed", email="***MASKED***", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
    
    async def get_user_by_id(
        self,
        db: AsyncSession,
        user_id: int,
        include_roles: bool = True
    ) -> Optional[User]:
        """Get user by ID with optional role loading."""
        try:
            # Try cache first
            cache_key = f"user:{user_id}:roles_{include_roles}"
            cached_user = await self.cache_service.get(cache_key)
            
            if cached_user:
                # Note: In production, you'd need to reconstruct the User object
                # from cached data. This is simplified for demonstration.
                pass
            
            # Query database
            query = select(User).where(User.id == user_id, User.is_deleted == False)
            
            if include_roles:
                query = query.options(
                    selectinload(User.roles).selectinload(Role.permissions)
                )
            
            result = await db.execute(query)
            user = result.scalar_one_or_none()
            
            # Cache result
            if user:
                await self.cache_service.set(cache_key, user.to_dict(), ttl=300)
            
            return user
        
        except Exception as e:
            logger.error("Failed to get user by ID", user_id=user_id, error=str(e))
            return None
    
    async def get_user_by_email(
        self,
        db: AsyncSession,
        email: str,
        include_roles: bool = True
    ) -> Optional[User]:
        """Get user by email with optional role loading."""
        # Note: Since email is encrypted, we use hash-based lookup
        # The User model handles decryption failures gracefully with bypass logic
        return await User.get_by_email(db, email)
    
    async def get_user_by_email_with_roles(
        self,
        db: AsyncSession,
        email: str
    ) -> Optional[User]:
        """Get user by email with roles and permissions eagerly loaded."""
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        
        # Get email hash for lookup
        email_hash = User._hash_email(email)
        
        # Query with eager loading of roles and permissions
        query = select(User).options(
            selectinload(User.roles).selectinload(Role.permissions)
        ).where(
            User.email_hash == email_hash,
            User.is_deleted == False
        )
        
        result = await db.execute(query)
        user = result.scalar_one_or_none()
        
        # Verify email matches (defense against hash collisions)
        if user:
            try:
                if user.email and user.email.startswith("__DECRYPTION_FAILED_"):
                    # Set the email for consistency
                    user.email = email
                elif user.email.lower() != email.lower():
                    logger.warning("Email hash collision detected", email_hash=email_hash)
                    return None
            except Exception as e:
                logger.warning("Email verification failed - using hash-based lookup", 
                              email_hash=email_hash, error=str(e))
                user.email = email
        
        return user
    
    async def update_user(
        self,
        db: AsyncSession,
        user_id: int,
        update_data: Dict[str, Any],
        updated_by_user_id: Optional[int] = None
    ) -> User:
        """
        Update user with audit logging.
        
        Args:
            db: Database session
            user_id: ID of user to update
            update_data: Dictionary of fields to update
            updated_by_user_id: ID of user performing the update
        
        Returns:
            Updated user instance
        """
        try:
            user = await self.get_user_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Store original values for audit
            original_data = user.to_dict()
            
            # Update allowed fields
            allowed_fields = {
                'first_name', 'last_name', 'phone_number', 'is_active',
                'is_verified', 'data_processing_consent', 'marketing_consent',
                'profile_data', 'preferences'
            }
            
            for field, value in update_data.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)
            
            await user.save(db)
            
            # Log update
            await self.audit_logger.log_data_access(
                db=db,
                action="update",
                resource_type="user",
                resource_id=str(user_id),
                user_id=updated_by_user_id,
                success=True,
                description=f"User updated: {user_id}",
                event_data={
                    "updated_fields": list(update_data.keys()),
                    "original_values": {k: v for k, v in original_data.items() if k in update_data}
                },
                pii_accessed=any(field in ['first_name', 'last_name', 'phone_number'] for field in update_data.keys())
            )
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("User updated successfully", user_id=user_id)
            return user
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("User update failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )
    
    async def change_password(
        self,
        db: AsyncSession,
        user_id: int,
        current_password: str,
        new_password: str,
        changed_by_user_id: Optional[int] = None
    ) -> bool:
        """
        Change user password with validation.
        
        Args:
            db: Database session
            user_id: ID of user to update
            current_password: Current password for verification
            new_password: New password
            changed_by_user_id: ID of user performing the change
        
        Returns:
            True if password changed successfully
        """
        try:
            user = await self.get_user_by_id(db, user_id, include_roles=False)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Verify current password (unless changed by admin)
            if changed_by_user_id != user_id:
                # Admin password change - skip current password verification
                pass
            else:
                if not await user.verify_password(current_password):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Current password is incorrect"
                    )
            
            # Update password
            await user.update_password(db, new_password)
            
            # Log password change
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.PASSWORD_CHANGE,
                user_id=user_id,
                success=True,
                description=f"Password changed for user {user_id}"
            )
            
            # Invalidate user sessions (force re-login)
            # This would be implemented in SessionService
            
            logger.info("Password changed successfully", user_id=user_id)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Password change failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to change password"
            )
    
    async def deactivate_user(
        self,
        db: AsyncSession,
        user_id: int,
        deactivated_by_user_id: Optional[int] = None,
        reason: Optional[str] = None
    ) -> User:
        """Deactivate user account."""
        try:
            user = await self.get_user_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            user.is_active = False
            await user.save(db)
            
            # Log deactivation
            await self.audit_logger.log_data_access(
                db=db,
                action="deactivate",
                resource_type="user",
                resource_id=str(user_id),
                user_id=deactivated_by_user_id,
                success=True,
                description=f"User deactivated: {reason or 'No reason provided'}",
                event_data={"reason": reason}
            )
            
            # Invalidate cache and sessions
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("User deactivated", user_id=user_id, reason=reason)
            return user
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("User deactivation failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to deactivate user"
            )
    
    async def delete_user(
        self,
        db: AsyncSession,
        user_id: int,
        deleted_by_user_id: Optional[int] = None,
        hard_delete: bool = False
    ) -> bool:
        """
        Delete user (soft delete by default for GDPR compliance).
        
        Args:
            db: Database session
            user_id: ID of user to delete
            deleted_by_user_id: ID of user performing the deletion
            hard_delete: Whether to permanently delete (use with caution)
        
        Returns:
            True if deletion successful
        """
        try:
            user = await self.get_user_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            await user.delete(db, hard_delete=hard_delete)
            
            # Log deletion
            event_type = AuditEventType.GDPR_DATA_DELETE if hard_delete else AuditEventType.USER_DELETED
            await self.audit_logger.log_data_access(
                db=db,
                action="delete",
                resource_type="user",
                resource_id=str(user_id),
                user_id=deleted_by_user_id,
                success=True,
                description=f"User {'permanently ' if hard_delete else ''}deleted",
                event_data={"hard_delete": hard_delete}
            )
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("User deleted", user_id=user_id, hard_delete=hard_delete)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("User deletion failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete user"
            )
    
    async def assign_role(
        self,
        db: AsyncSession,
        user_id: int,
        role_name: str,
        assigned_by_user_id: Optional[int] = None
    ) -> bool:
        """Assign role to user."""
        try:
            user = await self.get_user_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            role = await Role.get_by_name(db, role_name)
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found"
                )
            
            await user.add_role(db, role)
            
            # Log role assignment
            await self.audit_logger.log_data_access(
                db=db,
                action="assign_role",
                resource_type="user",
                resource_id=str(user_id),
                user_id=assigned_by_user_id,
                success=True,
                description=f"Role '{role_name}' assigned to user {user_id}",
                event_data={"role": role_name}
            )
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("Role assigned to user", user_id=user_id, role=role_name)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Role assignment failed", user_id=user_id, role=role_name, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to assign role"
            )
    
    async def remove_role(
        self,
        db: AsyncSession,
        user_id: int,
        role_name: str,
        removed_by_user_id: Optional[int] = None
    ) -> bool:
        """Remove role from user."""
        try:
            user = await self.get_user_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            role = await Role.get_by_name(db, role_name)
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found"
                )
            
            await user.remove_role(db, role)
            
            # Log role removal
            await self.audit_logger.log_data_access(
                db=db,
                action="remove_role",
                resource_type="user",
                resource_id=str(user_id),
                user_id=removed_by_user_id,
                success=True,
                description=f"Role '{role_name}' removed from user {user_id}",
                event_data={"role": role_name}
            )
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("Role removed from user", user_id=user_id, role=role_name)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Role removal failed", user_id=user_id, role=role_name, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to remove role"
            )
    
    async def search_users(
        self,
        db: AsyncSession,
        query: str = "",
        skip: int = 0,
        limit: int = 50,
        include_inactive: bool = False
    ) -> List[User]:
        """
        Search users with pagination.
        
        Note: In production with encrypted emails, you'd need a different
        search strategy, possibly using search indices or hashed lookups.
        """
        try:
            # This is a simplified implementation
            # In production, you'd implement proper search with indices
            users = await User.get_all(db, skip=skip, limit=limit)
            
            # Filter based on query if provided
            if query:
                # This is inefficient with encrypted data - in production,
                # you'd use search indices or other strategies
                filtered_users = []
                for user in users:
                    # Check if query matches any searchable field
                    if (query.lower() in (user.first_name or "").lower() or
                        query.lower() in (user.last_name or "").lower()):
                        filtered_users.append(user)
                users = filtered_users
            
            # Filter inactive users if requested
            if not include_inactive:
                users = [user for user in users if user.is_active]
            
            return users
        
        except Exception as e:
            logger.error("User search failed", query="***MASKED***", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User search failed"
            )
    
    async def get_user_audit_trail(
        self,
        db: AsyncSession,
        user_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit trail for a specific user."""
        try:
            return await AuditLog.get_user_audit_trail(
                db=db,
                user_id=user_id,
                start_date=start_date,
                end_date=end_date,
                limit=limit
            )
        
        except Exception as e:
            logger.error("Failed to get user audit trail", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get audit trail"
            )
    
    async def _assign_roles_to_user(
        self,
        db: AsyncSession,
        user: User,
        role_names: List[str]
    ) -> None:
        """Helper method to assign multiple roles to a user."""
        for role_name in role_names:
            role = await Role.get_by_name(db, role_name)
            if role:
                await user.add_role(db, role)
            else:
                logger.warning("Role not found during user creation", role=role_name)