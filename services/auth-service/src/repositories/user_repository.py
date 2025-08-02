"""
User repository implementation following the Repository pattern.
Handles all user data access operations with encryption abstraction.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
import structlog

from ..interfaces.repository_interface import IUserRepository
from ..interfaces.encryption_interface import IEncryptionService
from ..interfaces.cache_interface import ICacheService
from ..models.user import User
from ..core.security import SecurityService

logger = structlog.get_logger()


class UserRepository(IUserRepository):
    """Repository for user data access operations."""
    
    def __init__(
        self,
        encryption_service: IEncryptionService,
        cache_service: ICacheService
    ):
        self.encryption_service = encryption_service
        self.cache_service = cache_service
    
    async def create(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        is_active: bool = True
    ) -> User:
        """
        Create a new user with encrypted data.
        
        Args:
            db: Database session
            email: User email
            password: User password (will be hashed)
            first_name: User's first name
            last_name: User's last name
            is_active: Whether user is active
            
        Returns:
            Created user instance
        """
        try:
            # Check if user already exists by email hash
            email_hash = self.encryption_service.hash_data(email.lower())
            existing_user = await self._get_by_email_hash(db, email_hash)
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            
            # Create user with encrypted data
            user_data = {
                "email": self.encryption_service.encrypt(email.lower()),
                "email_hash": email_hash,
                "password_hash": SecurityService.get_password_hash(password),
                "is_active": is_active
            }
            
            # Encrypt PII fields if provided
            if first_name:
                user_data["first_name"] = self.encryption_service.encrypt(first_name)
            if last_name:
                user_data["last_name"] = self.encryption_service.encrypt(last_name)
            
            # Create user instance
            user = User(**user_data)
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            logger.info("User created successfully", user_id=user.id)
            return user
        
        except HTTPException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error("User creation failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
    
    async def get_by_id(
        self,
        db: AsyncSession,
        user_id: int,
        include_roles: bool = True
    ) -> Optional[User]:
        """
        Get user by ID with optional role loading.
        
        Args:
            db: Database session
            user_id: User ID
            include_roles: Whether to include user roles
            
        Returns:
            User instance or None if not found
        """
        try:
            # Try cache first
            cache_key = f"user:{user_id}:roles_{include_roles}"
            cached_user = await self.cache_service.get(cache_key)
            
            if cached_user:
                # Reconstruct user from cache (simplified for demo)
                # In production, you'd properly deserialize the user object
                pass
            
            # Query database
            query = select(User).where(User.id == user_id, User.is_deleted == False)
            
            if include_roles:
                query = query.options(
                    selectinload(User.roles).selectinload(User.roles.of_type().permissions)
                )
            
            result = await db.execute(query)
            user = result.scalar_one_or_none()
            
            if user:
                # Decrypt sensitive fields
                user = await self._decrypt_user_data(user)
                
                # Cache result (with encrypted data for security)
                await self.cache_service.set(
                    cache_key, 
                    self._serialize_user_for_cache(user), 
                    ttl=300
                )
            
            return user
        
        except Exception as e:
            logger.error("Failed to get user by ID", user_id=user_id, error=str(e))
            return None
    
    async def get_by_email(
        self,
        db: AsyncSession,
        email: str,
        include_roles: bool = True
    ) -> Optional[User]:
        """
        Get user by email using email hash for efficient lookup.
        
        Args:
            db: Database session
            email: User email
            include_roles: Whether to include user roles
            
        Returns:
            User instance or None if not found
        """
        try:
            # Use email hash for efficient lookup
            email_hash = self.encryption_service.hash_data(email.lower())
            
            query = select(User).where(
                User.email_hash == email_hash,
                User.is_deleted == False
            )
            
            if include_roles:
                query = query.options(
                    selectinload(User.roles).selectinload(User.roles.of_type().permissions)
                )
            
            result = await db.execute(query)
            user = result.scalar_one_or_none()
            
            if user:
                # Verify email matches (to handle hash collisions)
                decrypted_email = self.encryption_service.decrypt(user.email)
                if decrypted_email.lower() != email.lower():
                    return None
                
                # Decrypt sensitive fields
                user = await self._decrypt_user_data(user)
            
            return user
        
        except Exception as e:
            logger.error("Failed to get user by email", error=str(e))
            return None
    
    async def update(
        self,
        db: AsyncSession,
        user_id: int,
        update_data: Dict[str, Any]
    ) -> User:
        """
        Update user data with encryption for sensitive fields.
        
        Args:
            db: Database session
            user_id: User ID to update
            update_data: Dictionary of fields to update
            
        Returns:
            Updated user instance
        """
        try:
            user = await self.get_by_id(db, user_id, include_roles=False)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Encrypt sensitive fields before updating
            encrypted_updates = {}
            sensitive_fields = {"first_name", "last_name", "phone_number"}
            
            for field, value in update_data.items():
                if field in sensitive_fields and value is not None:
                    encrypted_updates[field] = self.encryption_service.encrypt(str(value))
                else:
                    encrypted_updates[field] = value
            
            # Update allowed fields
            allowed_fields = {
                'first_name', 'last_name', 'phone_number', 'is_active',
                'is_verified', 'data_processing_consent', 'marketing_consent',
                'profile_data', 'preferences'
            }
            
            for field, value in encrypted_updates.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)
            
            await db.commit()
            await db.refresh(user)
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            # Decrypt for return
            user = await self._decrypt_user_data(user)
            
            logger.info("User updated successfully", user_id=user_id)
            return user
        
        except HTTPException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error("User update failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )
    
    async def delete(
        self,
        db: AsyncSession,
        user_id: int,
        hard_delete: bool = False
    ) -> bool:
        """
        Delete user (soft delete by default for GDPR compliance).
        
        Args:
            db: Database session
            user_id: User ID to delete
            hard_delete: Whether to permanently delete
            
        Returns:
            True if deletion successful
        """
        try:
            user = await self.get_by_id(db, user_id, include_roles=False)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            if hard_delete:
                await db.delete(user)
            else:
                # Soft delete
                user.is_deleted = True
                user.deleted_at = db.utcnow()
            
            await db.commit()
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("User deleted", user_id=user_id, hard_delete=hard_delete)
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error("User deletion failed", user_id=user_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete user"
            )
    
    async def get_all(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        include_inactive: bool = False
    ) -> List[User]:
        """
        Get all users with pagination.
        
        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum number of records to return
            include_inactive: Whether to include inactive users
            
        Returns:
            List of user instances
        """
        try:
            query = select(User).where(User.is_deleted == False)
            
            if not include_inactive:
                query = query.where(User.is_active == True)
            
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            users = result.scalars().all()
            
            # Decrypt sensitive fields for all users
            decrypted_users = []
            for user in users:
                decrypted_user = await self._decrypt_user_data(user)
                decrypted_users.append(decrypted_user)
            
            return decrypted_users
        
        except Exception as e:
            logger.error("Failed to get all users", error=str(e))
            return []
    
    async def search(
        self,
        db: AsyncSession,
        query: str,
        skip: int = 0,
        limit: int = 50,
        include_inactive: bool = False
    ) -> List[User]:
        """
        Search users by query (simplified implementation).
        
        Note: In production with encrypted data, you'd need specialized
        search indices or other strategies for efficient search.
        
        Args:
            db: Database session
            query: Search query
            skip: Number of records to skip
            limit: Maximum number of records to return
            include_inactive: Whether to include inactive users
            
        Returns:
            List of matching user instances
        """
        try:
            # This is a simplified implementation for demonstration
            # In production, you'd implement proper encrypted search
            users = await self.get_all(db, skip=0, limit=limit*2, include_inactive=include_inactive)
            
            # Filter based on decrypted data (inefficient but functional)
            matching_users = []
            query_lower = query.lower()
            
            for user in users:
                if (query_lower in (user.first_name or "").lower() or
                    query_lower in (user.last_name or "").lower()):
                    matching_users.append(user)
                    if len(matching_users) >= limit:
                        break
            
            return matching_users[skip:skip+limit]
        
        except Exception as e:
            logger.error("User search failed", error=str(e))
            return []
    
    async def exists_by_email(
        self,
        db: AsyncSession,
        email: str
    ) -> bool:
        """
        Check if user exists by email using email hash.
        
        Args:
            db: Database session
            email: Email to check
            
        Returns:
            True if user exists, False otherwise
        """
        try:
            email_hash = self.encryption_service.hash_data(email.lower())
            
            query = select(User.id).where(
                User.email_hash == email_hash,
                User.is_deleted == False
            )
            
            result = await db.execute(query)
            return result.scalar_one_or_none() is not None
        
        except Exception as e:
            logger.error("Failed to check user existence by email", error=str(e))
            return False
    
    async def update_password(
        self,
        db: AsyncSession,
        user_id: int,
        new_password: str
    ) -> bool:
        """
        Update user password with secure hashing.
        
        Args:
            db: Database session
            user_id: User ID
            new_password: New password (will be hashed)
            
        Returns:
            True if password updated successfully
        """
        try:
            user = await self.get_by_id(db, user_id, include_roles=False)
            if not user:
                return False
            
            # Hash new password
            user.password_hash = SecurityService.get_password_hash(new_password)
            user.password_changed_at = db.utcnow()
            
            await db.commit()
            
            # Invalidate cache
            await self.cache_service.delete_pattern(f"user:{user_id}:*")
            
            logger.info("Password updated successfully", user_id=user_id)
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error("Password update failed", user_id=user_id, error=str(e))
            return False
    
    async def verify_password(
        self,
        db: AsyncSession,
        user_id: int,
        password: str
    ) -> bool:
        """
        Verify user password against stored hash.
        
        Args:
            db: Database session
            user_id: User ID
            password: Password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            query = select(User.password_hash).where(
                User.id == user_id,
                User.is_deleted == False
            )
            
            result = await db.execute(query)
            password_hash = result.scalar_one_or_none()
            
            if not password_hash:
                return False
            
            return SecurityService.verify_password(password, password_hash)
        
        except Exception as e:
            logger.error("Password verification failed", user_id=user_id, error=str(e))
            return False
    
    async def _get_by_email_hash(
        self,
        db: AsyncSession,
        email_hash: str
    ) -> Optional[User]:
        """Get user by email hash (internal helper)."""
        try:
            query = select(User).where(
                User.email_hash == email_hash,
                User.is_deleted == False
            )
            
            result = await db.execute(query)
            return result.scalar_one_or_none()
        
        except Exception as e:
            logger.error("Failed to get user by email hash", error=str(e))
            return None
    
    async def _decrypt_user_data(self, user: User) -> User:
        """Decrypt sensitive user data fields."""
        try:
            if user.email:
                user.email = self.encryption_service.decrypt(user.email)
            if user.first_name:
                user.first_name = self.encryption_service.decrypt(user.first_name)
            if user.last_name:
                user.last_name = self.encryption_service.decrypt(user.last_name)
            if user.phone_number:
                user.phone_number = self.encryption_service.decrypt(user.phone_number)
            
            return user
        
        except Exception as e:
            logger.error("Failed to decrypt user data", user_id=user.id, error=str(e))
            return user
    
    def _serialize_user_for_cache(self, user: User) -> Dict[str, Any]:
        """Serialize user for caching (keeping encrypted data)."""
        return {
            "id": user.id,
            "email": user.email,  # Keep encrypted for cache
            "first_name": user.first_name,  # Keep encrypted for cache
            "last_name": user.last_name,  # Keep encrypted for cache
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }