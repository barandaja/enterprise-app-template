"""
Repository interfaces for dependency abstraction.
Defines contracts for data access operations to enable dependency injection
and improve testability.
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.user import User


@runtime_checkable
class IUserRepository(Protocol):
    """Protocol for user repository operations."""
    
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
        Create a new user.
        
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
        ...
    
    async def get_by_id(
        self,
        db: AsyncSession,
        user_id: int,
        include_roles: bool = True
    ) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            db: Database session
            user_id: User ID
            include_roles: Whether to include user roles
            
        Returns:
            User instance or None if not found
        """
        ...
    
    async def get_by_email(
        self,
        db: AsyncSession,
        email: str,
        include_roles: bool = True
    ) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            db: Database session
            email: User email
            include_roles: Whether to include user roles
            
        Returns:
            User instance or None if not found
        """
        ...
    
    async def update(
        self,
        db: AsyncSession,
        user_id: int,
        update_data: Dict[str, Any]
    ) -> User:
        """
        Update user data.
        
        Args:
            db: Database session
            user_id: User ID to update
            update_data: Dictionary of fields to update
            
        Returns:
            Updated user instance
        """
        ...
    
    async def delete(
        self,
        db: AsyncSession,
        user_id: int,
        hard_delete: bool = False
    ) -> bool:
        """
        Delete user (soft delete by default).
        
        Args:
            db: Database session
            user_id: User ID to delete
            hard_delete: Whether to permanently delete
            
        Returns:
            True if deletion successful
        """
        ...
    
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
        ...
    
    async def search(
        self,
        db: AsyncSession,
        query: str,
        skip: int = 0,
        limit: int = 50,
        include_inactive: bool = False
    ) -> List[User]:
        """
        Search users by query.
        
        Args:
            db: Database session
            query: Search query
            skip: Number of records to skip
            limit: Maximum number of records to return
            include_inactive: Whether to include inactive users
            
        Returns:
            List of matching user instances
        """
        ...
    
    async def exists_by_email(
        self,
        db: AsyncSession,
        email: str
    ) -> bool:
        """
        Check if user exists by email.
        
        Args:
            db: Database session
            email: Email to check
            
        Returns:
            True if user exists, False otherwise
        """
        ...
    
    async def update_password(
        self,
        db: AsyncSession,
        user_id: int,
        new_password: str
    ) -> bool:
        """
        Update user password.
        
        Args:
            db: Database session
            user_id: User ID
            new_password: New password (will be hashed)
            
        Returns:
            True if password updated successfully
        """
        ...
    
    async def verify_password(
        self,
        db: AsyncSession,
        user_id: int,
        password: str
    ) -> bool:
        """
        Verify user password.
        
        Args:
            db: Database session
            user_id: User ID
            password: Password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        ...