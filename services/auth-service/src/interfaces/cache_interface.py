"""
Cache service interface for dependency abstraction.
Defines the contract for caching operations to enable dependency injection
and improve testability.
"""

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class ICacheService(Protocol):
    """Protocol for cache service operations."""
    
    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        ...
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (optional)
            
        Returns:
            True if set successful, False otherwise
        """
        ...
    
    async def delete(self, key: str) -> bool:
        """
        Delete key from cache.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if deleted, False otherwise
        """
        ...
    
    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache.
        
        Args:
            key: Cache key to check
            
        Returns:
            True if key exists, False otherwise
        """
        ...
    
    async def expire(self, key: str, ttl: int) -> bool:
        """
        Set expiration time for existing key.
        
        Args:
            key: Cache key
            ttl: Time to live in seconds
            
        Returns:
            True if expiration set, False otherwise
        """
        ...
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment a numeric value in cache.
        
        Args:
            key: Cache key
            amount: Amount to increment by
            
        Returns:
            New value after increment, or None on error
        """
        ...
    
    async def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern.
        
        Args:
            pattern: Pattern to match keys
            
        Returns:
            Number of keys deleted
        """
        ...
    
    async def get_or_set(
        self, 
        key: str, 
        factory_func, 
        ttl: Optional[int] = None
    ) -> Optional[Any]:
        """
        Get value from cache or set it using factory function.
        
        Args:
            key: Cache key
            factory_func: Function to generate value if not in cache
            ttl: Time to live in seconds (optional)
            
        Returns:
            Cached or generated value
        """
        ...