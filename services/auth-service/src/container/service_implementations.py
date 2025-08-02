"""
Concrete implementations of service interfaces.
These implementations provide the actual functionality for the abstracted interfaces.
"""

import hashlib
from typing import Any, Optional
from cryptography.fernet import Fernet
import base64
import structlog

from ..interfaces.cache_interface import ICacheService
from ..interfaces.encryption_interface import IEncryptionService
from ..core.redis import get_cache_service
from ..core.config import settings

logger = structlog.get_logger()


class RedisCacheService(ICacheService):
    """Redis-based implementation of cache service interface."""
    
    def __init__(self):
        self._cache_service = None
    
    @property
    def cache_service(self):
        """Lazy initialization of cache service."""
        if self._cache_service is None:
            self._cache_service = get_cache_service()
        return self._cache_service
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        return await self.cache_service.get(key)
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """Set value in cache."""
        return await self.cache_service.set(key, value, ttl)
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        return await self.cache_service.delete(key)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        return await self.cache_service.exists(key)
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for existing key."""
        return await self.cache_service.expire(key, ttl)
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a numeric value in cache."""
        return await self.cache_service.increment(key, amount)
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern."""
        return await self.cache_service.delete_pattern(pattern)
    
    async def get_or_set(
        self, 
        key: str, 
        factory_func, 
        ttl: Optional[int] = None
    ) -> Optional[Any]:
        """Get value from cache or set it using factory function."""
        return await self.cache_service.get_or_set(key, factory_func, ttl)


class FernetEncryptionService(IEncryptionService):
    """Fernet-based implementation of encryption service interface."""
    
    def __init__(self):
        self._fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize Fernet encryption with key from config."""
        try:
            # Get encryption key from config
            encryption_key = settings.ENCRYPTION_KEY
            
            # Ensure key is properly formatted for Fernet
            if isinstance(encryption_key, str):
                # If it's a string, encode it and use first 32 bytes
                key_bytes = encryption_key.encode('utf-8')[:32]
                # Pad to 32 bytes if necessary
                key_bytes = key_bytes.ljust(32, b'0')
                # Base64 encode for Fernet
                fernet_key = base64.urlsafe_b64encode(key_bytes)
            else:
                # Assume it's already a proper Fernet key
                fernet_key = encryption_key
            
            self._fernet = Fernet(fernet_key)
            logger.info("Encryption service initialized successfully")
        
        except Exception as e:
            logger.error("Failed to initialize encryption service", error=str(e))
            # Use a default key for development (NOT for production)
            default_key = Fernet.generate_key()
            self._fernet = Fernet(default_key)
            logger.warning("Using default encryption key - NOT suitable for production")
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext data."""
        try:
            if not plaintext:
                return ""
            
            # Convert to bytes if string
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
            
            # Encrypt and return as base64 string
            encrypted_bytes = self._fernet.encrypt(plaintext_bytes)
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt encrypted data."""
        try:
            if not ciphertext:
                return ""
            
            # Decode from base64
            encrypted_bytes = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            
            # Decrypt
            decrypted_bytes = self._fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise
    
    def hash_data(self, data: str) -> str:
        """Create a hash of the data for indexing/comparison."""
        try:
            if not data:
                return ""
            
            # Use SHA-256 for hashing
            hash_obj = hashlib.sha256()
            hash_obj.update(data.encode('utf-8'))
            return hash_obj.hexdigest()
        
        except Exception as e:
            logger.error("Hashing failed", error=str(e))
            raise
    
    def verify_hash(self, data: str, hash_value: str) -> bool:
        """Verify data against hash."""
        try:
            computed_hash = self.hash_data(data)
            return computed_hash == hash_value
        
        except Exception as e:
            logger.error("Hash verification failed", error=str(e))
            return False
    
    def generate_key(self) -> str:
        """Generate a new encryption key."""
        try:
            new_key = Fernet.generate_key()
            return base64.urlsafe_b64encode(new_key).decode('utf-8')
        
        except Exception as e:
            logger.error("Key generation failed", error=str(e))
            raise
    
    def encrypt_with_key(self, plaintext: str, key: str) -> str:
        """Encrypt data with specific key."""
        try:
            # Create temporary Fernet instance with provided key
            key_bytes = base64.urlsafe_b64decode(key.encode('utf-8'))
            temp_fernet = Fernet(key_bytes)
            
            # Encrypt
            plaintext_bytes = plaintext.encode('utf-8')
            encrypted_bytes = temp_fernet.encrypt(plaintext_bytes)
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        
        except Exception as e:
            logger.error("Encryption with key failed", error=str(e))
            raise
    
    def decrypt_with_key(self, ciphertext: str, key: str) -> str:
        """Decrypt data with specific key."""
        try:
            # Create temporary Fernet instance with provided key
            key_bytes = base64.urlsafe_b64decode(key.encode('utf-8'))
            temp_fernet = Fernet(key_bytes)
            
            # Decrypt
            encrypted_bytes = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            decrypted_bytes = temp_fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        
        except Exception as e:
            logger.error("Decryption with key failed", error=str(e))
            raise


class InMemoryCacheService(ICacheService):
    """In-memory implementation of cache service for testing."""
    
    def __init__(self):
        self._cache: dict = {}
        self._ttl: dict = {}
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from in-memory cache."""
        if key in self._cache:
            return self._cache[key]
        return None
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """Set value in in-memory cache."""
        self._cache[key] = value
        if ttl:
            import time
            self._ttl[key] = time.time() + ttl
        return True
    
    async def delete(self, key: str) -> bool:
        """Delete key from in-memory cache."""
        if key in self._cache:
            del self._cache[key]
            if key in self._ttl:
                del self._ttl[key]
            return True
        return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in in-memory cache."""
        return key in self._cache
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for existing key."""
        if key in self._cache:
            import time
            self._ttl[key] = time.time() + ttl
            return True
        return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a numeric value in in-memory cache."""
        current = self._cache.get(key, 0)
        if isinstance(current, (int, float)):
            new_value = current + amount
            self._cache[key] = new_value
            return new_value
        return None
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern from in-memory cache."""
        import fnmatch
        keys_to_delete = [key for key in self._cache.keys() if fnmatch.fnmatch(key, pattern)]
        for key in keys_to_delete:
            del self._cache[key]
            if key in self._ttl:
                del self._ttl[key]
        return len(keys_to_delete)
    
    async def get_or_set(
        self, 
        key: str, 
        factory_func, 
        ttl: Optional[int] = None
    ) -> Optional[Any]:
        """Get value from in-memory cache or set it using factory function."""
        if key in self._cache:
            return self._cache[key]
        
        # Generate value
        import asyncio
        if asyncio.iscoroutinefunction(factory_func):
            value = await factory_func()
        else:
            value = factory_func()
        
        if value is not None:
            await self.set(key, value, ttl)
        
        return value