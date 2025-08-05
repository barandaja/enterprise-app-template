"""
Redis configuration and connection management for caching and session storage.
Implements connection pooling and health checks.
"""
import asyncio
import json
import time
from typing import Any, Optional, Union
import redis.asyncio as redis
from redis.asyncio import ConnectionPool
import structlog
from .config import settings

logger = structlog.get_logger()


class RedisManager:
    """Redis connection manager with connection pooling."""
    
    def __init__(self):
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
    
    async def initialize(self):
        """Initialize Redis connection pool."""
        try:
            # Parse Redis URL - configured to prevent recursion issues
            redis_kwargs = {
                "max_connections": settings.REDIS_POOL_SIZE,
                "retry_on_timeout": True,
                "retry_on_error": [ConnectionError, TimeoutError],
                "socket_keepalive": True,
                "socket_keepalive_options": {},
                # Disable health check during connection to prevent recursion
                # The health check will trigger PING which causes reconnection loop
                "health_check_interval": 0,  # Disable automatic health checks
                # Disable client info to prevent CLIENT SETINFO commands during connect
                "client_name": None,  # Don't set client name to avoid CLIENT SETINFO
            }
            
            # Only add password if not already in URL (to avoid conflicts)
            # Check if URL already contains authentication (format: redis://:password@host or redis://user:password@host)
            if settings.REDIS_PASSWORD and "@" not in settings.REDIS_URL:
                redis_kwargs["password"] = settings.REDIS_PASSWORD
            
            # Only add SSL parameters if SSL is enabled and we have a secure URL
            if settings.REDIS_SSL and settings.REDIS_URL.startswith(('rediss://', 'redis+ssl://')):
                redis_kwargs["ssl"] = True
                redis_kwargs["ssl_cert_reqs"] = None
            
            # Create connection pool
            self._pool = ConnectionPool.from_url(
                settings.REDIS_URL,
                **redis_kwargs
            )
            
            # Create Redis client
            self._client = redis.Redis(connection_pool=self._pool)
            
            # Test connection with timeout to prevent hanging
            try:
                # Simple connection test without triggering health checks
                await asyncio.wait_for(self._client.ping(), timeout=5.0)
                logger.info("Redis connection initialized and tested successfully")
            except asyncio.TimeoutError:
                logger.error("Redis connection test timed out")
                raise ConnectionError("Redis connection test timed out")
            except Exception as e:
                logger.error("Redis connection test failed", error=str(e))
                raise
            
        except Exception as e:
            logger.error("Failed to initialize Redis connection", error=str(e))
            raise
    
    async def close(self):
        """Close Redis connections."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis connections closed")
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if not self._client:
            raise RuntimeError("Redis client not initialized")
        return self._client
    
    async def health_check(self) -> bool:
        """Check Redis connection health."""
        try:
            if not self._client:
                logger.warning("Redis health check skipped - client not initialized")
                return False
            
            # Use a simple ping with explicit timeout to avoid recursion
            pong = await self._client.ping()
            if pong:
                return True
            else:
                logger.warning("Redis ping returned False")
                return False
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            return False
    
    async def get_pool_info(self) -> dict:
        """Get connection pool information."""
        if not self._pool:
            return {}
        
        return {
            "max_connections": self._pool.max_connections,
            "created_connections": len(self._pool._created_connections),
            "available_connections": len(self._pool._available_connections),
            "in_use_connections": len(self._pool._in_use_connections)
        }


# Global Redis manager instance
redis_manager = RedisManager()


class CacheService:
    """High-level caching service with serialization support."""
    
    def __init__(self, redis_client: redis.Redis, key_prefix: str = "auth:"):
        self.redis = redis_client
        self.key_prefix = key_prefix
    
    def _make_key(self, key: str) -> str:
        """Create prefixed cache key."""
        return f"{self.key_prefix}{key}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache with JSON deserialization."""
        try:
            cache_key = self._make_key(key)
            value = await self.redis.get(cache_key)
            
            if value is None:
                return None
            
            # Try to deserialize as JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                # Return as string if not JSON
                return value.decode('utf-8')
        
        except Exception as e:
            logger.warning("Cache get failed", key=key, error=str(e))
            return None
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None
    ) -> bool:
        """Set value in cache with JSON serialization."""
        try:
            cache_key = self._make_key(key)
            
            # Serialize value
            if isinstance(value, (dict, list)):
                serialized_value = json.dumps(value)
            elif isinstance(value, (int, float, bool)):
                serialized_value = json.dumps(value)
            else:
                serialized_value = str(value)
            
            if ttl:
                await self.redis.setex(cache_key, ttl, serialized_value)
            else:
                await self.redis.set(cache_key, serialized_value)
            
            return True
        
        except Exception as e:
            logger.warning("Cache set failed", key=key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        try:
            cache_key = self._make_key(key)
            result = await self.redis.delete(cache_key)
            return result > 0
        
        except Exception as e:
            logger.warning("Cache delete failed", key=key, error=str(e))
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        try:
            cache_key = self._make_key(key)
            return await self.redis.exists(cache_key) > 0
        
        except Exception as e:
            logger.warning("Cache exists check failed", key=key, error=str(e))
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for existing key."""
        try:
            cache_key = self._make_key(key)
            return await self.redis.expire(cache_key, ttl)
        
        except Exception as e:
            logger.warning("Cache expire failed", key=key, error=str(e))
            return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a numeric value in cache."""
        try:
            cache_key = self._make_key(key)
            return await self.redis.incrby(cache_key, amount)
        
        except Exception as e:
            logger.warning("Cache increment failed", key=key, error=str(e))
            return None
    
    async def set_with_lock(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        lock_timeout: int = 10
    ) -> bool:
        """Set value with distributed lock to prevent race conditions."""
        lock_key = f"lock:{key}"
        lock = self.redis.lock(lock_key, timeout=lock_timeout)
        
        try:
            if await lock.acquire(blocking=False):
                return await self.set(key, value, ttl)
            else:
                logger.warning("Could not acquire lock for cache set", key=key)
                return False
        
        except Exception as e:
            logger.warning("Cache set with lock failed", key=key, error=str(e))
            return False
        
        finally:
            try:
                await lock.release()
            except:
                pass  # Lock may have expired
    
    async def get_or_set(
        self, 
        key: str, 
        factory_func, 
        ttl: Optional[int] = None
    ) -> Optional[Any]:
        """Get value from cache or set it using factory function."""
        value = await self.get(key)
        
        if value is not None:
            return value
        
        # Generate value using factory function
        try:
            if asyncio.iscoroutinefunction(factory_func):
                new_value = await factory_func()
            else:
                new_value = factory_func()
            
            if new_value is not None:
                await self.set(key, new_value, ttl)
            
            return new_value
        
        except Exception as e:
            logger.error("Factory function failed in get_or_set", key=key, error=str(e))
            return None
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern."""
        try:
            pattern_key = self._make_key(pattern)
            keys = []
            
            async for key in self.redis.scan_iter(match=pattern_key):
                keys.append(key)
            
            if keys:
                return await self.redis.delete(*keys)
            
            return 0
        
        except Exception as e:
            logger.warning("Cache delete pattern failed", pattern=pattern, error=str(e))
            return 0


class RateLimitService:
    """Redis-based rate limiting service."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    async def is_rate_limited(
        self, 
        key: str, 
        limit: int, 
        window_seconds: int
    ) -> tuple[bool, int, int]:
        """
        Check if rate limit is exceeded using sliding window.
        
        Returns:
            (is_limited, current_count, time_to_reset)
        """
        try:
            current_time = int(time.time())
            window_start = current_time - window_seconds
            
            # Use Redis sorted set for sliding window
            pipe = self.redis.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current entries
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = await pipe.execute()
            current_count = results[1]
            
            is_limited = current_count >= limit
            time_to_reset = window_seconds if is_limited else 0
            
            return is_limited, current_count, time_to_reset
        
        except Exception as e:
            logger.error("Rate limit check failed", key=key, error=str(e))
            # Fail open - don't block on Redis errors
            return False, 0, 0
    
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a key."""
        try:
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error("Rate limit reset failed", key=key, error=str(e))
            return False


# Initialize services
def get_cache_service() -> CacheService:
    """Get cache service instance."""
    return CacheService(redis_manager.client)


def get_rate_limit_service() -> RateLimitService:
    """Get rate limit service instance."""
    return RateLimitService(redis_manager.client)


async def initialize_redis():
    """Initialize Redis connection."""
    await redis_manager.initialize()


async def close_redis():
    """Close Redis connections."""
    await redis_manager.close()