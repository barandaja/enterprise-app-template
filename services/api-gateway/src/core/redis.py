"""
Redis configuration and connection management for API Gateway.
Used for caching, rate limiting, circuit breaker state, and session management.
"""
import asyncio
import json
from typing import Any, Dict, List, Optional, Union
import redis.asyncio as redis
from redis.asyncio import ConnectionPool, Redis
import structlog

from .config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Global Redis connection
_redis_client: Optional[Redis] = None
_redis_pool: Optional[ConnectionPool] = None


async def init_redis() -> None:
    """Initialize Redis connection pool."""
    global _redis_client, _redis_pool
    
    try:
        # Create connection pool
        _redis_pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections=settings.redis_pool_size,
            socket_timeout=settings.redis_timeout,
            socket_connect_timeout=settings.redis_timeout,
            health_check_interval=30,
            retry_on_timeout=True,
            decode_responses=True
        )
        
        # Create Redis client
        _redis_client = Redis(connection_pool=_redis_pool)
        
        # Test connection
        await _redis_client.ping()
        
        logger.info("Redis initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize Redis", error=str(e))
        raise


async def get_redis() -> Redis:
    """Get Redis client instance."""
    if not _redis_client:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    
    return _redis_client


async def close_redis() -> None:
    """Close Redis connections."""
    global _redis_client, _redis_pool
    
    try:
        if _redis_client:
            await _redis_client.close()
        
        if _redis_pool:
            await _redis_pool.disconnect()
        
        logger.info("Redis connections closed")
        
    except Exception as e:
        logger.error("Error closing Redis connections", error=str(e))


class RedisManager:
    """Redis operations manager with utility methods."""
    
    def __init__(self):
        self.client = None
    
    async def get_client(self) -> Redis:
        """Get Redis client, initializing if needed."""
        if not self.client:
            self.client = await get_redis()
        return self.client
    
    async def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            client = await self.get_client()
            await client.ping()
            return True
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            return False
    
    async def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set JSON value with optional TTL."""
        try:
            client = await self.get_client()
            json_value = json.dumps(value, default=str)
            
            if ttl:
                return await client.setex(key, ttl, json_value)
            else:
                return await client.set(key, json_value)
                
        except Exception as e:
            logger.error("Failed to set JSON value", key=key, error=str(e))
            return False
    
    async def get_json(self, key: str, default: Any = None) -> Any:
        """Get JSON value."""
        try:
            client = await self.get_client()
            value = await client.get(key)
            
            if value is None:
                return default
            
            return json.loads(value)
            
        except Exception as e:
            logger.error("Failed to get JSON value", key=key, error=str(e))
            return default
    
    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        try:
            client = await self.get_client()
            return await client.delete(*keys)
        except Exception as e:
            logger.error("Failed to delete keys", keys=keys, error=str(e))
            return 0
    
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        try:
            client = await self.get_client()
            return bool(await client.exists(key))
        except Exception as e:
            logger.error("Failed to check key existence", key=key, error=str(e))
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key."""
        try:
            client = await self.get_client()
            return await client.expire(key, ttl)
        except Exception as e:
            logger.error("Failed to set TTL", key=key, ttl=ttl, error=str(e))
            return False
    
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment counter."""
        try:
            client = await self.get_client()
            return await client.incrby(key, amount)
        except Exception as e:
            logger.error("Failed to increment counter", key=key, error=str(e))
            return 0
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get Redis connection statistics."""
        try:
            client = await self.get_client()
            info = await client.info("clients")
            
            return {
                "connected_clients": info.get("connected_clients", 0),
                "blocked_clients": info.get("blocked_clients", 0),
                "tracking_clients": info.get("tracking_clients", 0),
            }
            
        except Exception as e:
            logger.error("Failed to get Redis stats", error=str(e))
            return {}


# Global Redis manager instance
redis_manager = RedisManager()