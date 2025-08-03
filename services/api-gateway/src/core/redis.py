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

# Global Redis connection
_redis_client: Optional[Redis] = None
_redis_pool: Optional[ConnectionPool] = None


async def init_redis() -> None:
    """Initialize Redis connection pool."""
    global _redis_client, _redis_pool
    
    # Check if already initialized
    if _redis_client is not None:
        logger.debug("Redis already initialized, skipping")
        return
    
    try:
        logger.info("Initializing Redis connection...")
        
        # Get settings when called, not at module load time
        settings = get_settings()
        
        # Create connection pool
        pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections=settings.redis_pool_size,
            socket_timeout=settings.redis_timeout,
            socket_connect_timeout=settings.redis_timeout,
            health_check_interval=0,  # Disable automatic health checks to prevent recursion
            retry_on_timeout=True,
            decode_responses=True
        )
        
        # Create Redis client
        client = Redis(connection_pool=pool)
        
        # Test connection before setting globals with timeout
        await asyncio.wait_for(client.ping(), timeout=5.0)
        logger.debug("Redis connection test successful")
        
        # Only set globals after successful test
        _redis_pool = pool
        _redis_client = client
        
        logger.info("Redis initialized successfully")
        
    except asyncio.TimeoutError:
        logger.error("Failed to initialize Redis - connection timeout")
        # Clean up on failure
        _redis_client = None
        _redis_pool = None
        raise RuntimeError("Redis connection timeout during initialization")
    except Exception as e:
        logger.error("Failed to initialize Redis", error=str(e))
        # Clean up on failure
        _redis_client = None
        _redis_pool = None
        raise


async def get_redis() -> Redis:
    """Get Redis client instance."""
    if not _redis_client:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    
    return _redis_client


def is_redis_initialized() -> bool:
    """Check if Redis is initialized without raising an exception."""
    return _redis_client is not None


async def close_redis() -> None:
    """Close Redis connections."""
    global _redis_client, _redis_pool
    
    try:
        if _redis_client:
            await asyncio.wait_for(_redis_client.close(), timeout=5.0)
        
        if _redis_pool:
            await asyncio.wait_for(_redis_pool.disconnect(), timeout=5.0)
        
        logger.info("Redis connections closed")
        
    except asyncio.TimeoutError:
        logger.warning("Redis connection close timeout")
    except Exception as e:
        logger.error("Error closing Redis connections", error=str(e))
    finally:
        # Always reset globals
        _redis_client = None
        _redis_pool = None


class RedisManager:
    """Redis operations manager with utility methods."""
    
    def __init__(self):
        self.client = None
    
    async def get_client(self) -> Redis:
        """Get Redis client, initializing if needed."""
        if not self.client:
            if not is_redis_initialized():
                raise RuntimeError("Redis not initialized. Call init_redis() first.")
            self.client = await get_redis()
        return self.client
    
    async def health_check(self) -> bool:
        """Check Redis connectivity with recursion protection."""
        try:
            if not is_redis_initialized():
                logger.warning("Redis health check skipped - Redis not initialized")
                return False
            
            # Use the global client directly to avoid potential recursion in get_client()
            if not _redis_client:
                logger.warning("Redis health check skipped - client not available")
                return False
            
            # Simple ping with timeout to prevent hanging
            await asyncio.wait_for(_redis_client.ping(), timeout=2.0)
            return True
        except asyncio.TimeoutError:
            logger.error("Redis health check failed - timeout")
            return False
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            return False
    
    async def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set JSON value with optional TTL."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis set_json skipped - Redis not initialized", key=key)
                return False
            
            client = await self.get_client()
            json_value = json.dumps(value, default=str)
            
            if ttl:
                return await client.setex(key, ttl, json_value)
            else:
                return await client.set(key, json_value)
                
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis set_json skipped - Redis not initialized", key=key)
                return False
            logger.error("Failed to set JSON value", key=key, error=str(e))
            return False
        except Exception as e:
            logger.error("Failed to set JSON value", key=key, error=str(e))
            return False
    
    async def get_json(self, key: str, default: Any = None) -> Any:
        """Get JSON value."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis get_json skipped - Redis not initialized", key=key)
                return default
            
            client = await self.get_client()
            value = await client.get(key)
            
            if value is None:
                return default
            
            return json.loads(value)
            
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis get_json skipped - Redis not initialized", key=key)
                return default
            logger.error("Failed to get JSON value", key=key, error=str(e))
            return default
        except Exception as e:
            logger.error("Failed to get JSON value", key=key, error=str(e))
            return default
    
    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis delete skipped - Redis not initialized", keys=keys)
                return 0
            client = await self.get_client()
            return await client.delete(*keys)
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis delete skipped - Redis not initialized", keys=keys)
                return 0
            logger.error("Failed to delete keys", keys=keys, error=str(e))
            return 0
        except Exception as e:
            logger.error("Failed to delete keys", keys=keys, error=str(e))
            return 0
    
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis exists check skipped - Redis not initialized", key=key)
                return False
            client = await self.get_client()
            return bool(await client.exists(key))
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis exists check skipped - Redis not initialized", key=key)
                return False
            logger.error("Failed to check key existence", key=key, error=str(e))
            return False
        except Exception as e:
            logger.error("Failed to check key existence", key=key, error=str(e))
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis expire skipped - Redis not initialized", key=key)
                return False
            client = await self.get_client()
            return await client.expire(key, ttl)
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis expire skipped - Redis not initialized", key=key)
                return False
            logger.error("Failed to set TTL", key=key, ttl=ttl, error=str(e))
            return False
        except Exception as e:
            logger.error("Failed to set TTL", key=key, ttl=ttl, error=str(e))
            return False
    
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment counter."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis incr skipped - Redis not initialized", key=key)
                return 0
            client = await self.get_client()
            return await client.incrby(key, amount)
        except RuntimeError as e:
            if "Redis not initialized" in str(e):
                logger.debug("Redis incr skipped - Redis not initialized", key=key)
                return 0
            logger.error("Failed to increment counter", key=key, error=str(e))
            return 0
        except Exception as e:
            logger.error("Failed to increment counter", key=key, error=str(e))
            return 0
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get Redis connection statistics."""
        try:
            if not is_redis_initialized():
                logger.debug("Redis stats skipped - Redis not initialized")
                return {"status": "not_initialized"}
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