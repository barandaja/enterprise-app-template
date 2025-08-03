"""
Rate limiting service with Redis-based sliding window implementation.
Supports both global and per-user rate limiting with compliance features.
"""
import asyncio
import time
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager, is_redis_initialized

logger = structlog.get_logger()
settings = get_settings()


class RateLimitType(Enum):
    """Rate limit types."""
    GLOBAL = "global"
    USER = "user"
    IP = "ip"
    API_KEY = "api_key"
    ENDPOINT = "endpoint"


@dataclass
class RateLimit:
    """Rate limit configuration."""
    requests: int
    window: int  # seconds
    burst_requests: Optional[int] = None  # Allow burst above normal limit
    burst_window: Optional[int] = None    # Burst window in seconds


@dataclass
class RateLimitResult:
    """Rate limit check result."""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None
    limit_type: Optional[str] = None


class RateLimiterManager:
    """Redis-based rate limiter with sliding window."""
    
    def __init__(self):
        self.default_limits = {
            RateLimitType.GLOBAL: RateLimit(
                requests=settings.global_rate_limit_requests,
                window=settings.global_rate_limit_window
            ),
            RateLimitType.USER: RateLimit(
                requests=settings.user_rate_limit_requests,
                window=settings.user_rate_limit_window,
                burst_requests=settings.user_rate_limit_requests * 2,
                burst_window=10
            ),
            RateLimitType.IP: RateLimit(
                requests=200,  # Per IP limit
                window=60,
                burst_requests=300,
                burst_window=10
            ),
            RateLimitType.ENDPOINT: RateLimit(
                requests=100,  # Per endpoint limit
                window=60
            )
        }
    
    async def check_rate_limit(
        self,
        identifier: str,
        limit_type: RateLimitType,
        custom_limit: Optional[RateLimit] = None
    ) -> RateLimitResult:
        """
        Check if request is within rate limit using sliding window.
        
        Args:
            identifier: Unique identifier (user_id, ip, api_key, etc.)
            limit_type: Type of rate limit to apply
            custom_limit: Custom rate limit override
        
        Returns:
            RateLimitResult with allow/deny decision and metadata
        """
        
        limit = custom_limit or self.default_limits.get(limit_type)
        if not limit:
            # No limit configured, allow request
            return RateLimitResult(
                allowed=True,
                remaining=999999,
                reset_time=time.time() + 3600,
                limit_type=limit_type.value
            )
        
        current_time = time.time()
        window_start = current_time - limit.window
        
        # Redis key for this rate limit
        redis_key = f"rate_limit:{limit_type.value}:{identifier}"
        
        try:
            # Check if Redis is initialized
            if not is_redis_initialized():
                logger.warning("Rate limiting disabled - Redis not initialized", 
                              identifier=identifier, limit_type=limit_type.value)
                # Allow request if Redis is not available (fail open for availability)
                return RateLimitResult(
                    allowed=True,
                    remaining=999999,
                    reset_time=current_time + limit.window,
                    limit_type=limit_type.value
                )
            
            # Use Redis sorted set for sliding window
            client = await redis_manager.get_client()
            # Start pipeline for atomic operations
            pipe = client.pipeline()
            
            # Remove old entries outside the window
            pipe.zremrangebyscore(redis_key, 0, window_start)
            
            # Count current requests in window
            pipe.zcard(redis_key)
            
            # Execute pipeline
            results = await pipe.execute()
            current_requests = results[1]
            
            # Check if within limit
            if current_requests < limit.requests:
                # Add current request to the window
                await client.zadd(redis_key, {str(current_time): current_time})
                
                # Set expiration for cleanup
                await client.expire(redis_key, limit.window + 10)
                
                remaining = limit.requests - current_requests - 1
                reset_time = current_time + limit.window
                
                return RateLimitResult(
                    allowed=True,
                    remaining=max(0, remaining),
                    reset_time=reset_time,
                    limit_type=limit_type.value
                )
            else:
                # Check burst limit if configured
                if limit.burst_requests and limit.burst_window:
                    burst_result = await self._check_burst_limit(
                        identifier, limit_type, limit, current_time
                    )
                    if burst_result.allowed:
                        return burst_result
                
                # Rate limit exceeded
                oldest_request = await client.zrange(redis_key, 0, 0, withscores=True)
                if oldest_request:
                    oldest_time = oldest_request[0][1]
                    retry_after = int(oldest_time + limit.window - current_time)
                else:
                    retry_after = limit.window
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=current_time + limit.window,
                    retry_after=max(1, retry_after),
                    limit_type=limit_type.value
                )
        
        except Exception as e:
            logger.error(
                "Rate limit check failed",
                identifier=identifier,
                limit_type=limit_type.value,
                error=str(e)
            )
            
            # On Redis failure, fail securely - deny request to prevent rate limit bypass
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=current_time + limit.window,
                retry_after=limit.window,
                limit_type=limit_type.value
            )
    
    async def _check_burst_limit(
        self,
        identifier: str,
        limit_type: RateLimitType,
        limit: RateLimit,
        current_time: float
    ) -> RateLimitResult:
        """Check burst rate limit."""
        
        burst_window_start = current_time - limit.burst_window
        burst_redis_key = f"burst_rate_limit:{limit_type.value}:{identifier}"
        
        try:
            if not is_redis_initialized():
                logger.warning("Burst rate limiting disabled - Redis not initialized")
                return RateLimitResult(
                    allowed=True,
                    remaining=limit.burst_requests - 1,
                    reset_time=current_time + limit.burst_window,
                    limit_type=f"{limit_type.value}_burst"
                )
            
            client = await redis_manager.get_client()
            # Remove old burst entries
            await client.zremrangebyscore(burst_redis_key, 0, burst_window_start)
            
            # Count current burst requests
            burst_requests = await client.zcard(burst_redis_key)
            
            if burst_requests < limit.burst_requests:
                # Allow burst request
                await client.zadd(burst_redis_key, {str(current_time): current_time})
                await client.expire(burst_redis_key, limit.burst_window + 10)
                
                remaining = limit.burst_requests - burst_requests - 1
                
                logger.info(
                    "Burst rate limit allowed",
                    identifier=identifier,
                    limit_type=limit_type.value,
                    remaining=remaining
                )
                
                return RateLimitResult(
                    allowed=True,
                    remaining=max(0, remaining),
                    reset_time=current_time + limit.burst_window,
                    limit_type=f"{limit_type.value}_burst"
                )
            else:
                # Burst limit also exceeded
                oldest_burst = await client.zrange(burst_redis_key, 0, 0, withscores=True)
                if oldest_burst:
                    oldest_time = oldest_burst[0][1]
                    retry_after = int(oldest_time + limit.burst_window - current_time)
                else:
                    retry_after = limit.burst_window
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=current_time + limit.burst_window,
                    retry_after=max(1, retry_after),
                    limit_type=f"{limit_type.value}_burst"
                )
        
        except Exception as e:
            logger.error(
                "Burst rate limit check failed",
                identifier=identifier,
                error=str(e)
            )
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=current_time + limit.burst_window,
                retry_after=limit.burst_window
            )
    
    async def get_rate_limit_status(
        self,
        identifier: str,
        limit_type: RateLimitType
    ) -> Dict[str, Any]:
        """Get current rate limit status for identifier."""
        
        limit = self.default_limits.get(limit_type)
        if not limit:
            return {"error": "Rate limit not configured"}
        
        current_time = time.time()
        window_start = current_time - limit.window
        redis_key = f"rate_limit:{limit_type.value}:{identifier}"
        
        try:
            async with redis_manager.get_client() as redis:
                # Clean old entries and count current
                await redis.zremrangebyscore(redis_key, 0, window_start)
                current_requests = await redis.zcard(redis_key)
                
                # Get oldest request time for reset calculation
                oldest_request = await redis.zrange(redis_key, 0, 0, withscores=True)
                if oldest_request:
                    reset_time = oldest_request[0][1] + limit.window
                else:
                    reset_time = current_time + limit.window
                
                return {
                    "limit": limit.requests,
                    "used": current_requests,
                    "remaining": max(0, limit.requests - current_requests),
                    "reset_time": reset_time,
                    "window": limit.window
                }
        
        except Exception as e:
            logger.error(
                "Failed to get rate limit status",
                identifier=identifier,
                error=str(e)
            )
            return {"error": "Failed to get rate limit status"}
    
    async def reset_rate_limit(
        self,
        identifier: str,
        limit_type: RateLimitType
    ) -> bool:
        """Reset rate limit for identifier (admin function)."""
        
        redis_key = f"rate_limit:{limit_type.value}:{identifier}"
        burst_redis_key = f"burst_rate_limit:{limit_type.value}:{identifier}"
        
        try:
            async with redis_manager.get_client() as redis:
                deleted = await redis.delete(redis_key, burst_redis_key)
                
                logger.info(
                    "Rate limit reset",
                    identifier=identifier,
                    limit_type=limit_type.value,
                    keys_deleted=deleted
                )
                
                return deleted > 0
        
        except Exception as e:
            logger.error(
                "Failed to reset rate limit",
                identifier=identifier,
                error=str(e)
            )
            return False
    
    async def get_global_rate_limit_stats(self) -> Dict[str, Any]:
        """Get global rate limiting statistics."""
        
        try:
            async with redis_manager.get_client() as redis:
                # Find all rate limit keys
                keys = await redis.keys("rate_limit:*")
                
                stats = {
                    "total_keys": len(keys),
                    "by_type": {}
                }
                
                # Analyze by type
                for key in keys:
                    parts = key.split(":")
                    if len(parts) >= 2:
                        limit_type = parts[1]
                        if limit_type not in stats["by_type"]:
                            stats["by_type"][limit_type] = 0
                        stats["by_type"][limit_type] += 1
                
                return stats
        
        except Exception as e:
            logger.error("Failed to get global rate limit stats", error=str(e))
            return {"error": "Failed to get stats"}