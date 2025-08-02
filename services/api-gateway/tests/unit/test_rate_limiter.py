"""
Unit tests for Rate Limiter functionality.
Tests sliding window rate limiting, burst limits, and Redis operations.
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch, MagicMock

from src.services.rate_limiter import (
    RateLimiterManager,
    RateLimit,
    RateLimitResult,
    RateLimitType
)


@pytest.mark.unit
class TestRateLimit:
    """Test RateLimit configuration class."""
    
    def test_rate_limit_creation(self):
        """Test RateLimit instance creation."""
        limit = RateLimit(requests=100, window=60)
        
        assert limit.requests == 100
        assert limit.window == 60
        assert limit.burst_requests is None
        assert limit.burst_window is None
    
    def test_rate_limit_with_burst(self):
        """Test RateLimit with burst configuration."""
        limit = RateLimit(
            requests=100,
            window=60,
            burst_requests=150,
            burst_window=10
        )
        
        assert limit.requests == 100
        assert limit.window == 60
        assert limit.burst_requests == 150
        assert limit.burst_window == 10


@pytest.mark.unit
class TestRateLimitResult:
    """Test RateLimitResult data class."""
    
    def test_result_creation(self):
        """Test RateLimitResult creation."""
        result = RateLimitResult(
            allowed=True,
            remaining=99,
            reset_time=time.time() + 60,
            limit_type="user"
        )
        
        assert result.allowed is True
        assert result.remaining == 99
        assert result.limit_type == "user"
        assert result.retry_after is None
    
    def test_result_with_retry_after(self):
        """Test RateLimitResult with retry_after."""
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_time=time.time() + 60,
            retry_after=30,
            limit_type="global"
        )
        
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 30
        assert result.limit_type == "global"


@pytest.mark.unit
class TestRateLimiterManager:
    """Test RateLimiterManager functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create rate limiter manager."""
        return RateLimiterManager()
    
    def test_default_limits_configuration(self, manager):
        """Test default rate limits are configured."""
        assert RateLimitType.GLOBAL in manager.default_limits
        assert RateLimitType.USER in manager.default_limits
        assert RateLimitType.IP in manager.default_limits
        assert RateLimitType.ENDPOINT in manager.default_limits
        
        global_limit = manager.default_limits[RateLimitType.GLOBAL]
        assert global_limit.requests > 0
        assert global_limit.window > 0
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_check_rate_limit_allowed(self, mock_redis_manager, manager):
        """Test rate limit check when request is allowed."""
        # Mock Redis operations
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 5]  # 5 current requests
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        result = await manager.check_rate_limit(
            identifier="user123",
            limit_type=RateLimitType.USER
        )
        
        assert result.allowed is True
        assert result.remaining >= 0
        assert result.limit_type == "user"
        
        # Verify Redis operations
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_redis.zadd.assert_called_once()
        mock_redis.expire.assert_called_once()
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_check_rate_limit_exceeded(self, mock_redis_manager, manager):
        """Test rate limit check when limit is exceeded."""
        # Mock Redis operations for exceeded limit
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 100]  # 100 current requests (at limit)
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zrange.return_value = [(b"oldest", time.time() - 30)]
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        result = await manager.check_rate_limit(
            identifier="user123",
            limit_type=RateLimitType.USER
        )
        
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None
        assert result.retry_after > 0
        assert result.limit_type == "user"
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_check_rate_limit_with_burst(self, mock_redis_manager, manager):
        """Test rate limit check with burst allowance."""
        # Mock Redis operations for normal limit exceeded but burst available
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 100]  # At normal limit
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zcard.return_value = 10  # Only 10 burst requests used
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        result = await manager.check_rate_limit(
            identifier="user123",
            limit_type=RateLimitType.USER  # Has burst configuration
        )
        
        assert result.allowed is True
        assert result.limit_type == "user_burst"
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_check_rate_limit_burst_exceeded(self, mock_redis_manager, manager):
        """Test rate limit check when both normal and burst limits exceeded."""
        # Mock Redis operations for both limits exceeded
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 100]  # At normal limit
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zcard.return_value = 200  # Burst limit also exceeded
        mock_redis.zrange.return_value = [(b"oldest", time.time() - 5)]
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        result = await manager.check_rate_limit(
            identifier="user123",
            limit_type=RateLimitType.USER
        )
        
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_check_rate_limit_redis_failure(self, mock_redis_manager, manager):
        """Test rate limit check when Redis fails."""
        # Mock Redis failure
        mock_redis_manager.get_client.side_effect = Exception("Redis connection failed")
        
        result = await manager.check_rate_limit(
            identifier="user123",
            limit_type=RateLimitType.USER
        )
        
        # Should allow request on Redis failure to avoid blocking traffic
        assert result.allowed is True
        assert result.remaining == 0
    
    async def test_check_rate_limit_no_limit_configured(self, manager):
        """Test rate limit check when no limit is configured."""
        # Create a new rate limit type not in defaults
        custom_type = RateLimitType.API_KEY
        if custom_type in manager.default_limits:
            del manager.default_limits[custom_type]
        
        result = await manager.check_rate_limit(
            identifier="api-key-123",
            limit_type=custom_type
        )
        
        assert result.allowed is True
        assert result.remaining == 999999  # Large number indicating no limit
    
    async def test_check_rate_limit_with_custom_limit(self, manager):
        """Test rate limit check with custom limit configuration."""
        custom_limit = RateLimit(requests=10, window=30)
        
        with patch("src.services.rate_limiter.redis_manager") as mock_redis_manager:
            mock_redis = AsyncMock()
            mock_pipeline = AsyncMock()
            mock_pipeline.execute.return_value = [0, 5]
            mock_redis.pipeline.return_value = mock_pipeline
            mock_redis.zadd.return_value = 1
            mock_redis.expire.return_value = True
            
            mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
            
            result = await manager.check_rate_limit(
                identifier="custom-user",
                limit_type=RateLimitType.USER,
                custom_limit=custom_limit
            )
            
            assert result.allowed is True
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_get_rate_limit_status(self, mock_redis_manager, manager):
        """Test getting rate limit status."""
        mock_redis = AsyncMock()
        mock_redis.zremrangebyscore.return_value = 0
        mock_redis.zcard.return_value = 25
        mock_redis.zrange.return_value = [(b"oldest", time.time() - 30)]
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        status = await manager.get_rate_limit_status("user123", RateLimitType.USER)
        
        assert "limit" in status
        assert "used" in status
        assert "remaining" in status
        assert "reset_time" in status
        assert "window" in status
        assert status["used"] == 25
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_get_rate_limit_status_redis_failure(self, mock_redis_manager, manager):
        """Test getting rate limit status when Redis fails."""
        mock_redis_manager.get_client.side_effect = Exception("Redis error")
        
        status = await manager.get_rate_limit_status("user123", RateLimitType.USER)
        
        assert "error" in status
        assert status["error"] == "Failed to get rate limit status"
    
    async def test_get_rate_limit_status_no_limit(self, manager):
        """Test getting status for unconfigured rate limit."""
        # Remove limit from defaults
        if RateLimitType.API_KEY in manager.default_limits:
            del manager.default_limits[RateLimitType.API_KEY]
        
        status = await manager.get_rate_limit_status("api-key", RateLimitType.API_KEY)
        
        assert "error" in status
        assert status["error"] == "Rate limit not configured"
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_reset_rate_limit(self, mock_redis_manager, manager):
        """Test resetting rate limit."""
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 2  # Deleted 2 keys
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        result = await manager.reset_rate_limit("user123", RateLimitType.USER)
        
        assert result is True
        mock_redis.delete.assert_called_once()
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_reset_rate_limit_failure(self, mock_redis_manager, manager):
        """Test resetting rate limit when Redis fails."""
        mock_redis_manager.get_client.side_effect = Exception("Redis error")
        
        result = await manager.reset_rate_limit("user123", RateLimitType.USER)
        
        assert result is False
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_get_global_rate_limit_stats(self, mock_redis_manager, manager):
        """Test getting global rate limit statistics."""
        mock_redis = AsyncMock()
        mock_redis.keys.return_value = [
            "rate_limit:user:123",
            "rate_limit:user:456",
            "rate_limit:ip:192.168.1.1",
            "rate_limit:global:global",
            "rate_limit:api_key:key123"
        ]
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        stats = await manager.get_global_rate_limit_stats()
        
        assert stats["total_keys"] == 5
        assert stats["by_type"]["user"] == 2
        assert stats["by_type"]["ip"] == 1
        assert stats["by_type"]["global"] == 1
        assert stats["by_type"]["api_key"] == 1
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_get_global_stats_redis_failure(self, mock_redis_manager, manager):
        """Test getting global stats when Redis fails."""
        mock_redis_manager.get_client.side_effect = Exception("Redis error")
        
        stats = await manager.get_global_rate_limit_stats()
        
        assert "error" in stats
        assert stats["error"] == "Failed to get stats"


@pytest.mark.unit
class TestRateLimiterSlidingWindow:
    """Test sliding window implementation details."""
    
    @pytest.fixture
    def manager(self):
        """Rate limiter manager."""
        return RateLimiterManager()
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_sliding_window_cleanup(self, mock_redis_manager, manager):
        """Test that old entries are cleaned up from sliding window."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [5, 10]  # Removed 5 old entries, 10 current
        mock_redis.pipeline.return_value = mock_pipeline
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        await manager.check_rate_limit("user123", RateLimitType.USER)
        
        # Verify cleanup was called
        mock_pipeline.zremrangebyscore.assert_called_once()
        call_args = mock_pipeline.zremrangebyscore.call_args[0]
        assert len(call_args) == 3  # key, min_score (0), max_score (window_start)
        assert call_args[1] == 0  # Remove from beginning
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_request_timestamping(self, mock_redis_manager, manager):
        """Test that requests are properly timestamped in Redis."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 5]
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zadd.return_value = 1
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        current_time = time.time()
        with patch("time.time", return_value=current_time):
            await manager.check_rate_limit("user123", RateLimitType.USER)
        
        # Verify request was added with current timestamp
        mock_redis.zadd.assert_called_once()
        call_args = mock_redis.zadd.call_args[0]
        assert len(call_args) == 2  # key, mapping
        mapping = call_args[1]
        assert len(mapping) == 1
        timestamp_key, timestamp_value = list(mapping.items())[0]
        assert abs(float(timestamp_value) - current_time) < 1  # Within 1 second
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_redis_key_expiration(self, mock_redis_manager, manager):
        """Test that Redis keys are set to expire."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 5]
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        await manager.check_rate_limit("user123", RateLimitType.USER)
        
        # Verify expiration was set
        mock_redis.expire.assert_called_once()
        call_args = mock_redis.expire.call_args[0]
        key, ttl = call_args
        assert "rate_limit:user:user123" in key
        assert ttl > 60  # Should be window + buffer


@pytest.mark.unit
class TestRateLimiterConcurrency:
    """Test rate limiter under concurrent access."""
    
    @pytest.fixture
    def manager(self):
        """Rate limiter manager."""
        return RateLimiterManager()
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_concurrent_rate_limit_checks(self, mock_redis_manager, manager):
        """Test concurrent rate limit checks for same user."""
        # Mock Redis to allow all requests
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 1]  # Low count
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        # Make concurrent requests
        tasks = [
            manager.check_rate_limit("user123", RateLimitType.USER)
            for _ in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # All should be allowed (due to mocking)
        assert all(result.allowed for result in results)
        assert len(results) == 10
    
    @patch("src.services.rate_limiter.redis_manager")
    async def test_concurrent_different_users(self, mock_redis_manager, manager):
        """Test concurrent rate limit checks for different users."""
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_pipeline.execute.return_value = [0, 1]
        mock_redis.pipeline.return_value = mock_pipeline
        mock_redis.zadd.return_value = 1
        mock_redis.expire.return_value = True
        
        mock_redis_manager.get_client.return_value.__aenter__.return_value = mock_redis
        
        # Make concurrent requests for different users
        tasks = [
            manager.check_rate_limit(f"user{i}", RateLimitType.USER)
            for i in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert all(result.allowed for result in results)
        assert len(results) == 10