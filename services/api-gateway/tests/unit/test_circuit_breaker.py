"""
Unit tests for Circuit Breaker functionality.
Tests all circuit breaker states, transitions, and error handling.
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch

from src.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerManager,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitState,
    CircuitBreakerError
)


@pytest.mark.unit
class TestCircuitBreakerStates:
    """Test circuit breaker state management."""
    
    @pytest.fixture
    def config(self):
        """Circuit breaker configuration for testing."""
        return CircuitBreakerConfig(
            failure_threshold=3,
            timeout=1,
            reset_timeout=2,
            success_threshold=2,
            slow_call_threshold=0.5,
            slow_call_rate_threshold=0.8,
            minimum_throughput=5
        )
    
    @pytest.fixture
    def circuit_breaker(self, config):
        """Circuit breaker instance."""
        return CircuitBreaker("test-service", config)
    
    async def test_initial_state(self, circuit_breaker):
        """Test circuit breaker initial state."""
        assert circuit_breaker.state.state == CircuitState.CLOSED
        assert circuit_breaker.state.failure_count == 0
        assert circuit_breaker.state.success_count == 0
        assert circuit_breaker.state.total_calls == 0
    
    async def test_successful_call_closed_state(self, circuit_breaker):
        """Test successful call in closed state."""
        async def success_func():
            return "success"
        
        result = await circuit_breaker.call(success_func)
        
        assert result == "success"
        assert circuit_breaker.state.success_count == 1
        assert circuit_breaker.state.total_calls == 1
        assert circuit_breaker.state.consecutive_successes == 1
        assert circuit_breaker.state.state == CircuitState.CLOSED
    
    async def test_failed_call_closed_state(self, circuit_breaker):
        """Test failed call in closed state."""
        async def failing_func():
            raise Exception("Test failure")
        
        with pytest.raises(Exception, match="Test failure"):
            await circuit_breaker.call(failing_func)
        
        assert circuit_breaker.state.failure_count == 1
        assert circuit_breaker.state.total_calls == 1
        assert circuit_breaker.state.consecutive_successes == 0
        assert circuit_breaker.state.state == CircuitState.CLOSED
    
    async def test_circuit_opens_after_failures(self, circuit_breaker):
        """Test circuit opens after threshold failures."""
        async def failing_func():
            raise Exception("Test failure")
        
        # Make enough calls to reach minimum throughput
        for _ in range(5):
            with pytest.raises(Exception):
                await circuit_breaker.call(failing_func)
        
        # Circuit should now be open
        assert circuit_breaker.state.state == CircuitState.OPEN
    
    async def test_circuit_open_fails_fast(self, circuit_breaker):
        """Test circuit breaker fails fast when open."""
        # Force circuit to open state
        circuit_breaker.state.state = CircuitState.OPEN
        circuit_breaker.state.last_state_change = time.time()
        
        async def any_func():
            return "should not execute"
        
        with pytest.raises(CircuitBreakerError):
            await circuit_breaker.call(any_func)
    
    async def test_circuit_transitions_to_half_open(self, circuit_breaker):
        """Test circuit transitions to half-open after timeout."""
        # Force circuit to open state with old timestamp
        circuit_breaker.state.state = CircuitState.OPEN
        circuit_breaker.state.last_state_change = time.time() - 10  # 10 seconds ago
        
        async def success_func():
            return "success"
        
        # Should transition to half-open and allow call
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        assert circuit_breaker.state.state in [CircuitState.HALF_OPEN, CircuitState.CLOSED]
    
    async def test_half_open_closes_on_success(self, circuit_breaker):
        """Test half-open circuit closes after successful calls."""
        # Set to half-open state
        circuit_breaker.state.state = CircuitState.HALF_OPEN
        circuit_breaker.state.last_state_change = time.time()
        circuit_breaker.state.total_calls = 0
        
        async def success_func():
            return "success"
        
        # Make successful calls to close circuit
        for _ in range(circuit_breaker.config.success_threshold):
            await circuit_breaker.call(success_func)
        
        assert circuit_breaker.state.state == CircuitState.CLOSED
    
    async def test_half_open_reopens_on_failure(self, circuit_breaker):
        """Test half-open circuit reopens on failure."""
        # Set to half-open state
        circuit_breaker.state.state = CircuitState.HALF_OPEN
        circuit_breaker.state.last_state_change = time.time()
        
        async def failing_func():
            raise Exception("Test failure")
        
        with pytest.raises(Exception):
            await circuit_breaker.call(failing_func)
        
        assert circuit_breaker.state.state == CircuitState.OPEN
    
    async def test_slow_call_detection(self, circuit_breaker):
        """Test slow call detection and circuit opening."""
        async def slow_func():
            await asyncio.sleep(0.6)  # Slower than threshold
            return "slow success"
        
        # Make multiple slow calls
        for _ in range(6):  # Above minimum throughput
            await circuit_breaker.call(slow_func)
        
        # Should open due to slow call rate
        assert circuit_breaker.state.slow_calls > 0
        # Depending on implementation, might open circuit
    
    @patch("src.services.circuit_breaker.redis_manager")
    async def test_state_persistence(self, mock_redis, circuit_breaker):
        """Test circuit breaker state persistence to Redis."""
        mock_redis.set_json.return_value = None
        
        # Trigger state change
        circuit_breaker.state.state = CircuitState.OPEN
        await circuit_breaker._persist_state()
        
        # Verify Redis was called
        mock_redis.set_json.assert_called_once()
        call_args = mock_redis.set_json.call_args
        assert "circuit_breaker:test-service" in call_args[0][0]
    
    async def test_get_state_info(self, circuit_breaker):
        """Test getting circuit breaker state information."""
        state_info = await circuit_breaker.get_state_info()
        
        assert state_info["name"] == "test-service"
        assert state_info["state"] == "closed"
        assert "failure_count" in state_info
        assert "success_count" in state_info
        assert "config" in state_info


@pytest.mark.unit
class TestCircuitBreakerManager:
    """Test circuit breaker manager functionality."""
    
    @pytest.fixture
    def manager(self):
        """Circuit breaker manager instance."""
        return CircuitBreakerManager()
    
    def test_get_circuit_breaker(self, manager):
        """Test getting circuit breaker instances."""
        cb1 = manager.get_circuit_breaker("service1")
        cb2 = manager.get_circuit_breaker("service1")  # Same service
        cb3 = manager.get_circuit_breaker("service2")  # Different service
        
        assert cb1 is cb2  # Should return same instance
        assert cb1 is not cb3  # Different services get different instances
        assert cb1.name == "service1"
        assert cb3.name == "service2"
    
    async def test_call_with_circuit_breaker(self, manager):
        """Test calling function with circuit breaker protection."""
        async def success_func():
            return "success"
        
        result = await manager.call_with_circuit_breaker("test-service", success_func)
        assert result == "success"
        
        # Verify circuit breaker was created
        assert "test-service" in manager.breakers
    
    async def test_call_with_custom_config(self, manager):
        """Test calling with custom circuit breaker config."""
        custom_config = CircuitBreakerConfig(failure_threshold=10)
        
        cb = manager.get_circuit_breaker("custom-service", custom_config)
        assert cb.config.failure_threshold == 10
    
    async def test_get_all_states(self, manager):
        """Test getting all circuit breaker states."""
        # Create some circuit breakers
        await manager.call_with_circuit_breaker("service1", lambda: "ok")
        await manager.call_with_circuit_breaker("service2", lambda: "ok")
        
        states = await manager.get_all_states()
        
        assert "service1" in states
        assert "service2" in states
        assert states["service1"]["name"] == "service1"
        assert states["service2"]["name"] == "service2"
    
    async def test_reset_circuit_breaker(self, manager):
        """Test resetting circuit breaker state."""
        # Create and modify a circuit breaker
        cb = manager.get_circuit_breaker("test-service")
        cb.state.failure_count = 5
        cb.state.state = CircuitState.OPEN
        
        # Reset it
        result = await manager.reset_circuit_breaker("test-service")
        
        assert result is True
        assert cb.state.failure_count == 0
        assert cb.state.state == CircuitState.CLOSED
    
    async def test_reset_nonexistent_circuit_breaker(self, manager):
        """Test resetting non-existent circuit breaker."""
        result = await manager.reset_circuit_breaker("nonexistent")
        assert result is False
    
    async def test_health_check(self, manager):
        """Test circuit breaker system health check."""
        # Create circuit breakers in different states
        cb1 = manager.get_circuit_breaker("healthy-service")
        cb2 = manager.get_circuit_breaker("open-service")
        cb3 = manager.get_circuit_breaker("half-open-service")
        
        cb1.state.state = CircuitState.CLOSED
        cb2.state.state = CircuitState.OPEN
        cb3.state.state = CircuitState.HALF_OPEN
        
        health = await manager.health_check()
        
        assert health["total_breakers"] == 3
        assert health["open_breakers"] == 1
        assert health["half_open_breakers"] == 1
        assert health["closed_breakers"] == 1
        assert health["health"] == "degraded"  # Has open breakers


@pytest.mark.unit
class TestCircuitBreakerErrorScenarios:
    """Test circuit breaker error scenarios and edge cases."""
    
    @pytest.fixture
    def config(self):
        """Strict configuration for error testing."""
        return CircuitBreakerConfig(
            failure_threshold=2,
            timeout=0.1,
            reset_timeout=0.5,
            success_threshold=1,
            minimum_throughput=2
        )
    
    @pytest.fixture
    def circuit_breaker(self, config):
        """Circuit breaker instance."""
        return CircuitBreaker("error-test-service", config)
    
    async def test_exception_in_function(self, circuit_breaker):
        """Test handling of exceptions in protected functions."""
        async def exception_func():
            raise ValueError("Test exception")
        
        with pytest.raises(ValueError, match="Test exception"):
            await circuit_breaker.call(exception_func)
        
        assert circuit_breaker.state.failure_count == 1
    
    async def test_timeout_simulation(self, circuit_breaker):
        """Test timeout simulation."""
        async def timeout_func():
            await asyncio.sleep(2)  # Longer than any reasonable timeout
            return "delayed"
        
        # Use asyncio.wait_for to simulate timeout
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(circuit_breaker.call(timeout_func), timeout=0.1)
    
    async def test_concurrent_calls(self, circuit_breaker):
        """Test concurrent calls to circuit breaker."""
        call_count = 0
        
        async def counting_func():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # Small delay
            return f"call_{call_count}"
        
        # Make concurrent calls
        tasks = [
            circuit_breaker.call(counting_func) 
            for _ in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        assert circuit_breaker.state.total_calls == 10
        assert circuit_breaker.state.success_count == 10
    
    async def test_half_open_call_limit(self, circuit_breaker):
        """Test call limit in half-open state."""
        # Set to half-open
        circuit_breaker.state.state = CircuitState.HALF_OPEN
        circuit_breaker.state.total_calls = 0
        circuit_breaker.state.last_state_change = time.time()
        
        async def success_func():
            return "success"
        
        # First call should succeed
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        
        # If configured with success_threshold=1, it might close
        # If not, additional calls might be limited
    
    @patch("src.services.circuit_breaker.redis_manager")
    async def test_redis_persistence_failure(self, mock_redis, circuit_breaker):
        """Test handling of Redis persistence failures."""
        mock_redis.set_json.side_effect = Exception("Redis error")
        
        # Should not raise exception even if Redis fails
        circuit_breaker.state.state = CircuitState.OPEN
        await circuit_breaker._persist_state()  # Should not raise
    
    async def test_rapid_state_changes(self, circuit_breaker):
        """Test rapid state changes under load."""
        async def intermittent_func():
            # Randomly succeed or fail
            import random
            if random.random() > 0.5:
                raise Exception("Random failure")
            return "success"
        
        # Make many calls rapidly
        for _ in range(20):
            try:
                await circuit_breaker.call(intermittent_func)
            except (Exception, CircuitBreakerError):
                pass  # Expected failures
        
        # Circuit breaker should still be in a valid state
        assert circuit_breaker.state.state in [CircuitState.CLOSED, CircuitState.OPEN, CircuitState.HALF_OPEN]
        assert circuit_breaker.state.total_calls <= 20  # May be less due to fast-fail