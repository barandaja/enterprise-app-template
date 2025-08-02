"""
Circuit breaker implementation for backend service resilience.
Prevents cascading failures and provides fast failure for unhealthy services.
"""
import asyncio
import time
from typing import Dict, Optional, Any, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager

logger = structlog.get_logger()
settings = get_settings()


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, failing fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5         # Failures to trigger open state
    timeout: int = 60                  # Timeout in seconds
    reset_timeout: int = 300           # Time to wait before trying half-open
    success_threshold: int = 3         # Successes needed to close from half-open
    slow_call_threshold: float = 5.0   # Slow call threshold in seconds
    slow_call_rate_threshold: float = 0.5  # % of slow calls to trigger
    minimum_throughput: int = 10       # Minimum calls before evaluating


@dataclass
class CircuitBreakerState:
    """Current state of a circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0
    last_state_change: float = 0
    total_calls: int = 0
    slow_calls: int = 0
    consecutive_successes: int = 0


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class CircuitBreaker:
    """Individual circuit breaker for a service."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitBreakerState()
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        
        async with self._lock:
            current_time = time.time()
            
            # Check if circuit should be opened
            if self.state.state == CircuitState.CLOSED:
                if await self._should_open_circuit():
                    await self._open_circuit(current_time)
            
            # Check if circuit should transition to half-open
            elif self.state.state == CircuitState.OPEN:
                if current_time - self.state.last_state_change > self.config.reset_timeout:
                    await self._half_open_circuit(current_time)
            
            # Handle different states
            if self.state.state == CircuitState.OPEN:
                await self._record_failure(current_time)
                raise CircuitBreakerError(f"Circuit breaker {self.name} is OPEN")
            
            elif self.state.state == CircuitState.HALF_OPEN:
                # Only allow limited calls in half-open state
                if self.state.total_calls >= self.config.success_threshold:
                    await self._record_failure(current_time)
                    raise CircuitBreakerError(f"Circuit breaker {self.name} is HALF_OPEN - too many calls")
        
        # Execute the function
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            await self._record_success(execution_time)
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            await self._record_failure(time.time(), execution_time)
            raise
    
    async def _record_success(self, execution_time: float):
        """Record successful call."""
        async with self._lock:
            self.state.success_count += 1
            self.state.consecutive_successes += 1
            self.state.total_calls += 1
            
            # Check if call was slow
            if execution_time > self.config.slow_call_threshold:
                self.state.slow_calls += 1
            
            # Transition to closed if in half-open and enough successes
            if (self.state.state == CircuitState.HALF_OPEN and 
                self.state.consecutive_successes >= self.config.success_threshold):
                await self._close_circuit(time.time())
    
    async def _record_failure(self, current_time: float, execution_time: float = 0):
        """Record failed call."""
        async with self._lock:
            self.state.failure_count += 1
            self.state.consecutive_successes = 0
            self.state.last_failure_time = current_time
            self.state.total_calls += 1
            
            # Check if call was slow
            if execution_time > self.config.slow_call_threshold:
                self.state.slow_calls += 1
            
            # Transition to open if in half-open state
            if self.state.state == CircuitState.HALF_OPEN:
                await self._open_circuit(current_time)
    
    async def _should_open_circuit(self) -> bool:
        """Check if circuit should be opened."""
        if self.state.total_calls < self.config.minimum_throughput:
            return False
        
        # Check absolute failure count threshold
        if self.state.failure_count >= self.config.failure_threshold:
            return True
        
        # Check failure rate (percentage of failures)
        failure_rate = self.state.failure_count / self.state.total_calls
        # Open circuit if failure rate exceeds 50%
        if failure_rate >= 0.5:
            return True
        
        # Check slow call rate
        if self.state.total_calls > 0:
            slow_call_rate = self.state.slow_calls / self.state.total_calls
            if slow_call_rate >= self.config.slow_call_rate_threshold:
                return True
        
        return False
    
    async def _open_circuit(self, current_time: float):
        """Open the circuit."""
        self.state.state = CircuitState.OPEN
        self.state.last_state_change = current_time
        
        logger.warning(
            "Circuit breaker opened",
            name=self.name,
            failure_count=self.state.failure_count,
            total_calls=self.state.total_calls
        )
        
        # Persist state to Redis
        await self._persist_state()
    
    async def _half_open_circuit(self, current_time: float):
        """Transition to half-open state."""
        self.state.state = CircuitState.HALF_OPEN
        self.state.last_state_change = current_time
        self.state.total_calls = 0  # Reset for testing
        
        logger.info(
            "Circuit breaker half-opened",
            name=self.name
        )
        
        await self._persist_state()
    
    async def _close_circuit(self, current_time: float):
        """Close the circuit."""
        self.state.state = CircuitState.CLOSED
        self.state.last_state_change = current_time
        self.state.failure_count = 0
        self.state.success_count = 0
        self.state.total_calls = 0
        self.state.slow_calls = 0
        
        logger.info(
            "Circuit breaker closed",
            name=self.name
        )
        
        await self._persist_state()
    
    async def _persist_state(self):
        """Persist circuit breaker state to Redis."""
        try:
            state_data = {
                "state": self.state.state.value,
                "failure_count": self.state.failure_count,
                "success_count": self.state.success_count,
                "last_failure_time": self.state.last_failure_time,
                "last_state_change": self.state.last_state_change,
                "total_calls": self.state.total_calls,
                "slow_calls": self.state.slow_calls
            }
            
            await redis_manager.set_json(
                f"circuit_breaker:{self.name}",
                state_data,
                ttl=3600  # 1 hour
            )
            
        except Exception as e:
            logger.error(
                "Failed to persist circuit breaker state",
                name=self.name,
                error=str(e)
            )
    
    async def get_state_info(self) -> Dict[str, Any]:
        """Get current circuit breaker state information."""
        return {
            "name": self.name,
            "state": self.state.state.value,
            "failure_count": self.state.failure_count,
            "success_count": self.state.success_count,
            "total_calls": self.state.total_calls,
            "slow_calls": self.state.slow_calls,
            "consecutive_successes": self.state.consecutive_successes,
            "last_failure_time": self.state.last_failure_time,
            "last_state_change": self.state.last_state_change,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "timeout": self.config.timeout,
                "reset_timeout": self.config.reset_timeout,
                "slow_call_threshold": self.config.slow_call_threshold
            }
        }


class CircuitBreakerManager:
    """Manager for multiple circuit breakers."""
    
    def __init__(self):
        self.breakers: Dict[str, CircuitBreaker] = {}
        self.default_config = CircuitBreakerConfig(
            failure_threshold=settings.circuit_breaker_failure_threshold,
            timeout=settings.circuit_breaker_timeout,
            reset_timeout=settings.circuit_breaker_reset_timeout
        )
    
    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create circuit breaker for service."""
        if name not in self.breakers:
            breaker_config = config or self.default_config
            self.breakers[name] = CircuitBreaker(name, breaker_config)
        
        return self.breakers[name]
    
    async def call_with_circuit_breaker(
        self,
        service_name: str,
        func: Callable[..., Awaitable[Any]],
        *args,
        **kwargs
    ) -> Any:
        """Execute function with circuit breaker protection."""
        circuit_breaker = self.get_circuit_breaker(service_name)
        return await circuit_breaker.call(func, *args, **kwargs)
    
    async def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get state of all circuit breakers."""
        states = {}
        for name, breaker in self.breakers.items():
            states[name] = await breaker.get_state_info()
        return states
    
    async def reset_circuit_breaker(self, name: str) -> bool:
        """Reset circuit breaker to closed state (admin function)."""
        if name in self.breakers:
            breaker = self.breakers[name]
            async with breaker._lock:
                breaker.state = CircuitBreakerState()
                await breaker._persist_state()
            
            logger.info("Circuit breaker reset", name=name)
            return True
        
        return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for circuit breaker system."""
        total_breakers = len(self.breakers)
        open_breakers = 0
        half_open_breakers = 0
        
        for breaker in self.breakers.values():
            if breaker.state.state == CircuitState.OPEN:
                open_breakers += 1
            elif breaker.state.state == CircuitState.HALF_OPEN:
                half_open_breakers += 1
        
        return {
            "total_breakers": total_breakers,
            "open_breakers": open_breakers,
            "half_open_breakers": half_open_breakers,
            "closed_breakers": total_breakers - open_breakers - half_open_breakers,
            "health": "healthy" if open_breakers == 0 else "degraded"
        }