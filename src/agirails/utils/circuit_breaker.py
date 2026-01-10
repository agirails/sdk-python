"""
Circuit Breaker Pattern for AGIRAILS SDK.

Provides gateway health tracking to prevent retry amplification
and protect against cascading failures.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Awaitable,
    Callable,
    List,
    Optional,
    TypeVar,
)

from agirails.storage.types import CircuitBreakerConfig

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    """Normal operation - requests are allowed."""

    OPEN = "open"
    """Circuit is open - requests are blocked."""

    HALF_OPEN = "half_open"
    """Testing recovery - limited requests allowed."""


@dataclass
class CircuitBreakerState:
    """Internal state of circuit breaker."""

    state: CircuitState = CircuitState.CLOSED
    """Current circuit state."""

    failures: int = 0
    """Current failure count within window."""

    successes: int = 0
    """Success count in half-open state."""

    last_failure_time: float = 0
    """Timestamp of last failure (time.time())."""

    failure_times: List[float] = field(default_factory=list)
    """Timestamps of failures within window (in ms)."""


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and blocking requests."""

    def __init__(
        self,
        message: str = "Circuit breaker is open",
        *,
        reset_at: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.reset_at = reset_at


class CircuitBreaker:
    """
    Circuit breaker for gateway health tracking.

    Implements the circuit breaker pattern to prevent cascading failures
    and retry amplification when a gateway is unhealthy.

    States:
    - CLOSED: Normal operation, requests allowed
    - OPEN: Circuit tripped, requests blocked
    - HALF_OPEN: Testing if service recovered

    Example:
        ```python
        from agirails.storage.types import CircuitBreakerConfig

        config = CircuitBreakerConfig(
            failure_threshold=5,
            reset_timeout_ms=60000,
        )
        breaker = CircuitBreaker(config)

        async def fetch_data():
            async with aiohttp.ClientSession() as session:
                return await session.get(url)

        try:
            result = await breaker.execute(fetch_data)
        except CircuitBreakerOpenError:
            # Circuit is open, use fallback
            result = get_cached_data()
        ```
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None) -> None:
        """
        Initialize circuit breaker.

        Args:
            config: Circuit breaker configuration (uses defaults if None)
        """
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state.state

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (blocking requests)."""
        return self._state.state == CircuitState.OPEN

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state.state == CircuitState.CLOSED

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self._state.state == CircuitState.HALF_OPEN

    @property
    def failure_count(self) -> int:
        """Get current failure count within window."""
        return self._state.failures

    async def _check_reset_timeout(self) -> None:
        """
        Check if enough time has passed to attempt reset.

        Transitions from OPEN to HALF_OPEN if reset timeout has elapsed.
        """
        if self._state.state != CircuitState.OPEN:
            return

        elapsed_ms = (time.time() - self._state.last_failure_time) * 1000
        if elapsed_ms >= self.config.reset_timeout_ms:
            self._state.state = CircuitState.HALF_OPEN
            self._state.successes = 0

    async def _clean_old_failures(self) -> None:
        """
        Remove failures outside the failure window.

        Only counts failures within the configured time window.
        """
        current_time_ms = time.time() * 1000
        window_start = current_time_ms - self.config.failure_window_ms

        self._state.failure_times = [
            t for t in self._state.failure_times if t > window_start
        ]
        self._state.failures = len(self._state.failure_times)

    async def record_success(self) -> None:
        """
        Record a successful operation.

        In HALF_OPEN state, counts successes toward recovery.
        Once success_threshold is reached, transitions to CLOSED.
        """
        async with self._lock:
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.successes += 1

                if self._state.successes >= self.config.success_threshold:
                    # Recovery confirmed, close circuit
                    self._state.state = CircuitState.CLOSED
                    self._state.failures = 0
                    self._state.failure_times = []
                    self._state.successes = 0

    async def record_failure(self) -> None:
        """
        Record a failed operation.

        Tracks failures within the window. Opens circuit if threshold reached.
        In HALF_OPEN state, immediately reopens circuit on failure.
        """
        async with self._lock:
            current_time_ms = time.time() * 1000
            self._state.failure_times.append(current_time_ms)
            self._state.last_failure_time = time.time()

            # Clean old failures
            await self._clean_old_failures()

            if self._state.state == CircuitState.HALF_OPEN:
                # Any failure in half-open immediately reopens circuit
                self._state.state = CircuitState.OPEN
            elif self._state.failures >= self.config.failure_threshold:
                # Threshold reached, open circuit
                self._state.state = CircuitState.OPEN

    async def execute(
        self,
        fn: Callable[[], Awaitable[T]],
        fallback: Optional[Callable[[], Awaitable[T]]] = None,
    ) -> T:
        """
        Execute function with circuit breaker protection.

        Args:
            fn: Async function to execute
            fallback: Optional fallback function when circuit is open

        Returns:
            Result of fn or fallback

        Raises:
            CircuitBreakerOpenError: If circuit is open and no fallback provided

        Example:
            ```python
            async def fetch():
                return await api.get_data()

            async def cached_fallback():
                return await cache.get_data()

            result = await breaker.execute(fetch, fallback=cached_fallback)
            ```
        """
        if not self.config.enabled:
            # Circuit breaker disabled, pass through
            return await fn()

        # Check if we should transition from OPEN to HALF_OPEN
        async with self._lock:
            await self._check_reset_timeout()

        if self.is_open:
            if fallback is not None:
                return await fallback()

            reset_at = self._state.last_failure_time + (
                self.config.reset_timeout_ms / 1000
            )
            raise CircuitBreakerOpenError(
                "Circuit breaker is open - service unavailable",
                reset_at=reset_at,
            )

        try:
            result = await fn()
            await self.record_success()
            return result
        except Exception:
            await self.record_failure()
            raise

    def reset(self) -> None:
        """
        Manually reset circuit breaker to closed state.

        Use with caution - typically circuit should heal automatically.
        """
        self._state = CircuitBreakerState()

    def get_stats(self) -> dict:
        """
        Get circuit breaker statistics.

        Returns:
            Dictionary with current stats
        """
        return {
            "state": self._state.state.value,
            "failures": self._state.failures,
            "successes": self._state.successes,
            "last_failure_time": self._state.last_failure_time,
            "config": {
                "enabled": self.config.enabled,
                "failure_threshold": self.config.failure_threshold,
                "reset_timeout_ms": self.config.reset_timeout_ms,
                "failure_window_ms": self.config.failure_window_ms,
                "success_threshold": self.config.success_threshold,
            },
        }
