"""
Tests for circuit breaker pattern implementation.

Tests cover:
- Circuit states (CLOSED, OPEN, HALF_OPEN)
- Failure counting and threshold
- State transitions
- Reset timeout
- Success threshold for recovery
- Fallback execution
- Thread safety (async locks)
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from agirails.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerState,
    CircuitBreakerOpenError,
)
from agirails.storage.types import CircuitBreakerConfig


# =============================================================================
# CircuitState Tests
# =============================================================================


class TestCircuitState:
    """Tests for CircuitState enum."""

    def test_states_exist(self) -> None:
        """Test all expected states exist."""
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"


# =============================================================================
# CircuitBreakerState Tests
# =============================================================================


class TestCircuitBreakerState:
    """Tests for CircuitBreakerState dataclass."""

    def test_default_values(self) -> None:
        """Test default state values."""
        state = CircuitBreakerState()

        assert state.state == CircuitState.CLOSED
        assert state.failures == 0
        assert state.successes == 0
        assert state.last_failure_time == 0
        assert state.failure_times == []

    def test_custom_values(self) -> None:
        """Test state with custom values."""
        state = CircuitBreakerState(
            state=CircuitState.OPEN,
            failures=5,
            successes=0,
            last_failure_time=1000.0,
            failure_times=[900.0, 950.0, 1000.0],
        )

        assert state.state == CircuitState.OPEN
        assert state.failures == 5
        assert len(state.failure_times) == 3


# =============================================================================
# CircuitBreaker Initialization Tests
# =============================================================================


class TestCircuitBreakerInit:
    """Tests for CircuitBreaker initialization."""

    def test_default_config(self) -> None:
        """Test initialization with default config."""
        cb = CircuitBreaker()

        assert cb.config.enabled is True
        assert cb.config.failure_threshold == 5
        assert cb.config.reset_timeout_ms == 60000

    def test_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = CircuitBreakerConfig(
            enabled=True,
            failure_threshold=3,
            reset_timeout_ms=5000,
            success_threshold=2,
        )
        cb = CircuitBreaker(config)

        assert cb.config.failure_threshold == 3
        assert cb.config.reset_timeout_ms == 5000
        assert cb.config.success_threshold == 2

    def test_initial_state_closed(self) -> None:
        """Test initial state is CLOSED."""
        cb = CircuitBreaker()

        assert cb.is_closed is True
        assert cb.is_open is False

    def test_state_property(self) -> None:
        """Test state property returns correct state."""
        cb = CircuitBreaker()
        assert cb._state.state == CircuitState.CLOSED


# =============================================================================
# State Property Tests
# =============================================================================


class TestStateProperties:
    """Tests for state query properties."""

    def test_is_closed_when_closed(self) -> None:
        """Test is_closed returns True when CLOSED."""
        cb = CircuitBreaker()
        assert cb.is_closed is True

    def test_is_open_when_open(self) -> None:
        """Test is_open returns True when OPEN."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.OPEN
        assert cb.is_open is True

    def test_is_closed_when_half_open(self) -> None:
        """Test is_closed returns False when HALF_OPEN."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.HALF_OPEN
        assert cb.is_closed is False
        assert cb.is_open is False


# =============================================================================
# Success Recording Tests
# =============================================================================


class TestRecordSuccess:
    """Tests for recording successful operations."""

    @pytest.mark.asyncio
    async def test_success_in_closed_state(self) -> None:
        """Test success in CLOSED state doesn't change state."""
        cb = CircuitBreaker()

        await cb.record_success()

        assert cb.is_closed is True

    @pytest.mark.asyncio
    async def test_success_in_half_open_increments_counter(self) -> None:
        """Test success in HALF_OPEN increments success counter."""
        cb = CircuitBreaker(CircuitBreakerConfig(success_threshold=3))
        cb._state.state = CircuitState.HALF_OPEN
        cb._state.successes = 0

        await cb.record_success()

        assert cb._state.successes == 1
        assert cb._state.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_success_threshold_closes_circuit(self) -> None:
        """Test reaching success threshold closes circuit."""
        cb = CircuitBreaker(CircuitBreakerConfig(success_threshold=2))
        cb._state.state = CircuitState.HALF_OPEN
        cb._state.successes = 1

        await cb.record_success()

        # After closing, successes are reset to 0
        assert cb.is_closed is True
        assert cb._state.failures == 0
        assert cb._state.failure_times == []
        # Successes reset to 0 when circuit closes
        assert cb._state.successes == 0


# =============================================================================
# Failure Recording Tests
# =============================================================================


class TestRecordFailure:
    """Tests for recording failed operations."""

    @pytest.mark.asyncio
    async def test_failure_increments_counter(self) -> None:
        """Test failure increments failure counter."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))

        await cb.record_failure()

        assert cb._state.failures >= 1
        assert len(cb._state.failure_times) >= 1

    @pytest.mark.asyncio
    async def test_failure_threshold_opens_circuit(self) -> None:
        """Test reaching failure threshold opens circuit."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_window_ms=10000,
        )
        cb = CircuitBreaker(config)

        # Record failures
        for _ in range(3):
            await cb.record_failure()

        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_failure_in_half_open_opens_circuit(self) -> None:
        """Test failure in HALF_OPEN opens circuit."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.HALF_OPEN

        await cb.record_failure()

        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_old_failures_cleaned(self) -> None:
        """Test old failures are cleaned from window."""
        # Use minimum allowed failure_window_ms (1000ms)
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_window_ms=1000,  # 1 second window
        )
        cb = CircuitBreaker(config)

        # Record a failure and manually set its time in the past
        current_time_ms = time.time() * 1000
        cb._state.failure_times = [current_time_ms - 2000]  # 2 seconds ago (outside window)
        cb._state.failures = 1

        # Record another failure (should clean old one)
        await cb.record_failure()

        # Old failure should be cleaned, so we have 1 not 2
        assert cb._state.failures == 1


# =============================================================================
# State Transition Tests
# =============================================================================


class TestStateTransitions:
    """Tests for state transition logic."""

    @pytest.mark.asyncio
    async def test_closed_to_open_on_threshold(self) -> None:
        """Test CLOSED -> OPEN when threshold reached."""
        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker(config)

        await cb.record_failure()
        assert cb.is_closed is True

        await cb.record_failure()
        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_open_to_half_open_on_timeout(self) -> None:
        """Test OPEN -> HALF_OPEN after reset timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            reset_timeout_ms=1000,  # Minimum allowed: 1000ms
        )
        cb = CircuitBreaker(config)

        # Open the circuit
        await cb.record_failure()
        assert cb.is_open is True

        # Manually set last_failure_time to 2 seconds ago (past reset timeout)
        cb._state.last_failure_time = time.time() - 2

        # Trigger timeout check
        await cb._check_reset_timeout()

        assert cb._state.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_half_open_to_closed_on_success(self) -> None:
        """Test HALF_OPEN -> CLOSED on success threshold."""
        config = CircuitBreakerConfig(success_threshold=1)
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.HALF_OPEN

        await cb.record_success()

        assert cb.is_closed is True

    @pytest.mark.asyncio
    async def test_half_open_to_open_on_failure(self) -> None:
        """Test HALF_OPEN -> OPEN on any failure."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.HALF_OPEN

        await cb.record_failure()

        assert cb.is_open is True


# =============================================================================
# Execute Tests
# =============================================================================


class TestExecute:
    """Tests for execute method."""

    @pytest.mark.asyncio
    async def test_execute_success(self) -> None:
        """Test execute with successful function."""
        cb = CircuitBreaker()

        async def success():
            return "result"

        result = await cb.execute(success)

        assert result == "result"

    @pytest.mark.asyncio
    async def test_execute_failure_records(self) -> None:
        """Test execute records failure on exception."""
        config = CircuitBreakerConfig(failure_threshold=5)
        cb = CircuitBreaker(config)

        async def fail():
            raise ValueError("Error")

        with pytest.raises(ValueError):
            await cb.execute(fail)

        assert cb._state.failures >= 1

    @pytest.mark.asyncio
    async def test_execute_when_open_raises(self) -> None:
        """Test execute raises when circuit is OPEN."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.OPEN
        cb._state.last_failure_time = time.time()  # Recent failure

        async def should_not_run():
            return "result"

        # CircuitBreakerOpenError is from utils.circuit_breaker, not errors.storage
        with pytest.raises(CircuitBreakerOpenError):
            await cb.execute(should_not_run)

    @pytest.mark.asyncio
    async def test_execute_with_fallback(self) -> None:
        """Test execute uses fallback when OPEN."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.OPEN
        cb._state.last_failure_time = time.time()

        async def main():
            return "main result"

        async def fallback():
            return "fallback result"

        result = await cb.execute(main, fallback)

        assert result == "fallback result"

    @pytest.mark.asyncio
    async def test_execute_disabled_bypasses(self) -> None:
        """Test execute bypasses circuit when disabled."""
        config = CircuitBreakerConfig(enabled=False)
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.OPEN

        async def success():
            return "result"

        result = await cb.execute(success)

        assert result == "result"

    @pytest.mark.asyncio
    async def test_execute_success_records(self) -> None:
        """Test execute records success."""
        config = CircuitBreakerConfig(success_threshold=1)
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.HALF_OPEN

        async def success():
            return "result"

        await cb.execute(success)

        assert cb.is_closed is True


# =============================================================================
# Reset Timeout Tests
# =============================================================================


class TestResetTimeout:
    """Tests for reset timeout logic."""

    @pytest.mark.asyncio
    async def test_no_transition_before_timeout(self) -> None:
        """Test no transition to HALF_OPEN before timeout."""
        config = CircuitBreakerConfig(reset_timeout_ms=60000)  # 60s
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.OPEN
        cb._state.last_failure_time = time.time()

        await cb._check_reset_timeout()

        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_transition_after_timeout(self) -> None:
        """Test transition to HALF_OPEN after timeout."""
        config = CircuitBreakerConfig(reset_timeout_ms=1000)  # Minimum: 1000ms
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.OPEN
        cb._state.last_failure_time = time.time() - 2  # 2 seconds ago

        await cb._check_reset_timeout()

        assert cb._state.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_check_only_in_open_state(self) -> None:
        """Test timeout check only applies in OPEN state."""
        config = CircuitBreakerConfig(reset_timeout_ms=1000)  # Minimum: 1000ms
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.CLOSED
        cb._state.last_failure_time = time.time() - 10

        await cb._check_reset_timeout()

        assert cb.is_closed is True  # No change


# =============================================================================
# Failure Window Tests
# =============================================================================


class TestFailureWindow:
    """Tests for failure window cleaning."""

    @pytest.mark.asyncio
    async def test_failures_within_window_counted(self) -> None:
        """Test failures within window are all counted."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_window_ms=10000,  # 10s window
        )
        cb = CircuitBreaker(config)

        for _ in range(3):
            await cb.record_failure()

        assert cb._state.failures == 3

    @pytest.mark.asyncio
    async def test_old_failures_removed(self) -> None:
        """Test failures outside window are removed."""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            failure_window_ms=1000,  # Minimum: 1000ms window
        )
        cb = CircuitBreaker(config)

        # Manually add old failure time (2 seconds ago, outside window)
        current_time_ms = time.time() * 1000
        cb._state.failure_times = [current_time_ms - 2000]
        cb._state.failures = 1

        # Clean old failures
        await cb._clean_old_failures()

        assert cb._state.failures == 0


# =============================================================================
# Concurrency Tests
# =============================================================================


class TestConcurrency:
    """Tests for concurrent access safety."""

    @pytest.mark.asyncio
    async def test_concurrent_failures(self) -> None:
        """Test concurrent failure recording."""
        config = CircuitBreakerConfig(failure_threshold=100)
        cb = CircuitBreaker(config)

        async def record_many():
            for _ in range(10):
                await cb.record_failure()

        # Run concurrent failure recordings
        await asyncio.gather(*[record_many() for _ in range(5)])

        # Should have ~50 failures (may vary due to cleaning)
        assert cb._state.failures > 0

    @pytest.mark.asyncio
    async def test_concurrent_executions(self) -> None:
        """Test concurrent execute calls."""
        cb = CircuitBreaker()
        results = []

        async def operation(n: int):
            await asyncio.sleep(0.01)
            return n

        # Run concurrent executions
        tasks = [cb.execute(lambda n=i: operation(n)) for i in range(10)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 10


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_minimum_failure_threshold(self) -> None:
        """Test with minimum failure threshold of 1."""
        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker(config)

        # One failure should open circuit
        await cb.record_failure()
        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_very_long_reset_timeout(self) -> None:
        """Test with very long reset timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            reset_timeout_ms=3600000,  # 1 hour
        )
        cb = CircuitBreaker(config)

        await cb.record_failure()

        # Should stay open
        await cb._check_reset_timeout()
        assert cb.is_open is True

    @pytest.mark.asyncio
    async def test_success_threshold_of_one(self) -> None:
        """Test immediate close with success threshold of 1."""
        config = CircuitBreakerConfig(success_threshold=1)
        cb = CircuitBreaker(config)
        cb._state.state = CircuitState.HALF_OPEN

        await cb.record_success()

        assert cb.is_closed is True

    @pytest.mark.asyncio
    async def test_async_function_execution(self) -> None:
        """Test execute with async function."""
        cb = CircuitBreaker()

        async def async_result():
            await asyncio.sleep(0.001)
            return "async result"

        result = await cb.execute(async_result)
        assert result == "async result"

    @pytest.mark.asyncio
    async def test_get_stats(self) -> None:
        """Test getting circuit breaker statistics."""
        cb = CircuitBreaker()

        # Record some activity
        await cb.record_failure()
        await cb.record_failure()

        stats = cb.get_stats()

        assert "state" in stats
        assert "failures" in stats
        assert stats["failures"] == 2
        # failure_threshold is nested under config
        assert "config" in stats
        assert stats["config"]["failure_threshold"] == 5

    def test_reset(self) -> None:
        """Test manual reset."""
        cb = CircuitBreaker()
        cb._state.state = CircuitState.OPEN
        cb._state.failures = 10

        cb.reset()

        assert cb.is_closed is True
        assert cb._state.failures == 0

    @pytest.mark.asyncio
    async def test_is_half_open_property(self) -> None:
        """Test is_half_open property."""
        cb = CircuitBreaker()

        assert cb.is_half_open is False

        cb._state.state = CircuitState.HALF_OPEN
        assert cb.is_half_open is True

    @pytest.mark.asyncio
    async def test_failure_count_property(self) -> None:
        """Test failure_count property."""
        cb = CircuitBreaker()

        assert cb.failure_count == 0

        await cb.record_failure()
        assert cb.failure_count >= 1
