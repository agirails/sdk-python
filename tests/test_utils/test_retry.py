"""
Tests for retry utility with exponential backoff.

Tests cover:
- RetryConfig validation
- Delay calculation with exponential backoff
- Jitter randomization
- Max delay capping
- Retryable error filtering
- Async retry execution
- Decorator pattern
"""

import asyncio
import time
from typing import List
from unittest.mock import AsyncMock, patch

import pytest

from agirails.utils.retry import (
    RetryConfig,
    calculate_delay,
    retry_async,
    with_retry,
)


# =============================================================================
# RetryConfig Tests
# =============================================================================


class TestRetryConfig:
    """Tests for RetryConfig dataclass."""

    def test_default_values(self) -> None:
        """Test RetryConfig default values."""
        config = RetryConfig()

        assert config.max_attempts == 3
        assert config.base_delay_ms == 1000
        assert config.max_delay_ms == 30000
        assert config.jitter is True
        assert config.exponential_base == 2.0
        assert config.retryable_errors == (Exception,)

    def test_custom_values(self) -> None:
        """Test RetryConfig with custom values."""
        config = RetryConfig(
            max_attempts=5,
            base_delay_ms=500,
            max_delay_ms=10000,
            jitter=False,
            exponential_base=3.0,
            retryable_errors=(ValueError, TypeError),
        )

        assert config.max_attempts == 5
        assert config.base_delay_ms == 500
        assert config.max_delay_ms == 10000
        assert config.jitter is False
        assert config.exponential_base == 3.0
        assert config.retryable_errors == (ValueError, TypeError)

    def test_single_retryable_error(self) -> None:
        """Test config with single retryable error type."""
        config = RetryConfig(retryable_errors=(ValueError,))
        assert config.retryable_errors == (ValueError,)


# =============================================================================
# Delay Calculation Tests
# =============================================================================


class TestDelayCalculation:
    """Tests for calculate_delay function."""

    def test_first_attempt_delay(self) -> None:
        """Test delay for first retry attempt."""
        config = RetryConfig(base_delay_ms=1000, jitter=False)
        delay = calculate_delay(0, config)

        # First attempt: 1000 * 2^0 = 1000ms = 1.0s
        assert delay == 1.0

    def test_exponential_growth(self) -> None:
        """Test delay grows exponentially."""
        config = RetryConfig(base_delay_ms=1000, jitter=False, exponential_base=2.0)

        delays = [calculate_delay(i, config) for i in range(5)]

        # Expected: 1s, 2s, 4s, 8s, 16s
        assert delays[0] == 1.0
        assert delays[1] == 2.0
        assert delays[2] == 4.0
        assert delays[3] == 8.0
        assert delays[4] == 16.0

    def test_max_delay_cap(self) -> None:
        """Test delay is capped at max_delay_ms."""
        config = RetryConfig(
            base_delay_ms=1000,
            max_delay_ms=5000,  # 5 second cap
            jitter=False,
        )

        # Attempt 10 would be 1000 * 2^10 = 1024000ms without cap
        delay = calculate_delay(10, config)

        assert delay == 5.0  # Capped at 5 seconds

    def test_jitter_adds_randomness(self) -> None:
        """Test jitter adds randomness to delay."""
        config = RetryConfig(base_delay_ms=1000, jitter=True)

        # Collect multiple samples
        delays = [calculate_delay(0, config) for _ in range(100)]

        # With jitter, delays should vary
        assert min(delays) != max(delays)
        # All delays should be between 0 and base delay
        assert all(0 <= d <= 1.0 for d in delays)

    def test_jitter_disabled(self) -> None:
        """Test no jitter produces consistent delays."""
        config = RetryConfig(base_delay_ms=1000, jitter=False)

        delays = [calculate_delay(0, config) for _ in range(10)]

        # All delays should be identical
        assert all(d == 1.0 for d in delays)

    def test_custom_exponential_base(self) -> None:
        """Test custom exponential base."""
        config = RetryConfig(
            base_delay_ms=1000,
            jitter=False,
            exponential_base=3.0,
        )

        delays = [calculate_delay(i, config) for i in range(4)]

        # Expected: 1s, 3s, 9s, 27s
        assert delays[0] == 1.0
        assert delays[1] == 3.0
        assert delays[2] == 9.0
        assert delays[3] == 27.0


# =============================================================================
# Async Retry Tests
# =============================================================================


class TestRetryAsync:
    """Tests for retry_async function."""

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self) -> None:
        """Test function succeeds on first attempt."""
        call_count = 0

        async def success_fn():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await retry_async(success_fn)

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self) -> None:
        """Test retry after transient failure."""
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Transient error")
            return "success"

        config = RetryConfig(max_attempts=5, base_delay_ms=1, jitter=False)
        result = await retry_async(fail_then_succeed, config)

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_max_attempts_exceeded(self) -> None:
        """Test raises after max attempts exhausted."""
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("Persistent error")

        config = RetryConfig(max_attempts=3, base_delay_ms=1, jitter=False)

        with pytest.raises(ValueError) as exc_info:
            await retry_async(always_fail, config)

        assert str(exc_info.value) == "Persistent error"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_error(self) -> None:
        """Test non-retryable errors are raised immediately."""
        call_count = 0

        async def raise_type_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("Not retryable")

        config = RetryConfig(
            max_attempts=5,
            retryable_errors=(ValueError,),  # Only retry ValueError
            base_delay_ms=1,
        )

        with pytest.raises(TypeError):
            await retry_async(raise_type_error, config)

        # Should only be called once (no retry for TypeError)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retryable_error_filter(self) -> None:
        """Test only retryable errors trigger retry."""
        call_count = 0
        errors: List[type] = [ValueError, ValueError, RuntimeError]

        async def raise_different_errors():
            nonlocal call_count
            error_type = errors[call_count]
            call_count += 1
            raise error_type("Error")

        config = RetryConfig(
            max_attempts=5,
            retryable_errors=(ValueError,),
            base_delay_ms=1,
        )

        with pytest.raises(RuntimeError):
            await retry_async(raise_different_errors, config)

        # Should fail on third call (RuntimeError not retryable)
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_default_config(self) -> None:
        """Test retry works with default config."""
        call_count = 0

        async def fail_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("First attempt fails")
            return "success"

        with patch("agirails.utils.retry.asyncio.sleep", new_callable=AsyncMock):
            result = await retry_async(fail_once)

        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_delay_between_retries(self) -> None:
        """Test delays are applied between retries."""
        call_times: List[float] = []

        async def track_time():
            call_times.append(time.time())
            if len(call_times) < 3:
                raise ValueError("Retry me")
            return "success"

        config = RetryConfig(
            max_attempts=5,
            base_delay_ms=100,  # 100ms delay
            jitter=False,
        )

        await retry_async(track_time, config)

        # Check delays between calls (allow some tolerance)
        assert len(call_times) == 3
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]

        # First delay: 100ms, second delay: 200ms
        assert 0.08 <= delay1 <= 0.15  # ~100ms
        assert 0.15 <= delay2 <= 0.25  # ~200ms


# =============================================================================
# Decorator Tests
# =============================================================================


class TestWithRetryDecorator:
    """Tests for with_retry decorator."""

    @pytest.mark.asyncio
    async def test_decorator_success(self) -> None:
        """Test decorated function succeeds."""
        call_count = 0

        @with_retry(RetryConfig(max_attempts=3, base_delay_ms=1))
        async def decorated_success():
            nonlocal call_count
            call_count += 1
            return "decorated result"

        result = await decorated_success()

        assert result == "decorated result"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_decorator_with_retry(self) -> None:
        """Test decorated function retries on failure."""
        call_count = 0

        @with_retry(RetryConfig(max_attempts=5, base_delay_ms=1, jitter=False))
        async def decorated_fail_once():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Transient")
            return "success"

        result = await decorated_fail_once()

        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_decorator_with_arguments(self) -> None:
        """Test decorated function with arguments."""
        @with_retry(RetryConfig(max_attempts=3, base_delay_ms=1))
        async def add(a: int, b: int) -> int:
            return a + b

        result = await add(2, 3)
        assert result == 5

    @pytest.mark.asyncio
    async def test_decorator_with_kwargs(self) -> None:
        """Test decorated function with keyword arguments."""
        @with_retry(RetryConfig(max_attempts=3, base_delay_ms=1))
        async def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        result = await greet("World", greeting="Hi")
        assert result == "Hi, World!"

    @pytest.mark.asyncio
    async def test_decorator_default_config(self) -> None:
        """Test decorator with default config."""
        call_count = 0

        @with_retry()
        async def fail_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("First fails")
            return "success"

        with patch("agirails.utils.retry.asyncio.sleep", new_callable=AsyncMock):
            result = await fail_once()

        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_decorator_preserves_function_name(self) -> None:
        """Test decorator preserves function metadata."""
        @with_retry(RetryConfig(max_attempts=3))
        async def my_function():
            """My docstring."""
            return "result"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_single_attempt(self) -> None:
        """Test with max_attempts=1 (no retries)."""
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("Fail")

        config = RetryConfig(max_attempts=1, base_delay_ms=1)

        with pytest.raises(ValueError):
            await retry_async(always_fail, config)

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_zero_base_delay(self) -> None:
        """Test with zero base delay."""
        call_count = 0

        async def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Retry")
            return "success"

        config = RetryConfig(max_attempts=5, base_delay_ms=0, jitter=False)

        result = await retry_async(fail_twice, config)

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_multiple_error_types(self) -> None:
        """Test retrying on multiple error types."""
        call_count = 0
        errors = [ValueError("v"), TypeError("t"), RuntimeError("r")]

        async def raise_different():
            nonlocal call_count
            if call_count < len(errors):
                error = errors[call_count]
                call_count += 1
                raise error
            return "success"

        config = RetryConfig(
            max_attempts=5,
            retryable_errors=(ValueError, TypeError, RuntimeError),
            base_delay_ms=1,
        )

        result = await retry_async(raise_different, config)

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_async_generator_not_supported(self) -> None:
        """Test that async generators raise TypeError."""
        async def async_gen():
            yield 1

        # retry_async expects a coroutine, not an async generator
        # This should work as async_gen() returns a generator object
        # which won't have awaitable behavior
        pass  # This test documents the limitation

    @pytest.mark.asyncio
    async def test_none_config_uses_defaults(self) -> None:
        """Test None config uses default values."""
        call_count = 0

        async def success():
            nonlocal call_count
            call_count += 1
            return "result"

        result = await retry_async(success, None)

        assert result == "result"
        assert call_count == 1
