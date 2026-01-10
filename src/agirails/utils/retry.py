"""
Retry Utilities for AGIRAILS SDK.

Provides exponential backoff with jitter for transient failures.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from functools import wraps
from typing import (
    Awaitable,
    Callable,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior.

    Example:
        ```python
        config = RetryConfig(
            max_attempts=5,
            base_delay_ms=1000,
            jitter=True,
            retryable_errors=(ConnectionError, TimeoutError),
        )
        ```
    """

    max_attempts: int = 3
    """Maximum number of retry attempts."""

    base_delay_ms: int = 1000
    """Base delay in milliseconds for exponential backoff."""

    max_delay_ms: int = 30000
    """Maximum delay in milliseconds (cap for exponential growth)."""

    jitter: bool = True
    """Whether to add random jitter to delays."""

    exponential_base: float = 2.0
    """Base for exponential backoff calculation."""

    retryable_errors: Tuple[Type[Exception], ...] = field(
        default_factory=lambda: (Exception,)
    )
    """Tuple of exception types that should trigger a retry."""


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """
    Calculate delay with exponential backoff and optional jitter.

    Args:
        attempt: Zero-based attempt number (0 = first retry)
        config: Retry configuration

    Returns:
        Delay in seconds
    """
    # Exponential backoff: base_delay * (exponential_base ^ attempt)
    delay_ms = config.base_delay_ms * (config.exponential_base ** attempt)

    # Cap at max delay
    delay_ms = min(delay_ms, config.max_delay_ms)

    if config.jitter:
        # Full jitter: random value between 0 and calculated delay
        # This prevents thundering herd problem
        delay_ms = random.uniform(0, delay_ms)

    # Convert to seconds
    return delay_ms / 1000


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    config: Optional[RetryConfig] = None,
) -> T:
    """
    Execute async function with retry logic.

    Args:
        fn: Async function to execute (no arguments)
        config: Retry configuration (uses defaults if None)

    Returns:
        Result of the function

    Raises:
        Last exception if all retries fail

    Example:
        ```python
        async def fetch_data():
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return await response.json()

        result = await retry_async(
            fetch_data,
            RetryConfig(max_attempts=5, retryable_errors=(aiohttp.ClientError,))
        )
        ```
    """
    config = config or RetryConfig()
    last_error: Optional[Exception] = None

    for attempt in range(config.max_attempts):
        try:
            return await fn()
        except config.retryable_errors as e:
            last_error = e

            # Don't delay after last attempt
            if attempt < config.max_attempts - 1:
                delay = calculate_delay(attempt, config)
                await asyncio.sleep(delay)

    # All attempts exhausted
    if last_error is not None:
        raise last_error

    # This should never happen, but just in case
    raise RuntimeError("Retry exhausted without error")


def with_retry(
    config: Optional[RetryConfig] = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator for adding retry logic to async functions.

    Args:
        config: Retry configuration (uses defaults if None)

    Returns:
        Decorator function

    Example:
        ```python
        @with_retry(RetryConfig(max_attempts=5))
        async def fetch_data(url: str) -> dict:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return await response.json()

        # Will retry up to 5 times on any exception
        data = await fetch_data("https://api.example.com/data")
        ```
    """
    def decorator(
        fn: Callable[..., Awaitable[T]],
    ) -> Callable[..., Awaitable[T]]:
        @wraps(fn)
        async def wrapper(*args: object, **kwargs: object) -> T:
            return await retry_async(
                lambda: fn(*args, **kwargs),
                config,
            )
        return wrapper
    return decorator


class RetryableError(Exception):
    """
    Base class for errors that should be retried.

    Subclass this to create custom retryable errors.
    """

    pass


class TransientError(RetryableError):
    """
    Transient error that may succeed on retry.

    Examples: network timeouts, rate limits, temporary service unavailability.
    """

    pass


class PermanentError(Exception):
    """
    Permanent error that should NOT be retried.

    Examples: authentication failures, validation errors, not found.
    """

    pass
