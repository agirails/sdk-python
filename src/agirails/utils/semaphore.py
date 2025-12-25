"""
Concurrency utilities for AGIRAILS SDK.

Provides Semaphore and RateLimiter for controlling concurrent operations.
These are critical for security (MEDIUM-4) to prevent resource exhaustion.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Deque, Optional


class Semaphore:
    """
    Async semaphore for limiting concurrent operations.

    Security Note (MEDIUM-4): Use this to limit concurrent processing
    and prevent resource exhaustion attacks.

    Example:
        >>> semaphore = Semaphore(limit=5)
        >>> async with semaphore:
        ...     await process_job()
        >>> # Or manually:
        >>> await semaphore.acquire()
        >>> try:
        ...     await process_job()
        ... finally:
        ...     semaphore.release()
    """

    def __init__(self, limit: int) -> None:
        """
        Initialize Semaphore.

        Args:
            limit: Maximum number of concurrent operations.

        Raises:
            ValueError: If limit is not positive.
        """
        if limit <= 0:
            raise ValueError("Semaphore limit must be positive")

        self._limit = limit
        self._value = limit
        self._waiters: Deque[asyncio.Future[None]] = deque()
        self._lock = asyncio.Lock()

    @property
    def available_permits(self) -> int:
        """Get number of available permits."""
        return self._value

    @property
    def queue_length(self) -> int:
        """Get number of waiters in queue."""
        return len(self._waiters)

    async def acquire(self, timeout_ms: Optional[int] = None) -> bool:
        """
        Acquire a permit.

        Args:
            timeout_ms: Optional timeout in milliseconds.

        Returns:
            True if permit acquired, False if timed out.
        """
        async with self._lock:
            if self._value > 0:
                self._value -= 1
                return True

            # Need to wait for a permit
            waiter: asyncio.Future[None] = asyncio.get_event_loop().create_future()
            self._waiters.append(waiter)

        try:
            if timeout_ms is not None:
                timeout_s = timeout_ms / 1000
                await asyncio.wait_for(waiter, timeout=timeout_s)
            else:
                await waiter
            return True
        except asyncio.TimeoutError:
            # Remove from waiters if still present
            async with self._lock:
                try:
                    self._waiters.remove(waiter)
                except ValueError:
                    pass
            return False

    def release(self) -> None:
        """Release a permit."""
        # Wake up next waiter if any
        if self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
        else:
            self._value += 1

    async def __aenter__(self) -> "Semaphore":
        """Async context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Async context manager exit."""
        self.release()


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.

    Uses a sliding window algorithm to limit the number of
    requests within a time window.

    Example:
        >>> limiter = RateLimiter(max_requests=100, window_seconds=60)
        >>> if await limiter.acquire():
        ...     await make_request()
        ... else:
        ...     print("Rate limit exceeded")
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        """
        Initialize RateLimiter.

        Args:
            max_requests: Maximum number of requests per window.
            window_seconds: Window duration in seconds.

        Raises:
            ValueError: If parameters are not positive.
        """
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: Deque[float] = deque()
        self._lock = asyncio.Lock()

    @property
    def available(self) -> int:
        """Get number of requests available in current window."""
        self._cleanup()
        return max(0, self._max_requests - len(self._requests))

    def _cleanup(self) -> None:
        """Remove expired timestamps from the window."""
        current_time = time.time()
        cutoff = current_time - self._window_seconds

        while self._requests and self._requests[0] < cutoff:
            self._requests.popleft()

    async def acquire(self) -> bool:
        """
        Attempt to acquire a rate limit token.

        Returns:
            True if request allowed, False if rate limit exceeded.
        """
        async with self._lock:
            self._cleanup()

            if len(self._requests) >= self._max_requests:
                return False

            self._requests.append(time.time())
            return True

    async def wait_and_acquire(self, timeout_ms: Optional[int] = None) -> bool:
        """
        Wait until a token is available, then acquire it.

        Args:
            timeout_ms: Maximum time to wait in milliseconds.

        Returns:
            True if token acquired, False if timed out.
        """
        start_time = time.time()
        timeout_s = (timeout_ms / 1000) if timeout_ms else None

        while True:
            if await self.acquire():
                return True

            # Check timeout
            if timeout_s is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout_s:
                    return False

            # Wait a bit before retrying
            await asyncio.sleep(0.01)

    def reset(self) -> None:
        """Reset the rate limiter, clearing all request timestamps."""
        self._requests.clear()

    @property
    def time_until_available(self) -> float:
        """
        Get time in seconds until next token becomes available.

        Returns:
            Seconds until a new request is allowed, or 0 if available now.
        """
        self._cleanup()

        if len(self._requests) < self._max_requests:
            return 0.0

        # Time until oldest request expires
        if self._requests:
            oldest = self._requests[0]
            expires_at = oldest + self._window_seconds
            return max(0.0, expires_at - time.time())

        return 0.0
