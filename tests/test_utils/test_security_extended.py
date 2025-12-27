"""
Extended security utilities tests for coverage improvement.

Tests for:
- SecurityLogger and SecurityEvent (L-2)
- SecureAccountWrapper (C-1)
- TokenBucketRateLimiter (C-3)
- retry_with_backoff (C-3)
- _secure_zero_memory

Target: Increase utils/security.py coverage from 58% to 90%+
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime
from typing import List
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from agirails.utils.security import (
    SecurityEventType,
    SecurityEvent,
    SecurityLogger,
    get_security_logger,
    SecureAccountWrapper,
    TokenBucketRateLimiter,
    RetryConfig,
    retry_with_backoff,
    _secure_zero_memory,
    _sanitize_object,
)


# ============================================================================
# SecurityEvent Tests
# ============================================================================


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""

    def test_create_event_with_defaults(self):
        """Event created with defaults should have correct structure."""
        event = SecurityEvent(event_type=SecurityEventType.AUTH_SUCCESS)

        assert event.event_type == SecurityEventType.AUTH_SUCCESS
        assert isinstance(event.timestamp, datetime)
        assert event.message == ""
        assert event.source == ""
        assert event.severity == "INFO"
        assert event.details == {}

    def test_create_event_with_all_fields(self):
        """Event created with all fields should preserve them."""
        details = {"address": "0x123", "reason": "invalid signature"}
        event = SecurityEvent(
            event_type=SecurityEventType.AUTH_FAILURE,
            message="Authentication failed",
            source="kernel.verify",
            severity="WARNING",
            details=details,
        )

        assert event.event_type == SecurityEventType.AUTH_FAILURE
        assert event.message == "Authentication failed"
        assert event.source == "kernel.verify"
        assert event.severity == "WARNING"
        assert event.details == details

    def test_to_dict(self):
        """to_dict should serialize event correctly."""
        event = SecurityEvent(
            event_type=SecurityEventType.TX_SUBMITTED,
            message="Transaction submitted",
            source="escrow.send",
            severity="INFO",
            details={"tx_hash": "0xabc123"},
        )

        result = event.to_dict()

        assert result["event_type"] == "tx_submitted"
        assert result["message"] == "Transaction submitted"
        assert result["source"] == "escrow.send"
        assert result["severity"] == "INFO"
        assert result["details"] == {"tx_hash": "0xabc123"}
        assert "timestamp" in result
        # Timestamp should be ISO format
        datetime.fromisoformat(result["timestamp"])

    def test_all_event_types(self):
        """All SecurityEventType values should be usable."""
        for event_type in SecurityEventType:
            event = SecurityEvent(event_type=event_type)
            assert event.event_type == event_type
            result = event.to_dict()
            assert result["event_type"] == event_type.value


# ============================================================================
# SecurityLogger Tests
# ============================================================================


class TestSecurityLogger:
    """Tests for SecurityLogger singleton."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton between tests."""
        # Save original instance
        original = SecurityLogger._instance
        SecurityLogger._instance = None
        yield
        # Restore original instance
        SecurityLogger._instance = original

    def test_singleton_pattern(self):
        """get_instance should return same instance."""
        logger1 = SecurityLogger.get_instance()
        logger2 = SecurityLogger.get_instance()
        assert logger1 is logger2

    def test_global_getter(self):
        """get_security_logger should return singleton."""
        logger1 = get_security_logger()
        logger2 = SecurityLogger.get_instance()
        assert logger1 is logger2

    def test_set_min_severity_valid(self):
        """set_min_severity should accept valid severities."""
        logger = SecurityLogger.get_instance()

        for severity in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            logger.set_min_severity(severity)
            assert logger._min_severity == severity

        # Case insensitive
        logger.set_min_severity("info")
        assert logger._min_severity == "INFO"

    def test_set_min_severity_invalid(self):
        """set_min_severity should reject invalid severities."""
        logger = SecurityLogger.get_instance()

        with pytest.raises(ValueError, match="Invalid severity"):
            logger.set_min_severity("INVALID")

    def test_add_remove_handler(self):
        """Handlers should be added and removed correctly."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_event(SecurityEventType.AUTH_SUCCESS, message="test")

        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.AUTH_SUCCESS

        logger.remove_handler(handler)
        logger.log_event(SecurityEventType.AUTH_SUCCESS, message="test2")

        # No new events after handler removed
        assert len(events) == 1

    def test_log_event_respects_severity_threshold(self):
        """Events below min severity should be filtered."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.set_min_severity("WARNING")

        # INFO should be filtered
        logger.log_event(SecurityEventType.AUTH_SUCCESS, severity="INFO")
        assert len(events) == 0

        # WARNING should pass
        logger.log_event(SecurityEventType.AUTH_FAILURE, severity="WARNING")
        assert len(events) == 1

        # ERROR should pass
        logger.log_event(SecurityEventType.TX_FAILED, severity="ERROR")
        assert len(events) == 2

        logger.remove_handler(handler)

    def test_log_event_handles_handler_exceptions(self):
        """Handler exceptions should not break logging."""
        logger = SecurityLogger.get_instance()

        def bad_handler(event: SecurityEvent):
            raise RuntimeError("Handler error")

        logger.add_handler(bad_handler)

        # Should not raise
        logger.log_event(SecurityEventType.AUTH_SUCCESS, message="test")

        logger.remove_handler(bad_handler)

    def test_log_auth_failure(self):
        """log_auth_failure should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_auth_failure(
            source="test.verify",
            reason="Invalid signature",
            address="0x1234567890123456789012345678901234567890",
        )

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.AUTH_FAILURE
        assert "Invalid signature" in event.message
        assert event.severity == "WARNING"
        # Address should be partially redacted
        assert "..." in event.details.get("address", "")

        logger.remove_handler(handler)

    def test_log_auth_failure_short_address(self):
        """log_auth_failure should redact short addresses."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_auth_failure(source="test", reason="test", address="0x123")

        assert events[0].details["address"] == "[redacted]"
        logger.remove_handler(handler)

    def test_log_rate_limit(self):
        """log_rate_limit should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_rate_limit(source="rpc.call", limit=10.0, window=1.0)

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.RATE_LIMIT_HIT
        assert event.details["limit"] == 10.0
        assert event.details["window"] == 1.0

        logger.remove_handler(handler)

    def test_log_invalid_input(self):
        """log_invalid_input should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_invalid_input(
            source="validation",
            input_type="address",
            reason="Invalid format",
        )

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.INVALID_INPUT
        assert event.details["input_type"] == "address"

        logger.remove_handler(handler)

    def test_log_path_traversal(self):
        """log_path_traversal should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_path_traversal(
            source="file.read",
            path="../../../etc/passwd",
            base_dir="/app/data",
        )

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.PATH_TRAVERSAL_ATTEMPT
        assert event.severity == "ERROR"
        # Path should be redacted
        assert event.details["attempted_path"] == "[redacted]"

        logger.remove_handler(handler)

    def test_log_tx_submitted(self):
        """log_tx_submitted should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_tx_submitted(
            source="kernel.send",
            tx_hash="0xabc123",
            tx_type="create_transaction",
        )

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.TX_SUBMITTED
        assert event.details["tx_hash"] == "0xabc123"
        assert event.details["tx_type"] == "create_transaction"

        logger.remove_handler(handler)

    def test_log_tx_failed(self):
        """log_tx_failed should create correct event."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []

        def handler(event: SecurityEvent):
            events.append(event)

        logger.add_handler(handler)
        logger.log_tx_failed(
            source="kernel.send",
            tx_hash="0xabc123",
            reason="Reverted",
        )

        assert len(events) == 1
        event = events[0]
        assert event.event_type == SecurityEventType.TX_FAILED
        assert event.severity == "ERROR"
        assert event.details["reason"] == "Reverted"

        logger.remove_handler(handler)

    def test_thread_safety(self):
        """Logger should be thread-safe."""
        logger = SecurityLogger.get_instance()
        events: List[SecurityEvent] = []
        lock = threading.Lock()

        def handler(event: SecurityEvent):
            with lock:
                events.append(event)

        logger.add_handler(handler)

        def log_events(count: int):
            for i in range(count):
                logger.log_event(
                    SecurityEventType.AUTH_SUCCESS,
                    message=f"Event {i}",
                )

        # Run 10 threads, each logging 10 events
        threads = [threading.Thread(target=log_events, args=(10,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 100 events should be logged
        assert len(events) == 100

        logger.remove_handler(handler)


# ============================================================================
# SecureAccountWrapper Tests
# ============================================================================


class TestSecureAccountWrapper:
    """Tests for SecureAccountWrapper (C-1)."""

    def test_create_wrapper(self):
        """Wrapper should store account correctly."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)

        assert wrapper.address == mock_account.address
        assert wrapper.account is mock_account

    def test_create_with_private_key_bytes(self):
        """Wrapper should accept private key bytes."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"
        key_bytes = b"\x00" * 32

        wrapper = SecureAccountWrapper(mock_account, key_bytes)

        assert wrapper.address == mock_account.address

    def test_sign_message(self):
        """sign_message should delegate to account."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"
        mock_account.sign_message.return_value = "signed"

        wrapper = SecureAccountWrapper(mock_account)
        result = wrapper.sign_message("test message")

        assert result == "signed"
        mock_account.sign_message.assert_called_once_with("test message")

    def test_sign_transaction(self):
        """sign_transaction should delegate to account."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"
        mock_account.sign_transaction.return_value = "signed_tx"

        wrapper = SecureAccountWrapper(mock_account)
        tx = {"to": "0x...", "value": 100}
        result = wrapper.sign_transaction(tx)

        assert result == "signed_tx"
        mock_account.sign_transaction.assert_called_once_with(tx)

    def test_dispose(self):
        """dispose should clear account reference."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)
        wrapper.dispose()

        # Accessing after dispose should raise
        with pytest.raises(RuntimeError, match="disposed"):
            _ = wrapper.address

        with pytest.raises(RuntimeError, match="disposed"):
            _ = wrapper.account

        with pytest.raises(RuntimeError, match="disposed"):
            wrapper.sign_message("test")

        with pytest.raises(RuntimeError, match="disposed"):
            wrapper.sign_transaction({})

    def test_dispose_idempotent(self):
        """dispose can be called multiple times."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)
        wrapper.dispose()
        wrapper.dispose()  # Should not raise

    def test_dispose_zeros_key_bytes(self):
        """dispose should attempt to zero key bytes."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"
        key_bytes = bytearray(b"\xff" * 32)

        wrapper = SecureAccountWrapper(mock_account, bytes(key_bytes))
        wrapper.dispose()

        # After dispose, private_key_bytes should be None
        assert wrapper._private_key_bytes is None

    def test_repr_safe(self):
        """repr should not leak key information."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)
        result = repr(wrapper)

        assert "SecureAccountWrapper" in result
        assert mock_account.address in result
        assert "private" not in result.lower()
        assert "key" not in result.lower()

    def test_repr_disposed(self):
        """repr of disposed wrapper should indicate disposal."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)
        wrapper.dispose()
        result = repr(wrapper)

        assert "disposed" in result

    def test_str_safe(self):
        """str should not leak key information."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)
        result = str(wrapper)

        assert "SecureAccountWrapper" in result

    def test_pickle_prevention(self):
        """Wrapper should not be picklable."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"

        wrapper = SecureAccountWrapper(mock_account)

        with pytest.raises(RuntimeError, match="cannot be pickled"):
            wrapper.__getstate__()

        with pytest.raises(RuntimeError, match="cannot be pickled"):
            wrapper.__reduce__()

    def test_thread_safety(self):
        """Wrapper should be thread-safe."""
        mock_account = MagicMock()
        mock_account.address = "0x1234567890123456789012345678901234567890"
        mock_account.sign_message.return_value = "signed"

        wrapper = SecureAccountWrapper(mock_account)
        results: List[str] = []
        lock = threading.Lock()

        def sign_messages(count: int):
            for i in range(count):
                result = wrapper.sign_message(f"message {i}")
                with lock:
                    results.append(result)

        threads = [threading.Thread(target=sign_messages, args=(10,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50


# ============================================================================
# TokenBucketRateLimiter Tests
# ============================================================================


class TestTokenBucketRateLimiter:
    """Tests for TokenBucketRateLimiter (C-3)."""

    @pytest.mark.asyncio
    async def test_basic_acquire(self):
        """Basic acquire should work within rate limit."""
        limiter = TokenBucketRateLimiter(max_rate=10.0, time_period=1.0)

        # Should acquire immediately
        result = await limiter.acquire()
        assert result is True

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Context manager should work correctly."""
        limiter = TokenBucketRateLimiter(max_rate=10.0, time_period=1.0)

        async with limiter:
            pass  # Should not raise

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Acquire should wait when tokens exhausted."""
        # 2 tokens per second, burst size 2
        limiter = TokenBucketRateLimiter(max_rate=2.0, time_period=1.0, burst_size=2)

        # First two should be immediate
        await limiter.acquire()
        await limiter.acquire()

        # Third should wait
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should have waited approximately 0.5 seconds for 1 token
        assert elapsed >= 0.4

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Acquire with timeout should return False if expired."""
        limiter = TokenBucketRateLimiter(max_rate=1.0, time_period=10.0, burst_size=1)

        # Use the one token
        await limiter.acquire()

        # Try to acquire with short timeout
        start = time.monotonic()
        result = await limiter.acquire(timeout=0.1)
        elapsed = time.monotonic() - start

        assert result is False
        assert elapsed >= 0.1
        assert elapsed < 0.5  # Should not wait longer than timeout

    @pytest.mark.asyncio
    async def test_multiple_tokens(self):
        """Acquire should support requesting multiple tokens."""
        limiter = TokenBucketRateLimiter(max_rate=10.0, time_period=1.0, burst_size=5)

        # Acquire 3 tokens
        result = await limiter.acquire(tokens=3)
        assert result is True

        # Acquire 2 more (total 5, at burst limit)
        result = await limiter.acquire(tokens=2)
        assert result is True

    @pytest.mark.asyncio
    async def test_properties(self):
        """Properties should return correct values."""
        limiter = TokenBucketRateLimiter(max_rate=5.0, time_period=2.0)

        assert limiter.max_rate == 5.0
        assert limiter.time_period == 2.0

    def test_invalid_max_rate(self):
        """Invalid max_rate should raise ValueError."""
        with pytest.raises(ValueError, match="max_rate must be positive"):
            TokenBucketRateLimiter(max_rate=0)

        with pytest.raises(ValueError, match="max_rate must be positive"):
            TokenBucketRateLimiter(max_rate=-1)

    def test_invalid_time_period(self):
        """Invalid time_period should raise ValueError."""
        with pytest.raises(ValueError, match="time_period must be positive"):
            TokenBucketRateLimiter(max_rate=10, time_period=0)

        with pytest.raises(ValueError, match="time_period must be positive"):
            TokenBucketRateLimiter(max_rate=10, time_period=-1)

    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Tokens should refill over time."""
        limiter = TokenBucketRateLimiter(max_rate=10.0, time_period=1.0, burst_size=2)

        # Use all tokens
        await limiter.acquire()
        await limiter.acquire()

        # Wait for refill
        await asyncio.sleep(0.3)

        # Should be able to acquire again (some tokens refilled)
        result = await limiter.acquire(timeout=0.1)
        assert result is True


# ============================================================================
# RetryConfig and retry_with_backoff Tests
# ============================================================================


class TestRetryConfig:
    """Tests for RetryConfig."""

    def test_default_values(self):
        """Default values should be reasonable."""
        config = RetryConfig()

        assert config.max_retries == 3
        assert config.initial_delay == 0.5
        assert config.max_delay == 30.0
        assert config.exponential_base == 2.0
        assert config.jitter is True

    def test_custom_values(self):
        """Custom values should be stored."""
        config = RetryConfig(
            max_retries=5,
            initial_delay=1.0,
            max_delay=60.0,
            exponential_base=3.0,
            jitter=False,
        )

        assert config.max_retries == 5
        assert config.initial_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 3.0
        assert config.jitter is False


class TestRetryWithBackoff:
    """Tests for retry_with_backoff function (C-3)."""

    @pytest.mark.asyncio
    async def test_success_first_try(self):
        """Successful operation should return immediately."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await retry_with_backoff(operation)

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Operation should be retried on failure."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        config = RetryConfig(max_retries=3, initial_delay=0.01, jitter=False)
        result = await retry_with_backoff(operation, config)

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self):
        """Should raise after max retries exceeded."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            raise ValueError("Persistent error")

        config = RetryConfig(max_retries=2, initial_delay=0.01, jitter=False)

        with pytest.raises(ValueError, match="Persistent error"):
            await retry_with_backoff(operation, config)

        # Initial attempt + 2 retries = 3 calls
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retryable_exceptions_filter(self):
        """Only specified exceptions should be retried."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            raise TypeError("Not retryable")

        config = RetryConfig(max_retries=3, initial_delay=0.01)

        # Only retry ValueError, not TypeError
        with pytest.raises(TypeError, match="Not retryable"):
            await retry_with_backoff(
                operation, config, retryable_exceptions=(ValueError,)
            )

        # Should not have retried
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Delays should increase exponentially."""
        call_times: List[float] = []

        async def operation():
            call_times.append(time.monotonic())
            if len(call_times) < 4:
                raise ValueError("Error")
            return "success"

        config = RetryConfig(
            max_retries=3,
            initial_delay=0.1,
            exponential_base=2.0,
            jitter=False,
        )

        await retry_with_backoff(operation, config)

        # Calculate delays between calls
        delays = [call_times[i + 1] - call_times[i] for i in range(len(call_times) - 1)]

        # Delays should be approximately: 0.1, 0.2, 0.4
        assert delays[0] >= 0.08  # ~0.1
        assert delays[1] >= 0.15  # ~0.2
        assert delays[2] >= 0.3   # ~0.4

    @pytest.mark.asyncio
    async def test_max_delay_cap(self):
        """Delay should not exceed max_delay."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            if call_count < 5:
                raise ValueError("Error")
            return "success"

        config = RetryConfig(
            max_retries=5,
            initial_delay=1.0,
            max_delay=0.5,  # Cap at 0.5s
            exponential_base=10.0,  # Would grow fast without cap
            jitter=False,
        )

        start = time.monotonic()
        await retry_with_backoff(operation, config)
        elapsed = time.monotonic() - start

        # With cap at 0.5s and 4 retries, should take ~2 seconds max
        # (each delay capped at 0.5s)
        assert elapsed < 3.0

    @pytest.mark.asyncio
    async def test_default_config(self):
        """Should use default config if none provided."""
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await retry_with_backoff(operation)

        assert result == "success"
        assert call_count == 1


# ============================================================================
# _secure_zero_memory Tests
# ============================================================================


class TestSecureZeroMemory:
    """Tests for _secure_zero_memory function."""

    def test_zero_memory_does_not_raise(self):
        """Function should not raise on any input."""
        # Normal bytes
        data = b"\xff" * 32
        _secure_zero_memory(data)  # Should not raise

        # Empty bytes
        _secure_zero_memory(b"")  # Should not raise

        # Large bytes
        _secure_zero_memory(b"\x00" * 10000)  # Should not raise

    def test_zero_memory_best_effort(self):
        """Function is best-effort and should handle errors gracefully."""
        # Even with unusual objects, should not raise
        _secure_zero_memory(b"test")


# ============================================================================
# _sanitize_object Tests
# ============================================================================


class TestSanitizeObject:
    """Tests for _sanitize_object helper function."""

    def test_removes_dangerous_keys_from_dict(self):
        """Should remove __proto__, constructor, prototype keys."""
        obj = {
            "safe": "value",
            "__proto__": {"admin": True},
            "constructor": "evil",
            "prototype": {},
        }

        result = _sanitize_object(obj)

        assert result == {"safe": "value"}

    def test_sanitizes_nested_dicts(self):
        """Should sanitize nested dictionaries."""
        obj = {
            "outer": {
                "inner": "value",
                "__proto__": "bad",
            }
        }

        result = _sanitize_object(obj)

        assert result == {"outer": {"inner": "value"}}

    def test_sanitizes_lists(self):
        """Should sanitize objects in lists."""
        obj = [
            {"safe": "value", "__proto__": "bad"},
            {"another": "item"},
        ]

        result = _sanitize_object(obj)

        assert result == [{"safe": "value"}, {"another": "item"}]

    def test_preserves_primitives(self):
        """Should preserve primitive values."""
        assert _sanitize_object("string") == "string"
        assert _sanitize_object(123) == 123
        assert _sanitize_object(3.14) == 3.14
        assert _sanitize_object(True) is True
        assert _sanitize_object(None) is None
