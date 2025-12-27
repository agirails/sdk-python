"""
Extended Coverage Tests for ReceivedNonceTracker.

These tests cover additional code paths not tested in test_secure_nonce_concurrency.py:
- InMemoryReceivedNonceTracker: has_been_used, get_highest_nonce, reset, clear_all, get_all_nonces
- SetBasedReceivedNonceTracker: constructor validation, invalid nonce format, auto-cleanup,
  has_been_used, get_highest_nonce, reset, clear_all, get_nonce_count, get_memory_usage
- Rate limit window expiry
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agirails.utils.received_nonce_tracker import (
    InMemoryReceivedNonceTracker,
    NonceValidationResult,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
)


def make_nonce(value: int) -> str:
    """Create a bytes32 nonce from an integer value."""
    return "0x" + format(value, "064x")


class TestInMemoryReceivedNonceTrackerExtended:
    """Extended tests for InMemoryReceivedNonceTracker."""

    @pytest.fixture
    def tracker(self) -> InMemoryReceivedNonceTracker:
        """Create a fresh tracker for each test."""
        return InMemoryReceivedNonceTracker()

    def test_has_been_used_no_sender(self, tracker):
        """has_been_used returns False when sender has no nonces."""
        result = tracker.has_been_used("did:ethr:0xsender", "msg.type", make_nonce(1))
        assert result is False

    def test_has_been_used_no_message_type(self, tracker):
        """has_been_used returns False when message type has no nonces."""
        # Record a nonce for one message type
        tracker.validate_and_record("did:ethr:0xsender", "type1", make_nonce(1))
        # Check a different message type
        result = tracker.has_been_used("did:ethr:0xsender", "type2", make_nonce(1))
        assert result is False

    def test_has_been_used_nonce_used(self, tracker):
        """has_been_used returns True for nonce <= highest seen."""
        sender = "did:ethr:0xsender"
        msg_type = "msg.type"

        # Record nonce 5
        tracker.validate_and_record(sender, msg_type, make_nonce(5))

        # Nonces <= 5 should be marked as used
        assert tracker.has_been_used(sender, msg_type, make_nonce(5)) is True
        assert tracker.has_been_used(sender, msg_type, make_nonce(3)) is True
        assert tracker.has_been_used(sender, msg_type, make_nonce(1)) is True

        # Nonces > 5 should not be marked as used
        assert tracker.has_been_used(sender, msg_type, make_nonce(6)) is False
        assert tracker.has_been_used(sender, msg_type, make_nonce(100)) is False

    def test_get_highest_nonce_no_sender(self, tracker):
        """get_highest_nonce returns None when sender has no nonces."""
        result = tracker.get_highest_nonce("did:ethr:0xsender", "msg.type")
        assert result is None

    def test_get_highest_nonce_no_message_type(self, tracker):
        """get_highest_nonce returns None when message type has no nonces."""
        sender = "did:ethr:0xsender"
        tracker.validate_and_record(sender, "type1", make_nonce(1))
        result = tracker.get_highest_nonce(sender, "type2")
        assert result is None

    def test_get_highest_nonce_returns_correct_value(self, tracker):
        """get_highest_nonce returns correct bytes32 format."""
        sender = "did:ethr:0xsender"
        msg_type = "msg.type"

        # Record nonces 1, 5, 3 (in order, all valid since monotonic)
        tracker.validate_and_record(sender, msg_type, make_nonce(1))
        tracker.validate_and_record(sender, msg_type, make_nonce(5))

        result = tracker.get_highest_nonce(sender, msg_type)
        assert result == make_nonce(5)

    def test_reset_removes_message_type(self, tracker):
        """reset removes specific sender + message type combination."""
        sender = "did:ethr:0xsender"

        tracker.validate_and_record(sender, "type1", make_nonce(1))
        tracker.validate_and_record(sender, "type2", make_nonce(2))

        tracker.reset(sender, "type1")

        # type1 should be reset
        assert tracker.get_highest_nonce(sender, "type1") is None
        # type2 should still exist
        assert tracker.get_highest_nonce(sender, "type2") == make_nonce(2)

    def test_reset_removes_sender_if_empty(self, tracker):
        """reset removes sender entry if no message types remain."""
        sender = "did:ethr:0xsender"

        tracker.validate_and_record(sender, "type1", make_nonce(1))
        tracker.reset(sender, "type1")

        # Sender should be removed from internal dict
        assert sender not in tracker._highest_nonces

    def test_reset_nonexistent_sender(self, tracker):
        """reset handles nonexistent sender gracefully."""
        tracker.reset("did:ethr:0xnonexistent", "msg.type")
        # Should not raise

    def test_reset_nonexistent_message_type(self, tracker):
        """reset handles nonexistent message type gracefully."""
        sender = "did:ethr:0xsender"
        tracker.validate_and_record(sender, "type1", make_nonce(1))
        tracker.reset(sender, "type2")  # type2 doesn't exist
        # Should not raise, and type1 should still exist
        assert tracker.get_highest_nonce(sender, "type1") == make_nonce(1)

    def test_clear_all(self, tracker):
        """clear_all removes all tracked nonces."""
        tracker.validate_and_record("sender1", "type1", make_nonce(1))
        tracker.validate_and_record("sender2", "type2", make_nonce(2))

        tracker.clear_all()

        assert tracker.get_highest_nonce("sender1", "type1") is None
        assert tracker.get_highest_nonce("sender2", "type2") is None
        assert len(tracker._highest_nonces) == 0

    def test_get_all_nonces_empty(self, tracker):
        """get_all_nonces returns empty dict when no nonces."""
        result = tracker.get_all_nonces()
        assert result == {}

    def test_get_all_nonces_with_data(self, tracker):
        """get_all_nonces returns all tracked nonces in bytes32 format."""
        tracker.validate_and_record("sender1", "type1", make_nonce(10))
        tracker.validate_and_record("sender1", "type2", make_nonce(20))
        tracker.validate_and_record("sender2", "type1", make_nonce(30))

        result = tracker.get_all_nonces()

        assert result == {
            "sender1": {
                "type1": make_nonce(10),
                "type2": make_nonce(20),
            },
            "sender2": {
                "type1": make_nonce(30),
            },
        }

    def test_invalid_nonce_format(self, tracker):
        """Invalid nonce format is rejected."""
        result = tracker.validate_and_record("sender", "type", "not-a-nonce")
        assert result.valid is False
        assert "Invalid nonce format" in result.reason
        assert result.received_nonce == "not-a-nonce"

    def test_invalid_nonce_too_short(self, tracker):
        """Too short nonce is rejected."""
        result = tracker.validate_and_record("sender", "type", "0x1234")
        assert result.valid is False
        assert "Invalid nonce format" in result.reason

    def test_invalid_nonce_no_prefix(self, tracker):
        """Nonce without 0x prefix is rejected."""
        result = tracker.validate_and_record("sender", "type", "00" * 32)
        assert result.valid is False


class TestSetBasedReceivedNonceTrackerExtended:
    """Extended tests for SetBasedReceivedNonceTracker."""

    def test_constructor_invalid_max_size_per_type(self):
        """Constructor rejects invalid max_size_per_type."""
        with pytest.raises(ValueError, match="max_size_per_type must be positive"):
            SetBasedReceivedNonceTracker(max_size_per_type=0)

        with pytest.raises(ValueError, match="max_size_per_type must be positive"):
            SetBasedReceivedNonceTracker(max_size_per_type=-1)

    def test_constructor_invalid_max_total_entries(self):
        """Constructor rejects invalid max_total_entries."""
        with pytest.raises(ValueError, match="max_total_entries must be positive"):
            SetBasedReceivedNonceTracker(max_total_entries=0)

        with pytest.raises(ValueError, match="max_total_entries must be positive"):
            SetBasedReceivedNonceTracker(max_total_entries=-5)

    def test_constructor_invalid_max_nonces_per_minute(self):
        """Constructor rejects invalid max_nonces_per_minute."""
        with pytest.raises(ValueError, match="max_nonces_per_minute must be positive"):
            SetBasedReceivedNonceTracker(max_nonces_per_minute=0)

        with pytest.raises(ValueError, match="max_nonces_per_minute must be positive"):
            SetBasedReceivedNonceTracker(max_nonces_per_minute=-10)

    def test_invalid_nonce_format(self):
        """Invalid nonce format is rejected."""
        tracker = SetBasedReceivedNonceTracker()
        result = tracker.validate_and_record("sender", "type", "invalid")
        assert result.valid is False
        assert "Invalid nonce format" in result.reason

    def test_has_been_used_no_sender(self):
        """has_been_used returns False when sender has no nonces."""
        tracker = SetBasedReceivedNonceTracker()
        result = tracker.has_been_used("did:ethr:0xsender", "msg.type", make_nonce(1))
        assert result is False

    def test_has_been_used_no_message_type(self):
        """has_been_used returns False when message type has no nonces."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender", "type1", make_nonce(1))
        result = tracker.has_been_used("sender", "type2", make_nonce(1))
        assert result is False

    def test_has_been_used_nonce_exists(self):
        """has_been_used returns True when exact nonce exists in set."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        sender = "sender"
        msg_type = "type"

        tracker.validate_and_record(sender, msg_type, make_nonce(5))
        tracker.validate_and_record(sender, msg_type, make_nonce(10))

        # Exact matches should be True
        assert tracker.has_been_used(sender, msg_type, make_nonce(5)) is True
        assert tracker.has_been_used(sender, msg_type, make_nonce(10)) is True

        # Non-matches should be False
        assert tracker.has_been_used(sender, msg_type, make_nonce(7)) is False

    def test_get_highest_nonce_no_sender(self):
        """get_highest_nonce returns None when sender has no nonces."""
        tracker = SetBasedReceivedNonceTracker()
        result = tracker.get_highest_nonce("sender", "type")
        assert result is None

    def test_get_highest_nonce_no_message_type(self):
        """get_highest_nonce returns None when message type has no nonces."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender", "type1", make_nonce(1))
        result = tracker.get_highest_nonce("sender", "type2")
        assert result is None

    def test_get_highest_nonce_empty_set(self):
        """get_highest_nonce returns None for empty set (after reset)."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender", "type", make_nonce(1))
        tracker.reset("sender", "type")
        result = tracker.get_highest_nonce("sender", "type")
        assert result is None

    def test_get_highest_nonce_returns_max(self):
        """get_highest_nonce returns maximum nonce in set."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        sender = "sender"
        msg_type = "type"

        # Add nonces out of order
        tracker.validate_and_record(sender, msg_type, make_nonce(5))
        tracker.validate_and_record(sender, msg_type, make_nonce(100))
        tracker.validate_and_record(sender, msg_type, make_nonce(50))

        result = tracker.get_highest_nonce(sender, msg_type)
        assert result == make_nonce(100)

    def test_reset_removes_message_type(self):
        """reset removes specific sender + message type combination."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        sender = "sender"

        tracker.validate_and_record(sender, "type1", make_nonce(1))
        tracker.validate_and_record(sender, "type2", make_nonce(2))

        initial_count = tracker._total_entries
        assert initial_count == 2

        tracker.reset(sender, "type1")

        # type1 should be reset
        assert tracker.has_been_used(sender, "type1", make_nonce(1)) is False
        # type2 should still exist
        assert tracker.has_been_used(sender, "type2", make_nonce(2)) is True
        # Total entries should be decremented
        assert tracker._total_entries == 1

    def test_reset_removes_sender_if_empty(self):
        """reset removes sender entry if no message types remain."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        sender = "sender"

        tracker.validate_and_record(sender, "type1", make_nonce(1))
        tracker.reset(sender, "type1")

        assert sender not in tracker._used_nonces

    def test_reset_nonexistent_sender(self):
        """reset handles nonexistent sender gracefully."""
        tracker = SetBasedReceivedNonceTracker()
        tracker.reset("nonexistent", "type")
        # Should not raise

    def test_reset_nonexistent_message_type(self):
        """reset handles nonexistent message type gracefully."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender", "type1", make_nonce(1))
        tracker.reset("sender", "type2")
        # type1 should still exist
        assert tracker.has_been_used("sender", "type1", make_nonce(1)) is True

    def test_clear_all(self):
        """clear_all removes all tracked nonces."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender1", "type1", make_nonce(1))
        tracker.validate_and_record("sender2", "type2", make_nonce(2))

        assert tracker._total_entries == 2

        tracker.clear_all()

        assert tracker._total_entries == 0
        assert len(tracker._used_nonces) == 0

    def test_get_nonce_count_no_sender(self):
        """get_nonce_count returns 0 when sender has no nonces."""
        tracker = SetBasedReceivedNonceTracker()
        result = tracker.get_nonce_count("sender", "type")
        assert result == 0

    def test_get_nonce_count_no_message_type(self):
        """get_nonce_count returns 0 when message type has no nonces."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        tracker.validate_and_record("sender", "type1", make_nonce(1))
        result = tracker.get_nonce_count("sender", "type2")
        assert result == 0

    def test_get_nonce_count_with_data(self):
        """get_nonce_count returns correct count."""
        tracker = SetBasedReceivedNonceTracker(max_nonces_per_minute=1000)
        sender = "sender"
        msg_type = "type"

        tracker.validate_and_record(sender, msg_type, make_nonce(1))
        tracker.validate_and_record(sender, msg_type, make_nonce(2))
        tracker.validate_and_record(sender, msg_type, make_nonce(3))

        assert tracker.get_nonce_count(sender, msg_type) == 3

    def test_get_memory_usage(self):
        """get_memory_usage returns correct statistics."""
        tracker = SetBasedReceivedNonceTracker(
            max_total_entries=50000,
            max_nonces_per_minute=1000,
        )

        tracker.validate_and_record("sender1", "type1", make_nonce(1))
        tracker.validate_and_record("sender1", "type2", make_nonce(2))
        tracker.validate_and_record("sender2", "type1", make_nonce(3))

        usage = tracker.get_memory_usage()

        assert usage["total_entries"] == 3
        assert usage["combinations"] == 3  # 2 for sender1, 1 for sender2
        assert usage["max_total_entries"] == 50000

    def test_auto_cleanup_when_max_size_reached(self):
        """Auto-cleanup triggers when max_size_per_type is reached."""
        tracker = SetBasedReceivedNonceTracker(
            max_size_per_type=10,
            max_total_entries=100000,
            max_nonces_per_minute=1000,
        )

        sender = "sender"
        msg_type = "type"

        # Add 10 nonces (reaches max)
        for i in range(10):
            result = tracker.validate_and_record(sender, msg_type, make_nonce(i))
            assert result.valid is True

        assert tracker.get_nonce_count(sender, msg_type) == 10

        # Add 11th nonce - should trigger cleanup keeping 80% = 8 entries
        result = tracker.validate_and_record(sender, msg_type, make_nonce(100))
        assert result.valid is True

        # After cleanup: 8 highest nonces kept + 1 new = 9
        assert tracker.get_nonce_count(sender, msg_type) == 9

        # Lowest nonces should be removed (0, 1 removed; 2-9 kept)
        assert tracker.has_been_used(sender, msg_type, make_nonce(0)) is False
        assert tracker.has_been_used(sender, msg_type, make_nonce(1)) is False
        assert tracker.has_been_used(sender, msg_type, make_nonce(9)) is True
        assert tracker.has_been_used(sender, msg_type, make_nonce(100)) is True

    def test_rate_limit_window_expiry(self):
        """Rate limit resets after window expires."""
        # Patch time.time in the module where it's used
        with patch('agirails.utils.received_nonce_tracker.time') as mock_time_module:
            base_time = 1000000.0  # Start at a fixed time
            mock_time_module.time.return_value = base_time

            tracker = SetBasedReceivedNonceTracker(
                max_nonces_per_minute=3,
            )

            sender = "sender"
            msg_type = "type"

            # Use up rate limit
            for i in range(3):
                result = tracker.validate_and_record(sender, msg_type, make_nonce(i))
                assert result.valid is True

            # Next should fail
            result = tracker.validate_and_record(sender, msg_type, make_nonce(3))
            assert result.valid is False
            assert "Rate limit exceeded" in result.reason

            # Advance time past the window (61 seconds)
            mock_time_module.time.return_value = base_time + 61

            # Now should succeed (rate limit reset)
            result = tracker.validate_and_record(sender, msg_type, make_nonce(4))
            assert result.valid is True

    def test_global_limit_prevents_dos(self):
        """Global limit prevents memory exhaustion attack."""
        tracker = SetBasedReceivedNonceTracker(
            max_size_per_type=100,
            max_total_entries=5,  # Very low for testing
            max_nonces_per_minute=1000,
        )

        # Fill up to global limit
        for i in range(5):
            result = tracker.validate_and_record(f"sender{i}", "type", make_nonce(i))
            assert result.valid is True

        # Next should fail due to global limit
        result = tracker.validate_and_record("sender100", "type", make_nonce(100))
        assert result.valid is False
        assert "Global nonce tracker limit reached" in result.reason


class TestCreateReceivedNonceTrackerFactory:
    """Tests for create_received_nonce_tracker factory function."""

    def test_default_creates_memory_efficient(self):
        """Default strategy creates InMemoryReceivedNonceTracker."""
        tracker = create_received_nonce_tracker()
        assert isinstance(tracker, InMemoryReceivedNonceTracker)

    def test_memory_efficient_strategy(self):
        """memory-efficient strategy creates InMemoryReceivedNonceTracker."""
        tracker = create_received_nonce_tracker("memory-efficient")
        assert isinstance(tracker, InMemoryReceivedNonceTracker)

    def test_set_based_strategy(self):
        """set-based strategy creates SetBasedReceivedNonceTracker."""
        tracker = create_received_nonce_tracker("set-based")
        assert isinstance(tracker, SetBasedReceivedNonceTracker)

    def test_unknown_strategy_defaults_to_memory_efficient(self):
        """Unknown strategy falls back to memory-efficient."""
        tracker = create_received_nonce_tracker("unknown-strategy")
        assert isinstance(tracker, InMemoryReceivedNonceTracker)


class TestNonceValidationResultDataclass:
    """Tests for NonceValidationResult dataclass."""

    def test_create_valid_result(self):
        """Can create valid result with minimal fields."""
        result = NonceValidationResult(valid=True)
        assert result.valid is True
        assert result.reason is None
        assert result.expected_minimum is None
        assert result.received_nonce is None

    def test_create_invalid_result_with_all_fields(self):
        """Can create invalid result with all fields."""
        result = NonceValidationResult(
            valid=False,
            reason="Replay attack detected",
            expected_minimum=make_nonce(10),
            received_nonce=make_nonce(5),
        )
        assert result.valid is False
        assert result.reason == "Replay attack detected"
        assert result.expected_minimum == make_nonce(10)
        assert result.received_nonce == make_nonce(5)
