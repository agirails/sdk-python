"""
Tests for helper utilities.

Tests for:
- USDC: Amount conversion (6 decimals)
- Deadline: Time utilities
- Address: Ethereum address utilities
- Bytes32: Transaction ID utilities
- StateHelper: State machine utilities
- DisputeWindow: Dispute window utilities
- ServiceHash: Service metadata hashing
"""

import time
from datetime import datetime

import pytest

from agirails.utils.helpers import (
    USDC,
    Deadline,
    Address,
    Bytes32,
    StateHelper,
    DisputeWindow,
    ServiceHash,
    ServiceMetadata,
    parse_usdc,
    format_usdc,
    shorten_address,
    hash_service_metadata,
)


class TestUSDC:
    """Tests for USDC utilities."""

    def test_to_wei_integer(self):
        """Integer USDC amounts."""
        assert USDC.to_wei(100) == 100_000_000
        assert USDC.to_wei(1) == 1_000_000
        assert USDC.to_wei(0) == 0

    def test_to_wei_string(self):
        """String USDC amounts."""
        assert USDC.to_wei("100") == 100_000_000
        assert USDC.to_wei("100.50") == 100_500_000
        assert USDC.to_wei("100.5") == 100_500_000
        assert USDC.to_wei("0.05") == 50_000
        assert USDC.to_wei("0.000001") == 1

    def test_to_wei_with_formatting(self):
        """Amounts with formatting characters."""
        assert USDC.to_wei("$100") == 100_000_000
        assert USDC.to_wei("1,000") == 1_000_000_000
        assert USDC.to_wei("$1,000.50") == 1_000_500_000

    def test_to_wei_float(self):
        """Float USDC amounts."""
        assert USDC.to_wei(100.50) == 100_500_000
        assert USDC.to_wei(0.05) == 50_000

    def test_to_wei_negative(self):
        """Negative amounts."""
        assert USDC.to_wei(-100) == -100_000_000
        assert USDC.to_wei("-50.50") == -50_500_000

    def test_from_wei_basic(self):
        """Basic wei to USDC conversion."""
        assert USDC.from_wei(100_000_000) == "100.00"
        assert USDC.from_wei(100_500_000) == "100.50"
        assert USDC.from_wei(50_000) == "0.05"
        assert USDC.from_wei(1) == "0.00"  # Rounds to 2 decimals

    def test_from_wei_string_input(self):
        """Wei as string input."""
        assert USDC.from_wei("100000000") == "100.00"

    def test_from_wei_custom_decimals(self):
        """Custom decimal places."""
        assert USDC.from_wei(100_126_000, decimals=4) == "100.1260"
        assert USDC.from_wei(100_126_000, decimals=6) == "100.126000"
        assert USDC.from_wei(100_126_000, decimals=0) == "100"

    def test_from_wei_negative(self):
        """Negative amounts."""
        assert USDC.from_wei(-100_000_000) == "-100.00"

    def test_format(self):
        """Format with USDC suffix."""
        assert USDC.format(100_000_000) == "100.00 USDC"
        assert USDC.format(50_000) == "0.05 USDC"

    def test_meets_minimum(self):
        """Minimum amount check."""
        assert USDC.meets_minimum(50_000) is True
        assert USDC.meets_minimum(50_001) is True
        assert USDC.meets_minimum(49_999) is False
        assert USDC.meets_minimum(0) is False
        assert USDC.meets_minimum("50000") is True

    def test_constants(self):
        """USDC constants."""
        assert USDC.DECIMALS == 6
        assert USDC.MIN_AMOUNT_WEI == 50_000


class TestDeadline:
    """Tests for Deadline utilities."""

    def test_hours_from_now(self):
        """Hours from now."""
        now = int(time.time())
        deadline = Deadline.hours_from_now(24)
        assert deadline >= now + 86400 - 2  # Allow 2s tolerance
        assert deadline <= now + 86400 + 2

    def test_days_from_now(self):
        """Days from now."""
        now = int(time.time())
        deadline = Deadline.days_from_now(7)
        expected = now + 7 * 86400
        assert deadline >= expected - 2
        assert deadline <= expected + 2

    def test_at_datetime(self):
        """From datetime object."""
        dt = datetime(2030, 1, 1, 0, 0, 0)
        deadline = Deadline.at(dt)
        assert deadline == int(dt.timestamp())

    def test_at_string(self):
        """From ISO string."""
        deadline = Deadline.at("2030-01-01T00:00:00")
        assert deadline > 0

    def test_is_past(self):
        """Check if past."""
        now = int(time.time())
        assert Deadline.is_past(now - 100) is True
        assert Deadline.is_past(now + 100) is False

    def test_time_remaining(self):
        """Time remaining calculation."""
        now = int(time.time())
        assert Deadline.time_remaining(now + 100) >= 98  # Allow tolerance
        assert Deadline.time_remaining(now - 100) <= -98

    def test_format_future(self):
        """Format future deadlines."""
        now = int(time.time())
        assert "seconds" in Deadline.format(now + 30)
        assert "minutes" in Deadline.format(now + 120)
        assert "hours" in Deadline.format(now + 3700)
        assert "days" in Deadline.format(now + 100000)

    def test_format_past(self):
        """Format past deadlines."""
        now = int(time.time())
        assert "expired" in Deadline.format(now - 30)


class TestAddress:
    """Tests for Address utilities."""

    def test_normalize(self):
        """Normalize to lowercase."""
        assert Address.normalize("0xABC") == "0xabc"
        assert Address.normalize("0XABC") == "0xabc"

    def test_equals(self):
        """Case-insensitive comparison."""
        assert Address.equals("0xabc", "0xABC") is True
        assert Address.equals("0xabc", "0xdef") is False

    def test_truncate(self):
        """Truncate for display."""
        addr = "0x1234567890123456789012345678901234567890"
        assert Address.truncate(addr) == "0x1234...7890"
        assert Address.truncate(addr, chars=6) == "0x123456...567890"

    def test_is_valid(self):
        """Valid address format."""
        assert Address.is_valid("0x" + "a" * 40) is True
        assert Address.is_valid("0x" + "A" * 40) is True
        assert Address.is_valid("0x123") is False
        assert Address.is_valid("abc") is False
        assert Address.is_valid("") is False

    def test_is_zero(self):
        """Zero address check."""
        assert Address.is_zero("0x" + "0" * 40) is True
        assert Address.is_zero("0x" + "a" * 40) is False


class TestBytes32:
    """Tests for Bytes32 utilities."""

    def test_is_valid(self):
        """Valid bytes32 format."""
        assert Bytes32.is_valid("0x" + "a" * 64) is True
        assert Bytes32.is_valid("0x" + "A" * 64) is True
        assert Bytes32.is_valid("0x123") is False
        assert Bytes32.is_valid("") is False

    def test_normalize(self):
        """Normalize to lowercase."""
        assert Bytes32.normalize("0x" + "ABC" * 21 + "A") == "0x" + "abc" * 21 + "a"

    def test_equals(self):
        """Case-insensitive comparison."""
        a = "0x" + "abc" * 21 + "a"
        b = "0x" + "ABC" * 21 + "A"
        assert Bytes32.equals(a, b) is True

    def test_is_zero(self):
        """Zero bytes32 check."""
        assert Bytes32.is_zero("0x" + "0" * 64) is True
        assert Bytes32.is_zero("0x" + "a" * 64) is False

    def test_zero(self):
        """Generate zero bytes32."""
        assert Bytes32.zero() == "0x" + "0" * 64
        assert len(Bytes32.zero()) == 66

    def test_truncate(self):
        """Truncate for display."""
        value = "0x" + "abc123" * 10 + "abcd"
        truncated = Bytes32.truncate(value)
        assert "..." in truncated


class TestStateHelper:
    """Tests for StateHelper utilities."""

    def test_is_terminal(self):
        """Terminal state check."""
        assert StateHelper.is_terminal("SETTLED") is True
        assert StateHelper.is_terminal("CANCELLED") is True
        assert StateHelper.is_terminal("COMMITTED") is False
        assert StateHelper.is_terminal("DELIVERED") is False

    def test_is_valid(self):
        """Valid state check."""
        assert StateHelper.is_valid("INITIATED") is True
        assert StateHelper.is_valid("SETTLED") is True
        assert StateHelper.is_valid("INVALID") is False

    def test_valid_transitions(self):
        """Get valid transitions."""
        from agirails.runtime.types import State

        transitions = StateHelper.valid_transitions("COMMITTED")
        assert "IN_PROGRESS" in transitions
        # AUDIT FIX: COMMITTED cannot skip to DELIVERED - must go through IN_PROGRESS
        assert "DELIVERED" not in transitions
        assert "CANCELLED" in transitions

        # Also test with State enum
        transitions = StateHelper.valid_transitions(State.COMMITTED)
        assert "IN_PROGRESS" in transitions

    def test_can_transition(self):
        """Check if transition is valid."""
        # AUDIT FIX: COMMITTED -> DELIVERED is no longer valid
        assert StateHelper.can_transition("COMMITTED", "DELIVERED") is False
        assert StateHelper.can_transition("COMMITTED", "IN_PROGRESS") is True
        assert StateHelper.can_transition("COMMITTED", "SETTLED") is False
        assert StateHelper.can_transition("DELIVERED", "SETTLED") is True

    def test_states_constant(self):
        """STATES tuple."""
        assert "INITIATED" in StateHelper.STATES
        assert "SETTLED" in StateHelper.STATES
        assert len(StateHelper.STATES) == 8


class TestDisputeWindow:
    """Tests for DisputeWindow utilities."""

    def test_hours(self):
        """Convert hours to seconds."""
        assert DisputeWindow.hours(1) == 3600
        assert DisputeWindow.hours(24) == 86400
        assert DisputeWindow.hours(0.5) == 1800

    def test_days(self):
        """Convert days to seconds."""
        assert DisputeWindow.days(1) == 86400
        assert DisputeWindow.days(2) == 172800
        assert DisputeWindow.days(30) == 2592000

    def test_is_active(self):
        """Check if dispute window is active."""
        now = int(time.time())
        assert DisputeWindow.is_active(now - 3600, 7200) is True  # 1h ago, 2h window
        assert DisputeWindow.is_active(now - 7200, 3600) is False  # 2h ago, 1h window

    def test_remaining(self):
        """Time remaining in window."""
        now = int(time.time())
        remaining = DisputeWindow.remaining(now - 3600, 7200)  # 1h ago, 2h window
        assert remaining >= 3598  # ~1h remaining
        assert remaining <= 3602

        # Expired window
        remaining = DisputeWindow.remaining(now - 7200, 3600)
        assert remaining == 0

    def test_constants(self):
        """DisputeWindow constants."""
        assert DisputeWindow.DEFAULT == 172800  # 2 days
        assert DisputeWindow.MIN == 3600  # 1 hour
        assert DisputeWindow.MAX == 30 * 24 * 3600  # 30 days


class TestServiceHash:
    """Tests for ServiceHash utilities."""

    def test_to_canonical(self):
        """Convert to canonical JSON."""
        metadata = ServiceMetadata(service="echo", input={"text": "hello"})
        canonical = ServiceHash.to_canonical(metadata)

        # Should be sorted, no spaces
        assert '"service":"echo"' in canonical
        assert '"input":{' in canonical

    def test_hash(self):
        """Hash service metadata."""
        metadata = ServiceMetadata(service="echo", input={"text": "hello"})
        hash_result = ServiceHash.hash(metadata)

        assert hash_result.startswith("0x")
        assert len(hash_result) == 66  # 0x + 64 hex chars

        # Same input = same hash
        hash2 = ServiceHash.hash(metadata)
        assert hash_result == hash2

    def test_hash_string(self):
        """Hash from string."""
        hash_result = ServiceHash.hash('{"service":"echo"}')
        assert hash_result.startswith("0x")
        assert len(hash_result) == 66

    def test_from_legacy(self):
        """Parse legacy format."""
        legacy = "service:echo;input:{\"text\":\"hello\"}"
        metadata = ServiceHash.from_legacy(legacy)

        assert metadata is not None
        assert metadata.service == "echo"
        assert metadata.input == {"text": "hello"}

    def test_from_legacy_invalid(self):
        """Invalid legacy format."""
        result = ServiceHash.from_legacy("invalid")
        assert result is None

    def test_get_service_name(self):
        """Extract service name."""
        metadata = ServiceMetadata(service="textgen")
        assert ServiceHash.get_service_name(metadata) == "textgen"

    def test_is_valid_hash(self):
        """Validate hash format."""
        assert ServiceHash.is_valid_hash("0x" + "a" * 64) is True
        assert ServiceHash.is_valid_hash("0x123") is False

    def test_zero_constant(self):
        """ZERO constant."""
        assert ServiceHash.ZERO == "0x" + "0" * 64


class TestConvenienceFunctions:
    """Tests for convenience wrapper functions."""

    def test_parse_usdc(self):
        """parse_usdc wrapper."""
        assert parse_usdc("100") == 100_000_000
        assert parse_usdc(50.5) == 50_500_000

    def test_format_usdc(self):
        """format_usdc wrapper."""
        assert format_usdc(100_000_000) == "100.00"
        assert format_usdc("50500000") == "50.50"

    def test_shorten_address(self):
        """shorten_address wrapper."""
        addr = "0x1234567890123456789012345678901234567890"
        assert shorten_address(addr) == "0x1234...7890"

    def test_hash_service_metadata(self):
        """hash_service_metadata wrapper."""
        result = hash_service_metadata("echo", {"text": "hello"})
        assert result.startswith("0x")
        assert len(result) == 66
