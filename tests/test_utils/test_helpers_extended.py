"""
Extended Coverage Tests for helpers.py.

These tests cover additional code paths not fully covered in test_helpers.py:
- USDC: invalid input, bounds checking
- Deadline: validation errors, expired formatting
- Address/Bytes32: truncate short values
- StateHelper: State enum handling, invalid state strings
- ServiceHash: optional fields, legacy parsing
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agirails.runtime.types import State
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


class TestUSDCExtended:
    """Extended tests for USDC class."""

    def test_to_wei_invalid_whole_part(self):
        """Reject invalid (non-numeric) whole part."""
        with pytest.raises(ValueError, match="Invalid USDC amount"):
            USDC.to_wei("abc.50")

    def test_to_wei_exceeds_max_human_amount(self):
        """Reject amount exceeding maximum human-readable value."""
        huge_amount = USDC.MAX_AMOUNT_HUMAN + 1
        with pytest.raises(ValueError, match="exceeds maximum"):
            USDC.to_wei(str(huge_amount))

    def test_to_wei_exceeds_max_wei(self):
        """Reject wei amount exceeding maximum."""
        # This triggers the second bounds check (line 107)
        # Create an amount that's just below max human but exceeds max wei when converted
        # Actually MAX_AMOUNT_HUMAN * 1_000_000 = MAX_AMOUNT_WEI, so they're aligned
        # We need to test with validate_bounds=True and a value near the edge
        with pytest.raises(ValueError, match="exceeds maximum"):
            USDC.to_wei(str(USDC.MAX_AMOUNT_HUMAN + 1))

    def test_to_wei_skip_bounds_validation(self):
        """Allow out-of-bounds when validate_bounds=False."""
        huge_amount = USDC.MAX_AMOUNT_HUMAN * 2
        result = USDC.to_wei(str(huge_amount), validate_bounds=False)
        assert result == huge_amount * 1_000_000

    def test_from_wei_exceeds_max(self):
        """Reject wei amount exceeding maximum in from_wei."""
        huge_wei = USDC.MAX_AMOUNT_WEI * 2
        with pytest.raises(ValueError, match="exceeds maximum"):
            USDC.from_wei(huge_wei)

    def test_from_wei_skip_bounds_validation(self):
        """Allow out-of-bounds when validate_bounds=False."""
        huge_wei = USDC.MAX_AMOUNT_WEI * 2
        result = USDC.from_wei(huge_wei, validate_bounds=False)
        assert result  # Just verify it returns something

    def test_from_wei_negative_divisor_exponent(self):
        """Test decimals > 6 (negative divisor exponent)."""
        # When decimals > 6, divisor_exponent becomes negative
        result = USDC.from_wei(100_500_000, decimals=8)
        # 100.500000 with 8 decimals = 100.50000000
        assert result == "100.50000000"

    def test_from_wei_zero_decimals(self):
        """Test decimals=0 (no decimal point)."""
        result = USDC.from_wei(100_500_000, decimals=0)
        assert result == "101"  # Rounded

    def test_from_wei_string_input(self):
        """Accept string input for wei amount."""
        result = USDC.from_wei("100500000")
        assert result == "100.50"


class TestDeadlineExtended:
    """Extended tests for Deadline class."""

    def test_hours_from_now_zero_raises(self):
        """Reject zero hours."""
        with pytest.raises(ValueError, match="must be positive"):
            Deadline.hours_from_now(0)

    def test_hours_from_now_negative_raises(self):
        """Reject negative hours."""
        with pytest.raises(ValueError, match="must be positive"):
            Deadline.hours_from_now(-5)

    def test_hours_from_now_exceeds_max_raises(self):
        """Reject hours exceeding maximum."""
        max_hours = 24 * Deadline.MAX_DEADLINE_DAYS
        with pytest.raises(ValueError, match="exceeds maximum"):
            Deadline.hours_from_now(max_hours + 1)

    def test_days_from_now_zero_raises(self):
        """Reject zero days."""
        with pytest.raises(ValueError, match="must be positive"):
            Deadline.days_from_now(0)

    def test_days_from_now_negative_raises(self):
        """Reject negative days."""
        with pytest.raises(ValueError, match="must be positive"):
            Deadline.days_from_now(-1)

    def test_days_from_now_exceeds_max_raises(self):
        """Reject days exceeding maximum."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            Deadline.days_from_now(Deadline.MAX_DEADLINE_DAYS + 1)

    def test_format_expired_seconds(self):
        """Format deadline expired seconds ago."""
        now = int(time.time())
        deadline = now - 30  # 30 seconds ago
        result = Deadline.format(deadline)
        assert "expired" in result
        assert "seconds ago" in result

    def test_format_expired_minutes(self):
        """Format deadline expired minutes ago."""
        now = int(time.time())
        deadline = now - 300  # 5 minutes ago
        result = Deadline.format(deadline)
        assert "expired" in result
        assert "minutes ago" in result

    def test_format_expired_hours(self):
        """Format deadline expired hours ago."""
        now = int(time.time())
        deadline = now - 7200  # 2 hours ago
        result = Deadline.format(deadline)
        assert "expired" in result
        assert "hours ago" in result

    def test_format_expired_days(self):
        """Format deadline expired days ago."""
        now = int(time.time())
        deadline = now - 172800  # 2 days ago
        result = Deadline.format(deadline)
        assert "expired" in result
        assert "days ago" in result


class TestAddressExtended:
    """Extended tests for Address class."""

    def test_truncate_short_address(self):
        """Short address returned as-is."""
        short = "0x1234"
        result = Address.truncate(short, chars=4)
        assert result == short  # Too short to truncate

    def test_truncate_exact_length(self):
        """Address exactly at truncation threshold."""
        # With chars=4, threshold is 2 + 4*2 = 10 chars
        exact = "0x12345678"  # 10 chars
        result = Address.truncate(exact, chars=4)
        assert result == exact  # Not truncated


class TestBytes32Extended:
    """Extended tests for Bytes32 class."""

    def test_truncate_short_value(self):
        """Short bytes32 value returned as-is."""
        short = "0x1234"
        result = Bytes32.truncate(short, chars=6)
        assert result == short  # Too short to truncate

    def test_truncate_exact_length(self):
        """Value exactly at truncation threshold."""
        # With chars=6, threshold is 2 + 6*2 = 14 chars
        exact = "0x123456789abc"  # 14 chars
        result = Bytes32.truncate(exact, chars=6)
        assert result == exact  # Not truncated


class TestStateHelperExtended:
    """Extended tests for StateHelper class."""

    def test_is_terminal_with_state_enum(self):
        """Test is_terminal with State enum."""
        assert StateHelper.is_terminal(State.SETTLED) is True
        assert StateHelper.is_terminal(State.CANCELLED) is True
        assert StateHelper.is_terminal(State.COMMITTED) is False

    def test_valid_transitions_invalid_state_string(self):
        """Return empty list for invalid state string."""
        result = StateHelper.valid_transitions("INVALID_STATE")
        assert result == []

    def test_valid_transitions_with_state_enum(self):
        """Test valid_transitions with State enum."""
        result = StateHelper.valid_transitions(State.COMMITTED)
        assert "IN_PROGRESS" in result or "DELIVERED" in result

    def test_can_transition_invalid_from_state(self):
        """Return False for invalid from_state string."""
        result = StateHelper.can_transition("INVALID", "COMMITTED")
        assert result is False

    def test_can_transition_invalid_to_state(self):
        """Return False for invalid to_state string."""
        result = StateHelper.can_transition("COMMITTED", "INVALID")
        assert result is False

    def test_can_transition_both_state_enums(self):
        """Test can_transition with both State enums."""
        result = StateHelper.can_transition(State.COMMITTED, State.DELIVERED)
        assert result is True

        result = StateHelper.can_transition(State.SETTLED, State.COMMITTED)
        assert result is False  # Can't transition from terminal

    def test_can_transition_string_to_enum(self):
        """Test can_transition with string from and State enum to."""
        result = StateHelper.can_transition("COMMITTED", State.DELIVERED)
        assert result is True


class TestServiceHashExtended:
    """Extended tests for ServiceHash class."""

    def test_to_canonical_with_all_optional_fields(self):
        """Test canonical JSON with all optional fields."""
        metadata = ServiceMetadata(
            service="test-service",
            input={"key": "value"},
            version="1.0.0",
            timestamp=1234567890,
        )
        result = ServiceHash.to_canonical(metadata)

        # Verify all fields present in order
        assert '"service":"test-service"' in result
        assert '"input":{"key":"value"}' in result
        assert '"version":"1.0.0"' in result
        assert '"timestamp":1234567890' in result

        # Verify insertion order (service before input before version before timestamp)
        assert result.index("service") < result.index("input")
        assert result.index("input") < result.index("version")
        assert result.index("version") < result.index("timestamp")

    def test_to_canonical_with_version_only(self):
        """Test canonical JSON with version but no input."""
        metadata = ServiceMetadata(
            service="test-service",
            input=None,
            version="2.0.0",
        )
        result = ServiceHash.to_canonical(metadata)

        assert '"service":"test-service"' in result
        assert '"version":"2.0.0"' in result
        assert "input" not in result  # No input field

    def test_to_canonical_with_timestamp_only(self):
        """Test canonical JSON with timestamp but no input/version."""
        metadata = ServiceMetadata(
            service="test-service",
            timestamp=9999999999,
        )
        result = ServiceHash.to_canonical(metadata)

        assert '"service":"test-service"' in result
        assert '"timestamp":9999999999' in result
        assert "input" not in result
        assert "version" not in result

    def test_from_legacy_with_json_input(self):
        """Parse legacy format with valid JSON input."""
        legacy = 'service:echo;input:{"text":"hello"}'
        result = ServiceHash.from_legacy(legacy)

        assert result is not None
        assert result.service == "echo"
        assert result.input == {"text": "hello"}

    def test_from_legacy_with_non_json_input(self):
        """Parse legacy format with non-JSON input (raw string)."""
        legacy = "service:echo;input:plain-text-value"
        result = ServiceHash.from_legacy(legacy)

        assert result is not None
        assert result.service == "echo"
        assert result.input == "plain-text-value"

    def test_from_legacy_invalid_format(self):
        """Return None for invalid legacy format."""
        result = ServiceHash.from_legacy("not-a-valid-format")
        assert result is None

        result = ServiceHash.from_legacy("random:text;stuff")
        assert result is None

    def test_get_service_name_from_string(self):
        """Extract service name from legacy string."""
        result = ServiceHash.get_service_name("service:my-service;input:data")
        assert result == "my-service"

    def test_get_service_name_from_invalid_string(self):
        """Return 'unknown' for invalid legacy string."""
        result = ServiceHash.get_service_name("invalid-string")
        assert result == "unknown"

    def test_get_service_name_from_metadata(self):
        """Extract service name from ServiceMetadata object."""
        metadata = ServiceMetadata(service="test-service")
        result = ServiceHash.get_service_name(metadata)
        assert result == "test-service"

    def test_hash_with_string_input(self):
        """Hash pre-formatted canonical JSON string."""
        canonical = '{"service":"echo"}'
        result = ServiceHash.hash(canonical)

        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars


class TestConvenienceWrappers:
    """Test convenience wrapper functions."""

    def test_parse_usdc(self):
        """parse_usdc wraps USDC.to_wei."""
        assert parse_usdc("100") == 100_000_000
        assert parse_usdc(50) == 50_000_000

    def test_format_usdc(self):
        """format_usdc wraps USDC.from_wei."""
        assert format_usdc(100_000_000) == "100.00"
        assert format_usdc("100500000") == "100.50"

    def test_shorten_address(self):
        """shorten_address wraps Address.truncate."""
        addr = "0x1234567890123456789012345678901234567890"
        assert shorten_address(addr) == "0x1234...7890"
        assert shorten_address(addr, 6) == "0x123456...567890"

    def test_hash_service_metadata(self):
        """hash_service_metadata creates and hashes ServiceMetadata."""
        result = hash_service_metadata("echo", {"text": "hello"})
        assert result.startswith("0x")
        assert len(result) == 66
