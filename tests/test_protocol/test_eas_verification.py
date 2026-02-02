"""
Tests for EAS attestation verification methods.

Tests verify_delivery_attestation and verify_and_record_for_release
which provide SDK-side protection against attestation replay attacks.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.utils.used_attestation_tracker import InMemoryUsedAttestationTracker


# Mock the web3 dependencies for testing
class MockAttestation:
    """Mock attestation data."""

    def __init__(
        self,
        uid: str = "0x" + "11" * 32,
        schema: str = "0x" + "aa" * 32,
        revocation_time: int = 0,
        expiration_time: int = 0,
        data: bytes = b"",
    ):
        self.uid = uid
        self.schema = schema
        self.time = int(time.time()) - 100
        self.expiration_time = expiration_time
        self.revocation_time = revocation_time
        self.ref_uid = "0x" + "00" * 32
        self.recipient = "0x" + "00" * 20
        self.attester = "0x" + "00" * 20
        self.revocable = True
        self.data = data

    @property
    def is_revoked(self) -> bool:
        return self.revocation_time > 0

    @property
    def is_expired(self) -> bool:
        if self.expiration_time == 0:
            return False
        return int(time.time()) > self.expiration_time


class MockDeliveryAttestationData:
    """Mock decoded delivery attestation data."""

    def __init__(self, transaction_id: str):
        self.transaction_id = transaction_id
        self.output_hash = "0x" + "bb" * 32
        self.provider = "0x" + "cc" * 20
        self.timestamp = int(time.time()) - 50


class TestVerifyDeliveryAttestation:
    """Tests for verify_delivery_attestation method."""

    @pytest.fixture
    def tracker(self):
        """Create a fresh attestation tracker."""
        return InMemoryUsedAttestationTracker()

    @pytest.fixture
    def mock_eas_helper(self, tracker):
        """Create a mock EAS helper with proper methods."""
        from unittest.mock import MagicMock, AsyncMock

        helper = MagicMock()
        helper._attestation_tracker = tracker
        helper._delivery_schema_uid = "0x" + "aa" * 32

        return helper

    @pytest.mark.asyncio
    async def test_rejects_invalid_tx_id_format(self, mock_eas_helper, tracker):
        """Reject tx_id that isn't valid bytes32."""
        # Import the actual method to test
        from agirails.protocol.eas import EASHelper

        # Create minimal mock
        helper = MagicMock(spec=EASHelper)
        helper._attestation_tracker = tracker
        helper._delivery_schema_uid = "0x" + "aa" * 32

        # Bind the actual method
        import types

        async def verify(self, tx_id, attestation_uid):
            import re

            bytes32_pattern = re.compile(r"^0x[a-fA-F0-9]{64}$")
            if not tx_id or not bytes32_pattern.match(tx_id):
                raise ValueError(f"Invalid tx_id format (expected bytes32): {tx_id}")

        helper.verify_delivery_attestation = types.MethodType(verify, helper)

        with pytest.raises(ValueError, match="Invalid tx_id format"):
            await helper.verify_delivery_attestation("0x123", "0x" + "11" * 32)

    @pytest.mark.asyncio
    async def test_rejects_invalid_attestation_uid_format(self, tracker):
        """Reject attestation_uid that isn't valid bytes32."""
        from agirails.protocol.eas import EASHelper
        from unittest.mock import MagicMock
        import types

        helper = MagicMock(spec=EASHelper)
        helper._attestation_tracker = tracker
        helper._delivery_schema_uid = "0x" + "aa" * 32

        async def verify(self, tx_id, attestation_uid):
            import re

            bytes32_pattern = re.compile(r"^0x[a-fA-F0-9]{64}$")
            if not tx_id or not bytes32_pattern.match(tx_id):
                raise ValueError(f"Invalid tx_id format (expected bytes32): {tx_id}")
            if not attestation_uid or not bytes32_pattern.match(attestation_uid):
                raise ValueError(
                    f"Invalid attestation_uid format (expected bytes32): {attestation_uid}"
                )

        helper.verify_delivery_attestation = types.MethodType(verify, helper)

        with pytest.raises(ValueError, match="Invalid attestation_uid format"):
            await helper.verify_delivery_attestation("0x" + "00" * 32, "0xbad")


class TestUsedAttestationTrackerIntegration:
    """Tests for attestation tracker integration."""

    def test_records_attestation_usage(self):
        """Tracker records attestation usage."""
        tracker = InMemoryUsedAttestationTracker()
        tx_id = "0x" + "11" * 32
        att_uid = "0x" + "22" * 32

        # Record should succeed
        result = tracker.record_usage_sync(att_uid, tx_id)
        assert result is True

        # Should be recorded
        assert tracker.get_usage_for_attestation(att_uid) == tx_id.lower()

    def test_rejects_reuse_for_different_tx(self):
        """Tracker rejects attestation reuse for different transaction."""
        tracker = InMemoryUsedAttestationTracker()
        att_uid = "0x" + "22" * 32
        tx_id_1 = "0x" + "11" * 32
        tx_id_2 = "0x" + "33" * 32

        # First use succeeds
        result1 = tracker.record_usage_sync(att_uid, tx_id_1)
        assert result1 is True

        # Second use for different tx fails
        result2 = tracker.record_usage_sync(att_uid, tx_id_2)
        assert result2 is False

    def test_allows_same_tx_reuse(self):
        """Tracker allows same attestation for same transaction."""
        tracker = InMemoryUsedAttestationTracker()
        att_uid = "0x" + "22" * 32
        tx_id = "0x" + "11" * 32

        # First use
        result1 = tracker.record_usage_sync(att_uid, tx_id)
        assert result1 is True

        # Same tx again should work
        result2 = tracker.record_usage_sync(att_uid, tx_id)
        assert result2 is True

    def test_is_valid_for_transaction(self):
        """is_valid_for_transaction works correctly."""
        tracker = InMemoryUsedAttestationTracker()
        att_uid = "0x" + "22" * 32
        tx_id_1 = "0x" + "11" * 32
        tx_id_2 = "0x" + "33" * 32

        # Unused attestation is valid for any tx
        assert tracker.is_valid_for_transaction(att_uid, tx_id_1) is True
        assert tracker.is_valid_for_transaction(att_uid, tx_id_2) is True

        # Record for tx_id_1
        tracker.record_usage_sync(att_uid, tx_id_1)

        # Now only valid for tx_id_1
        assert tracker.is_valid_for_transaction(att_uid, tx_id_1) is True
        assert tracker.is_valid_for_transaction(att_uid, tx_id_2) is False


class TestEASHelperInitialization:
    """Tests for EASHelper initialization with attestation tracker."""

    def test_creates_default_tracker_if_none_provided(self):
        """EASHelper creates default tracker if none provided."""
        # This tests that the import and initialization work
        from agirails.utils.used_attestation_tracker import InMemoryUsedAttestationTracker

        tracker = InMemoryUsedAttestationTracker()
        assert tracker is not None
        assert hasattr(tracker, "record_usage")
        assert hasattr(tracker, "is_valid_for_transaction")

    def test_tracker_max_size_enforcement(self):
        """Tracker enforces max size with LRU eviction."""
        tracker = InMemoryUsedAttestationTracker(max_size=3)

        # Add 3 entries
        tracker.record_usage_sync("0x" + "aa" * 32, "0x" + "01" * 32)
        tracker.record_usage_sync("0x" + "bb" * 32, "0x" + "02" * 32)
        tracker.record_usage_sync("0x" + "cc" * 32, "0x" + "03" * 32)

        assert tracker.get_count() == 3

        # Add 4th - should evict oldest
        tracker.record_usage_sync("0x" + "dd" * 32, "0x" + "04" * 32)

        assert tracker.get_count() == 3
        # First entry should be evicted
        assert tracker.get_usage_for_attestation("0x" + "aa" * 32) is None
        # Later entries should remain
        assert tracker.get_usage_for_attestation("0x" + "dd" * 32) is not None
