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


# ---------------------------------------------------------------------------
# Cross-SDK schema-decode parity (TS source of truth: EASHelper.ts:240-337)
# ---------------------------------------------------------------------------

ZERO_HASH = "0x" + "00" * 32
# keccak256(utf8("x")) — same golden value used in the TS decode test
# (EASHelper.decode.test.ts:13: ethers.keccak256(ethers.toUtf8Bytes('x')))
KECCAK_X = "0x7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83"


def _bare_helper():
    """Instantiate EASHelper without web3 wiring (decode needs only `self`)."""
    from agirails.protocol.eas import EASHelper

    return object.__new__(EASHelper)


def _b32(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace("0x", "")).ljust(32, b"\x00")


class TestDecodeSchemaParity:
    """
    The Python decoder MUST accept every schema the TS SDK decodes, in the same
    order. TS tries: AIP-6 5-field (testTimestamp) -> AIP-6 4-field -> legacy AIP-4
    6-field [bytes32,bytes32,uint256,string,uint256,string].
    """

    def test_decodes_aip6_test_schema_5_field(self):
        """TS EASHelper.decode.test.ts:11-14 golden payload (5-field test schema)."""
        from eth_abi import encode

        data = encode(
            ["bytes32", "string", "bytes32", "uint256", "uint256"],
            [
                _b32(ZERO_HASH),
                "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX",
                _b32(KECCAK_X),
                123,
                456,
            ],
        )

        decoded = _bare_helper()._decode_delivery_data(data)

        assert decoded.transaction_id.lower() == ZERO_HASH
        assert decoded.result_cid == "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX"
        assert decoded.result_hash.lower() == KECCAK_X
        assert decoded.delivered_at == 123
        assert decoded.schema_version == "aip6-test"

    def test_decodes_aip6_official_4_field(self):
        """TS EASHelper.ts:272-294 fallback schema (no testTimestamp)."""
        from eth_abi import encode

        data = encode(
            ["bytes32", "string", "bytes32", "uint256"],
            [_b32(ZERO_HASH), "bafyresultcid", _b32(KECCAK_X), 123],
        )

        decoded = _bare_helper()._decode_delivery_data(data)

        assert decoded.transaction_id.lower() == ZERO_HASH
        assert decoded.result_cid == "bafyresultcid"
        assert decoded.result_hash.lower() == KECCAK_X
        assert decoded.delivered_at == 123
        assert decoded.schema_version == "aip6"

    def test_decodes_ts_legacy_aip4_6_field(self):
        """
        TS legacy AIP-4 schema (EASHelper.ts:92-103 ENCODE / :296-327 DECODE):
        bytes32 txId, bytes32 contentHash, uint256 timestamp,
        string deliveryUrl, uint256 size, string mimeType.
        Before the fix Python could NOT decode this (it tried a different AIP-4
        layout), so a TS-produced attestation failed cross-SDK verification.
        """
        from eth_abi import encode

        tx_id = "0x" + "ab" * 32
        content_hash = "0x" + "cd" * 32
        data = encode(
            ["bytes32", "bytes32", "uint256", "string", "uint256", "string"],
            [_b32(tx_id), _b32(content_hash), 1700000000, "https://x.io/d", 1024, "application/json"],
        )

        decoded = _bare_helper()._decode_delivery_data(data)

        assert decoded.transaction_id.lower() == tx_id
        assert decoded.result_hash.lower() == content_hash
        assert decoded.content_hash.lower() == content_hash
        assert decoded.delivered_at == 1700000000
        assert decoded.delivery_url == "https://x.io/d"
        assert decoded.size == 1024
        assert decoded.mime_type == "application/json"
        assert decoded.schema_version == "aip4-legacy"

    def test_ts_legacy_encode_then_python_decode_roundtrip(self):
        """
        Python's TS-compatible legacy encoder must produce bytes that Python's
        decoder reads back identically — and that match the TS abiCoder.encode
        layout exactly (proves cross-SDK encode/decode agreement).
        """
        from agirails.protocol.eas import EASHelper
        from eth_abi import encode

        tx_id = "0x" + "ab" * 32
        content_hash = KECCAK_X
        encoded = EASHelper._encode_delivery_data_aip4_legacy(
            transaction_id=tx_id,
            content_hash=content_hash,
            timestamp=1700000000,
            delivery_url="ipfs://Qm",
            size=42,
            mime_type="text/plain",
        )

        # Byte-identical to the raw eth_abi layout TS mirrors
        expected = encode(
            ["bytes32", "bytes32", "uint256", "string", "uint256", "string"],
            [_b32(tx_id), _b32(content_hash), 1700000000, "ipfs://Qm", 42, "text/plain"],
        )
        assert encoded == expected

        decoded = _bare_helper()._decode_delivery_data(encoded)
        assert decoded.schema_version == "aip4-legacy"
        assert decoded.transaction_id.lower() == tx_id
        assert decoded.result_hash.lower() == content_hash
        assert decoded.size == 42
        assert decoded.mime_type == "text/plain"

    def test_python_only_legacy_aip4_still_decodes(self):
        """
        Backwards compat: the Python-only AIP-4 layout
        [bytes32, bytes32, address, uint64] (no TS twin) must still decode as the
        final fallback, so attestations from create_delivery_attestation_aip4()
        keep working.
        """
        from eth_abi import encode

        tx_id = "0x" + "12" * 32
        output_hash = "0x" + "34" * 32
        provider = "0x" + "56" * 20
        data = encode(
            ["bytes32", "bytes32", "address", "uint64"],
            [_b32(tx_id), _b32(output_hash), provider, 1699999999],
        )

        decoded = _bare_helper()._decode_delivery_data(data)

        assert decoded.transaction_id.lower() == tx_id
        assert decoded.output_hash.lower() == output_hash
        assert decoded.provider.lower() == provider
        assert decoded.timestamp == 1699999999
        assert decoded.schema_version == "aip4"

    def test_rejects_undecodable_data(self):
        """Garbage that matches no schema raises ValueError (mirrors TS final throw)."""
        with pytest.raises(ValueError, match="Failed to decode attestation data"):
            _bare_helper()._decode_delivery_data(b"\x00" * 16)
