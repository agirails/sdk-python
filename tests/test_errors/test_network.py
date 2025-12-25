"""Tests for network error classes."""

from __future__ import annotations

import pytest

from agirails.errors.base import ACTPError
from agirails.errors.network import (
    NetworkError,
    TransactionRevertedError,
    SignatureVerificationError,
)


class TestNetworkError:
    """Tests for NetworkError."""

    def test_basic_creation(self) -> None:
        """Test creating with message."""
        error = NetworkError("Connection failed")

        assert error.message == "Connection failed"
        assert error.code == "NETWORK_ERROR"
        assert error.endpoint is None
        assert error.status_code is None

    def test_with_endpoint(self) -> None:
        """Test with endpoint URL."""
        error = NetworkError(
            "RPC timeout",
            endpoint="https://rpc.base.org",
        )

        assert error.endpoint == "https://rpc.base.org"
        assert error.details["endpoint"] == "https://rpc.base.org"

    def test_with_status_code(self) -> None:
        """Test with HTTP status code."""
        error = NetworkError(
            "Server error",
            status_code=503,
        )

        assert error.status_code == 503
        assert error.details["status_code"] == 503

    def test_inherits_from_actp_error(self) -> None:
        """Test inheritance."""
        error = NetworkError("Test")
        assert isinstance(error, ACTPError)


class TestTransactionRevertedError:
    """Tests for TransactionRevertedError."""

    def test_basic_creation(self) -> None:
        """Test creating with tx hash."""
        tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        error = TransactionRevertedError(tx_hash)

        assert tx_hash[:18] in error.message
        assert error.code == "TRANSACTION_REVERTED"
        assert error.tx_hash == tx_hash

    def test_with_revert_reason(self) -> None:
        """Test with revert reason."""
        error = TransactionRevertedError(
            "0xabc123",
            revert_reason="Insufficient balance",
        )

        assert error.revert_reason == "Insufficient balance"
        assert "Insufficient balance" in error.message
        assert error.details["revert_reason"] == "Insufficient balance"

    def test_with_gas_info(self) -> None:
        """Test with gas information."""
        error = TransactionRevertedError(
            "0xdef456",
            gas_used=21000,
            block_number=12345678,
        )

        assert error.gas_used == 21000
        assert error.block_number == 12345678
        assert error.details["gas_used"] == 21000
        assert error.details["block_number"] == 12345678


class TestSignatureVerificationError:
    """Tests for SignatureVerificationError."""

    def test_basic_creation(self) -> None:
        """Test creating with message."""
        error = SignatureVerificationError("Invalid signature")

        assert error.message == "Invalid signature"
        assert error.code == "SIGNATURE_VERIFICATION_FAILED"

    def test_with_signer_info(self) -> None:
        """Test with signer addresses."""
        error = SignatureVerificationError(
            "Signer mismatch",
            expected_signer="0xExpected",
            actual_signer="0xActual",
        )

        assert error.expected_signer == "0xExpected"
        assert error.actual_signer == "0xActual"
        assert error.details["expected_signer"] == "0xExpected"
        assert error.details["actual_signer"] == "0xActual"

    def test_signature_preview_truncated(self) -> None:
        """Test that signature is truncated for security."""
        long_sig = "0x" + "ab" * 65  # 130 chars + 0x

        error = SignatureVerificationError(
            "Invalid",
            signature=long_sig,
        )

        # Should only show first 10 and last 8 chars
        preview = error.details["signature_preview"]
        assert preview.startswith(long_sig[:10])
        assert preview.endswith(long_sig[-8:])
        assert "..." in preview
