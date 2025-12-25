"""Tests for transaction error classes."""

from __future__ import annotations

import pytest

from agirails.errors.base import ACTPError
from agirails.errors.transaction import (
    TransactionNotFoundError,
    InvalidStateTransitionError,
    EscrowNotFoundError,
    InsufficientBalanceError,
    DeadlinePassedError,
    DeadlineExpiredError,
    DisputeWindowActiveError,
    ContractPausedError,
)


class TestTransactionNotFoundError:
    """Tests for TransactionNotFoundError."""

    def test_basic_creation(self) -> None:
        """Test creating with transaction ID."""
        error = TransactionNotFoundError("0x123abc")

        assert "0x123abc" in error.message
        assert error.code == "TRANSACTION_NOT_FOUND"
        assert error.tx_id == "0x123abc"
        assert error.tx_hash == "0x123abc"

    def test_inherits_from_actp_error(self) -> None:
        """Test inheritance."""
        error = TransactionNotFoundError("0x")
        assert isinstance(error, ACTPError)


class TestInvalidStateTransitionError:
    """Tests for InvalidStateTransitionError."""

    def test_basic_creation(self) -> None:
        """Test creating with states."""
        error = InvalidStateTransitionError("INITIATED", "SETTLED")

        assert "INITIATED" in error.message
        assert "SETTLED" in error.message
        assert error.code == "INVALID_STATE_TRANSITION"
        assert error.current_state == "INITIATED"
        assert error.target_state == "SETTLED"

    def test_with_tx_id(self) -> None:
        """Test with transaction ID."""
        error = InvalidStateTransitionError(
            "COMMITTED",
            "INITIATED",
            tx_id="0xabc",
        )

        assert error.tx_hash == "0xabc"

    def test_with_allowed_transitions(self) -> None:
        """Test with allowed transitions list."""
        error = InvalidStateTransitionError(
            "INITIATED",
            "SETTLED",
            allowed_transitions=["QUOTED", "COMMITTED", "CANCELLED"],
        )

        assert error.allowed_transitions == ["QUOTED", "COMMITTED", "CANCELLED"]
        assert error.details["allowed_transitions"] == ["QUOTED", "COMMITTED", "CANCELLED"]


class TestEscrowNotFoundError:
    """Tests for EscrowNotFoundError."""

    def test_basic_creation(self) -> None:
        """Test creating with escrow ID."""
        error = EscrowNotFoundError("escrow-123")

        assert "escrow-123" in error.message
        assert error.code == "ESCROW_NOT_FOUND"
        assert error.escrow_id == "escrow-123"


class TestInsufficientBalanceError:
    """Tests for InsufficientBalanceError."""

    def test_basic_creation(self) -> None:
        """Test creating with balance info."""
        error = InsufficientBalanceError(
            "0xRequester",
            required=1000000,
            available=500000,
        )

        assert "1000000" in error.message
        assert "500000" in error.message
        assert error.code == "INSUFFICIENT_BALANCE"
        assert error.address == "0xRequester"
        assert error.required == 1000000
        assert error.available == 500000

    def test_details_include_shortfall(self) -> None:
        """Test shortfall is calculated in details."""
        error = InsufficientBalanceError(
            "0x",
            required=1000,
            available=300,
        )

        assert error.details["shortfall_wei"] == "700"


class TestDeadlinePassedError:
    """Tests for DeadlinePassedError."""

    def test_basic_creation(self) -> None:
        """Test creating with timestamps."""
        error = DeadlinePassedError(
            deadline=1700000000,
            current_time=1700001000,
        )

        assert "1700000000" in error.message
        assert error.code == "DEADLINE_PASSED"
        assert error.deadline == 1700000000
        assert error.current_time == 1700001000

    def test_details_include_seconds_past(self) -> None:
        """Test seconds past is calculated."""
        error = DeadlinePassedError(
            deadline=1000,
            current_time=1500,
        )

        assert error.details["seconds_past"] == 500

    def test_with_tx_id(self) -> None:
        """Test with transaction ID."""
        error = DeadlinePassedError(
            deadline=1000,
            current_time=2000,
            tx_id="0xtx",
        )

        assert error.tx_hash == "0xtx"


class TestDeadlineExpiredError:
    """Tests for DeadlineExpiredError alias."""

    def test_is_alias_for_deadline_passed(self) -> None:
        """Test that DeadlineExpiredError is alias."""
        assert DeadlineExpiredError is DeadlinePassedError


class TestDisputeWindowActiveError:
    """Tests for DisputeWindowActiveError."""

    def test_basic_creation(self) -> None:
        """Test creating with remaining seconds."""
        error = DisputeWindowActiveError(remaining_seconds=3600)

        assert "3600" in error.message
        assert error.code == "DISPUTE_WINDOW_ACTIVE"
        assert error.remaining_seconds == 3600

    def test_with_escrow_id(self) -> None:
        """Test with escrow ID."""
        error = DisputeWindowActiveError(
            remaining_seconds=1800,
            escrow_id="escrow-abc",
        )

        assert error.escrow_id == "escrow-abc"
        assert error.details["escrow_id"] == "escrow-abc"


class TestContractPausedError:
    """Tests for ContractPausedError."""

    def test_basic_creation(self) -> None:
        """Test creating with default contract name."""
        error = ContractPausedError()

        assert "ACTPKernel" in error.message
        assert error.code == "CONTRACT_PAUSED"
        assert error.contract_name == "ACTPKernel"

    def test_with_custom_contract(self) -> None:
        """Test with custom contract name."""
        error = ContractPausedError(contract_name="EscrowVault")

        assert "EscrowVault" in error.message
        assert error.contract_name == "EscrowVault"
        assert error.details["contract"] == "EscrowVault"
