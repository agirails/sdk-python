"""Tests for transaction types."""

import pytest
from datetime import datetime, timedelta
from agirails.types.transaction import (
    Transaction,
    TransactionState,
    TransactionFilter,
    is_valid_transition,
    VALID_TRANSITIONS,
)


class TestTransactionState:
    """Tests for TransactionState enum."""

    def test_state_values(self):
        """Test state integer values."""
        assert TransactionState.INITIATED.value == 0
        assert TransactionState.QUOTED.value == 1
        assert TransactionState.COMMITTED.value == 2
        assert TransactionState.IN_PROGRESS.value == 3
        assert TransactionState.DELIVERED.value == 4
        assert TransactionState.SETTLED.value == 5
        assert TransactionState.DISPUTED.value == 6
        assert TransactionState.CANCELLED.value == 7

    def test_terminal_states(self):
        """Test is_terminal property."""
        assert TransactionState.SETTLED.is_terminal
        assert TransactionState.CANCELLED.is_terminal
        assert not TransactionState.INITIATED.is_terminal
        assert not TransactionState.DELIVERED.is_terminal

    def test_active_states(self):
        """Test is_active property."""
        assert TransactionState.INITIATED.is_active
        assert TransactionState.COMMITTED.is_active
        assert not TransactionState.SETTLED.is_active
        assert not TransactionState.CANCELLED.is_active

    def test_can_cancel(self):
        """Test can_cancel property."""
        assert TransactionState.INITIATED.can_cancel
        assert TransactionState.QUOTED.can_cancel
        assert TransactionState.COMMITTED.can_cancel
        assert not TransactionState.DELIVERED.can_cancel
        assert not TransactionState.SETTLED.can_cancel

    def test_can_dispute(self):
        """Test can_dispute property."""
        assert TransactionState.DELIVERED.can_dispute
        assert not TransactionState.INITIATED.can_dispute
        assert not TransactionState.SETTLED.can_dispute

    def test_next_states(self):
        """Test next_states method."""
        initiated_next = TransactionState.INITIATED.next_states()
        assert TransactionState.QUOTED in initiated_next
        assert TransactionState.COMMITTED in initiated_next
        assert TransactionState.CANCELLED in initiated_next

        delivered_next = TransactionState.DELIVERED.next_states()
        assert TransactionState.SETTLED in delivered_next
        assert TransactionState.DISPUTED in delivered_next

        # Terminal states have no next states
        assert TransactionState.SETTLED.next_states() == []
        assert TransactionState.CANCELLED.next_states() == []


class TestValidTransitions:
    """Tests for state transition validation."""

    def test_valid_happy_path(self):
        """Test valid happy path transitions."""
        assert is_valid_transition(TransactionState.INITIATED, TransactionState.COMMITTED)
        assert is_valid_transition(TransactionState.COMMITTED, TransactionState.DELIVERED)
        assert is_valid_transition(TransactionState.DELIVERED, TransactionState.SETTLED)

    def test_valid_dispute_path(self):
        """Test valid dispute path transitions."""
        assert is_valid_transition(TransactionState.DELIVERED, TransactionState.DISPUTED)
        assert is_valid_transition(TransactionState.DISPUTED, TransactionState.SETTLED)

    def test_valid_cancel_path(self):
        """Test valid cancellation transitions."""
        assert is_valid_transition(TransactionState.INITIATED, TransactionState.CANCELLED)
        assert is_valid_transition(TransactionState.QUOTED, TransactionState.CANCELLED)
        assert is_valid_transition(TransactionState.COMMITTED, TransactionState.CANCELLED)

    def test_invalid_backwards(self):
        """Test that backwards transitions are invalid."""
        assert not is_valid_transition(TransactionState.COMMITTED, TransactionState.INITIATED)
        assert not is_valid_transition(TransactionState.DELIVERED, TransactionState.COMMITTED)
        assert not is_valid_transition(TransactionState.SETTLED, TransactionState.DELIVERED)

    def test_invalid_from_terminal(self):
        """Test that no transitions from terminal states."""
        assert not is_valid_transition(TransactionState.SETTLED, TransactionState.INITIATED)
        assert not is_valid_transition(TransactionState.CANCELLED, TransactionState.INITIATED)

    def test_invalid_skip_states(self):
        """Test invalid state skipping."""
        # Can't go from DELIVERED to CANCELLED
        assert not is_valid_transition(TransactionState.DELIVERED, TransactionState.CANCELLED)


class TestTransaction:
    """Tests for Transaction dataclass."""

    def test_basic_creation(self):
        """Test creating a transaction."""
        tx = Transaction(
            id="0x123",
            state=TransactionState.INITIATED,
            requester="0xabc",
            provider="0xdef",
            amount=1000000,
        )
        assert tx.id == "0x123"
        assert tx.state == TransactionState.INITIATED
        assert tx.amount == 1000000

    def test_amount_usdc(self):
        """Test USDC amount conversion."""
        tx = Transaction(
            id="0x123",
            state=TransactionState.INITIATED,
            requester="0xabc",
            provider="0xdef",
            amount=1500000,  # 1.5 USDC
            fee=50000,  # 0.05 USDC
        )
        assert tx.amount_usdc == 1.5
        assert tx.fee_usdc == 0.05
        assert tx.total_usdc == 1.55

    def test_deadline_datetime(self):
        """Test deadline conversion."""
        deadline_ts = int((datetime.now() + timedelta(hours=1)).timestamp())
        tx = Transaction(
            id="0x123",
            state=TransactionState.INITIATED,
            requester="0xabc",
            provider="0xdef",
            amount=1000000,
            deadline=deadline_ts,
        )
        deadline_dt = tx.deadline_datetime
        assert isinstance(deadline_dt, datetime)

    def test_is_expired(self):
        """Test expiration check."""
        # Past deadline
        past_deadline = int((datetime.now() - timedelta(hours=1)).timestamp())
        tx_expired = Transaction(
            id="0x123",
            state=TransactionState.INITIATED,
            requester="0xabc",
            provider="0xdef",
            amount=1000000,
            deadline=past_deadline,
        )
        assert tx_expired.is_expired

        # Future deadline
        future_deadline = int((datetime.now() + timedelta(hours=1)).timestamp())
        tx_not_expired = Transaction(
            id="0x456",
            state=TransactionState.INITIATED,
            requester="0xabc",
            provider="0xdef",
            amount=1000000,
            deadline=future_deadline,
        )
        assert not tx_not_expired.is_expired

    def test_to_dict(self):
        """Test dictionary conversion."""
        tx = Transaction(
            id="0x123",
            state=TransactionState.COMMITTED,
            requester="0xabc",
            provider="0xdef",
            amount=1000000,
            fee=10000,
        )
        d = tx.to_dict()

        assert d["id"] == "0x123"
        assert d["state"] == 2  # COMMITTED
        assert d["stateName"] == "COMMITTED"
        assert d["amountUsdc"] == 1.0
        assert d["feeUsdc"] == 0.01

    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "id": "0x123",
            "state": 2,
            "requester": "0xabc",
            "provider": "0xdef",
            "amount": 1000000,
            "fee": 10000,
            "deadline": 0,
            "disputeWindow": 3600,
        }
        tx = Transaction.from_dict(data)

        assert tx.id == "0x123"
        assert tx.state == TransactionState.COMMITTED
        assert tx.amount == 1000000


class TestTransactionFilter:
    """Tests for TransactionFilter."""

    def _make_tx(self, **kwargs) -> Transaction:
        """Create a test transaction."""
        defaults = {
            "id": "0x123",
            "state": TransactionState.INITIATED,
            "requester": "0xabc",
            "provider": "0xdef",
            "amount": 1000000,
        }
        defaults.update(kwargs)
        return Transaction(**defaults)

    def test_requester_filter(self):
        """Test filtering by requester."""
        filter = TransactionFilter(requester="0xabc")

        tx_match = self._make_tx(requester="0xabc")
        assert filter.matches(tx_match)

        tx_no_match = self._make_tx(requester="0x999")
        assert not filter.matches(tx_no_match)

    def test_provider_filter(self):
        """Test filtering by provider."""
        filter = TransactionFilter(provider="0xdef")

        tx_match = self._make_tx(provider="0xdef")
        assert filter.matches(tx_match)

        tx_no_match = self._make_tx(provider="0x999")
        assert not filter.matches(tx_no_match)

    def test_states_filter(self):
        """Test filtering by states."""
        filter = TransactionFilter(
            states=[TransactionState.INITIATED, TransactionState.COMMITTED]
        )

        tx_match = self._make_tx(state=TransactionState.INITIATED)
        assert filter.matches(tx_match)

        tx_no_match = self._make_tx(state=TransactionState.SETTLED)
        assert not filter.matches(tx_no_match)

    def test_amount_filter(self):
        """Test filtering by amount range."""
        filter = TransactionFilter(min_amount=500000, max_amount=1500000)

        tx_match = self._make_tx(amount=1000000)
        assert filter.matches(tx_match)

        tx_too_low = self._make_tx(amount=100000)
        assert not filter.matches(tx_too_low)

        tx_too_high = self._make_tx(amount=2000000)
        assert not filter.matches(tx_too_high)

    def test_combined_filters(self):
        """Test multiple filters combined."""
        filter = TransactionFilter(
            requester="0xabc",
            states=[TransactionState.INITIATED],
            min_amount=500000,
        )

        tx_match = self._make_tx(
            requester="0xabc",
            state=TransactionState.INITIATED,
            amount=1000000,
        )
        assert filter.matches(tx_match)

        # Wrong requester
        tx_wrong_requester = self._make_tx(
            requester="0x999",
            state=TransactionState.INITIATED,
            amount=1000000,
        )
        assert not filter.matches(tx_wrong_requester)
