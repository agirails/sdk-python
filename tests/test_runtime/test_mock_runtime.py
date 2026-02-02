"""
Tests for MockRuntime.

Comprehensive tests for the mock runtime implementation including:
- Transaction creation and validation
- Escrow linking and fund management
- State transitions (8-state machine)
- Escrow release and dispute windows
- Time manipulation
- Balance management
- Filtered queries (H-1 security)
"""

import time
import tempfile
from pathlib import Path

import pytest

from agirails.runtime import MockRuntime, State
from agirails.runtime.base import CreateTransactionParams
from agirails.errors import (
    TransactionNotFoundError,
    InvalidStateTransitionError,
    EscrowNotFoundError,
    DeadlinePassedError,
    DisputeWindowActiveError,
    InsufficientBalanceError,
    InvalidAmountError,
    QueryCapExceededError,
)


# Test addresses
REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40
OTHER = "0x" + "3" * 40


@pytest.fixture
def temp_dir():
    """Create a temporary directory for state files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def runtime(temp_dir):
    """Create a fresh MockRuntime for each test."""
    rt = MockRuntime(state_directory=temp_dir / ".actp")
    yield rt
    await rt.reset()


@pytest.fixture
async def funded_runtime(runtime):
    """Create a runtime with pre-funded accounts."""
    await runtime.mint_tokens(REQUESTER, "1000000000")  # 1000 USDC
    await runtime.mint_tokens(PROVIDER, "100000000")  # 100 USDC
    return runtime


class TestCreateTransaction:
    """Tests for create_transaction method."""

    @pytest.mark.asyncio
    async def test_create_transaction_happy_path(self, funded_runtime):
        """Should create transaction with valid parameters."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",  # 100 USDC
                deadline=current_time + 86400,  # 24 hours
            )
        )

        assert tx_id is not None
        assert tx_id.startswith("0x")
        assert len(tx_id) == 66  # 0x + 64 hex chars

        # Verify transaction was created
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.requester == REQUESTER.lower()
        assert tx.provider == PROVIDER.lower()
        assert tx.amount == "100000000"
        assert tx.state == State.INITIATED
        assert tx.deadline == current_time + 86400

    @pytest.mark.asyncio
    async def test_create_transaction_with_description(self, funded_runtime):
        """Should store service description."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
                service_description="text-generation:gpt-4",
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.service_description == "text-generation:gpt-4"

    @pytest.mark.asyncio
    async def test_create_transaction_deadline_in_past(self, funded_runtime):
        """Should reject deadline in the past."""
        current_time = funded_runtime.time.now()

        with pytest.raises(DeadlinePassedError):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount="100000000",
                    deadline=current_time - 1,  # In the past
                )
            )

    @pytest.mark.asyncio
    async def test_create_transaction_zero_amount(self, funded_runtime):
        """Should reject zero amount."""
        current_time = funded_runtime.time.now()

        with pytest.raises(InvalidAmountError):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount="0",
                    deadline=current_time + 86400,
                )
            )

    @pytest.mark.asyncio
    async def test_create_transaction_negative_amount(self, funded_runtime):
        """Should reject negative amount."""
        current_time = funded_runtime.time.now()

        with pytest.raises(InvalidAmountError):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount="-100",
                    deadline=current_time + 86400,
                )
            )

    @pytest.mark.asyncio
    async def test_create_transaction_below_minimum(self, funded_runtime):
        """Should reject amount below $0.05 minimum."""
        current_time = funded_runtime.time.now()

        with pytest.raises(InvalidAmountError, match="below minimum"):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount="49999",  # $0.049999 - below $0.05
                    deadline=current_time + 86400,
                )
            )

    @pytest.mark.asyncio
    async def test_create_transaction_at_minimum(self, funded_runtime):
        """Should accept amount exactly at $0.05 minimum."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="50000",  # $0.05 exactly
                deadline=current_time + 86400,
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.amount == "50000"


class TestLinkEscrow:
    """Tests for link_escrow method."""

    @pytest.mark.asyncio
    async def test_link_escrow_happy_path(self, funded_runtime):
        """Should link escrow and transition to COMMITTED."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")

        assert escrow_id is not None

        # Transaction should be in COMMITTED state
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED
        assert tx.escrow_id == escrow_id

        # Requester balance should be reduced
        balance = await funded_runtime.get_balance(REQUESTER)
        assert balance == "900000000"  # 1000 - 100 USDC

        # Escrow should have funds
        escrow_balance = await funded_runtime.get_escrow_balance(escrow_id)
        assert escrow_balance == "100000000"

    @pytest.mark.asyncio
    async def test_link_escrow_insufficient_balance(self, runtime):
        """Should reject if requester has insufficient balance."""
        # Give requester only 50 USDC
        await runtime.mint_tokens(REQUESTER, "50000000")
        current_time = runtime.time.now()

        tx_id = await runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",  # 100 USDC
                deadline=current_time + 86400,
            )
        )

        with pytest.raises(InsufficientBalanceError):
            await runtime.link_escrow(tx_id, "100000000")

        # Transaction should still be in INITIATED
        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.INITIATED

    @pytest.mark.asyncio
    async def test_link_escrow_transaction_not_found(self, runtime):
        """Should raise if transaction doesn't exist."""
        with pytest.raises(TransactionNotFoundError):
            await runtime.link_escrow("0x" + "a" * 64, "100000000")

    @pytest.mark.asyncio
    async def test_link_escrow_wrong_state(self, funded_runtime):
        """Should reject if transaction not in INITIATED or QUOTED."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        # Link escrow first time
        await funded_runtime.link_escrow(tx_id, "100000000")

        # Try to link again - should fail (already COMMITTED)
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.link_escrow(tx_id, "100000000")


class TestStateTransitions:
    """Tests for state machine transitions."""

    @pytest.mark.asyncio
    async def test_initiated_to_quoted(self, funded_runtime):
        """INITIATED -> QUOTED transition."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        await funded_runtime.transition_state(tx_id, State.QUOTED)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.QUOTED

    @pytest.mark.asyncio
    async def test_initiated_to_cancelled(self, funded_runtime):
        """INITIATED -> CANCELLED transition."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        await funded_runtime.transition_state(tx_id, State.CANCELLED)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.CANCELLED

    @pytest.mark.asyncio
    async def test_committed_to_in_progress(self, funded_runtime):
        """COMMITTED -> IN_PROGRESS transition."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")

        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_committed_to_delivered_rejected(self, funded_runtime):
        """AUDIT FIX: COMMITTED -> DELIVERED direct transition is rejected."""
        from agirails.errors import InvalidStateTransitionError

        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")

        # AUDIT FIX: Direct COMMITTED -> DELIVERED should now fail
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.transition_state(tx_id, State.DELIVERED, proof="0xproof")

        # Transaction should still be in COMMITTED
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

    @pytest.mark.asyncio
    async def test_in_progress_to_delivered(self, funded_runtime):
        """IN_PROGRESS -> DELIVERED transition with proof."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)

        await funded_runtime.transition_state(tx_id, State.DELIVERED, proof="0xproof")

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.DELIVERED
        assert tx.delivery_proof == "0xproof"  # PARITY: Renamed from 'proof'

    @pytest.mark.asyncio
    async def test_delivered_to_disputed(self, funded_runtime):
        """DELIVERED -> DISPUTED transition."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.DELIVERED)

        await funded_runtime.transition_state(tx_id, State.DISPUTED)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.DISPUTED

    @pytest.mark.asyncio
    async def test_disputed_to_settled(self, funded_runtime):
        """DISPUTED -> SETTLED transition."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.DELIVERED)
        await funded_runtime.transition_state(tx_id, State.DISPUTED)

        await funded_runtime.transition_state(tx_id, State.SETTLED)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.SETTLED

    @pytest.mark.asyncio
    async def test_invalid_transition_backwards(self, funded_runtime):
        """Should reject backward transitions."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")

        # COMMITTED -> INITIATED should fail
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.transition_state(tx_id, State.INITIATED)

    @pytest.mark.asyncio
    async def test_invalid_transition_from_terminal(self, funded_runtime):
        """Should reject transitions from terminal states."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.transition_state(tx_id, State.CANCELLED)

        # CANCELLED -> anything should fail
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.transition_state(tx_id, State.INITIATED)

        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.transition_state(tx_id, State.COMMITTED)

    @pytest.mark.asyncio
    async def test_invalid_transition_skip_states(self, funded_runtime):
        """Should reject skipping required states."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        # INITIATED -> DELIVERED should fail (need COMMITTED first)
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.transition_state(tx_id, State.DELIVERED)

    @pytest.mark.asyncio
    async def test_transition_with_string_state(self, funded_runtime):
        """Should accept state as string."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        await funded_runtime.transition_state(tx_id, "QUOTED")

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.QUOTED


class TestReleaseEscrow:
    """Tests for release_escrow method."""

    @pytest.mark.asyncio
    async def test_release_escrow_happy_path(self, funded_runtime):
        """Should release funds after dispute window expires."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
                dispute_window=3600,  # 1 hour
            )
        )
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.DELIVERED)

        # Advance time past dispute window
        await funded_runtime.time.advance_time(3601)

        await funded_runtime.release_escrow(escrow_id)

        # Transaction should be SETTLED
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.SETTLED

        # Provider should have received funds
        provider_balance = await funded_runtime.get_balance(PROVIDER)
        assert provider_balance == "200000000"  # 100 + 100

        # Escrow should be empty
        escrow_balance = await funded_runtime.get_escrow_balance(escrow_id)
        assert escrow_balance == "0"

    @pytest.mark.asyncio
    async def test_release_escrow_dispute_window_active(self, funded_runtime):
        """Should reject release during active dispute window."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
                dispute_window=3600,  # 1 hour
            )
        )
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.DELIVERED)

        # Try to release immediately (dispute window still active)
        with pytest.raises(DisputeWindowActiveError):
            await funded_runtime.release_escrow(escrow_id)

    @pytest.mark.asyncio
    async def test_release_escrow_not_found(self, runtime):
        """Should raise if escrow doesn't exist."""
        with pytest.raises(EscrowNotFoundError):
            await runtime.release_escrow("0x" + "a" * 64)

    @pytest.mark.asyncio
    async def test_release_escrow_wrong_state(self, funded_runtime):
        """Should reject release if not in DELIVERED state."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")

        # Still in COMMITTED state
        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.release_escrow(escrow_id)


class TestTimeManipulation:
    """Tests for time manipulation methods."""

    @pytest.mark.asyncio
    async def test_time_now(self, runtime):
        """time.now() should return current timestamp."""
        now = runtime.time.now()
        # Should be close to actual time
        assert abs(now - int(time.time())) < 5

    @pytest.mark.asyncio
    async def test_advance_time(self, runtime):
        """Should advance time correctly."""
        initial = runtime.time.now()

        await runtime.time.advance_time(3600)

        after = runtime.time.now()
        assert after == initial + 3600

    @pytest.mark.asyncio
    async def test_advance_time_negative(self, runtime):
        """Should reject negative time advance."""
        with pytest.raises(ValueError):
            await runtime.time.advance_time(-100)

    @pytest.mark.asyncio
    async def test_advance_blocks(self, runtime):
        """Should advance time by blocks."""
        initial = runtime.time.now()

        await runtime.time.advance_blocks(100)

        after = runtime.time.now()
        # Default block time is 2 seconds
        assert after == initial + 200

    @pytest.mark.asyncio
    async def test_advance_blocks_negative(self, runtime):
        """Should reject negative block advance."""
        with pytest.raises(ValueError):
            await runtime.time.advance_blocks(-10)

    @pytest.mark.asyncio
    async def test_set_time(self, runtime):
        """Should set exact timestamp."""
        future = runtime.time.now() + 86400

        await runtime.time.set_time(future)

        assert runtime.time.now() == future

    @pytest.mark.asyncio
    async def test_set_time_in_past(self, runtime):
        """Should reject setting time in the past."""
        past = runtime.time.now() - 100

        with pytest.raises(ValueError, match="Cannot set time to past"):
            await runtime.time.set_time(past)


class TestBalanceManagement:
    """Tests for mint_tokens and get_balance."""

    @pytest.mark.asyncio
    async def test_mint_tokens(self, runtime):
        """Should mint tokens to address."""
        await runtime.mint_tokens(REQUESTER, "1000000")

        balance = await runtime.get_balance(REQUESTER)
        assert balance == "1000000"

    @pytest.mark.asyncio
    async def test_mint_tokens_additive(self, runtime):
        """Minting should add to existing balance."""
        await runtime.mint_tokens(REQUESTER, "1000000")
        await runtime.mint_tokens(REQUESTER, "500000")

        balance = await runtime.get_balance(REQUESTER)
        assert balance == "1500000"

    @pytest.mark.asyncio
    async def test_get_balance_nonexistent(self, runtime):
        """Non-existent address should have zero balance."""
        balance = await runtime.get_balance(OTHER)
        assert balance == "0"

    @pytest.mark.asyncio
    async def test_balance_case_insensitive(self, runtime):
        """Address lookup should be case-insensitive."""
        await runtime.mint_tokens(REQUESTER.upper(), "1000000")

        balance = await runtime.get_balance(REQUESTER.lower())
        assert balance == "1000000"


class TestReset:
    """Tests for reset method."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, funded_runtime):
        """Reset should clear all state."""
        current_time = funded_runtime.time.now()

        # Create some state
        await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        await funded_runtime.reset()

        # Balances should be cleared
        balance = await funded_runtime.get_balance(REQUESTER)
        assert balance == "0"

        # Transactions should be cleared
        txs = await funded_runtime.get_all_transactions()
        assert len(txs) == 0


class TestGetTransactions:
    """Tests for get_transaction and get_all_transactions."""

    @pytest.mark.asyncio
    async def test_get_transaction(self, funded_runtime):
        """Should get transaction by ID."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.id == tx_id

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self, runtime):
        """Should return None for non-existent transaction."""
        tx = await runtime.get_transaction("0x" + "a" * 64)
        assert tx is None

    @pytest.mark.asyncio
    async def test_get_all_transactions(self, funded_runtime):
        """Should get all transactions."""
        current_time = funded_runtime.time.now()

        # Create 3 transactions
        for i in range(3):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount=f"{(i + 1) * 100000000}",
                    deadline=current_time + 86400 + i,
                )
            )

        txs = await funded_runtime.get_all_transactions()
        assert len(txs) == 3


class TestGetTransactionsByProvider:
    """Tests for get_transactions_by_provider (H-1 security fix)."""

    @pytest.mark.asyncio
    async def test_filter_by_provider(self, funded_runtime):
        """Should filter transactions by provider."""
        current_time = funded_runtime.time.now()

        # Create transactions for different providers
        await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=OTHER,
                requester=REQUESTER,
                amount="200000000",
                deadline=current_time + 86400 + 1,
            )
        )
        await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="300000000",
                deadline=current_time + 86400 + 2,
            )
        )

        # Get only PROVIDER's transactions
        txs = await funded_runtime.get_transactions_by_provider(PROVIDER)
        assert len(txs) == 2
        for tx in txs:
            assert tx.provider == PROVIDER.lower()

    @pytest.mark.asyncio
    async def test_filter_by_state(self, funded_runtime):
        """Should filter by state."""
        current_time = funded_runtime.time.now()

        # Create transactions in different states
        tx1 = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        tx2 = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="200000000",
                deadline=current_time + 86400 + 1,
            )
        )
        await funded_runtime.link_escrow(tx2, "200000000")  # COMMITTED

        # Filter by INITIATED
        initiated = await funded_runtime.get_transactions_by_provider(
            PROVIDER, state=State.INITIATED
        )
        assert len(initiated) == 1
        assert initiated[0].id == tx1

        # Filter by COMMITTED
        committed = await funded_runtime.get_transactions_by_provider(
            PROVIDER, state=State.COMMITTED
        )
        assert len(committed) == 1
        assert committed[0].id == tx2

    @pytest.mark.asyncio
    async def test_respects_limit(self, funded_runtime):
        """Should respect limit parameter."""
        current_time = funded_runtime.time.now()

        # Create 10 transactions
        for i in range(10):
            await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider=PROVIDER,
                    requester=REQUESTER,
                    amount=f"{(i + 1) * 100000000}",
                    deadline=current_time + 86400 + i,
                )
            )

        txs = await funded_runtime.get_transactions_by_provider(PROVIDER, limit=5)
        assert len(txs) == 5

    @pytest.mark.asyncio
    async def test_exceeds_max_limit(self, runtime):
        """Should reject limit exceeding maximum."""
        with pytest.raises(QueryCapExceededError):
            await runtime.get_transactions_by_provider(PROVIDER, limit=1001)

    @pytest.mark.asyncio
    async def test_case_insensitive_address(self, funded_runtime):
        """Should match provider case-insensitively."""
        current_time = funded_runtime.time.now()

        await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER.upper(),
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        txs = await funded_runtime.get_transactions_by_provider(PROVIDER.lower())
        assert len(txs) == 1


class TestFullLifecycle:
    """Integration tests for full transaction lifecycle."""

    @pytest.mark.asyncio
    async def test_happy_path_lifecycle(self, funded_runtime):
        """Complete happy path from creation to settlement."""
        current_time = funded_runtime.time.now()

        # 1. Create transaction
        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",  # 100 USDC
                deadline=current_time + 86400,
                dispute_window=3600,
            )
        )

        # 2. Link escrow (INITIATED -> COMMITTED)
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

        # 3. Provider starts work (COMMITTED -> IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.IN_PROGRESS

        # 4. Provider delivers (IN_PROGRESS -> DELIVERED)
        await funded_runtime.transition_state(tx_id, State.DELIVERED, proof="0xdelivered")
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.DELIVERED

        # 5. Wait for dispute window
        await funded_runtime.time.advance_time(3601)

        # 6. Release escrow (DELIVERED -> SETTLED)
        await funded_runtime.release_escrow(escrow_id)
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.SETTLED

        # Verify balances
        requester_balance = await funded_runtime.get_balance(REQUESTER)
        provider_balance = await funded_runtime.get_balance(PROVIDER)
        assert requester_balance == "900000000"  # 1000 - 100
        assert provider_balance == "200000000"  # 100 + 100

    @pytest.mark.asyncio
    async def test_dispute_lifecycle(self, funded_runtime):
        """Dispute path from delivery to resolution."""
        current_time = funded_runtime.time.now()

        # Create and fund transaction
        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        await funded_runtime.link_escrow(tx_id, "100000000")
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await funded_runtime.transition_state(tx_id, State.IN_PROGRESS)
        await funded_runtime.transition_state(tx_id, State.DELIVERED)

        # Dispute
        await funded_runtime.transition_state(tx_id, State.DISPUTED)
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.DISPUTED

        # Resolve
        await funded_runtime.transition_state(tx_id, State.SETTLED)
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.SETTLED

    @pytest.mark.asyncio
    async def test_cancellation_lifecycle(self, funded_runtime):
        """Cancellation path before commitment."""
        current_time = funded_runtime.time.now()

        # Create transaction
        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        # Cancel immediately
        await funded_runtime.transition_state(tx_id, State.CANCELLED)
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.CANCELLED

        # Balance should be unchanged
        requester_balance = await funded_runtime.get_balance(REQUESTER)
        assert requester_balance == "1000000000"
