"""
Tests for accept_quote() method.

Test cases:
1. Happy path: updates amount, state stays QUOTED
2. Wrong state: revert from INITIATED, COMMITTED
3. Transaction not found
4. Below minimum: revert if newAmount <= 0
5. Deadline expired: revert if past deadline
6. Event emitted: QuoteAccepted with correct old/new amounts
7. Full flow: create → quote → accept_quote → link_escrow → COMMITTED
8. Multiple accept_quote calls
"""

import tempfile
from pathlib import Path

import pytest

from agirails.runtime import MockRuntime, State
from agirails.runtime.base import CreateTransactionParams
from agirails.errors import (
    TransactionNotFoundError,
    InvalidStateTransitionError,
    DeadlinePassedError,
    InvalidAmountError,
)


REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40


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


async def _create_quoted_tx(runtime) -> str:
    """Helper to create a transaction in QUOTED state."""
    current_time = runtime.time.now()
    tx_id = await runtime.create_transaction(
        CreateTransactionParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount="1000000",  # 1 USDC
            deadline=current_time + 86400,
        )
    )
    await runtime.transition_state(tx_id, State.QUOTED)
    return tx_id


class TestAcceptQuote:
    """Tests for accept_quote method."""

    @pytest.mark.asyncio
    async def test_happy_path_updates_amount_stays_quoted(self, runtime):
        """Should update amount and stay in QUOTED state."""
        tx_id = await _create_quoted_tx(runtime)

        await runtime.accept_quote(tx_id, "2000000")

        tx = await runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.state == State.QUOTED
        assert tx.amount == "2000000"

    @pytest.mark.asyncio
    async def test_revert_from_initiated_state(self, runtime):
        """Should revert from INITIATED state."""
        current_time = runtime.time.now()
        tx_id = await runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="1000000",
                deadline=current_time + 86400,
            )
        )

        with pytest.raises(InvalidStateTransitionError):
            await runtime.accept_quote(tx_id, "2000000")

    @pytest.mark.asyncio
    async def test_revert_from_committed_state(self, funded_runtime):
        """Should revert from COMMITTED state."""
        runtime = funded_runtime
        current_time = runtime.time.now()
        tx_id = await runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="1000000",
                deadline=current_time + 86400,
            )
        )
        await runtime.link_escrow(tx_id, "1000000")

        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

        with pytest.raises(InvalidStateTransitionError):
            await runtime.accept_quote(tx_id, "2000000")

    @pytest.mark.asyncio
    async def test_revert_not_found(self, runtime):
        """Should revert for non-existent transaction."""
        fake_tx_id = "0x" + "0" * 64

        with pytest.raises(TransactionNotFoundError):
            await runtime.accept_quote(fake_tx_id, "2000000")

    @pytest.mark.asyncio
    async def test_revert_zero_amount(self, runtime):
        """Should revert if newAmount is zero."""
        tx_id = await _create_quoted_tx(runtime)

        with pytest.raises(InvalidAmountError):
            await runtime.accept_quote(tx_id, "0")

    @pytest.mark.asyncio
    async def test_revert_deadline_expired(self, runtime):
        """Should revert if deadline has passed."""
        tx_id = await _create_quoted_tx(runtime)

        # Advance time past deadline
        await runtime.time.advance_time(86401)

        with pytest.raises(DeadlinePassedError):
            await runtime.accept_quote(tx_id, "2000000")

    @pytest.mark.asyncio
    async def test_event_emitted(self, runtime):
        """Should emit QuoteAccepted event with correct amounts."""
        tx_id = await _create_quoted_tx(runtime)

        await runtime.accept_quote(tx_id, "2000000")

        # Check events in state
        from agirails.runtime.mock_state_manager import MockStateManager
        state = await runtime._state_manager.load()
        quote_events = [e for e in state.events if e.event_type == "QuoteAccepted"]
        assert len(quote_events) >= 1
        event = quote_events[-1]
        assert event.data["oldAmount"] == "1000000"
        assert event.data["newAmount"] == "2000000"

    @pytest.mark.asyncio
    async def test_full_negotiation_flow(self, funded_runtime):
        """Full flow: create → quote → accept_quote → link_escrow → COMMITTED."""
        runtime = funded_runtime
        current_time = runtime.time.now()

        # Create transaction (INITIATED)
        tx_id = await runtime.create_transaction(
            CreateTransactionParams(
                provider=PROVIDER,
                requester=REQUESTER,
                amount="1000000",
                deadline=current_time + 86400,
            )
        )
        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.INITIATED

        # Provider submits quote (INITIATED → QUOTED)
        await runtime.transition_state(tx_id, State.QUOTED)
        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.QUOTED

        # Requester accepts quote with new amount
        await runtime.accept_quote(tx_id, "1500000")
        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.QUOTED
        assert tx.amount == "1500000"

        # Link escrow to commit (QUOTED → COMMITTED)
        await runtime.link_escrow(tx_id, "1500000")
        tx = await runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

    @pytest.mark.asyncio
    async def test_multiple_accept_quote_calls(self, runtime):
        """Should allow multiple accept_quote calls while QUOTED."""
        tx_id = await _create_quoted_tx(runtime)

        await runtime.accept_quote(tx_id, "2000000")
        await runtime.accept_quote(tx_id, "1500000")

        tx = await runtime.get_transaction(tx_id)
        assert tx.amount == "1500000"
        assert tx.state == State.QUOTED
