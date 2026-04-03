"""Tests for SettleOnInteract — background sweep for expired DELIVERED transactions."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from agirails.runtime import MockRuntime
from agirails.runtime.base import CreateTransactionParams
from agirails.settle.settle_on_interact import SettleOnInteract


REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def runtime(temp_dir):
    rt = MockRuntime(state_directory=temp_dir / ".actp")
    await rt.mint_tokens(REQUESTER, "10000000000")
    yield rt
    await rt.reset()


async def create_delivered_tx(
    runtime: MockRuntime, dispute_window: int = 3600
) -> str:
    """Helper: create a DELIVERED transaction."""
    current_time = runtime.time.now()
    tx_id = await runtime.create_transaction(
        CreateTransactionParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount="1000000",
            deadline=current_time + 86400,
            dispute_window=dispute_window,
        )
    )
    await runtime.link_escrow(tx_id, "1000000")
    await runtime.transition_state(tx_id, "IN_PROGRESS")
    await runtime.transition_state(tx_id, "DELIVERED")
    return tx_id


class TestMockRuntimeSweep:
    @pytest.mark.asyncio
    async def test_settles_expired_delivered_transactions(self, runtime):
        tx_id = await create_delivered_tx(runtime)
        await runtime.time.advance_time(3601)

        settler = SettleOnInteract(runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()

        tx = await runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.state.value == "SETTLED"

    @pytest.mark.asyncio
    async def test_does_not_settle_active_window(self, runtime):
        tx_id = await create_delivered_tx(runtime)
        # Don't advance time — window still active

        settler = SettleOnInteract(runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()

        tx = await runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.state.value == "DELIVERED"

    @pytest.mark.asyncio
    async def test_handles_zero_transactions(self, runtime):
        settler = SettleOnInteract(runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()  # Should not raise

    @pytest.mark.asyncio
    async def test_only_sweeps_for_specified_provider(self, runtime):
        other_provider = "0x" + "3" * 40
        tx_id = await create_delivered_tx(runtime)
        await runtime.time.advance_time(3601)

        settler = SettleOnInteract(runtime, other_provider, cooldown_s=0)
        await settler.sweep_now()

        # Check via get_all_transactions to avoid auto-settle side effects
        all_txs = await runtime.get_all_transactions()
        tx = next((t for t in all_txs if t.id == tx_id), None)
        assert tx is not None
        assert tx.state.value == "DELIVERED"

    @pytest.mark.asyncio
    async def test_settles_multiple_expired(self, runtime):
        tx_id1 = await create_delivered_tx(runtime)
        tx_id2 = await create_delivered_tx(runtime)
        await runtime.time.advance_time(3601)

        settler = SettleOnInteract(runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()

        tx1 = await runtime.get_transaction(tx_id1)
        tx2 = await runtime.get_transaction(tx_id2)
        assert tx1 is not None and tx1.state.value == "SETTLED"
        assert tx2 is not None and tx2.state.value == "SETTLED"


class TestCooldown:
    @pytest.mark.asyncio
    async def test_sweep_now_calls_sweep(self):
        """sweep_now() calls the runtime's sweep method."""
        sweep_count = 0

        class FakeRuntime:
            async def sweep_expired_delivered_for_provider(self, addr: str) -> None:
                nonlocal sweep_count
                sweep_count += 1

        settler = SettleOnInteract(FakeRuntime(), PROVIDER, cooldown_s=0)
        await settler.sweep_now()
        assert sweep_count == 1

        # Second call also works (sweep_now bypasses cooldown)
        await settler.sweep_now()
        assert sweep_count == 2


class TestDuckTyping:
    @pytest.mark.asyncio
    async def test_blockchain_runtime_path(self):
        mock_runtime = AsyncMock()
        mock_runtime.get_expired_delivered_transactions = AsyncMock(
            return_value=[{"tx_id": "0xabc"}, {"tx_id": "0xdef"}]
        )
        mock_runtime.release_escrow = AsyncMock()

        settler = SettleOnInteract(mock_runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()

        mock_runtime.get_expired_delivered_transactions.assert_called_once_with(PROVIDER)
        assert mock_runtime.release_escrow.call_count == 2

    @pytest.mark.asyncio
    async def test_swallows_per_tx_errors(self):
        mock_runtime = AsyncMock()
        mock_runtime.get_expired_delivered_transactions = AsyncMock(
            return_value=[{"tx_id": "0xabc"}, {"tx_id": "0xdef"}]
        )
        mock_runtime.release_escrow = AsyncMock(
            side_effect=[Exception("failed"), None]
        )

        settler = SettleOnInteract(mock_runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()  # Should not raise

        # Both were attempted despite first failure
        assert mock_runtime.release_escrow.call_count == 2

    @pytest.mark.asyncio
    async def test_unknown_runtime_skips_silently(self):
        bare_runtime = AsyncMock(spec=[])  # No methods at all

        settler = SettleOnInteract(bare_runtime, PROVIDER, cooldown_s=0)
        await settler.sweep_now()  # Should not raise
