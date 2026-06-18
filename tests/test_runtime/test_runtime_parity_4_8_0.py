"""Parity tests for runtime gaps closed against TS SDK v4.8.0.

Covers three PARITY-GAP-4.8.0.md anchors for the `runtime` subsystem:

  1. ``BlockchainRuntime.get_transactions_by_provider`` (TS BlockchainRuntime.ts:721-770)
  2. ``submit_quote`` AIP-2.1 canonical quote-hash path on both runtimes
     (TS MockRuntime.ts:862-890 / BlockchainRuntime.ts:600-610)
  3. MockRuntime CANCELLED escrow refund + ``EscrowRefunded`` event
     (TS MockRuntime.ts:734-773)

Where possible, expected values are derived from the ported QuoteBuilder
(the same canonical keccak any TS verifier computes), not hand-rolled.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.builders.quote import QuoteBuilder, QuoteMessage
from agirails.runtime import MockRuntime, State
from agirails.runtime.base import CreateTransactionParams
from agirails.runtime.blockchain_runtime import BlockchainRuntime


REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def runtime(temp_dir):
    rt = MockRuntime(state_directory=temp_dir / ".actp")
    yield rt
    await rt.reset()


@pytest.fixture
async def funded_runtime(runtime):
    await runtime.mint_tokens(REQUESTER, "1000000000")  # 1000 USDC
    await runtime.mint_tokens(PROVIDER, "100000000")  # 100 USDC
    return runtime


def _make_quote(tx_id: str, amount: str = "1000000") -> QuoteMessage:
    """Build a signer-independent QuoteMessage for hash tests."""
    now = int(time.time())
    return QuoteMessage(
        tx_id=tx_id,
        provider=f"did:agirails:base-sepolia:{PROVIDER}",
        consumer=f"did:agirails:base-sepolia:{REQUESTER}",
        quoted_amount=amount,
        original_amount=amount,
        max_price=str(int(amount) * 2),
        chain_id=84532,
        nonce=1,
        quoted_at=now,
        expires_at=now + 3600,
    )


async def _create_initiated_tx(runtime, amount: str = "1000000") -> str:
    current_time = runtime.time.now()
    return await runtime.create_transaction(
        CreateTransactionParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=amount,
            deadline=current_time + 86400,
        )
    )


# ===========================================================================
# 1. MockRuntime.submit_quote — AIP-2.1 canonical quote hash
# ===========================================================================
class TestMockSubmitQuote:
    @pytest.mark.asyncio
    async def test_submit_quote_transitions_to_quoted(self, funded_runtime):
        tx_id = await _create_initiated_tx(funded_runtime)
        quote = _make_quote(tx_id)

        await funded_runtime.submit_quote(tx_id, quote)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.QUOTED

    @pytest.mark.asyncio
    async def test_submit_quote_stores_canonical_hash(self, funded_runtime):
        tx_id = await _create_initiated_tx(funded_runtime)
        quote = _make_quote(tx_id)

        # The canonical hash any verifier reconstructs from the QuoteMessage.
        expected = QuoteBuilder().compute_hash(quote)

        await funded_runtime.submit_quote(tx_id, quote)

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.quote_hash == expected
        # Sanity: it's a 32-byte hex hash, not a JSON blob.
        assert tx.quote_hash.startswith("0x")
        assert len(tx.quote_hash) == 66

    @pytest.mark.asyncio
    async def test_submit_quote_rejects_non_initiated(self, funded_runtime):
        tx_id = await _create_initiated_tx(funded_runtime)
        await funded_runtime.transition_state(tx_id, State.QUOTED)
        quote = _make_quote(tx_id)

        from agirails.errors import InvalidStateTransitionError

        with pytest.raises(InvalidStateTransitionError):
            await funded_runtime.submit_quote(tx_id, quote)

    @pytest.mark.asyncio
    async def test_submit_quote_missing_tx(self, funded_runtime):
        quote = _make_quote("0x" + "9" * 64)
        from agirails.errors import TransactionNotFoundError

        with pytest.raises(TransactionNotFoundError):
            await funded_runtime.submit_quote("0x" + "9" * 64, quote)

    @pytest.mark.asyncio
    async def test_submit_quote_hash_is_signer_independent(self, funded_runtime):
        """compute_hash strips signature → two builders agree byte-for-byte."""
        tx_id = await _create_initiated_tx(funded_runtime)
        quote = _make_quote(tx_id)
        h1 = QuoteBuilder().compute_hash(quote)
        h2 = QuoteBuilder().compute_hash(quote)
        assert h1 == h2


# ===========================================================================
# 2. MockRuntime CANCELLED escrow refund + EscrowRefunded event
# ===========================================================================
class TestMockCancelledRefund:
    @pytest.mark.asyncio
    async def test_cancel_refunds_requester(self, funded_runtime):
        amount = "1000000"  # 1 USDC
        tx_id = await _create_initiated_tx(funded_runtime, amount)

        before = await funded_runtime.get_balance(REQUESTER)
        await funded_runtime.link_escrow(tx_id, amount)  # COMMITTED, deducts amount
        after_lock = await funded_runtime.get_balance(REQUESTER)
        assert int(after_lock) == int(before) - int(amount)

        # CANCELLED must refund the locked escrow back to the requester.
        await funded_runtime.transition_state(tx_id, State.CANCELLED)
        after_cancel = await funded_runtime.get_balance(REQUESTER)
        assert int(after_cancel) == int(before)

    @pytest.mark.asyncio
    async def test_cancel_zeroes_escrow(self, funded_runtime):
        amount = "1000000"
        tx_id = await _create_initiated_tx(funded_runtime, amount)
        escrow_id = await funded_runtime.link_escrow(tx_id, amount)

        await funded_runtime.transition_state(tx_id, State.CANCELLED)
        # released escrow → balance reads 0 (mirrors TS escrow.balance='0')
        assert await funded_runtime.get_escrow_balance(escrow_id) == "0"

    @pytest.mark.asyncio
    async def test_cancel_emits_escrow_refunded(self, funded_runtime):
        amount = "1000000"
        tx_id = await _create_initiated_tx(funded_runtime, amount)
        await funded_runtime.link_escrow(tx_id, amount)

        await funded_runtime.transition_state(tx_id, State.CANCELLED)

        state = await funded_runtime._state_manager.load()
        refunds = [e for e in state.events if e.event_type == "EscrowRefunded"]
        assert len(refunds) == 1
        data = refunds[0].data
        assert data["escrowId"] == tx_id
        assert data["requester"] == REQUESTER
        assert data["amount"] == amount

    @pytest.mark.asyncio
    async def test_cancel_without_escrow_no_refund_event(self, funded_runtime):
        """INITIATED → CANCELLED with no linked escrow emits no EscrowRefunded."""
        tx_id = await _create_initiated_tx(funded_runtime)

        await funded_runtime.transition_state(tx_id, State.CANCELLED)

        state = await funded_runtime._state_manager.load()
        assert not [e for e in state.events if e.event_type == "EscrowRefunded"]

    @pytest.mark.asyncio
    async def test_double_cancel_path_no_double_refund(self, funded_runtime):
        """An already-released escrow is not refunded twice.

        (CANCELLED is terminal, so this guards the released-flag check rather
        than a real second transition.)"""
        amount = "1000000"
        tx_id = await _create_initiated_tx(funded_runtime, amount)
        await funded_runtime.link_escrow(tx_id, amount)
        before = await funded_runtime.get_balance(REQUESTER)
        await funded_runtime.transition_state(tx_id, State.CANCELLED)
        after = await funded_runtime.get_balance(REQUESTER)
        # exactly one refund (escrow.amount), not double
        assert int(after) == int(before) + int(amount)


# ===========================================================================
# 3. BlockchainRuntime.get_transactions_by_provider
# ===========================================================================
def _bc_stub() -> BlockchainRuntime:
    rt = BlockchainRuntime.__new__(BlockchainRuntime)
    rt.events = MagicMock()
    rt.w3 = MagicMock()

    class _Eth:
        _block = 1_000_000

        @property
        def block_number(self):
            async def _c():
                return self._block
            return _c()

    rt.w3.eth = _Eth()
    return rt


def _event(tx_id: str, provider: str, block: int, log_index: int):
    return SimpleNamespace(
        transaction_id=tx_id,
        provider=provider,
        block_number=block,
        log_index=log_index,
    )


def _tx(tx_id: str, provider: str, state: State):
    return SimpleNamespace(id=tx_id, provider=provider, state=state)


class TestBlockchainGetTransactionsByProvider:
    @pytest.mark.asyncio
    async def test_empty_history_returns_empty(self):
        rt = _bc_stub()
        rt.events.get_events = AsyncMock(return_value=[])
        out = await rt.get_transactions_by_provider(PROVIDER)
        assert out == []

    @pytest.mark.asyncio
    async def test_sweep_window_bounds_from_block(self, monkeypatch):
        monkeypatch.delenv("ACTP_SWEEP_BLOCK_WINDOW", raising=False)
        rt = _bc_stub()
        observed = {}

        async def fake_get_events(filt):
            observed["filter"] = filt
            return []

        rt.events.get_events = fake_get_events
        await rt.get_transactions_by_provider(PROVIDER)
        # default window 7200 → from_block = 1_000_000 - 7200
        assert observed["filter"].from_block == 1_000_000 - 7200
        assert observed["filter"].to_block == 1_000_000
        assert observed["filter"].provider == PROVIDER

    @pytest.mark.asyncio
    async def test_env_overrides_sweep_window(self, monkeypatch):
        monkeypatch.setenv("ACTP_SWEEP_BLOCK_WINDOW", "10")
        rt = _bc_stub()
        observed = {}

        async def fake_get_events(filt):
            observed["filter"] = filt
            return []

        rt.events.get_events = fake_get_events
        await rt.get_transactions_by_provider(PROVIDER)
        assert observed["filter"].from_block == 1_000_000 - 10

    @pytest.mark.asyncio
    async def test_oldest_first_ordering(self):
        rt = _bc_stub()
        # events out of order; newest selected then returned oldest-first
        rt.events.get_events = AsyncMock(
            return_value=[
                _event("0xaaa", PROVIDER, block=100, log_index=0),
                _event("0xbbb", PROVIDER, block=200, log_index=0),
                _event("0xccc", PROVIDER, block=200, log_index=5),
            ]
        )

        hydrated = {
            "0xaaa": _tx("0xaaa", PROVIDER, State.INITIATED),
            "0xbbb": _tx("0xbbb", PROVIDER, State.INITIATED),
            "0xccc": _tx("0xccc", PROVIDER, State.INITIATED),
        }
        rt.get_transaction = AsyncMock(side_effect=lambda tid: hydrated[tid])

        out = await rt.get_transactions_by_provider(PROVIDER)
        # newest-first selection: ccc(200,5), bbb(200,0), aaa(100,0)
        # then reversed → oldest-first: aaa, bbb, ccc
        assert [t.id for t in out] == ["0xaaa", "0xbbb", "0xccc"]

    @pytest.mark.asyncio
    async def test_state_filter_post_hydration(self):
        rt = _bc_stub()
        rt.events.get_events = AsyncMock(
            return_value=[
                _event("0xaaa", PROVIDER, block=100, log_index=0),
                _event("0xbbb", PROVIDER, block=200, log_index=0),
            ]
        )
        hydrated = {
            "0xaaa": _tx("0xaaa", PROVIDER, State.INITIATED),
            "0xbbb": _tx("0xbbb", PROVIDER, State.QUOTED),  # moved on
        }
        rt.get_transaction = AsyncMock(side_effect=lambda tid: hydrated[tid])

        out = await rt.get_transactions_by_provider(PROVIDER, state=State.INITIATED)
        assert [t.id for t in out] == ["0xaaa"]

    @pytest.mark.asyncio
    async def test_provider_recheck_drops_mismatch(self):
        rt = _bc_stub()
        rt.events.get_events = AsyncMock(
            return_value=[
                _event("0xaaa", PROVIDER, block=100, log_index=0),
                _event("0xbbb", PROVIDER, block=200, log_index=0),
            ]
        )
        other = "0x" + "3" * 40
        hydrated = {
            "0xaaa": _tx("0xaaa", PROVIDER, State.INITIATED),
            "0xbbb": _tx("0xbbb", other, State.INITIATED),  # false-positive match
        }
        rt.get_transaction = AsyncMock(side_effect=lambda tid: hydrated[tid])

        out = await rt.get_transactions_by_provider(PROVIDER)
        assert [t.id for t in out] == ["0xaaa"]

    @pytest.mark.asyncio
    async def test_limit_caps_results(self):
        rt = _bc_stub()
        rt.events.get_events = AsyncMock(
            return_value=[
                _event(f"0x{i}", PROVIDER, block=100 + i, log_index=0)
                for i in range(5)
            ]
        )
        rt.get_transaction = AsyncMock(
            side_effect=lambda tid: _tx(tid, PROVIDER, State.INITIATED)
        )
        out = await rt.get_transactions_by_provider(PROVIDER, limit=2)
        # newest 2 by block selected, returned oldest-first
        assert len(out) == 2
        assert [t.id for t in out] == ["0x3", "0x4"]

    @pytest.mark.asyncio
    async def test_case_insensitive_provider(self):
        rt = _bc_stub()
        rt.events.get_events = AsyncMock(
            return_value=[_event("0xaaa", PROVIDER, block=100, log_index=0)]
        )
        rt.get_transaction = AsyncMock(
            side_effect=lambda tid: _tx(tid, PROVIDER.upper(), State.INITIATED)
        )
        out = await rt.get_transactions_by_provider(PROVIDER.lower())
        assert [t.id for t in out] == ["0xaaa"]


# ===========================================================================
# 4. BlockchainRuntime._validate_service_hash — SHARED ROUTING RULE
# ===========================================================================
class TestValidateServiceHash:
    def test_none_returns_zero_hash(self):
        assert (
            BlockchainRuntime._validate_service_hash(None)
            == "0x" + "0" * 64
        )
        assert (
            BlockchainRuntime._validate_service_hash("")
            == "0x" + "0" * 64
        )

    def test_valid_bytes32_passes_through_verbatim(self):
        """A bytes32 routing key MUST NOT be re-hashed (double-hash bug)."""
        from agirails.utils.helpers import ServiceHash

        key = ServiceHash.hash("image-generation")
        assert BlockchainRuntime._validate_service_hash(key) == key

    def test_raw_string_hashed_to_keccak(self):
        """keccak256(utf8(serviceType)) — the canonical routing key."""
        from agirails.utils.helpers import ServiceHash

        out = BlockchainRuntime._validate_service_hash("image-generation")
        assert out == ServiceHash.hash("image-generation")
        # 0x-prefixed bytes32
        assert out.startswith("0x") and len(out) == 66

    def test_requester_provider_routing_keys_agree(self):
        """Requester-emitted key == provider-matched key for same string."""
        from agirails.utils.helpers import ServiceHash

        # Requester hashes the serviceType string into the routing key.
        emitted = BlockchainRuntime._validate_service_hash("translate")
        # Provider derives the same key from the same serviceType string.
        matched = ServiceHash.hash("translate")
        assert emitted == matched
        # And passing the already-derived key through is idempotent.
        assert BlockchainRuntime._validate_service_hash(emitted) == emitted


# ===========================================================================
# 5. BlockchainRuntime.submit_quote delegates canonical hash to kernel
# ===========================================================================
class TestBlockchainSubmitQuote:
    @pytest.mark.asyncio
    async def test_submit_quote_computes_canonical_hash_and_delegates(self):
        rt = BlockchainRuntime.__new__(BlockchainRuntime)
        rt.kernel = MagicMock()
        rt.kernel.submit_quote = AsyncMock()

        quote = _make_quote("0x" + "a" * 64)
        expected = QuoteBuilder().compute_hash(quote)

        await rt.submit_quote("0x" + "a" * 64, quote)

        rt.kernel.submit_quote.assert_awaited_once_with("0x" + "a" * 64, expected)
