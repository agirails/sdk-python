"""Tests for SmartWalletRouter + StandardAdapter Smart Wallet routing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.adapters.standard import StandardAdapter, StandardTransactionParams
from agirails.runtime.types import State
from agirails.wallet.aa.transaction_batcher import ContractAddresses
from agirails.wallet.smart_wallet_router import (
    SmartWalletContractAddresses,
    SmartWalletRouter,
    compute_dispute_window_ends,
    create_smart_wallet_router,
)


KERNEL = "0x" + "2" * 40
USDC = "0x" + "1" * 40
ESCROW_VAULT = "0x" + "3" * 40
REQUESTER = "0x" + "7" * 40
PROVIDER = "0x" + "4" * 40
TX_ID = "0x" + "a" * 64


def _make_router_contracts() -> SmartWalletContractAddresses:
    return SmartWalletContractAddresses(
        usdc=USDC, actp_kernel=KERNEL, escrow_vault=ESCROW_VAULT
    )


def _make_aa_wallet(address: str = REQUESTER) -> MagicMock:
    """AA-capable wallet provider: has pay_actp_batched + send_transaction + send_batch_transaction."""
    wallet = MagicMock()
    wallet.pay_actp_batched = MagicMock()  # presence marker
    wallet.get_address = MagicMock(return_value=address)

    receipt = MagicMock()
    receipt.hash = "0x" + "b" * 64
    receipt.success = True
    wallet.send_transaction = AsyncMock(return_value=receipt)
    wallet.send_batch_transaction = AsyncMock(return_value=receipt)
    return wallet


class TestSmartWalletRouterEncoders:
    """Pure-encoding tests — no mocking needed beyond the construction triple."""

    def test_should_route_true_for_aa_wallet(self):
        router = SmartWalletRouter(
            _make_aa_wallet(), _make_router_contracts(), MagicMock()
        )
        assert router.should_route() is True

    def test_should_route_false_without_pay_actp_batched(self):
        eoa = MagicMock(spec=["send_transaction", "get_address"])
        router = SmartWalletRouter(eoa, _make_router_contracts(), MagicMock())
        assert router.should_route() is False

    def test_factory_returns_none_for_eoa(self):
        eoa = MagicMock(spec=["send_transaction", "get_address"])
        assert (
            create_smart_wallet_router(eoa, _make_router_contracts(), MagicMock())
            is None
        )

    def test_factory_returns_none_when_contracts_missing(self):
        assert (
            create_smart_wallet_router(_make_aa_wallet(), None, MagicMock()) is None
        )

    def test_encode_transition_state_targets_kernel(self):
        router = SmartWalletRouter(
            _make_aa_wallet(), _make_router_contracts(), MagicMock()
        )
        tx = router.encode_transition_state_tx(TX_ID, "IN_PROGRESS")
        assert tx.to == KERNEL
        assert tx.value == "0"
        # transitionState(bytes32,uint8,bytes) selector = 0x48d6ecd6
        assert tx.data.startswith("0x48d6ecd6")

    def test_encode_settle_uses_settled_state(self):
        router = SmartWalletRouter(
            _make_aa_wallet(), _make_router_contracts(), MagicMock()
        )
        tx_settle = router.encode_settle_tx(TX_ID)
        tx_in_progress = router.encode_transition_state_tx(TX_ID, "IN_PROGRESS")
        # Same selector + same txId, but state byte differs (5 vs 3) → calldata differs
        assert tx_settle.data != tx_in_progress.data
        assert tx_settle.data.startswith("0x48d6ecd6")

    def test_encode_accept_quote_uses_correct_selector(self):
        router = SmartWalletRouter(
            _make_aa_wallet(), _make_router_contracts(), MagicMock()
        )
        tx = router.encode_accept_quote_tx(TX_ID, "1500000")
        assert tx.to == KERNEL
        # acceptQuote(bytes32,uint256) selector = 0xfdc1f231
        assert tx.data.startswith("0xfdc1f231")

    def test_encode_link_escrow_returns_two_calls(self):
        router = SmartWalletRouter(
            _make_aa_wallet(), _make_router_contracts(), MagicMock()
        )
        calls = router.encode_link_escrow_calls(TX_ID, "1000000", USDC)
        assert len(calls) == 2
        # call 0: USDC.approve(escrowVault, amount)
        assert calls[0].to == USDC
        assert calls[0].data.startswith("0x095ea7b3")  # approve selector
        # call 1: ACTPKernel.linkEscrow(txId, escrowVault, txId)
        assert calls[1].to == KERNEL
        assert calls[1].data.startswith("0xb76f85ae")  # linkEscrow selector


class TestSmartWalletRouterSenders:
    """End-to-end: verify the router calls send_transaction / send_batch_transaction."""

    @pytest.mark.asyncio
    async def test_send_transition_uses_send_transaction(self):
        wallet = _make_aa_wallet()
        router = SmartWalletRouter(wallet, _make_router_contracts(), MagicMock())
        await router.send_transition(TX_ID, "IN_PROGRESS")
        assert wallet.send_transaction.call_count == 1
        sent = wallet.send_transaction.call_args.args[0]
        assert sent.to == KERNEL

    @pytest.mark.asyncio
    async def test_send_link_escrow_uses_send_batch_transaction(self):
        wallet = _make_aa_wallet()
        router = SmartWalletRouter(wallet, _make_router_contracts(), MagicMock())
        await router.send_link_escrow(TX_ID, "1000000", USDC)
        assert wallet.send_batch_transaction.call_count == 1
        batch = wallet.send_batch_transaction.call_args.args[0]
        assert len(batch) == 2

    @pytest.mark.asyncio
    async def test_send_failure_raises(self):
        wallet = _make_aa_wallet()
        bad_receipt = MagicMock()
        bad_receipt.hash = "0xfailed"
        bad_receipt.success = False
        wallet.send_transaction = AsyncMock(return_value=bad_receipt)

        router = SmartWalletRouter(wallet, _make_router_contracts(), MagicMock())
        with pytest.raises(RuntimeError, match="UserOp failed"):
            await router.send_transition(TX_ID, "IN_PROGRESS")


class TestDisputeWindowHelper:
    def test_duration_returns_completed_plus_window(self):
        assert (
            compute_dispute_window_ends(1_700_000_000, 86_400)
            == 1_700_000_000 + 86_400
        )

    def test_absolute_timestamp_returned_as_is(self):
        # disputeWindow > 1B → treated as absolute timestamp
        assert compute_dispute_window_ends(0, 1_800_000_000) == 1_800_000_000


class TestStandardAdapterSmartWalletRouting:
    """Lifecycle calls on StandardAdapter must route through the router
    when wallet_provider is AA-capable."""

    def _make_adapter(self, wallet):
        runtime = MagicMock()
        runtime.create_transaction = AsyncMock(return_value=TX_ID)
        runtime.link_escrow = AsyncMock(
            side_effect=AssertionError("runtime.link_escrow MUST NOT be called")
        )
        runtime.accept_quote = AsyncMock(
            side_effect=AssertionError("runtime.accept_quote MUST NOT be called")
        )
        runtime.transition_state = AsyncMock(
            side_effect=AssertionError("runtime.transition_state MUST NOT be called")
        )
        runtime.release_escrow = AsyncMock(
            side_effect=AssertionError("runtime.release_escrow MUST NOT be called")
        )
        # tx record for link_escrow lookup + release preconditions
        tx_record = MagicMock()
        tx_record.amount = "1000000"
        tx_record.state = State.DELIVERED
        tx_record.requester = REQUESTER
        tx_record.completed_at = None  # skip dispute window check in test
        tx_record.dispute_window = 0
        runtime.get_transaction = AsyncMock(return_value=tx_record)
        runtime.maxTransactionAmount = None

        contracts = ContractAddresses(
            usdc=USDC, actp_kernel=KERNEL, escrow_vault=ESCROW_VAULT
        )
        adapter = StandardAdapter(
            runtime,
            REQUESTER,
            None,
            wallet_provider=wallet,
            contract_addresses=contracts,
        )
        return adapter, runtime

    @pytest.mark.asyncio
    async def test_accept_quote_routes_through_wallet(self):
        wallet = _make_aa_wallet()
        adapter, runtime = self._make_adapter(wallet)
        await adapter.accept_quote(TX_ID, "1.50")
        assert wallet.send_transaction.call_count == 1
        assert runtime.accept_quote.call_count == 0

    @pytest.mark.asyncio
    async def test_link_escrow_routes_through_wallet(self):
        wallet = _make_aa_wallet()
        adapter, runtime = self._make_adapter(wallet)
        escrow_id = await adapter.link_escrow(TX_ID)
        # In the batched path escrowId == txId
        assert escrow_id == TX_ID
        assert wallet.send_batch_transaction.call_count == 1
        assert runtime.link_escrow.call_count == 0

    @pytest.mark.asyncio
    async def test_transition_state_routes_through_wallet(self):
        wallet = _make_aa_wallet()
        adapter, runtime = self._make_adapter(wallet)
        await adapter.transition_state(TX_ID, "IN_PROGRESS")
        assert wallet.send_transaction.call_count == 1
        assert runtime.transition_state.call_count == 0

    @pytest.mark.asyncio
    async def test_release_escrow_routes_through_wallet(self):
        wallet = _make_aa_wallet()
        adapter, runtime = self._make_adapter(wallet)
        await adapter.release_escrow(TX_ID)
        # 1 send_transaction (transitionState SETTLED) — preconditions+attestation
        # are local checks; settle is the only on-chain call.
        assert wallet.send_transaction.call_count == 1
        assert runtime.release_escrow.call_count == 0

    @pytest.mark.asyncio
    async def test_eoa_falls_back_to_runtime(self):
        """EOAWalletProvider lacks pay_actp_batched → legacy runtime path."""
        eoa_wallet = MagicMock(spec=["send_transaction", "get_address"])

        runtime = MagicMock()
        runtime.accept_quote = AsyncMock(return_value=None)
        runtime.transition_state = AsyncMock(return_value=None)
        runtime.maxTransactionAmount = None
        contracts = ContractAddresses(
            usdc=USDC, actp_kernel=KERNEL, escrow_vault=ESCROW_VAULT
        )

        adapter = StandardAdapter(
            runtime, REQUESTER, None,
            wallet_provider=eoa_wallet, contract_addresses=contracts,
        )
        await adapter.accept_quote(TX_ID, "1.00")
        assert runtime.accept_quote.call_count == 1
