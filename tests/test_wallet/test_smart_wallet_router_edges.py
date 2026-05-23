"""Edge-case tests for SmartWalletRouter — fills coverage gaps in
``validate_release_preconditions``, ``verify_release_attestation``,
``send_settle`` / ``send_accept_quote`` failure paths, and the static
``extract_tx_id`` helper.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

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
TX_ID = "0x" + "a" * 64


def _contracts():
    return SmartWalletContractAddresses(
        usdc=USDC, actp_kernel=KERNEL, escrow_vault=ESCROW_VAULT
    )


def _aa_wallet(success=True, address=REQUESTER):
    wallet = MagicMock()
    wallet.pay_actp_batched = MagicMock()
    wallet.get_address = MagicMock(return_value=address)
    receipt = SimpleNamespace(hash="0x" + ("d" if success else "e") * 64, success=success)
    wallet.send_transaction = AsyncMock(return_value=receipt)
    wallet.send_batch_transaction = AsyncMock(return_value=receipt)
    return wallet


# ============================================================================
# Factory edge cases
# ============================================================================


class TestFactoryNegativePaths:
    def test_none_wallet_returns_none(self):
        assert create_smart_wallet_router(None, _contracts(), MagicMock()) is None

    def test_none_runtime_returns_none(self):
        assert create_smart_wallet_router(_aa_wallet(), _contracts(), None) is None

    def test_all_three_required_returns_router(self):
        r = create_smart_wallet_router(_aa_wallet(), _contracts(), MagicMock())
        assert r is not None


# ============================================================================
# send_settle / send_accept_quote sender wrappers
# ============================================================================


class TestSendWrappers:
    @pytest.mark.asyncio
    async def test_send_settle_uses_settled_state(self):
        wallet = _aa_wallet()
        router = SmartWalletRouter(wallet, _contracts(), MagicMock())
        receipt = await router.send_settle(TX_ID)
        assert receipt.success
        # Sent tx should target kernel address with transitionState selector.
        sent = wallet.send_transaction.call_args.args[0]
        assert sent.to == KERNEL
        assert sent.data.startswith("0x48d6ecd6")

    @pytest.mark.asyncio
    async def test_send_settle_failure_propagates(self):
        wallet = _aa_wallet(success=False)
        router = SmartWalletRouter(wallet, _contracts(), MagicMock())
        with pytest.raises(RuntimeError, match="release"):
            await router.send_settle(TX_ID)

    @pytest.mark.asyncio
    async def test_send_accept_quote_calls_kernel(self):
        wallet = _aa_wallet()
        router = SmartWalletRouter(wallet, _contracts(), MagicMock())
        await router.send_accept_quote(TX_ID, "1500000")
        sent = wallet.send_transaction.call_args.args[0]
        assert sent.to == KERNEL
        assert sent.data.startswith("0xfdc1f231")  # acceptQuote selector

    @pytest.mark.asyncio
    async def test_send_accept_quote_failure_propagates(self):
        wallet = _aa_wallet(success=False)
        router = SmartWalletRouter(wallet, _contracts(), MagicMock())
        with pytest.raises(RuntimeError, match="acceptQuote"):
            await router.send_accept_quote(TX_ID, "1500000")


# ============================================================================
# validate_release_preconditions — accepts both txId-string and tx-object
# ============================================================================


class TestValidateReleasePreconditions:
    @pytest.mark.asyncio
    async def test_with_string_tx_id_fetches_from_runtime(self):
        tx_record = SimpleNamespace(
            id=TX_ID, state="DELIVERED", requester=REQUESTER,
            completed_at=None, dispute_window=0,
        )
        runtime = MagicMock()
        runtime.get_transaction = AsyncMock(return_value=tx_record)
        router = SmartWalletRouter(_aa_wallet(), _contracts(), runtime)
        tx = await router.validate_release_preconditions(TX_ID)
        assert tx is tx_record
        runtime.get_transaction.assert_awaited_once_with(TX_ID)

    @pytest.mark.asyncio
    async def test_with_tx_object_skips_runtime_fetch(self):
        tx = SimpleNamespace(
            id=TX_ID, state="DELIVERED", requester=REQUESTER,
            completed_at=None, dispute_window=0,
        )
        runtime = MagicMock()
        runtime.get_transaction = AsyncMock(
            side_effect=AssertionError("runtime should NOT be hit")
        )
        router = SmartWalletRouter(_aa_wallet(), _contracts(), runtime)
        result = await router.validate_release_preconditions(tx)
        assert result is tx

    @pytest.mark.asyncio
    async def test_runtime_returns_none_raises(self):
        runtime = MagicMock()
        runtime.get_transaction = AsyncMock(return_value=None)
        router = SmartWalletRouter(_aa_wallet(), _contracts(), runtime)
        with pytest.raises(RuntimeError, match="not found"):
            await router.validate_release_preconditions(TX_ID)

    @pytest.mark.asyncio
    async def test_wrong_state_raises(self):
        for state in ("INITIATED", "COMMITTED", "IN_PROGRESS", "SETTLED", "CANCELLED"):
            tx = SimpleNamespace(
                id=TX_ID, state=state, requester=REQUESTER,
                completed_at=None, dispute_window=0,
            )
            router = SmartWalletRouter(_aa_wallet(), _contracts(), MagicMock())
            with pytest.raises(RuntimeError, match=f"state {state}"):
                await router.validate_release_preconditions(tx)

    @pytest.mark.asyncio
    async def test_dispute_window_active_blocks_non_requester(self):
        # Mock-mode: completed_at = real timestamp, dispute_window = duration sec.
        import time
        now = int(time.time())
        tx = SimpleNamespace(
            id=TX_ID, state="DELIVERED",
            requester="0x" + "9" * 40,  # NOT the wallet caller
            completed_at=now,
            dispute_window=86400,  # 1 day, still active
        )
        router = SmartWalletRouter(_aa_wallet(address=REQUESTER), _contracts(), MagicMock())
        with pytest.raises(RuntimeError, match="dispute window"):
            await router.validate_release_preconditions(tx)

    @pytest.mark.asyncio
    async def test_dispute_window_active_allows_requester(self):
        """Requester can release early during dispute window."""
        import time
        now = int(time.time())
        tx = SimpleNamespace(
            id=TX_ID, state="DELIVERED",
            requester=REQUESTER.lower(),
            completed_at=now,
            dispute_window=86400,
        )
        router = SmartWalletRouter(_aa_wallet(address=REQUESTER), _contracts(), MagicMock())
        result = await router.validate_release_preconditions(tx)
        assert result is tx


# ============================================================================
# verify_release_attestation
# ============================================================================


class TestVerifyReleaseAttestation:
    @pytest.mark.asyncio
    async def test_no_uid_no_helper_noop(self):
        router = SmartWalletRouter(_aa_wallet(), _contracts(), MagicMock(), eas_helper=None)
        await router.verify_release_attestation(TX_ID, None)  # no-op

    @pytest.mark.asyncio
    async def test_uid_without_helper_noop(self):
        router = SmartWalletRouter(_aa_wallet(), _contracts(), MagicMock(), eas_helper=None)
        await router.verify_release_attestation(TX_ID, "0xfeed")  # no-op

    @pytest.mark.asyncio
    async def test_uid_with_helper_calls_verify_and_record(self):
        helper = MagicMock()
        helper.verify_and_record_for_release = AsyncMock()
        router = SmartWalletRouter(_aa_wallet(), _contracts(), MagicMock(), eas_helper=helper)
        await router.verify_release_attestation(TX_ID, "0xfeed")
        helper.verify_and_record_for_release.assert_awaited_once_with(TX_ID, "0xfeed")


# ============================================================================
# extract_tx_id static helper
# ============================================================================


class TestExtractTxId:
    def test_plain_tx_id_returned_unchanged(self):
        assert SmartWalletRouter.extract_tx_id(TX_ID) == TX_ID

    def test_legacy_format_extracted(self):
        # legacy: "escrow-{txid}-{timestamp}"
        legacy = f"escrow-{TX_ID}-1700000000"
        assert SmartWalletRouter.extract_tx_id(legacy) == TX_ID

    def test_unknown_format_returned_as_is(self):
        s = "some-random-string"
        assert SmartWalletRouter.extract_tx_id(s) == s
