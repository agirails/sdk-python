"""Parity tests for the 4.9.0 additions against TS SDK.

Covers:
  1. F-6 recovery helpers: ``recovery_grace``, ``get_recovery_deadline``,
     ``recover_stalled_in_progress`` (PARITY: TS ACTPKernel F-6 helpers).
  2. SDK-2: ``RequestResult.transaction.escrow_id`` requester-side escrow
     visibility (PARITY: TS RequestResult).
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

from agirails.level0.request import RequestResult
from agirails.protocol.kernel import ACTPKernel, TransactionView
from agirails.types.transaction import TransactionState


REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40
TX_ID = "0x" + "0" * 64


def _make_kernel() -> ACTPKernel:
    contract = MagicMock()
    contract.address = "0x" + "c" * 40
    account = MagicMock()
    account.address = REQUESTER
    account.key = b"\x01" * 32
    w3 = MagicMock()
    w3.to_checksum_address = lambda a: a
    return ACTPKernel(contract, account, w3, chain_id=84532)


def _make_view(deadline: int) -> TransactionView:
    return TransactionView(
        transaction_id=TX_ID,
        requester=REQUESTER,
        provider=PROVIDER,
        state=TransactionState.IN_PROGRESS,
        amount=1_000_000,
        created_at=int(time.time()),
        updated_at=int(time.time()),
        deadline=deadline,
        service_hash="0x" + "0" * 64,
        escrow_contract="0x" + "0" * 40,
        escrow_id="0x" + "0" * 64,
        attestation_uid="0x" + "0" * 64,
        dispute_window=172800,
        metadata="0x" + "0" * 64,
        platform_fee_bps_locked=100,
    )


class TestF6RecoveryHelpers:
    async def test_recovery_grace_reads_kernel(self):
        kernel = _make_kernel()
        kernel.contract.functions.recoveryGrace.return_value.call = AsyncMock(
            return_value=3600
        )
        assert await kernel.recovery_grace() == 3600

    async def test_get_recovery_deadline_is_deadline_plus_grace(self):
        kernel = _make_kernel()
        deadline = int(time.time()) + 3600
        kernel.get_transaction = AsyncMock(return_value=_make_view(deadline))
        kernel.recovery_grace = AsyncMock(return_value=7200)
        assert await kernel.get_recovery_deadline(TX_ID) == deadline + 7200

    async def test_recover_stalled_in_progress_builds_and_sends(self):
        kernel = _make_kernel()
        contract_fn = MagicMock()
        contract_fn.build_transaction = AsyncMock(return_value={"to": "0x"})
        kernel.contract.functions.recoverStalledInProgress.return_value = contract_fn
        kernel._estimate_gas = AsyncMock(return_value=150_000)
        kernel._build_tx_params = AsyncMock(return_value={})
        sentinel = object()
        kernel._sign_and_send = AsyncMock(return_value=MagicMock())
        kernel._to_receipt = MagicMock(return_value=sentinel)

        result = await kernel.recover_stalled_in_progress(TX_ID)

        assert result is sentinel
        kernel.contract.functions.recoverStalledInProgress.assert_called_once()
        kernel._sign_and_send.assert_awaited_once()


class TestSDK2EscrowId:
    def test_escrow_id_passthrough(self):
        r = RequestResult.from_delivery(
            output={"ok": True},
            tx_id=TX_ID,
            provider=PROVIDER,
            budget=1.0,
            duration=10,
            proof="",
            escrow_id="0xESCROW",
        )
        assert r.transaction.escrow_id == "0xESCROW"

    def test_escrow_id_defaults_none(self):
        r = RequestResult.from_delivery(
            output={"ok": True},
            tx_id=TX_ID,
            provider=PROVIDER,
            budget=1.0,
            duration=10,
            proof="",
        )
        assert r.transaction.escrow_id is None
