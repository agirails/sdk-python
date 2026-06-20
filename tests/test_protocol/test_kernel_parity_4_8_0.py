"""Parity tests for ACTPKernel gaps closed against TS SDK v4.8.0.

Covers:
  1. ``submit_quote`` — INITIATED → QUOTED with abi-encoded bytes32 proof
     (PARITY: ACTPKernel.ts:330-358).
  2. ``get_economic_params`` — assembled from individual view getters
     (PARITY: ACTPKernel.ts:667-685).
  3. ``estimate_create_transaction`` — gas estimate without sending
     (PARITY: ACTPKernel.ts:689-714).
  4. ``get_transaction`` legacy 16-field BAD_DATA fallback
     (PARITY: ACTPKernel.ts:564-636).
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from eth_abi import encode

from agirails.errors import (
    InvalidStateTransitionError,
    TransactionNotFoundError,
    ValidationError,
)
from agirails.protocol.kernel import (
    ACTPKernel,
    CreateTransactionParams,
    EconomicParams,
    TransactionView,
)
from agirails.types.transaction import TransactionState


REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40
NON_ZERO_HASH = "0x" + "ab" * 32


def _make_kernel() -> ACTPKernel:
    """Build an ACTPKernel with a fully mocked contract/account/w3."""
    contract = MagicMock()
    contract.address = "0x" + "c" * 40
    account = MagicMock()
    account.address = REQUESTER
    account.key = b"\x01" * 32
    w3 = MagicMock()
    w3.to_checksum_address = lambda a: a
    kernel = ACTPKernel(contract, account, w3, chain_id=84532)
    return kernel


def _make_view(state: TransactionState) -> TransactionView:
    return TransactionView(
        transaction_id="0x" + "0" * 64,
        requester=REQUESTER,
        provider=PROVIDER,
        state=state,
        amount=1_000_000,
        created_at=int(time.time()),
        updated_at=int(time.time()),
        deadline=int(time.time()) + 3600,
        service_hash="0x" + "0" * 64,
        escrow_contract="0x" + "0" * 40,
        escrow_id="0x" + "0" * 64,
        attestation_uid="0x" + "0" * 64,
        dispute_window=172800,
        metadata="0x" + "0" * 64,
        platform_fee_bps_locked=100,
    )


# ---------------------------------------------------------------------------
# submit_quote
# ---------------------------------------------------------------------------


class TestSubmitQuote:
    async def test_transitions_initiated_to_quoted_with_encoded_proof(self):
        kernel = _make_kernel()
        kernel.get_transaction = AsyncMock(return_value=_make_view(TransactionState.INITIATED))
        kernel.transition_state = AsyncMock(return_value=MagicMock())

        await kernel.submit_quote("0x" + "9" * 64, NON_ZERO_HASH)

        kernel.transition_state.assert_awaited_once()
        args, kwargs = kernel.transition_state.call_args
        assert args[0] == "0x" + "9" * 64
        assert args[1] == TransactionState.QUOTED
        # Proof must be abi.encode(['bytes32'], [hash]) — PARITY: ts:352-354.
        expected_proof = encode(["bytes32"], [bytes.fromhex(NON_ZERO_HASH[2:])])
        assert args[2] == expected_proof

    async def test_rejects_non_initiated_state(self):
        kernel = _make_kernel()
        kernel.get_transaction = AsyncMock(return_value=_make_view(TransactionState.QUOTED))
        kernel.transition_state = AsyncMock()

        with pytest.raises(InvalidStateTransitionError):
            await kernel.submit_quote("0x" + "9" * 64, NON_ZERO_HASH)
        kernel.transition_state.assert_not_called()

    async def test_rejects_zero_hash(self):
        kernel = _make_kernel()
        kernel.get_transaction = AsyncMock()
        with pytest.raises(ValidationError):
            await kernel.submit_quote("0x" + "9" * 64, "0x" + "0" * 64)
        # State must NOT be read for a structurally-invalid hash.
        kernel.get_transaction.assert_not_called()

    @pytest.mark.parametrize("bad", ["0xshort", "ab" * 32, "0x" + "zz" * 32, ""])
    async def test_rejects_malformed_hash(self, bad):
        kernel = _make_kernel()
        with pytest.raises(ValidationError):
            await kernel.submit_quote("0x" + "9" * 64, bad)


# ---------------------------------------------------------------------------
# get_economic_params
# ---------------------------------------------------------------------------


class TestGetEconomicParams:
    async def test_assembles_from_individual_getters(self):
        kernel = _make_kernel()
        fee_recipient = "0x" + "f" * 40
        kernel.contract.functions.platformFeeBps.return_value.call = AsyncMock(return_value=100)
        kernel.contract.functions.requesterPenaltyBps.return_value.call = AsyncMock(return_value=250)
        kernel.contract.functions.feeRecipient.return_value.call = AsyncMock(return_value=fee_recipient)

        params = await kernel.get_economic_params()

        assert isinstance(params, EconomicParams)
        assert params.base_fee_numerator == 100
        assert params.base_fee_denominator == 10000  # BPS always /10000
        assert params.fee_recipient == fee_recipient
        assert params.requester_penalty_bps == 250
        assert params.provider_penalty_bps == 0  # Not in current ABI


# ---------------------------------------------------------------------------
# estimate_create_transaction
# ---------------------------------------------------------------------------


class TestEstimateCreateTransaction:
    async def test_returns_gas_estimate_without_sending(self):
        kernel = _make_kernel()
        contract_fn = MagicMock()
        contract_fn.estimate_gas = AsyncMock(return_value=187_500)
        kernel.contract.functions.createTransaction.return_value = contract_fn

        params = CreateTransactionParams(
            provider=PROVIDER,
            amount=1_000_000,
            deadline=int(time.time()) + 3600,
        )
        gas = await kernel.estimate_create_transaction(params)

        assert gas == 187_500
        contract_fn.estimate_gas.assert_awaited_once_with({"from": kernel.account.address})

    async def test_accepts_dict_params(self):
        kernel = _make_kernel()
        contract_fn = MagicMock()
        contract_fn.estimate_gas = AsyncMock(return_value=200_000)
        kernel.contract.functions.createTransaction.return_value = contract_fn

        gas = await kernel.estimate_create_transaction(
            {
                "provider": PROVIDER,
                "amount": 1_000_000,
                "deadline": int(time.time()) + 3600,
            }
        )
        assert gas == 200_000


# ---------------------------------------------------------------------------
# get_transaction legacy fallback
# ---------------------------------------------------------------------------


def _legacy_tuple() -> tuple:
    """A 16-field legacy getTransaction tuple."""
    return (
        bytes.fromhex("0" * 64),  # transactionId
        REQUESTER,                # requester
        PROVIDER,                 # provider
        0,                        # state INITIATED
        1_000_000,                # amount
        1_700_000_000,            # createdAt
        1_700_000_001,            # updatedAt
        1_700_003_600,            # deadline
        bytes.fromhex("0" * 64),  # serviceHash
        "0x" + "0" * 40,          # escrowContract
        bytes.fromhex("0" * 64),  # escrowId
        bytes.fromhex("0" * 64),  # attestationUID
        172800,                   # disputeWindow
        bytes.fromhex("0" * 64),  # metadata
        100,                      # platformFeeBpsLocked
        7,                        # agentId
    )


class TestGetTransactionLegacyFallback:
    async def test_falls_back_to_legacy_abi_on_decode_failure(self):
        kernel = _make_kernel()

        # Primary 21-field call raises a decode failure.
        primary_fn = MagicMock()
        primary_fn.call = AsyncMock(side_effect=Exception("Could not decode contract function call"))
        kernel.contract.functions.getTransaction.return_value = primary_fn

        # Legacy contract returns the 16-field tuple.
        legacy_contract = MagicMock()
        legacy_fn = MagicMock()
        legacy_fn.call = AsyncMock(return_value=_legacy_tuple())
        legacy_contract.functions.getTransaction.return_value = legacy_fn
        kernel.w3.eth.contract = MagicMock(return_value=legacy_contract)

        view = await kernel.get_transaction("0x" + "9" * 64)

        assert view.state == TransactionState.INITIATED
        assert view.agent_id == 7
        # Fields absent in legacy shape default to 0 / "".
        assert view.requester_penalty_bps_locked == 0
        assert view.dispute_bond_bps_locked == 0
        assert view.requester_agent_id == 0
        assert view.dispute_initiator == ""
        assert view.dispute_bond == 0

    async def test_tx_missing_maps_to_not_found(self):
        kernel = _make_kernel()
        primary_fn = MagicMock()
        primary_fn.call = AsyncMock(side_effect=Exception("execution reverted: Tx missing"))
        kernel.contract.functions.getTransaction.return_value = primary_fn

        with pytest.raises(TransactionNotFoundError):
            await kernel.get_transaction("0x" + "9" * 64)

    async def test_non_decode_error_propagates(self):
        kernel = _make_kernel()
        primary_fn = MagicMock()
        primary_fn.call = AsyncMock(side_effect=Exception("connection refused"))
        kernel.contract.functions.getTransaction.return_value = primary_fn

        with pytest.raises(Exception) as exc_info:
            await kernel.get_transaction("0x" + "9" * 64)
        assert "connection refused" in str(exc_info.value)
