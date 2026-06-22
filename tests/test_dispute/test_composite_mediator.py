# PARITY: sdk-js/tests/composite-mediator.test.ts
"""
P2-5 — CompositeMediator read/event client + decoders (Py side).

Mirrors ``sdk-js/tests/composite-mediator.test.ts`` 1:1 and consumes the SAME
shared cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/composite-mediator-vectors.json``.

Proves:
  1. decode_dispute_split_recorded decodes a DisputeSplitRecorded log.
  2. decode_resolution_proof obeys the ZERO-REMAINING CONSUMER RULE — a drained
     dispute (remaining==0) surfaces NO 1-wei payout (phantom sentinel).
  3. compute_split_rate counts DisputeSplitRecorded + kernel DISPUTED→CANCELLED
     at identical weight (OQ-11) over the fixture rows.
  4. EventMonitor surfaces DisputeSplitRecorded, kernel DISPUTED→CANCELLED,
     and UMADisputeEscalated.
  5. resolve() is NOT a public client method (it's onlyBondEscalation).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from eth_abi import encode
from eth_utils import keccak
from web3 import Web3

from agirails.dispute.composite_mediator import (
    CompositeMediator,
    compute_split_rate,
    decode_dispute_split_recorded,
    decode_resolution_proof,
)
from agirails.protocol.events import EventMonitor
from agirails.types.transaction import TransactionState

# Shared cross-SDK fixture (the SAME file the TS jest suite loads).
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
_FIXTURE = json.loads((_VECTORS_DIR / "composite-mediator-vectors.json").read_text())

_ABI_DIR = Path(__file__).resolve().parents[2] / "src" / "agirails" / "abis"
_MEDIATOR_ABI = json.loads((_ABI_DIR / "composite_mediator.json").read_text())
_KERNEL_ABI = json.loads((_ABI_DIR / "actp_kernel.json").read_text())
_BOND_ABI = json.loads((_ABI_DIR / "bond_escalation.json").read_text())

_MEDIATOR_CONTRACT = Web3().eth.contract(abi=_MEDIATOR_ABI)
_KERNEL_CONTRACT = Web3().eth.contract(abi=_KERNEL_ABI)
_BOND_CONTRACT = Web3().eth.contract(abi=_BOND_ABI)


def _bytes32(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)


def _addr_topic(addr: str) -> bytes:
    return bytes(12) + bytes.fromhex(addr[2:])


def _make_split_log(ev: Dict[str, Any], block: int = 100, idx: int = 0) -> Dict[str, Any]:
    """Build a raw DisputeSplitRecorded log + process it via the mediator ABI."""
    topic0 = keccak(text="DisputeSplitRecorded(bytes32,address,address,uint16)")
    raw_log = {
        "address": "0x0000000000000000000000000000000000000000",
        "topics": [
            topic0,
            _bytes32(ev["txId"]),
            _addr_topic(ev["requester"]),
            _addr_topic(ev["provider"]),
        ],
        "data": "0x" + encode(["uint16"], [ev["splitBps"]]).hex(),
        "blockNumber": block,
        "transactionHash": b"\xfe" * 32,
        "logIndex": idx,
        "transactionIndex": 0,
        "blockHash": b"\x00" * 32,
    }
    return _MEDIATOR_CONTRACT.events.DisputeSplitRecorded().process_log(raw_log)


def _make_state_log(
    old_state: int, new_state: int, tx_id: str, block: int, idx: int
) -> Dict[str, Any]:
    topic0 = keccak(text="StateTransitioned(bytes32,uint8,uint8,address,uint256)")
    raw_log = {
        "address": "0x0000000000000000000000000000000000000000",
        "topics": [
            topic0,
            _bytes32(tx_id),
            old_state.to_bytes(32, "big"),
            new_state.to_bytes(32, "big"),
        ],
        "data": "0x"
        + encode(
            ["address", "uint256"],
            ["0x3333333333333333333333333333333333333333", 1700000000],
        ).hex(),
        "blockNumber": block,
        "transactionHash": b"\xaa" * 32,
        "logIndex": idx,
        "transactionIndex": 0,
        "blockHash": b"\x00" * 32,
    }
    return _KERNEL_CONTRACT.events.StateTransitioned().process_log(raw_log)


def _make_uma_log(
    dispute_id: str, assertion_id: str, block: int, idx: int
) -> Dict[str, Any]:
    topic0 = keccak(text="UMADisputeEscalated(bytes32,bytes32)")
    raw_log = {
        "address": "0x0000000000000000000000000000000000000000",
        "topics": [topic0, _bytes32(dispute_id), _bytes32(assertion_id)],
        "data": "0x",
        "blockNumber": block,
        "transactionHash": b"\xbb" * 32,
        "logIndex": idx,
        "transactionIndex": 0,
        "blockHash": b"\x00" * 32,
    }
    return _BOND_CONTRACT.events.UMADisputeEscalated().process_log(raw_log)


# ---------------------------------------------------------------------------
# 1. decode_dispute_split_recorded
# ---------------------------------------------------------------------------


def test_decode_dispute_split_recorded():
    ev = _FIXTURE["splitRecordedEvent"]
    decoded = decode_dispute_split_recorded(_make_split_log(ev))
    assert decoded.tx_id.lower() == ev["txId"].lower()
    assert decoded.requester.lower() == ev["requester"].lower()
    assert decoded.provider.lower() == ev["provider"].lower()
    assert decoded.split_bps == ev["splitBps"]


def test_decode_dispute_split_recorded_rejects_wrong_event():
    state_log = _make_state_log(
        TransactionState.DISPUTED, TransactionState.CANCELLED, _FIXTURE["splitRecordedEvent"]["txId"], 1, 0
    )
    with pytest.raises(ValueError, match="not a DisputeSplitRecorded"):
        decode_dispute_split_recorded(state_log)


# ---------------------------------------------------------------------------
# 2. decode_resolution_proof — ZERO-REMAINING CONSUMER RULE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _FIXTURE["resolutionProofs"], ids=lambda r: r["name"])
def test_decode_resolution_proof_matches_fixture(row):
    decoded = decode_resolution_proof(row["proof"], int(row["remaining"]))
    exp = row["expected"]
    assert decoded.is_split == exp["isSplit"]
    assert decoded.phantom_sentinel == exp["phantomSentinel"]
    assert str(decoded.requester_amount) == exp["requesterAmount"]
    assert str(decoded.provider_amount) == exp["providerAmount"]
    if exp["providerAtFault"] is None:
        assert decoded.provider_at_fault is None
    else:
        assert decoded.provider_at_fault == exp["providerAtFault"]


def test_drained_dispute_no_1_wei_payout():
    # On-chain proof carries a 1-wei sentinel, but remaining==0 → both payouts 0.
    sentinel_proof = "0x" + encode(["uint256", "uint256", "bool"], [0, 1, False]).hex()
    decoded = decode_resolution_proof(sentinel_proof, 0)
    assert decoded.phantom_sentinel is True
    assert decoded.requester_amount == 0
    assert decoded.provider_amount == 0
    # Hard assertion of the rule: the surfaced amount is NEVER the 1-wei sentinel.
    assert decoded.provider_amount != 1


# ---------------------------------------------------------------------------
# 3. compute_split_rate — OQ-11
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _FIXTURE["splitRate"], ids=lambda r: r["name"])
def test_compute_split_rate_matches_fixture(row):
    got = compute_split_rate(
        row["splitRecorded"], row["kernelDisputedToCancelled"], row["totalDisputes"]
    )
    assert got == pytest.approx(row["expected"], abs=1e-10)


# ---------------------------------------------------------------------------
# 4. EventMonitor dispute surfacing
# ---------------------------------------------------------------------------


class _MockEvents:
    """Mimics ``contract.events.<Name>`` returning a filter that replays logs."""

    def __init__(self, logs_by_event: Dict[str, List[Any]]):
        self._logs = logs_by_event

    def __getattr__(self, name: str):
        logs = self._logs.get(name, [])

        class _EventObj:
            @staticmethod
            def create_filter(*_a, **_k):
                class _Filter:
                    async def get_all_entries():  # type: ignore[no-untyped-def]
                        return logs

                # get_all_entries needs to be an instance coroutine
                f = _Filter()

                async def _get_all():
                    return logs

                f.get_all_entries = _get_all  # type: ignore[attr-defined]
                return f

        return _EventObj()


class _MockContract:
    def __init__(self, logs_by_event: Dict[str, List[Any]]):
        self.events = _MockEvents(logs_by_event)


@pytest.mark.asyncio
async def test_get_dispute_events_surfaces_all_three(monkeypatch):
    tx = _FIXTURE["splitRecordedEvent"]["txId"]
    dispute_id = "0x" + "11" * 32
    assertion_id = "0x" + "22" * 32

    kernel = _MockContract(
        {
            "StateTransitioned": [
                _make_state_log(TransactionState.DISPUTED, TransactionState.CANCELLED, tx, 10, 0),
                _make_state_log(TransactionState.DELIVERED, TransactionState.SETTLED, tx, 11, 0),
            ]
        }
    )
    mediator = _MockContract(
        {"DisputeSplitRecorded": [_make_split_log(_FIXTURE["splitRecordedEvent"], 12, 0)]}
    )
    bond = _MockContract(
        {"UMADisputeEscalated": [_make_uma_log(dispute_id, assertion_id, 9, 0)]}
    )

    monitor = EventMonitor(kernel, object(), object(), mediator, bond)
    events = await monitor.get_dispute_events()

    types = [e.event_type.value for e in events]
    assert "DisputeSplitRecorded" in types
    assert "UMADisputeEscalated" in types
    # kernel DISPUTED→CANCELLED surfaces as a StateTransitioned event (exactly one).
    cancelled = [
        e
        for e in events
        if e.event_type.value == "StateTransitioned"
        and getattr(e, "previous_state", None) == TransactionState.DISPUTED
        and getattr(e, "new_state", None) == TransactionState.CANCELLED
    ]
    assert len(cancelled) == 1
    # DELIVERED→SETTLED noise is NOT surfaced.
    assert not any(
        getattr(e, "new_state", None) == TransactionState.SETTLED for e in events
    )
    # Block-ordered: UMA(9) < DisputedToCancelled(10) < Split(12).
    assert [e.block_number for e in events] == [9, 10, 12]


@pytest.mark.asyncio
async def test_dispute_subscriptions_require_their_contracts():
    kernel = _MockContract({})
    monitor = EventMonitor(kernel, object(), object())

    with pytest.raises(ValueError, match="without a CompositeMediator"):
        await monitor.on_dispute_split_recorded(lambda _e: None)
    with pytest.raises(ValueError, match="without a BondEscalation"):
        await monitor.on_uma_dispute_escalated(lambda _e: None)


# ---------------------------------------------------------------------------
# 5. resolve() is NOT a public client method (onlyBondEscalation)
# ---------------------------------------------------------------------------


def test_resolve_is_not_a_public_client_method():
    # resolve() exists on the ABI but is guarded onlyBondEscalation; the SDK
    # client deliberately omits it so callers cannot build a reverting tx.
    abi_fns = {x["name"] for x in _MEDIATOR_ABI if x.get("type") == "function"}
    assert "resolve" in abi_fns  # exists on-chain

    client = CompositeMediator(object(), "0x000000000000000000000000000000000000dEaD")
    assert not hasattr(client, "resolve")
    # The observational surface it DOES expose:
    assert hasattr(client, "get_split_recorded_events")
    assert hasattr(client, "get_address")
