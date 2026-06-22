# PARITY: sdk-js/tests/bond-escalation.test.ts
"""
P2-4 — BondEscalationClient unit tests (Py side).

Mirrors ``sdk-js/tests/bond-escalation.test.ts`` 1:1 and consumes the SAME
shared cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/bond-escalation-vectors.json``.

Proves, with a mock contract (no live chain):
  1. Each IBondEscalation write method builds the CORRECT calldata
     (selector + ABI-encoded args == what the contract's ``encode_abi`` produces
     independently — the same assertion surface as the TS twin's
     ``Interface.encodeFunctionData``).
  2. get_dispute_state decodes the disputes() tuple to the fixture-expected
     DisputeState (the TS twin asserts the identical fixture).
  3. The two pure quote helpers match every fixture row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

import pytest
from web3 import Web3

from agirails.dispute.bond_escalation import BondEscalationClient
from agirails.types.dispute import AIRuling, Ruling

# Shared cross-SDK fixture (the SAME file the TS jest suite loads).
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
_FIXTURE = json.loads((_VECTORS_DIR / "bond-escalation-vectors.json").read_text())

_ABI = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "src"
        / "agirails"
        / "abis"
        / "bond_escalation.json"
    ).read_text()
)

# Reference contract for INDEPENDENT calldata encoding (the assertion oracle).
_REF_CONTRACT = Web3().eth.contract(abi=_ABI)

TX_ID = "0xabcdef0000000000000000000000000000000000000000000000000000000001"
DISPUTE_ID = "0x1234567890123456789012345678901234567890123456789012345678901234"


def _ref_calldata(method: str, args: List[Any]) -> str:
    """Independently encode calldata via the reference contract."""
    return _REF_CONTRACT.encode_abi(abi_element_identifier=method, args=args)


class _MockFunction:
    """Awaitable mock that records the positional args it was called with."""

    def __init__(self, recorder, name: str):
        self._recorder = recorder
        self._name = name

    def __call__(self, *args):
        self._recorder.append((self._name, args))
        return self

    def __await__(self):
        async def _coro():
            return b"\xaa" * 32  # mock tx hash

        return _coro().__await__()


class _MockFunctions:
    def __init__(self, recorder, disputes_tuple):
        self._recorder = recorder
        self._disputes_tuple = disputes_tuple

    def __getattr__(self, name):
        if name == "disputes":
            return self._DisputesFn(self._disputes_tuple)
        return _MockFunction(self._recorder, name)

    class _DisputesFn:
        def __init__(self, tuple_):
            self._tuple = tuple_

        def __call__(self, *_args):
            return self

        async def call(self):
            return self._tuple


class _MockContract:
    """Records calldata + args, returns a configurable disputes() tuple."""

    def __init__(self, disputes_tuple=None):
        self.calls: List = []
        self.functions = _MockFunctions(self.calls, disputes_tuple)
        self.address = "0x000000000000000000000000000000000000dEaD"

    def encode_abi(self, *, abi_element_identifier: str, args):
        return _ref_calldata(abi_element_identifier, args)


def _make_client(disputes_tuple=None):
    contract = _MockContract(disputes_tuple)
    client = BondEscalationClient(
        contract,
        address="0x000000000000000000000000000000000000dEaD",
    )
    return client, contract


def _normalize_tuple(raw):
    """Fixture stores big-ints as strings + tx ids as hex; coerce for decode."""
    out = list(raw)
    # currentBond[3], accumulatedBonds[4], livenessEnd[5], disputedAt[6],
    # originalPool[11], escrowAmount[12] are big-int strings in the fixture.
    for idx in (3, 4, 5, 6, 11, 12):
        out[idx] = int(out[idx])
    return out


# ---------------------------------------------------------------------------
# 1. Quote helpers (shared fixture)
# ---------------------------------------------------------------------------


def test_quote_initial_bond_matches_every_fixture_row():
    for row in _FIXTURE["quoteInitialBond"]:
        got = BondEscalationClient.quote_initial_bond(int(row["escrowAmount"]))
        assert str(got) == row["expected"], row.get("_note", "")


def test_quote_escalation_bond_matches_every_fixture_row():
    for row in _FIXTURE["quoteEscalationBond"]:
        got = BondEscalationClient.quote_escalation_bond(int(row["currentBond"]))
        assert str(got) == row["expected"], row.get("_note", "")


def test_quote_initial_bond_floor_and_rate():
    assert BondEscalationClient.quote_initial_bond(0) == 1_000_000
    assert BondEscalationClient.quote_initial_bond(100_000_000) == 2_000_000


def test_quote_escalation_bond_double_then_cap():
    assert BondEscalationClient.quote_escalation_bond(1_000_000) == 2_000_000
    assert BondEscalationClient.quote_escalation_bond(300_000_000) == 500_000_000


# ---------------------------------------------------------------------------
# 2. get_dispute_state decode (shared fixture)
# ---------------------------------------------------------------------------


async def test_get_dispute_state_decodes_fixture_open_split():
    fx = _FIXTURE["getDisputeState"]
    client, _ = _make_client(_normalize_tuple(fx["tuple"]))
    state = await client.get_dispute_state(fx["disputeId"])
    assert state.tx_id == fx["expected"]["txId"]
    assert state.dispute_id == fx["expected"]["disputeId"]
    assert int(state.tier) == fx["expected"]["tier"]
    assert int(state.ruling) == fx["expected"]["ruling"]
    assert state.split_bps == fx["expected"]["splitBps"]
    assert state.resolved == fx["expected"]["resolved"]


async def test_get_dispute_state_decodes_resolved_non_split():
    fx = _FIXTURE["getDisputeStateResolved"]
    client, _ = _make_client(_normalize_tuple(fx["tuple"]))
    state = await client.get_dispute_state(fx["disputeId"])
    assert int(state.tier) == fx["expected"]["tier"]
    assert int(state.ruling) == fx["expected"]["ruling"]
    assert state.resolved is True


def test_decode_dispute_state_static_handles_bytes_tx_id():
    raw = [
        bytes.fromhex("ab" * 32),  # transactionId as bytes
        1,  # currentRuling
        0,  # splitBps
        0,  # currentBond
        0,  # accumulatedBonds
        0,  # livenessEnd
        0,  # disputedAt
        "0x" + "11" * 20,  # lastProposer
        2,  # tier
        False,  # resolved
        False,  # winnerPaid
        0,  # originalPool
        0,  # escrowAmount
    ]
    state = BondEscalationClient.decode_dispute_state(DISPUTE_ID, raw)
    assert state.tx_id == "0x" + "ab" * 32
    assert int(state.tier) == 2
    assert int(state.ruling) == Ruling.REQUESTER_WINS


# ---------------------------------------------------------------------------
# 3. Calldata per IBondEscalation method
# ---------------------------------------------------------------------------


async def test_open_dispute_calldata():
    client, contract = _make_client()
    result = await client.open_dispute(TX_ID)
    name, args = contract.calls[0]
    assert name == "openDispute"
    assert contract.encode_abi(
        abi_element_identifier="openDispute", args=list(args)
    ) == _ref_calldata("openDispute", [bytes.fromhex(TX_ID[2:])])
    assert result["dispute_id"].startswith("0x") and len(result["dispute_id"]) == 66


async def test_submit_ai_ruling_calldata():
    client, contract = _make_client()
    ruling = AIRuling(
        dispute_id=DISPUTE_ID,
        ruling=Ruling.SPLIT,
        confidence=9500,
        split_bps=6000,
        timestamp=1700000000,
        reasoning_hash="0x" + "11" * 32,
        bundle_hash="0x" + "22" * 32,
    )
    sigs = ["0x" + "ab" * 65, "0x" + "cd" * 65]
    await client.submit_ai_ruling(ruling, sigs)
    name, args = contract.calls[0]
    assert name == "submitAIRuling"
    tuple_arg = (
        bytes.fromhex(DISPUTE_ID[2:]),
        2,
        9500,
        6000,
        1700000000,
        bytes.fromhex("11" * 32),
        bytes.fromhex("22" * 32),
    )
    expected = _ref_calldata(
        "submitAIRuling",
        [
            bytes.fromhex(DISPUTE_ID[2:]),
            tuple_arg,
            [bytes.fromhex("ab" * 65), bytes.fromhex("cd" * 65)],
        ],
    )
    assert contract.encode_abi(abi_element_identifier="submitAIRuling", args=list(args)) == expected


async def test_propose_directly_calldata():
    client, contract = _make_client()
    await client.propose_directly(DISPUTE_ID, Ruling.SPLIT, 6500)
    name, args = contract.calls[0]
    assert name == "proposeDirectly"
    assert contract.encode_abi(
        abi_element_identifier="proposeDirectly", args=list(args)
    ) == _ref_calldata("proposeDirectly", [bytes.fromhex(DISPUTE_ID[2:]), 2, 6500])


async def test_challenge_calldata():
    client, contract = _make_client()
    await client.challenge(DISPUTE_ID, Ruling.REQUESTER_WINS, 0)
    name, args = contract.calls[0]
    assert name == "challenge"
    assert contract.encode_abi(
        abi_element_identifier="challenge", args=list(args)
    ) == _ref_calldata("challenge", [bytes.fromhex(DISPUTE_ID[2:]), 1, 0])


async def test_finalize_calldata():
    client, contract = _make_client()
    await client.finalize(DISPUTE_ID)
    name, args = contract.calls[0]
    assert name == "finalize"
    assert contract.encode_abi(
        abi_element_identifier="finalize", args=list(args)
    ) == _ref_calldata("finalize", [bytes.fromhex(DISPUTE_ID[2:])])


async def test_escalate_to_uma_calldata():
    client, contract = _make_client()
    cid = "bafybeigdyrztabcdefghijklmnopqrstuvwxyz1234567890"
    await client.escalate_to_uma(DISPUTE_ID, cid)
    name, args = contract.calls[0]
    assert name == "escalateToUMA"
    assert contract.encode_abi(
        abi_element_identifier="escalateToUMA", args=list(args)
    ) == _ref_calldata("escalateToUMA", [bytes.fromhex(DISPUTE_ID[2:]), cid])


async def test_claim_escalation_refund_calldata():
    client, contract = _make_client()
    await client.claim_escalation_refund(DISPUTE_ID)
    name, args = contract.calls[0]
    assert name == "claimEscalationRefund"
    assert contract.encode_abi(
        abi_element_identifier="claimEscalationRefund", args=list(args)
    ) == _ref_calldata("claimEscalationRefund", [bytes.fromhex(DISPUTE_ID[2:])])


async def test_sync_external_resolution_calldata():
    client, contract = _make_client()
    await client.sync_external_resolution(DISPUTE_ID)
    name, args = contract.calls[0]
    assert name == "syncExternalResolution"
    assert contract.encode_abi(
        abi_element_identifier="syncExternalResolution", args=list(args)
    ) == _ref_calldata("syncExternalResolution", [bytes.fromhex(DISPUTE_ID[2:])])


async def test_force_resolve_stale_calldata():
    client, contract = _make_client()
    await client.force_resolve_stale(DISPUTE_ID)
    name, args = contract.calls[0]
    assert name == "forceResolveStale"
    assert contract.encode_abi(
        abi_element_identifier="forceResolveStale", args=list(args)
    ) == _ref_calldata("forceResolveStale", [bytes.fromhex(DISPUTE_ID[2:])])


# ---------------------------------------------------------------------------
# 4. Config guards
# ---------------------------------------------------------------------------


def test_rejects_confirmations_below_one():
    contract = _MockContract()
    with pytest.raises(ValueError, match="confirmations must be >= 1"):
        BondEscalationClient(contract, confirmations=0)


def test_accessors():
    client, _ = _make_client()
    assert client.get_address() == "0x000000000000000000000000000000000000dEaD"
    assert client.get_contract() is not None
