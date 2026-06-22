# PARITY: sdk-js/tests/uma-helper.test.ts
"""
P2-7 — UMAHelper unit tests (Py side): the requester self-dispute DVM helper
(AIP-14b §8.6).

Mirrors ``sdk-js/tests/uma-helper.test.ts`` 1:1 and consumes the SAME shared
cross-SDK fixture ``DISPUTE SYSTEM/test-vectors/uma-self-dispute-vectors.json``.

Proves, with mock contracts (no live chain):
  1. requester_force_dvm issues EXACTLY the call sequence
     approve -> escalateToUMA -> (read assertionId) -> approve -> disputeAssertion,
     in that order, with the correct target contract + calldata per step.
  2. quote_self_dispute_cost returns {total $1000, recover $750, lose $250}.
  3. The §8.6 asymmetry warning AND the "settleAssertion yourself or risk a
     30-day forced 50/50 split" warning are BOTH present in the source
     (a grep test reads the .py file).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, List

import pytest
from web3 import Web3

from agirails.dispute.uma_helper import (
    UMAHelper,
    UMA_BOND,
    SELF_DISPUTE_TOTAL,
    SELF_DISPUTE_RECOVER,
    SELF_DISPUTE_LOSS,
)

# Shared cross-SDK fixture (the SAME file the TS jest suite loads).
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
_FIXTURE = json.loads((_VECTORS_DIR / "uma-self-dispute-vectors.json").read_text())

_ABI_DIR = Path(__file__).resolve().parents[2] / "src" / "agirails" / "abis"
_BOND_ABI = json.loads((_ABI_DIR / "bond_escalation.json").read_text())
_OOV3_ABI = json.loads((_ABI_DIR / "i_optimistic_oracle_v3.json").read_text())
_USDC_ABI = json.loads((_ABI_DIR / "usdc.json").read_text())

# Reference contracts for INDEPENDENT calldata encoding (the assertion oracle).
_REF_BOND = Web3().eth.contract(abi=_BOND_ABI)
_REF_OOV3 = Web3().eth.contract(abi=_OOV3_ABI)
_REF_USDC = Web3().eth.contract(abi=_USDC_ABI)

BOND_ADDR = "0x000000000000000000000000000000000000BE11"
OOV3_ADDR = "0x2aBf1Bd76655de80eDB3086114315Eec75AF500c"
USDC_ADDR = "0x000000000000000000000000000000000000C0dc"


def _b32(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)


class _MockFunction:
    """Awaitable mock that records (target, name, args) into a shared sink."""

    def __init__(self, sink: List, target: str, name: str):
        self._sink = sink
        self._target = target
        self._name = name

    def __call__(self, *args):
        self._sink.append((self._target, self._name, args))
        return self

    def __await__(self):
        async def _coro():
            return b"\xaa" * 32

        return _coro().__await__()


class _DisputeToAssertionFn:
    """Read fn: records the read into the sink, returns a configured assertion."""

    def __init__(self, sink: List, assertion_id: str):
        self._sink = sink
        self._assertion_id = assertion_id

    def __call__(self, *_args):
        return self

    async def call(self):
        self._sink.append(("bondEscalation", "disputeToAssertion(read)", ()))
        return _b32(self._assertion_id)


class _MockFunctions:
    def __init__(self, sink: List, target: str, assertion_id: str = None):
        self._sink = sink
        self._target = target
        self._assertion_id = assertion_id

    def __getattr__(self, name):
        if name == "disputeToAssertion" and self._assertion_id is not None:
            return _DisputeToAssertionFn(self._sink, self._assertion_id)
        return _MockFunction(self._sink, self._target, name)


class _MockContract:
    """Records calldata via a reference contract's encode_abi."""

    def __init__(self, sink: List, target: str, ref, address: str, assertion_id: str = None):
        self._ref = ref
        self.address = address
        self.functions = _MockFunctions(sink, target, assertion_id)

    def encode_abi(self, *, abi_element_identifier: str, args):
        return self._ref.encode_abi(abi_element_identifier=abi_element_identifier, args=args)


def _make_helper(assertion_id: str = None):
    assertion_id = assertion_id or _FIXTURE["requesterForceDVM"]["assertionId"]
    sink: List = []
    bond = _MockContract(sink, "bondEscalation", _REF_BOND, BOND_ADDR, assertion_id)
    oov3 = _MockContract(sink, "oov3", _REF_OOV3, OOV3_ADDR)
    usdc = _MockContract(sink, "usdc", _REF_USDC, USDC_ADDR)
    helper = UMAHelper(
        bond,
        oov3,
        usdc,
        bond_escalation_address=BOND_ADDR,
        oov3_address=OOV3_ADDR,
        usdc_address=USDC_ADDR,
    )
    return helper, sink


# ---------------------------------------------------------------------------
# 1. quote_self_dispute_cost (shared fixture)
# ---------------------------------------------------------------------------


def test_quote_self_dispute_cost_matches_fixture():
    cost = UMAHelper.quote_self_dispute_cost()
    fx = _FIXTURE["quoteSelfDisputeCost"]
    assert str(cost["total"]) == fx["total"]
    assert str(cost["recover"]) == fx["recover"]
    assert str(cost["lose"]) == fx["lose"]


def test_quote_self_dispute_cost_exact_dollars():
    cost = UMAHelper.quote_self_dispute_cost()
    assert cost["total"] == 1_000_000_000  # $1000
    assert cost["recover"] == 750_000_000  # $750
    assert cost["lose"] == 250_000_000  # $250
    # identity: total - recover == lose (UMA Store fee = 50% of losing bond)
    assert cost["total"] - cost["recover"] == cost["lose"]
    # attribute access parity with the TS object shape
    assert cost.total == cost["total"]
    assert cost.recover == cost["recover"]
    assert cost.lose == cost["lose"]


def test_constants_internally_consistent():
    assert UMA_BOND == 500_000_000
    assert SELF_DISPUTE_TOTAL == UMA_BOND * 2
    assert SELF_DISPUTE_RECOVER == UMA_BOND + UMA_BOND // 2
    assert SELF_DISPUTE_LOSS == SELF_DISPUTE_TOTAL - SELF_DISPUTE_RECOVER


# ---------------------------------------------------------------------------
# 2. requester_force_dvm call sequence (shared fixture)
# ---------------------------------------------------------------------------


async def test_requester_force_dvm_exact_call_sequence():
    fx = _FIXTURE["requesterForceDVM"]
    helper, sink = _make_helper(fx["assertionId"])

    result = await helper.requester_force_dvm(
        fx["disputeId"], fx["evidenceCID"], fx["disputer"]
    )

    # Full ordered sequence INCLUDING the read between escalate and dispute.
    seq = [(t, n) for (t, n, _a) in sink]
    assert seq == [
        ("usdc", "approve"),
        ("bondEscalation", "escalateToUMA"),
        ("bondEscalation", "disputeToAssertion(read)"),
        ("usdc", "approve"),
        ("oov3", "disputeAssertion"),
    ]

    # The fixture's declared sequence MUST match (read step mapped 1:1).
    fixture_seq = []
    for step in fx["sequence"]:
        method = "disputeToAssertion(read)" if step["method"] == "disputeToAssertion" else step["method"]
        fixture_seq.append((step["target"], method))
    assert seq == fixture_seq

    # The read produced the assertionId returned to the caller.
    assert result["assertion_id"] == fx["assertionId"]

    # Per-step calldata (writes only) matches an independent encode.
    writes = [(t, n, a) for (t, n, a) in sink if "read" not in n]
    # Step 1: approve(bondEscalation, $500)
    t, n, a = writes[0]
    assert (t, n) == ("usdc", "approve")
    assert _REF_USDC.encode_abi(abi_element_identifier="approve", args=list(a)) == _REF_USDC.encode_abi(
        abi_element_identifier="approve", args=[BOND_ADDR, UMA_BOND]
    )
    # Step 2: escalateToUMA(disputeId, evidenceCID)
    t, n, a = writes[1]
    assert (t, n) == ("bondEscalation", "escalateToUMA")
    assert _REF_BOND.encode_abi(abi_element_identifier="escalateToUMA", args=list(a)) == _REF_BOND.encode_abi(
        abi_element_identifier="escalateToUMA", args=[_b32(fx["disputeId"]), fx["evidenceCID"]]
    )
    # Step 3: approve(oov3, $500)
    t, n, a = writes[2]
    assert (t, n) == ("usdc", "approve")
    assert _REF_USDC.encode_abi(abi_element_identifier="approve", args=list(a)) == _REF_USDC.encode_abi(
        abi_element_identifier="approve", args=[OOV3_ADDR, UMA_BOND]
    )
    # Step 4: disputeAssertion(assertionId, disputer)
    t, n, a = writes[3]
    assert (t, n) == ("oov3", "disputeAssertion")
    assert _REF_OOV3.encode_abi(abi_element_identifier="disputeAssertion", args=list(a)) == _REF_OOV3.encode_abi(
        abi_element_identifier="disputeAssertion", args=[_b32(fx["assertionId"]), fx["disputer"]]
    )


async def test_read_happens_after_escalate_before_dispute():
    fx = _FIXTURE["requesterForceDVM"]
    helper, sink = _make_helper(fx["assertionId"])
    await helper.requester_force_dvm(fx["disputeId"], fx["evidenceCID"], fx["disputer"])
    names = [n for (_t, n, _a) in sink]
    escalate_idx = names.index("escalateToUMA")
    read_idx = names.index("disputeToAssertion(read)")
    dispute_idx = names.index("disputeAssertion")
    assert escalate_idx < read_idx < dispute_idx


async def test_get_assertion_id_reads_dispute_to_assertion():
    fx = _FIXTURE["requesterForceDVM"]
    helper, _ = _make_helper(fx["assertionId"])
    got = await helper.get_assertion_id(fx["disputeId"])
    assert got == fx["assertionId"]


async def test_settle_assertion_calldata():
    fx = _FIXTURE["requesterForceDVM"]
    helper, sink = _make_helper(fx["assertionId"])
    await helper.settle_assertion(fx["assertionId"])
    assert len(sink) == 1
    t, n, a = sink[0]
    assert (t, n) == ("oov3", "settleAssertion")
    assert _REF_OOV3.encode_abi(abi_element_identifier="settleAssertion", args=list(a)) == _REF_OOV3.encode_abi(
        abi_element_identifier="settleAssertion", args=[_b32(fx["assertionId"])]
    )


# ---------------------------------------------------------------------------
# 3. Config guards
# ---------------------------------------------------------------------------


def test_rejects_confirmations_below_one():
    helper, _ = _make_helper()
    with pytest.raises(ValueError, match="confirmations must be >= 1"):
        UMAHelper(
            helper._bond_escalation,
            helper._oov3,
            helper._usdc,
            confirmations=0,
        )


def test_address_accessors():
    helper, _ = _make_helper()
    assert helper.get_bond_escalation_address() == BOND_ADDR
    assert helper.get_oov3_address() == OOV3_ADDR


# ---------------------------------------------------------------------------
# 4. Required docstring warnings (grep over source)
# ---------------------------------------------------------------------------

_SRC = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "agirails"
    / "dispute"
    / "uma_helper.py"
).read_text()


def test_source_contains_asymmetry_warning():
    # The §8.6 asymmetry: escalate_to_uma is provider-directional, rational only
    # for the provider side; the requester normally wins for free via finalize().
    assert re.search(r"§8\.6 ASYMMETRY WARNING", _SRC)
    assert re.search(r"provider-directional", _SRC, re.IGNORECASE)
    assert re.search(r"asymmetr", _SRC, re.IGNORECASE)


def test_source_contains_settle_warning():
    assert re.search(
        r"[Cc]all\s+settleAssertion\s+yourself\s+or\s+risk\s+a\s+30-day\s+forced\s+50/50\s+split",
        _SRC,
    )
