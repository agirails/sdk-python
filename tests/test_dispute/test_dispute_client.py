# PARITY: sdk-js/tests/dispute-client.test.ts
"""
P2-9 — DisputeClient facade unit tests (Py side).

Mirrors ``sdk-js/tests/dispute-client.test.ts`` 1:1 and consumes the SAME shared
cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/dispute-client-status-vectors.json``.

Proves, with a mock contract / mock sub-clients (no live chain):
  1. The §9 sub-state decode (``decode_dispute_sub_state`` + ``get_dispute_status``)
     matches every fixture row — the single cross-SDK decode.
  2. The facade composes the five primitives and exposes them via properties;
     unconfigured properties raise; the split indexer is always present.
  3. ``get_dispute_status`` raises a clear error when the bond client is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

import pytest

from agirails.dispute.bond_escalation import BondEscalationClient
from agirails.dispute.dispute_client import (
    DisputeClient,
    decode_dispute_sub_state,
)
from agirails.reputation.dispute_split_indexer import (
    DisputeOutcome,
    DisputeSplitIndexer,
)

# Shared cross-SDK fixture (the SAME file the TS jest suite loads).
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
_FIXTURE = json.loads(
    (_VECTORS_DIR / "dispute-client-status-vectors.json").read_text()
)


# ---------------------------------------------------------------------------
# Mock BondEscalation contract whose disputes().call() returns a fixed tuple.
# ---------------------------------------------------------------------------


class _DisputesFn:
    def __init__(self, tuple_):
        self._tuple = tuple_

    def __call__(self, *_args):
        return self

    async def call(self):
        return self._tuple


class _MockFunctions:
    def __init__(self, disputes_tuple):
        self._disputes_tuple = disputes_tuple

    def __getattr__(self, name):
        if name == "disputes":
            return _DisputesFn(self._disputes_tuple)
        raise AttributeError(name)


class _MockContract:
    def __init__(self, disputes_tuple):
        self.functions = _MockFunctions(disputes_tuple)
        self.address = "0x000000000000000000000000000000000000dEaD"


def _normalize_tuple(raw) -> List[Any]:
    """Fixture stores big-ints as strings; coerce the numeric fields for decode.
    Indices: currentBond[3], accumulatedBonds[4], livenessEnd[5], disputedAt[6],
    originalPool[11], escrowAmount[12]."""
    out = list(raw)
    for idx in (3, 4, 5, 6, 11, 12):
        out[idx] = int(out[idx])
    return out


def _make_bond_client_with_tuple(tuple_) -> BondEscalationClient:
    contract = _MockContract(_normalize_tuple(tuple_))
    return BondEscalationClient(
        contract,
        address="0x000000000000000000000000000000000000dEaD",
    )


# ---------------------------------------------------------------------------
# 1. §9 sub-state decode (cross-SDK golden fixture)
# ---------------------------------------------------------------------------


def test_decode_dispute_sub_state_matches_every_fixture_row():
    for vec in _FIXTURE["vectors"]:
        got = decode_dispute_sub_state(_normalize_tuple(vec["tuple"]))
        assert got == vec["expected"]["substate"], vec["name"]


@pytest.mark.asyncio
async def test_get_dispute_status_matches_every_fixture_row():
    for vec in _FIXTURE["vectors"]:
        client = DisputeClient(
            bond=_make_bond_client_with_tuple(vec["tuple"])
        )
        status = await client.get_dispute_status(vec["disputeId"])
        exp = vec["expected"]
        assert status.substate == exp["substate"], vec["name"]
        assert status.tier == exp["tier"], vec["name"]
        assert status.resolved == exp["resolved"], vec["name"]
        assert status.ruling == exp["ruling"], vec["name"]
        assert status.split_bps == exp["splitBps"], vec["name"]
        assert status.dispute_id == vec["disputeId"], vec["name"]


# ---------------------------------------------------------------------------
# 2. Composition + properties
# ---------------------------------------------------------------------------


def test_split_indexer_always_present_with_no_config():
    client = DisputeClient()
    assert isinstance(client.split_indexer, DisputeSplitIndexer)
    assert client.has_bond() is False
    assert client.has_mediator() is False
    assert client.has_uma() is False
    assert client.has_evaluator() is False


def test_unconfigured_properties_raise_clear_error():
    client = DisputeClient()
    with pytest.raises(RuntimeError, match="not configured"):
        _ = client.bond
    with pytest.raises(RuntimeError, match="not configured"):
        _ = client.mediator
    with pytest.raises(RuntimeError, match="not configured"):
        _ = client.uma
    with pytest.raises(RuntimeError, match="not configured"):
        _ = client.evaluator


def test_configured_bond_is_exposed_via_property():
    bond = _make_bond_client_with_tuple(_FIXTURE["vectors"][0]["tuple"])
    client = DisputeClient(bond=bond)
    assert client.bond is bond
    assert client.has_bond() is True


@pytest.mark.asyncio
async def test_get_dispute_status_raises_when_bond_absent():
    client = DisputeClient()
    with pytest.raises(RuntimeError, match="not configured"):
        await client.get_dispute_status("0x" + "11" * 32)


def test_record_outcomes_feeds_split_indexer():
    client = DisputeClient()
    client.record_outcomes(
        [
            DisputeOutcome(
                provider="0xabc",
                requester="0xdef",
                kind="disputeSplitRecorded",
                remaining=0,
            )
        ]
    )
    assert client.split_indexer.size() == 1
