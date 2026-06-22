"""
P2-8 — DisputeSplitIndexer (Python side).

Mirrors sdk-js/tests/dispute-split-indexer.test.ts 1:1 and consumes the SAME
shared cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/dispute-split-indexer-vectors.json``.

Proves:
    1. get_split_rate is the headline ~14% case: 1 split / 6 settled = 1/7,
       where the single split is an ADMIN-CANCELLED (kernel DISPUTED->CANCELLED) —
       OQ-11 counts admin-CANCELLED at IDENTICAL weight in the headline.
    2. DisputeSplitRecorded + kernel DISPUTED->CANCELLED weighted identically.
    3. ZERO-REMAINING RULE: a drained split (remaining==0) still counts as a
       split, and classify_payout reports NO 1-wei payout (phantom sentinel).
    4. Per-agent scoping + div-by-zero safety.

PARITY: test asserts mirror the TS twin's assertions row-for-row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from agirails.reputation import (
    DisputeOutcome,
    DisputeSplitIndexer,
    is_split_kind,
    outcome_from_split_recorded,
)
from agirails.dispute.composite_mediator import DisputeSplitRecorded

# PARITY: dispute-split-indexer.test.ts — same fixture, same assertions.
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
_FIXTURE: Dict[str, Any] = json.loads(
    (_VECTORS_DIR / "dispute-split-indexer-vectors.json").read_text()
)

_AGENT: str = _FIXTURE["agent"]


def _indexer_from_fixture(outcomes: List[Dict[str, Any]]) -> DisputeSplitIndexer:
    """Build a DisputeSplitIndexer seeded from a fixture ``outcomes`` array."""
    mapped = [
        DisputeOutcome(
            provider=o["provider"],
            requester=o["requester"],
            kind=o["kind"],
            remaining=int(o.get("remaining", "0")),
            split_bps=o.get("splitBps"),
            proof=o.get("proof"),
            tx_id=o.get("txId"),
        )
        for o in outcomes
    ]
    return DisputeSplitIndexer(mapped)


# ---------------------------------------------------------------------------
# get_split_rate — the headline ~14% fixture (OQ-11 admin-CANCELLED counted)
# ---------------------------------------------------------------------------


class TestHeadlineFourteenPercent:
    def test_one_split_six_settled_is_one_seventh_admin_cancelled(self):
        f = _FIXTURE["headlineFourteenPercent"]
        indexer = _indexer_from_fixture(f["outcomes"])
        rate = indexer.get_split_rate(_AGENT)

        assert rate.split_count == f["expected"]["splitCount"]  # 1
        assert rate.total_disputes == f["expected"]["totalDisputes"]  # 7
        assert rate.split_rate == pytest.approx(f["expected"]["splitRate"], abs=1e-12)
        # ~14%
        assert round(rate.split_rate * 100) == f["expected"]["approxPercent"]

        # The single split was an admin-CANCELLED kernel transition — prove OQ-11
        # counts it in the HEADLINE (R11 under-count trap closed).
        breakdown = indexer.get_split_rate_breakdown(_AGENT)
        assert breakdown.mediator_split_count == 0
        assert breakdown.admin_split_count == 1
        assert breakdown.split_rate == pytest.approx(
            f["expected"]["splitRate"], abs=1e-12
        )  # headline unchanged

    def test_mediator_and_admin_split_weighted_identically(self):
        f = _FIXTURE["mixedSourceEqualWeight"]
        indexer = _indexer_from_fixture(f["outcomes"])
        rate = indexer.get_split_rate(_AGENT)
        breakdown = indexer.get_split_rate_breakdown(_AGENT)

        assert rate.split_count == f["expected"]["splitCount"]  # 2
        assert rate.total_disputes == f["expected"]["totalDisputes"]  # 7
        assert rate.split_rate == pytest.approx(f["expected"]["splitRate"], abs=1e-12)
        assert breakdown.mediator_split_count == f["expected"]["mediatorSplitCount"]
        assert breakdown.admin_split_count == f["expected"]["adminSplitCount"]
        # identical weight: 1 mediator + 1 admin == 2 toward the same rate.
        assert (
            breakdown.mediator_split_count + breakdown.admin_split_count
            == rate.split_count
        )

    def test_per_agent_scoping(self):
        f = _FIXTURE["perAgentScoping"]
        indexer = _indexer_from_fixture(f["outcomes"])
        rate = indexer.get_split_rate(f["queryAgent"])
        assert rate.split_count == f["expected"]["splitCount"]  # 1
        assert rate.total_disputes == f["expected"]["totalDisputes"]  # 2
        assert rate.split_rate == pytest.approx(f["expected"]["splitRate"], abs=1e-12)

    def test_zero_disputes_no_div_by_zero(self):
        f = _FIXTURE["zeroDisputesNoDivByZero"]
        indexer = _indexer_from_fixture(f["outcomes"])
        rate = indexer.get_split_rate(f["queryAgent"])
        assert rate.split_count == 0
        assert rate.total_disputes == 0
        assert rate.split_rate == 0.0


# ---------------------------------------------------------------------------
# ZERO-REMAINING CONSUMER RULE — drained split counts, no phantom payout
# ---------------------------------------------------------------------------


class TestZeroRemainingRule:
    def test_drained_splits_count_but_report_no_phantom_payout(self):
        f = _FIXTURE["drainedSplitNoPhantomPayout"]
        indexer = _indexer_from_fixture(f["outcomes"])
        rate = indexer.get_split_rate(_AGENT)

        # The split STILL counts toward the rate even though escrow was drained.
        assert rate.split_count == f["expected"]["splitCount"]  # 2
        assert rate.total_disputes == f["expected"]["totalDisputes"]  # 2
        assert rate.split_rate == pytest.approx(f["expected"]["splitRate"], abs=1e-12)

        # But the indexer NEVER surfaces a 1-wei payout — proof amounts are phantom.
        for o in indexer.get_outcomes():
            decoded = indexer.classify_payout(o)
            assert decoded is not None
            assert decoded.phantom_sentinel is True
            assert decoded.requester_amount == 0
            assert decoded.provider_amount == 0
            # Hard assertion of the rule: never the 1-wei sentinel.
            assert decoded.requester_amount != 1
            assert decoded.provider_amount != 1
        assert f["expected"]["phantomPayoutReported"] is False


# ---------------------------------------------------------------------------
# Helpers / parity surface
# ---------------------------------------------------------------------------


class TestIndexerHelpers:
    def test_is_split_kind(self):
        assert is_split_kind("disputeSplitRecorded") is True
        assert is_split_kind("kernelDisputedToCancelled") is True
        assert is_split_kind("settled") is False

    def test_outcome_from_split_recorded(self):
        o = outcome_from_split_recorded(
            DisputeSplitRecorded(
                tx_id="0x1",
                requester="0x1111111111111111111111111111111111111111",
                provider=_AGENT,
                split_bps=3000,
            ),
            remaining=1000000,
        )
        assert o.kind == "disputeSplitRecorded"
        assert o.provider == _AGENT
        assert o.split_bps == 3000
        assert o.remaining == 1000000

    def test_classify_payout_returns_none_without_proof(self):
        indexer = DisputeSplitIndexer()
        decoded = indexer.classify_payout(
            DisputeOutcome(
                provider=_AGENT,
                requester="0x1",
                kind="settled",
                remaining=100,
            )
        )
        assert decoded is None
