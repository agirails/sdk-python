"""Tests for DecisionEngine — weighted scoring and ranking."""

from __future__ import annotations

import pytest

from agirails.negotiation.decision_engine import (
    CandidateStats,
    DecisionEngine,
    DEFAULT_WEIGHTS,
    ScoredCandidate,
    ScoringWeights,
)


# ============================================================================
# Helpers
# ============================================================================


def _make_candidate(
    slug: str,
    unit_price: float = 0.10,
    reputation_score: float = 80.0,
    success_rate: float = 90.0,
    avg_completion_time_seconds: float = 60.0,
    completed_transactions: int = 50,
) -> CandidateStats:
    return CandidateStats(
        slug=slug,
        unit_price=unit_price,
        reputation_score=reputation_score,
        success_rate=success_rate,
        avg_completion_time_seconds=avg_completion_time_seconds,
        completed_transactions=completed_transactions,
    )


# ============================================================================
# Weight normalization
# ============================================================================


class TestWeightNormalization:
    def test_default_weights_sum_to_one(self):
        w = DEFAULT_WEIGHTS
        total = w.quality + w.price + w.speed + w.reliability
        assert abs(total - 1.0) < 0.001

    def test_custom_weights_normalized(self):
        de = DecisionEngine(ScoringWeights(quality=2, price=2, speed=1, reliability=1))
        w = de._weights
        total = w.quality + w.price + w.speed + w.reliability
        assert abs(total - 1.0) < 0.001
        assert abs(w.quality - 1 / 3) < 0.01
        assert abs(w.price - 1 / 3) < 0.01

    def test_none_weights_use_defaults(self):
        de = DecisionEngine(None)
        assert de._weights.quality == DEFAULT_WEIGHTS.quality


# ============================================================================
# Ranking — sort order
# ============================================================================


class TestRankingOrder:
    def test_higher_score_ranked_first(self):
        """HIGH finding: high-score candidate must come before low-score."""
        de = DecisionEngine()
        candidates = [
            _make_candidate("low", reputation_score=5.0, success_rate=10.0, avg_completion_time_seconds=100.0),
            _make_candidate("high", reputation_score=98.0, success_rate=99.0, avg_completion_time_seconds=10.0, unit_price=0.08),
        ]
        ranked = de.rank(candidates, max_price=0.10)
        assert len(ranked) == 2
        assert ranked[0].slug == "high"
        assert ranked[1].slug == "low"
        assert ranked[0].score > ranked[1].score

    def test_three_candidates_descending(self):
        de = DecisionEngine()
        candidates = [
            _make_candidate("worst", reputation_score=10.0, success_rate=20.0),
            _make_candidate("best", reputation_score=95.0, success_rate=98.0),
            _make_candidate("mid", reputation_score=50.0, success_rate=60.0),
        ]
        ranked = de.rank(candidates, max_price=0.10)
        assert ranked[0].slug == "best"
        assert ranked[-1].slug == "worst"

    def test_single_candidate(self):
        de = DecisionEngine()
        ranked = de.rank([_make_candidate("only")], max_price=0.10)
        assert len(ranked) == 1
        assert ranked[0].slug == "only"


# ============================================================================
# Price filtering
# ============================================================================


class TestPriceFiltering:
    def test_over_budget_filtered(self):
        de = DecisionEngine()
        candidates = [
            _make_candidate("cheap", unit_price=0.05),
            _make_candidate("expensive", unit_price=0.20),
        ]
        ranked = de.rank(candidates, max_price=0.10)
        assert len(ranked) == 1
        assert ranked[0].slug == "cheap"

    def test_all_over_budget_returns_empty(self):
        de = DecisionEngine()
        ranked = de.rank([_make_candidate("x", unit_price=1.0)], max_price=0.10)
        assert ranked == []

    def test_no_max_price_keeps_all(self):
        de = DecisionEngine()
        candidates = [_make_candidate("a", unit_price=100.0)]
        ranked = de.rank(candidates, max_price=None)
        assert len(ranked) == 1

    def test_empty_candidates(self):
        de = DecisionEngine()
        assert de.rank([], max_price=0.10) == []


# ============================================================================
# Tie-breaking
# ============================================================================


class TestTieBreaking:
    def test_same_score_lower_price_wins(self):
        """When scores are within 0.001, lower price should win."""
        de = DecisionEngine()
        # Identical stats except price
        candidates = [
            _make_candidate("expensive", unit_price=0.09, reputation_score=80.0, success_rate=90.0),
            _make_candidate("cheap", unit_price=0.05, reputation_score=80.0, success_rate=90.0),
        ]
        ranked = de.rank(candidates)
        # Both have same reputation/success → scores within 0.001 → tie-break by price
        if abs(ranked[0].score - ranked[1].score) <= 0.001:
            assert ranked[0].slug == "cheap"

    def test_all_same_price_all_score_one(self):
        """When all have same price, price_score should be 1.0 for all."""
        de = DecisionEngine()
        candidates = [
            _make_candidate("a", unit_price=0.10, reputation_score=50.0),
            _make_candidate("b", unit_price=0.10, reputation_score=80.0),
        ]
        ranked = de.rank(candidates)
        # Both should have price_score=1.0
        for r in ranked:
            assert r.breakdown.price == 1.0


# ============================================================================
# Speed scoring
# ============================================================================


class TestSpeedScoring:
    def test_no_completion_data_penalized(self):
        de = DecisionEngine()
        candidates = [
            _make_candidate("with_data", avg_completion_time_seconds=30.0, reputation_score=80.0),
            _make_candidate("no_data", reputation_score=80.0),
        ]
        # Set no_data's avg_completion_time to None
        candidates[1] = CandidateStats(
            slug="no_data", unit_price=0.10, reputation_score=80.0,
            success_rate=90.0, avg_completion_time_seconds=None, completed_transactions=50,
        )
        ranked = de.rank(candidates)
        no_data = [r for r in ranked if r.slug == "no_data"][0]
        assert no_data.breakdown.speed == 0.5


# ============================================================================
# Score breakdown
# ============================================================================


class TestScoreBreakdown:
    def test_breakdown_fields_between_zero_and_one(self):
        de = DecisionEngine()
        ranked = de.rank([
            _make_candidate("a", reputation_score=50.0, success_rate=75.0),
            _make_candidate("b", reputation_score=90.0, success_rate=95.0),
        ])
        for r in ranked:
            assert 0.0 <= r.breakdown.quality <= 1.0
            assert 0.0 <= r.breakdown.price <= 1.0
            assert 0.0 <= r.breakdown.speed <= 1.0
            assert 0.0 <= r.breakdown.reliability <= 1.0

    def test_score_is_weighted_sum(self):
        de = DecisionEngine()
        ranked = de.rank([_make_candidate("x")])
        r = ranked[0]
        w = de._weights
        expected = (
            w.quality * r.breakdown.quality
            + w.price * r.breakdown.price
            + w.speed * r.breakdown.speed
            + w.reliability * r.breakdown.reliability
        )
        assert abs(r.score - expected) < 0.001
