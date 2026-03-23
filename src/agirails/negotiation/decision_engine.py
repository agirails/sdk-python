"""
DecisionEngine -- Weighted scoring for agent candidate ranking.

Scores policy-valid candidates using configurable weights:
  score = w_quality * quality + w_price * price + w_speed * speed + w_reliability * reliability

Default weights: quality=0.35, price=0.30, speed=0.20, reliability=0.15

Tie-breakers: lower price -> better on-time rate -> earlier in discovery results.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import List, Optional


# ============================================================================
# Types
# ============================================================================

@dataclass
class ScoringWeights:
    quality: float = 0.35
    price: float = 0.30
    speed: float = 0.20
    reliability: float = 0.15


@dataclass
class CandidateStats:
    slug: str
    unit_price: float
    reputation_score: float  # 0-100
    success_rate: float  # 0-100
    avg_completion_time_seconds: Optional[float]
    completed_transactions: int


@dataclass
class ScoreBreakdown:
    quality: float
    price: float
    speed: float
    reliability: float


@dataclass
class ScoredCandidate:
    slug: str
    score: float
    breakdown: ScoreBreakdown


# ============================================================================
# Constants
# ============================================================================

DEFAULT_WEIGHTS = ScoringWeights(
    quality=0.35,
    price=0.30,
    speed=0.20,
    reliability=0.15,
)


# ============================================================================
# DecisionEngine
# ============================================================================

class DecisionEngine:
    def __init__(self, weights: Optional[ScoringWeights] = None) -> None:
        w = weights or DEFAULT_WEIGHTS
        self._weights = ScoringWeights(
            quality=w.quality,
            price=w.price,
            speed=w.speed,
            reliability=w.reliability,
        )

        # Normalize weights to sum to 1.0
        total = (
            self._weights.quality
            + self._weights.price
            + self._weights.speed
            + self._weights.reliability
        )
        if total > 0 and abs(total - 1.0) > 0.001:
            self._weights.quality /= total
            self._weights.price /= total
            self._weights.speed /= total
            self._weights.reliability /= total

    def rank(
        self,
        candidates: List[CandidateStats],
        max_price: Optional[float] = None,
    ) -> List[ScoredCandidate]:
        """
        Score and rank candidates. Returns sorted by score descending.
        If max_price is provided, candidates exceeding it are filtered out.
        """
        # Filter out over-budget candidates
        if max_price is not None:
            eligible = [c for c in candidates if c.unit_price <= max_price]
        else:
            eligible = list(candidates)

        if not eligible:
            return []

        # Compute min/max for normalization
        prices = [c.unit_price for c in eligible]
        times = [
            c.avg_completion_time_seconds
            for c in eligible
            if c.avg_completion_time_seconds is not None
        ]

        min_price = min(prices)
        max_price_val = max(prices)
        price_range = max_price_val - min_price

        min_time = min(times) if times else 0.0
        max_time = max(times) if times else 1.0
        time_range = max_time - min_time

        scored: List[ScoredCandidate] = []
        for c in eligible:
            # Quality: reputation_score normalized to 0-1
            quality = c.reputation_score / 100.0

            # Price: inverted (lower is better), normalized to 0-1
            if price_range > 0:
                price_score = 1.0 - (c.unit_price - min_price) / price_range
            else:
                price_score = 1.0  # all same price -> all get max score

            # Speed: inverted (faster is better), normalized to 0-1
            # Agents with no completion data are penalized (0.5) vs those with data
            if c.avg_completion_time_seconds is not None:
                if time_range > 0:
                    speed = 1.0 - (c.avg_completion_time_seconds - min_time) / time_range
                else:
                    speed = 1.0  # all candidates with data are equal on speed
            else:
                speed = 0.5  # no data -- penalized vs agents with track record

            # Reliability: success_rate normalized to 0-1
            reliability = c.success_rate / 100.0

            score = (
                self._weights.quality * quality
                + self._weights.price * price_score
                + self._weights.speed * speed
                + self._weights.reliability * reliability
            )

            scored.append(ScoredCandidate(
                slug=c.slug,
                score=score,
                breakdown=ScoreBreakdown(
                    quality=quality,
                    price=price_score,
                    speed=speed,
                    reliability=reliability,
                ),
            ))

        # Build a lookup for tie-breaking
        eligible_by_slug = {c.slug: c for c in eligible}

        # Sort by score descending, then tie-breakers.
        # Matches TS: if abs(b.score - a.score) > 0.001, sort by score;
        # otherwise fall through to tie-breakers (lower price, higher success_rate, original order).
        def _comparator(a: ScoredCandidate, b: ScoredCandidate) -> int:
            if abs(b.score - a.score) > 0.001:
                return -1 if b.score > a.score else 1  # descending by score

            a_raw = eligible_by_slug[a.slug]
            b_raw = eligible_by_slug[b.slug]

            # Tie-breaker 1: lower price wins
            if a_raw.unit_price != b_raw.unit_price:
                return -1 if a_raw.unit_price < b_raw.unit_price else 1

            # Tie-breaker 2: higher success rate wins
            if a_raw.success_rate != b_raw.success_rate:
                return -1 if a_raw.success_rate > b_raw.success_rate else 1

            # Tie-breaker 3: preserve original order (stable sort)
            return 0

        scored.sort(key=functools.cmp_to_key(_comparator))

        return scored
