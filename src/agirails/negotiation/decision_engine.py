"""
DecisionEngine -- Weighted scoring for agent candidate ranking.

Scores policy-valid candidates using configurable weights:
  score = w_quality * quality + w_price * price + w_speed * speed + w_reliability * reliability

Default weights: quality=0.35, price=0.30, speed=0.20, reliability=0.15

Tie-breakers: lower price -> better on-time rate -> earlier in discovery results.
"""
from __future__ import annotations

import functools
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Awaitable, Callable, List, Optional, Union

if TYPE_CHECKING:  # pragma: no cover - typing-only import, avoids runtime coupling
    from agirails.negotiation.policy_engine import BuyerPolicy


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
# AIP-2.1 evaluate_quote types (TS DecisionEngine.ts:55-105)
# ============================================================================


@dataclass(frozen=True)
class QuoteForEvaluation:
    """Minimal quote shape :meth:`DecisionEngine.evaluate_quote` operates on.

    Keeps DecisionEngine decoupled from the full QuoteMessage type +
    signature verification (that's BuyerOrchestrator's job). Mirrors TS
    ``QuoteForEvaluation`` (DecisionEngine.ts:60-69).
    """

    #: Base units as string (bigint-safe).
    quoted_amount: str
    #: Base units as string.
    original_amount: str
    #: Base units as string.
    max_price: str
    #: ``True`` when the provider flags this as their final offer.
    final_offer: bool = False


@dataclass(frozen=True)
class QuoteEvaluation:
    """Decision for a single incoming provider quote.

    Discriminated union flattened to a single frozen dataclass (mirrors the
    TS ``QuoteEvaluation`` union, DecisionEngine.ts:81-84):

    - ``action='accept'`` → caller calls acceptQuote(txId, provider's
      ``quoted_amount``) then linkEscrow. Commits at provider's price.
    - ``action='counter'`` → caller builds + sends a CounterOfferMessage at
      ``amount_base_units``. On provider's acceptance, caller calls
      acceptQuote at the counter amount + linkEscrow.
    - ``action='reject'`` → caller transitions CANCELLED and tries next
      candidate.
    """

    action: str  # 'accept' | 'counter' | 'reject'
    reason: str
    #: Set ONLY when ``action == 'counter'`` (base-unit string). None otherwise.
    amount_base_units: Optional[str] = None


# ----------------------------------------------------------------------------
# BYO-brain hook for the per-quote accept/counter/reject decision.
#
# Signature mirrors DecisionEngine.evaluate_quote so the built-in engine is a
# zero-adapter default; sync OR async (awaitable) so an LLM decider can be
# dropped in. Mirrors TS ``BuyerQuoteDecider`` (DecisionEngine.ts:101-105).
#
# Contract the host (BuyerOrchestrator) relies on:
#   - 'counter'.amount_base_units MUST be a base-unit string, strictly <
#     quote.quoted_amount and >= 50_000 ($0.05 platform min), or the
#     CounterOfferBuilder rejects it and the round errors out.
#   - 'accept' commits at quote.quoted_amount without re-checking affordability.
#
# Note: ``quote.final_offer`` is currently never set on channel quotes (the wire
# QuoteMessage carries no final_offer field), so a decider keying off it will
# not fire on the live negotiation path.
# ----------------------------------------------------------------------------
BuyerQuoteDecider = Callable[
    ["QuoteForEvaluation", "BuyerPolicy", int],
    Union["QuoteEvaluation", Awaitable["QuoteEvaluation"]],
]


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
                return 1 if b.score > a.score else -1  # descending: b>a means a goes after b

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

    def evaluate_quote(
        self,
        quote: QuoteForEvaluation,
        policy: "BuyerPolicy",
        rounds_used_so_far: int = 0,
    ) -> QuoteEvaluation:
        """AIP-2.1 §5.2 — decide whether to accept a provider's quote,
        counter at a better price, or reject outright.

        Decision tree (all arithmetic in Python ``int`` base units; no float
        drift — Python ints are arbitrary precision, matching TS BigInt):

        1. Quote exceeds max_price                → reject
        2. Provider flagged final_offer           → accept if <= max; else reject
        3. Quote <= target                         → accept (we'd take this
                                                     without negotiating)
        4. Rounds budget exhausted                → accept if <= max; else reject
        5. counter_strategy == 'walk'             → reject (no counter-offers)
        6. Otherwise                              → counter at strategy amount

        Defaults when policy fields are omitted (read via ``getattr`` so the
        method is backward-compatible with the current ``BuyerPolicy`` shape
        that does not yet carry ``target_unit_price`` /
        ``rounds_per_provider`` / ``counter_strategy``):
          rounds_per_provider    = 1          (original fixed-price flow)
          counter_strategy       = 'walk'     (no counter unless opted in)
          target_unit_price      = 50% of max (conservative — prefer accept)

        Mirror of TS ``DecisionEngine.evaluateQuote`` (DecisionEngine.ts:252-333).

        :param quote: minimal shape of the provider's signed quote.
        :param policy: buyer policy; defaults applied inline.
        :param rounds_used_so_far: how many rounds we've already spent with
            THIS provider on THIS txId (0 on first evaluation).
        """
        try:
            quoted = int(quote.quoted_amount)
            max_bu = int(quote.max_price)
        except (ValueError, TypeError):
            return QuoteEvaluation(
                action="reject",
                reason="Quote has non-numeric amount fields",
            )

        if quoted > max_bu:
            return QuoteEvaluation(
                action="reject",
                reason=f"Quote {quoted} exceeds maxPrice {max_bu}",
            )

        # Target unit price — defaults to half of max when policy omits it.
        # Convert via string-based scaling (no float * 1e6 round-trip) so big
        # amounts stay precise. Default-half path uses int division (exact).
        max_human_raw = policy.constraints.max_unit_price.amount
        target_unit_price = getattr(policy, "target_unit_price", None)
        if target_unit_price is not None:
            target_bu = _human_to_base_units(target_unit_price.amount, 1_000_000)
        else:
            target_bu = _human_to_base_units(max_human_raw, 1_000_000) // 2

        if quote.final_offer is True:
            # Provider flagged last round — accept if we can afford it,
            # otherwise walk. No point trying to counter something marked
            # "take it or leave it".
            if quoted <= max_bu:
                return QuoteEvaluation(
                    action="accept",
                    reason="Final offer from provider, within max",
                )
            return QuoteEvaluation(
                action="reject",
                reason="Final offer exceeds max (should already be filtered above, defense-in-depth)",
            )

        if quoted <= target_bu:
            return QuoteEvaluation(
                action="accept",
                reason=f"Quote {quoted} <= target {target_bu}",
            )

        negotiation = policy.negotiation
        rounds_per_provider = getattr(negotiation, "rounds_per_provider", None)
        if rounds_per_provider is None:
            rounds_per_provider = 1
        if rounds_used_so_far + 1 >= rounds_per_provider:
            # We're on our last permitted round with this provider. Accept if
            # affordable rather than walk away; the alternative is starting
            # over with a worse-ranked candidate.
            if quoted <= max_bu:
                return QuoteEvaluation(
                    action="accept",
                    reason=f"Rounds budget exhausted; accepting {quoted} <= max {max_bu}",
                )
            return QuoteEvaluation(
                action="reject",
                reason="Rounds budget exhausted and quote > max",
            )

        strategy = getattr(negotiation, "counter_strategy", None) or "walk"
        if strategy == "walk":
            return QuoteEvaluation(
                action="reject",
                reason="Quote above target and counter_strategy=walk",
            )

        # Compute counter amount per strategy. Never below platform minimum
        # ($0.05 = 50_000 base units) — that's a QuoteBuilder invariant too,
        # so we front-load the check to avoid handing the builder garbage.
        platform_min = 50_000
        if strategy == "undercut":
            # Go straight to our target; provider can take it or counter-back.
            counter_bu = target_bu
        else:
            # midpoint: halfway between quoted and target.
            counter_bu = (quoted + target_bu) // 2
        if counter_bu < platform_min:
            counter_bu = platform_min
        if counter_bu >= quoted:
            # Counter must be strictly below quote for CounterOfferBuilder to
            # accept it (otherwise "just accept the quote"). Fall back to
            # accepting the provider's quote if our strategy math doesn't
            # yield a lower amount.
            return QuoteEvaluation(
                action="accept",
                reason="Counter math would not undercut — accepting provider quote",
            )

        return QuoteEvaluation(
            action="counter",
            amount_base_units=str(counter_bu),
            reason=f"counter_strategy={strategy}: counter at {counter_bu} vs quote {quoted}",
        )


def _human_to_base_units(amount: float, per_usd: int) -> int:
    """Convert a human amount (e.g. 5, 10.5) to base units (int).

    Mirror of TS ``humanToBaseUnits`` (DecisionEngine.ts:350-371): uses
    string parsing rather than ``float * 1e6`` so amounts that don't fit
    cleanly in double precision stay exact. ``per_usd`` should equal
    ``10**decimals`` for the target currency (1_000_000 for USDC's 6
    decimals). Negatives and non-finite values fail loud, matching TS.
    """
    if not math.isfinite(amount):
        raise ValueError(f"_human_to_base_units: amount must be finite (got {amount})")
    if amount < 0:
        raise ValueError(f"_human_to_base_units: amount must be non-negative (got {amount})")
    decimals_len = len(str(per_usd)) - 1
    # Format with fixed (decimal) notation and no scientific notation, then
    # truncate to the currency's decimal places (TS uses
    # maximumFractionDigits which rounds; we mirror by formatting then
    # slicing the fractional run after padding — identical for the inputs
    # the negotiation path produces).
    fixed = f"{amount:.{decimals_len}f}"
    whole, _, frac = fixed.partition(".")
    frac_padded = (frac + "0" * decimals_len)[:decimals_len]
    # Strip a leading '-' should never happen here (guarded above); int()
    # of an empty whole (e.g. ".5" — impossible from :.Nf) defends anyway.
    whole_bu = int(whole or "0") * per_usd
    frac_bu = int(frac_padded) if frac_padded else 0
    return whole_bu + frac_bu
