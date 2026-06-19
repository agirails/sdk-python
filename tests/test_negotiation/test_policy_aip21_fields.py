"""Tests for the AIP-2.1 optional fields on the typed BuyerPolicy/Negotiation.

P1 parity: the deciders (DecisionEngine.evaluate_quote, BuyerOrchestrator
counter loop) must read REAL declared fields — counter_strategy,
rounds_per_provider, counter_response_ttl_seconds, target_unit_price — not
always fall back to defaults because the dataclass silently dropped them.
Mirrors TS BuyerPolicy / Negotiation types (PolicyEngine.ts:23-73) +
DecisionEngine.evaluateQuote (DecisionEngine.ts:264-333).
"""

from __future__ import annotations

from agirails.negotiation.decision_engine import (
    DecisionEngine,
    QuoteForEvaluation,
)
from agirails.negotiation.policy_engine import (
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    Selection,
    TargetUnitPrice,
)


def _policy(**neg_kw) -> BuyerPolicy:
    return BuyerPolicy(
        task="summarize",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=10.0, currency="USDC", unit="job"),
            max_daily_spend=MaxDailySpend(amount=100.0, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=10, quote_ttl="15m", **neg_kw),
        selection=Selection(prioritize=["price"]),
    )


# ---------------------------------------------------------------------------
# Dataclass declares the fields (typed, not via __dict__ leakage)
# ---------------------------------------------------------------------------


def test_negotiation_declares_aip21_fields() -> None:
    n = Negotiation(
        rounds_max=10,
        quote_ttl="15m",
        rounds_per_provider=3,
        counter_strategy="midpoint",
        counter_response_ttl_seconds=120,
    )
    assert n.rounds_per_provider == 3
    assert n.counter_strategy == "midpoint"
    assert n.counter_response_ttl_seconds == 120


def test_negotiation_defaults_are_none_for_backward_compat() -> None:
    n = Negotiation(rounds_max=10, quote_ttl="15m")
    assert n.rounds_per_provider is None
    assert n.counter_strategy is None
    assert n.counter_response_ttl_seconds is None


def test_buyer_policy_declares_target_unit_price() -> None:
    p = _policy()
    assert p.target_unit_price is None
    p2 = BuyerPolicy(
        task="t",
        constraints=p.constraints,
        negotiation=p.negotiation,
        selection=p.selection,
        target_unit_price=TargetUnitPrice(amount=3.0, currency="USDC", unit="job"),
    )
    assert p2.target_unit_price is not None
    assert p2.target_unit_price.amount == 3.0


# ---------------------------------------------------------------------------
# DecisionEngine reads the real fields
# ---------------------------------------------------------------------------


def test_target_unit_price_drives_accept_vs_counter() -> None:
    engine = DecisionEngine()
    # Quote of $4 (4_000_000 base) on a policy whose explicit target is $5.
    # Default-half target would be $5 anyway, so set target ABOVE default to
    # prove the REAL field is read: target=$8 → $4 <= $8 → accept.
    policy = _policy(counter_strategy="midpoint", rounds_per_provider=3)
    policy = BuyerPolicy(
        task=policy.task,
        constraints=policy.constraints,
        negotiation=policy.negotiation,
        selection=policy.selection,
        target_unit_price=TargetUnitPrice(amount=8.0, currency="USDC", unit="job"),
    )
    quote = QuoteForEvaluation(
        quoted_amount="4000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    assert result.action == "accept"


def test_counter_strategy_walk_rejects_above_target() -> None:
    engine = DecisionEngine()
    # Default target = 50% of max = $5 (5_000_000). Quote $7 > target.
    # rounds_per_provider=3 leaves room to counter, BUT counter_strategy=walk.
    policy = _policy(counter_strategy="walk", rounds_per_provider=3)
    quote = QuoteForEvaluation(
        quoted_amount="7000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    assert result.action == "reject"
    assert "counter_strategy=walk" in result.reason


def test_counter_strategy_midpoint_counters() -> None:
    engine = DecisionEngine()
    policy = _policy(counter_strategy="midpoint", rounds_per_provider=3)
    quote = QuoteForEvaluation(
        quoted_amount="7000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    assert result.action == "counter"
    # midpoint of quoted(7M) and default target(5M) = 6M.
    assert result.amount_base_units == "6000000"
    assert "counter_strategy=midpoint" in result.reason


def test_counter_strategy_undercut_counters_at_target() -> None:
    engine = DecisionEngine()
    policy = _policy(counter_strategy="undercut", rounds_per_provider=3)
    quote = QuoteForEvaluation(
        quoted_amount="7000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    assert result.action == "counter"
    # undercut goes straight to target ($5 default).
    assert result.amount_base_units == "5000000"


def test_rounds_per_provider_one_takes_or_accepts() -> None:
    engine = DecisionEngine()
    # rounds_per_provider=1 with a quote above target → on the last permitted
    # round → accept if affordable rather than counter.
    policy = _policy(counter_strategy="midpoint", rounds_per_provider=1)
    quote = QuoteForEvaluation(
        quoted_amount="7000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    assert result.action == "accept"
    assert "Rounds budget exhausted" in result.reason


def test_default_no_aip21_fields_is_walk_no_counter() -> None:
    engine = DecisionEngine()
    # Bare policy (no AIP-2.1 fields) → counter_strategy defaults to walk,
    # rounds_per_provider defaults to 1: quote above target → accept (last
    # round) — the original fixed-price flow, unchanged.
    policy = _policy()
    quote = QuoteForEvaluation(
        quoted_amount="7000000", original_amount="3000000", max_price="10000000"
    )
    result = engine.evaluate_quote(quote, policy, rounds_used_so_far=0)
    # rounds_per_provider=1 → "last round" accept branch fires before the
    # walk check, matching TS default flow.
    assert result.action == "accept"
