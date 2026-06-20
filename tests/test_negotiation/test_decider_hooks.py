"""Parity tests for the injectable decider hooks (BYO-brain).

Covers:
- DecisionEngine.evaluate_quote — the built-in default the buyer decider
  mirrors. Vectors copied verbatim from
  sdk-js/src/negotiation/DecisionEngine.test.ts so the two SDKs cannot drift
  on the AIP-2.1 accept/counter/reject decision matrix.
- BuyerOrchestrator.decide_quote — the BYO-brain hook wiring: default
  delegates to the built-in engine (zero behavior change); a custom
  sync/async decider replaces ONLY the decision.
- ProviderPolicyEngine.decide_counter — provider-side BYO-brain hook:
  default delegates to evaluate_counter; a custom sync/async decider
  replaces ONLY the decision (verification stays the caller's job).

TS refs:
- DecisionEngine.ts:55-105, 252-333, 350-371
- BuyerOrchestrator.ts:120-125, 199-201, 846
- ProviderOrchestrator.ts:107-139, 338-362
"""

from __future__ import annotations

import asyncio

import pytest

from agirails.negotiation.buyer_orchestrator import BuyerOrchestrator
from agirails.negotiation.decision_engine import (
    DecisionEngine,
    QuoteEvaluation,
    QuoteForEvaluation,
    _human_to_base_units,
)
from agirails.negotiation.policy_engine import (
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    Selection,
)
from agirails.negotiation.provider_policy import (
    CounterContext,
    CounterDecision,
    PriceTerm,
    ProviderPolicy,
    ProviderPolicyEngine,
    ProviderPricing,
)


# ============================================================================
# Fixtures (mirror DecisionEngine.test.ts:10-37)
# ============================================================================


def _policy(
    *,
    rounds_per_provider=None,
    counter_strategy=None,
    target_unit_price=None,
    max_amount=10,
    max_daily=100,
) -> BuyerPolicy:
    """Mirror DecisionEngine.test.ts:10-28 policy().

    target_unit_price / rounds_per_provider / counter_strategy are attached
    dynamically because the canonical Python BuyerPolicy/Negotiation shape
    (owned by policy_engine.py) does not yet carry them — evaluate_quote
    reads them via getattr with TS-matching defaults.
    """
    p = BuyerPolicy(
        task="code-review",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=max_amount, currency="USDC", unit="job"),
            max_daily_spend=MaxDailySpend(amount=max_daily, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=3, quote_ttl="15m"),
        selection=Selection(prioritize=["price"]),
    )
    if rounds_per_provider is not None:
        p.negotiation.rounds_per_provider = rounds_per_provider
    if counter_strategy is not None:
        p.negotiation.counter_strategy = counter_strategy
    if target_unit_price is not None:
        amount, currency, unit = target_unit_price
        p.target_unit_price = MaxUnitPrice(amount=amount, currency=currency, unit=unit)
    return p


def _quote(
    quoted_amount="7000000",  # $7
    original_amount="5000000",  # $5
    max_price="10000000",  # $10
    final_offer=False,
) -> QuoteForEvaluation:
    return QuoteForEvaluation(
        quoted_amount=quoted_amount,
        original_amount=original_amount,
        max_price=max_price,
        final_offer=final_offer,
    )


# ============================================================================
# DecisionEngine.evaluate_quote — decision matrix (DecisionEngine.test.ts:39-238)
# ============================================================================


class TestEvaluateQuoteHardRejects:
    def test_rejects_when_quote_above_max_price(self):
        r = DecisionEngine().evaluate_quote(_quote(quoted_amount="15000000"), _policy())
        assert r.action == "reject"

    def test_rejects_when_amount_fields_non_numeric(self):
        r = DecisionEngine().evaluate_quote(_quote(quoted_amount="abc"), _policy())
        assert r.action == "reject"


class TestEvaluateQuoteAcceptPaths:
    def test_accepts_when_quote_at_or_below_default_target(self):
        # max=$10, default target=$5. Quote=$5 -> accept.
        r = DecisionEngine().evaluate_quote(_quote(quoted_amount="5000000"), _policy())
        assert r.action == "accept"

    def test_accepts_when_quote_at_or_below_explicit_target(self):
        r = DecisionEngine().evaluate_quote(
            _quote(quoted_amount="8000000"),  # $8
            _policy(target_unit_price=(8, "USDC", "job")),
        )
        assert r.action == "accept"

    def test_accepts_on_final_offer_within_max(self):
        r = DecisionEngine().evaluate_quote(
            _quote(quoted_amount="9500000", final_offer=True),
            _policy(target_unit_price=(5, "USDC", "job")),
        )
        assert r.action == "accept"
        assert "Final offer" in r.reason

    def test_accepts_on_rounds_budget_exhausted_default(self):
        # rounds_per_provider defaults to 1; round 0 -> 0+1 >= 1 -> exhausted.
        # Quote $7 > target $5 would normally counter, but no rounds left -> accept.
        r = DecisionEngine().evaluate_quote(_quote(), _policy(), 0)
        assert r.action == "accept"
        assert "Rounds budget exhausted" in r.reason


class TestEvaluateQuoteRejectPaths:
    def test_rejects_above_target_and_walk_strategy(self):
        r = DecisionEngine().evaluate_quote(
            _quote(),  # $7 > $5 default target
            _policy(rounds_per_provider=3, counter_strategy="walk"),
        )
        assert r.action == "reject"

    def test_rejects_on_final_offer_above_max(self):
        r = DecisionEngine().evaluate_quote(
            _quote(quoted_amount="11000000", final_offer=True),
            _policy(),
        )
        assert r.action == "reject"


class TestEvaluateQuoteCounterPaths:
    def test_counters_at_midpoint_by_default(self):
        # quote=$7, target=$5 -> midpoint = $6
        r = DecisionEngine().evaluate_quote(
            _quote(),
            _policy(rounds_per_provider=3, counter_strategy="midpoint"),
        )
        assert r.action == "counter"
        assert r.amount_base_units == "6000000"  # $6

    def test_counters_at_target_with_undercut(self):
        r = DecisionEngine().evaluate_quote(
            _quote(),
            _policy(rounds_per_provider=3, counter_strategy="undercut"),
        )
        assert r.action == "counter"
        assert r.amount_base_units == "5000000"  # target $5

    def test_falls_back_to_accept_when_target_above_quote(self):
        # target=$8 > quote=$7 -> quote <= target -> accept (path 3 in tree).
        r = DecisionEngine().evaluate_quote(
            _quote(quoted_amount="7000000"),
            _policy(
                rounds_per_provider=3,
                counter_strategy="midpoint",
                target_unit_price=(8, "USDC", "job"),
            ),
        )
        assert r.action == "accept"

    def test_counters_above_platform_min_when_math_lower(self):
        # target=$0.01 -> undercut counter = 10_000 base units -> lifted to
        # platform min 50_000 = $0.05. $0.05 < $0.06 quote -> still counter.
        r = DecisionEngine().evaluate_quote(
            _quote(quoted_amount="60000", max_price="70000"),  # 6c quote, 7c max
            _policy(
                rounds_per_provider=3,
                counter_strategy="undercut",
                target_unit_price=(0.01, "USDC", "job"),
            ),
        )
        assert r.action == "counter"
        assert r.amount_base_units == "50000"


class TestEvaluateQuotePrecision:
    def test_handles_scientific_notation_target(self):
        p = _policy(
            rounds_per_provider=3,
            counter_strategy="midpoint",
            max_amount=2e21,
            max_daily=1e22,
            target_unit_price=(1e21, "USDC", "job"),
        )
        r = DecisionEngine().evaluate_quote(
            QuoteForEvaluation(
                quoted_amount="1000000000000000000000000000",  # 1e27 base units
                original_amount="500000000000000000000000000",
                max_price="2000000000000000000000000000",
            ),
            p,
        )
        assert r.action in ("accept", "counter", "reject")

    def test_raises_on_negative_target(self):
        p = _policy(
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_unit_price=(-5, "USDC", "job"),
        )
        with pytest.raises(ValueError, match="non-negative"):
            DecisionEngine().evaluate_quote(_quote(), p)

    def test_raises_on_nan_target(self):
        p = _policy(
            rounds_per_provider=3,
            counter_strategy="midpoint",
            target_unit_price=(float("nan"), "USDC", "job"),
        )
        with pytest.raises(ValueError, match="finite"):
            DecisionEngine().evaluate_quote(_quote(), p)

    def test_preserves_exact_base_units_on_big_numbers(self):
        # $1M target, $10M quote, $20M max — beyond float safe-integer.
        p = _policy(
            rounds_per_provider=3,
            counter_strategy="midpoint",
            max_amount=20_000_000,
            max_daily=100_000_000,
            target_unit_price=(1_000_000, "USDC", "job"),
        )
        r = DecisionEngine().evaluate_quote(
            QuoteForEvaluation(
                quoted_amount="10000000000000",  # $10M
                original_amount="1000000000000",  # $1M
                max_price="20000000000000",  # $20M
            ),
            p,
        )
        assert r.action == "counter"
        # midpoint = ($10M + $1M)/2 = $5.5M = 5_500_000_000_000 base units.
        assert r.amount_base_units == "5500000000000"


class TestHumanToBaseUnits:
    @pytest.mark.parametrize(
        "amount,expected",
        [
            (5, 5_000_000),
            (10.5, 10_500_000),
            (0.1, 100_000),
            (0.05, 50_000),
            (0, 0),
        ],
    )
    def test_matches_ts_scaling(self, amount, expected):
        assert _human_to_base_units(amount, 1_000_000) == expected

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            _human_to_base_units(-1, 1_000_000)

    def test_rejects_non_finite(self):
        with pytest.raises(ValueError, match="finite"):
            _human_to_base_units(float("inf"), 1_000_000)


# ============================================================================
# BuyerOrchestrator.decide_quote — BYO-brain hook (BuyerOrchestrator.ts:199-201)
# ============================================================================


class TestBuyerDeciderHook:
    def _make_orchestrator(self, decide_quote=None):
        # runtime/requester_address are unused by decide_quote; pass minimal stubs.
        return BuyerOrchestrator(
            policy=_policy(rounds_per_provider=3, counter_strategy="midpoint"),
            runtime=object(),
            requester_address="0x" + "1" * 40,
            decide_quote=decide_quote,
        )

    def test_default_delegates_to_builtin_engine(self):
        # No injected decider -> identical to DecisionEngine.evaluate_quote.
        orch = self._make_orchestrator()
        result = asyncio.run(orch.decide_quote(_quote(), 0))
        expected = DecisionEngine().evaluate_quote(
            _quote(), _policy(rounds_per_provider=3, counter_strategy="midpoint"), 0
        )
        assert result.action == expected.action == "counter"
        assert result.amount_base_units == expected.amount_base_units == "6000000"

    def test_sync_custom_decider_replaces_decision(self):
        sentinel = QuoteEvaluation(action="reject", reason="BYO says no")

        def brain(quote, policy, rounds):
            assert isinstance(quote, QuoteForEvaluation)
            assert rounds == 2
            return sentinel

        orch = self._make_orchestrator(decide_quote=brain)
        result = asyncio.run(orch.decide_quote(_quote(), 2))
        assert result is sentinel
        assert result.action == "reject"

    def test_async_custom_decider_is_awaited(self):
        async def brain(quote, policy, rounds):
            await asyncio.sleep(0)
            return QuoteEvaluation(action="accept", reason="LLM brain accept")

        orch = self._make_orchestrator(decide_quote=brain)
        result = asyncio.run(orch.decide_quote(_quote(), 0))
        assert result.action == "accept"
        assert result.reason == "LLM brain accept"

    def test_custom_decider_receives_policy(self):
        seen = {}

        def brain(quote, policy, rounds):
            seen["policy"] = policy
            return QuoteEvaluation(action="reject", reason="x")

        orch = self._make_orchestrator(decide_quote=brain)
        asyncio.run(orch.decide_quote(_quote(), 0))
        assert seen["policy"].task == "code-review"


# ============================================================================
# ProviderPolicyEngine.decide_counter — BYO-brain hook
# (ProviderOrchestrator.ts:338-362 minus verification)
# ============================================================================


class _FakeCounter:
    """Minimal CounterOfferMessage stand-in (only the fields decide_counter reads)."""

    def __init__(self, counter_amount, quote_amount):
        self.counterAmount = counter_amount
        self.quoteAmount = quote_amount


def _provider_policy(**overrides) -> ProviderPolicy:
    defaults = dict(
        services=["code-review"],
        pricing=ProviderPricing(
            min_acceptable=PriceTerm(amount=5, currency="USDC", unit="job"),
            ideal_price=PriceTerm(amount=10, currency="USDC", unit="job"),
        ),
        quote_ttl="15m",
    )
    defaults.update(overrides)
    return ProviderPolicy(**defaults)


class TestProviderCounterDeciderHook:
    def test_default_accepts_counter_at_or_above_floor(self):
        engine = ProviderPolicyEngine(_provider_policy())
        # counter $6 >= floor $5 -> accept (delegates to evaluate_counter).
        counter = _FakeCounter(counter_amount="6000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "10000000", 0))
        assert isinstance(decision, CounterDecision)
        assert decision.action == "accept"

    def test_default_requote_maps_amount(self):
        # concede strategy, counter below floor -> requote at concession price.
        engine = ProviderPolicyEngine(
            _provider_policy(counter_strategy="concede", concede_pct=30, max_requotes=2)
        )
        counter = _FakeCounter(counter_amount="4000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "10000000", 0))
        assert decision.action == "requote"
        # last $10, floor $5, gap $5, 30% concession = $1.5 -> new quote $8.5.
        assert decision.amount_base_units == "8500000"

    def test_default_walk_rejects_below_floor(self):
        engine = ProviderPolicyEngine(_provider_policy())  # default walk
        counter = _FakeCounter(counter_amount="4000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "10000000", 0))
        assert decision.action == "reject"

    def test_last_quote_defaults_to_counter_quote_amount(self):
        # When last_quote_amount_base_units omitted, defaults to counter.quoteAmount.
        engine = ProviderPolicyEngine(
            _provider_policy(counter_strategy="concede", concede_pct=30, max_requotes=2)
        )
        counter = _FakeCounter(counter_amount="4000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter))  # no last amount
        assert decision.action == "requote"
        assert decision.amount_base_units == "8500000"

    def test_sync_custom_decider_replaces_decision(self):
        sentinel = CounterDecision(action="reject", reason="provider BYO walks")

        def brain(ctx: CounterContext) -> CounterDecision:
            assert ctx.requotes_used == 1
            assert ctx.last_quote_amount_base_units == "9000000"
            assert ctx.policy.services == ["code-review"]
            return sentinel

        engine = ProviderPolicyEngine(_provider_policy(), counter_decider=brain)
        counter = _FakeCounter(counter_amount="6000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "9000000", 1))
        assert decision is sentinel

    def test_async_custom_decider_is_awaited(self):
        async def brain(ctx: CounterContext) -> CounterDecision:
            await asyncio.sleep(0)
            return CounterDecision(
                action="requote", amount_base_units="7000000", reason="LLM requote"
            )

        engine = ProviderPolicyEngine(_provider_policy(), counter_decider=brain)
        counter = _FakeCounter(counter_amount="6000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "10000000", 0))
        assert decision.action == "requote"
        assert decision.amount_base_units == "7000000"

    def test_custom_decider_bypasses_builtin_floor_accept(self):
        # counter $6 >= floor $5 would be 'accept' under the built-in engine;
        # the injected decider overrides it entirely.
        def brain(ctx: CounterContext) -> CounterDecision:
            return CounterDecision(action="reject", reason="override")

        engine = ProviderPolicyEngine(_provider_policy(), counter_decider=brain)
        counter = _FakeCounter(counter_amount="6000000", quote_amount="10000000")
        decision = asyncio.run(engine.decide_counter(counter, "10000000", 0))
        assert decision.action == "reject"
        assert decision.reason == "override"
