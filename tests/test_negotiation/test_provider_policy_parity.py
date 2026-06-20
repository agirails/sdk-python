"""Parity tests for negotiation/provider_policy.py (ProviderPolicyEngine).

Mirrors sdk-js/src/negotiation/ProviderPolicy.test.ts byte-for-byte:
construction invariants + evaluate() decision matrix + evaluateCounter()
verdict + parse_ttl. Asserted values are copied verbatim from the TS test
so the two SDKs cannot drift on the quoting/concede math.
"""

from __future__ import annotations

import time

import pytest

from agirails.negotiation.provider_policy import (
    IncomingRequest,
    PriceTerm,
    ProviderPolicy,
    ProviderPolicyEngine,
    ProviderPricing,
    parse_ttl,
)


def base_policy(**overrides) -> ProviderPolicy:
    """Mirror ProviderPolicy.test.ts:13-23 basePolicy()."""
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


def make_req(**overrides) -> IncomingRequest:
    """Mirror ProviderPolicy.test.ts:25-37 req()."""
    defaults = dict(
        tx_id="0x" + "a" * 64,
        consumer="did:ethr:84532:0x2222222222222222222222222222222222222222",
        offered_amount="5000000",
        max_price="10000000",
        deadline=int(time.time()) + 3600,
        service_type="code-review",
        currency="USDC",
        unit="job",
    )
    defaults.update(overrides)
    return IncomingRequest(**defaults)


# ----- construction invariants (ProviderPolicy.test.ts:40-67) ---------------


class TestConstructionInvariants:
    def test_rejects_min_acceptable_below_platform_min(self):
        with pytest.raises(ValueError, match="platform minimum"):
            ProviderPolicyEngine(
                base_policy(
                    pricing=ProviderPricing(
                        min_acceptable=PriceTerm(amount=0.01, currency="USDC", unit="job"),
                        ideal_price=PriceTerm(amount=10, currency="USDC", unit="job"),
                    )
                )
            )

    def test_rejects_ideal_below_min_acceptable(self):
        with pytest.raises(ValueError, match="must be >= min_acceptable"):
            ProviderPolicyEngine(
                base_policy(
                    pricing=ProviderPricing(
                        min_acceptable=PriceTerm(amount=10, currency="USDC", unit="job"),
                        ideal_price=PriceTerm(amount=5, currency="USDC", unit="job"),
                    )
                )
            )

    def test_rejects_currency_mismatch_floor_vs_ideal(self):
        with pytest.raises(ValueError, match="currency"):
            ProviderPolicyEngine(
                base_policy(
                    pricing=ProviderPricing(
                        min_acceptable=PriceTerm(amount=5, currency="USDC", unit="job"),
                        ideal_price=PriceTerm(amount=10, currency="EUR", unit="job"),
                    )
                )
            )


# ----- evaluate() (ProviderPolicy.test.ts:69-150) ---------------------------


class TestEvaluate:
    def test_happy_path_quotes_at_ideal(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(max_price="15000000"))  # $15
        assert r.allowed is True
        assert r.recommended_quote_amount_base_units == "10000000"  # $10 ideal

    def test_quotes_at_max_price_between_floor_and_ideal(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(max_price="7000000"))  # $7
        assert r.allowed is True
        assert r.recommended_quote_amount_base_units == "7000000"

    def test_skips_unoffered_service(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(service_type="translation"))
        assert r.allowed is False
        assert any(v.rule == "service_not_offered" for v in r.violations)

    def test_skips_max_price_below_floor(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(max_price="3000000"))  # $3 < $5 floor
        assert r.allowed is False
        assert any(v.rule == "max_price_below_floor" for v in r.violations)

    def test_skips_deadline_too_tight(self):
        engine = ProviderPolicyEngine(base_policy(min_deadline_seconds=300))
        now = int(time.time())
        r = engine.evaluate(make_req(deadline=now + 60))  # only 60s
        assert r.allowed is False
        assert any(v.rule == "deadline_too_tight" for v in r.violations)

    def test_skips_currency_mismatch(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(currency="EUR"))
        assert r.allowed is False
        assert any(v.rule == "currency_mismatch" for v in r.violations)

    def test_skips_unit_mismatch(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(unit="hour"))
        assert r.allowed is False
        assert any(v.rule == "unit_mismatch" for v in r.violations)

    def test_accumulates_multiple_violations(self):
        engine = ProviderPolicyEngine(base_policy())
        r = engine.evaluate(make_req(service_type="translation", max_price="1000000"))
        assert r.allowed is False
        rules = [v.rule for v in r.violations]
        assert "service_not_offered" in rules
        assert "max_price_below_floor" in rules

    def test_large_amounts_no_float_drift(self):
        engine = ProviderPolicyEngine(
            base_policy(
                pricing=ProviderPricing(
                    min_acceptable=PriceTerm(amount=1_000_000, currency="USDC", unit="job"),
                    ideal_price=PriceTerm(amount=10_000_000, currency="USDC", unit="job"),
                )
            )
        )
        # $20,000,000 in base units = 20_000_000_000_000 (> 2^53).
        r = engine.evaluate(make_req(max_price="20000000000000"))
        assert r.allowed is True
        assert r.recommended_quote_amount_base_units == "10000000000000"  # $10M ideal


# ----- evaluate_counter() (ProviderPolicy.test.ts:152-215) ------------------


class TestEvaluateCounter:
    def test_accepts_counter_at_or_above_floor(self):
        engine = ProviderPolicyEngine(base_policy())
        verdict = engine.evaluate_counter("5000000", "7000000", 0)  # $5 exactly floor
        assert verdict.decision == "accept"

    def test_rejects_below_floor_default_walk(self):
        engine = ProviderPolicyEngine(base_policy())
        verdict = engine.evaluate_counter("4000000", "7000000", 0)
        assert verdict.decision == "reject"
        assert "walk" in verdict.reason

    def test_requotes_concede(self):
        engine = ProviderPolicyEngine(
            base_policy(counter_strategy="concede", concede_pct=50, max_requotes=3)
        )
        # Counter $3 below floor $5; last quote $7. Concede 50% of (7-5)=$1 → $6.
        verdict = engine.evaluate_counter("3000000", "7000000", 0)
        assert verdict.decision == "requote"
        assert verdict.amount_base_units == "6000000"

    def test_rejects_when_requote_budget_exhausted(self):
        engine = ProviderPolicyEngine(
            base_policy(counter_strategy="concede", max_requotes=1)
        )
        verdict = engine.evaluate_counter("3000000", "7000000", 1)  # already used 1
        assert verdict.decision == "reject"
        assert "budget exhausted" in verdict.reason

    def test_rejects_when_last_quote_at_floor(self):
        engine = ProviderPolicyEngine(base_policy(counter_strategy="concede"))
        verdict = engine.evaluate_counter("3000000", "5000000", 0)  # last == floor
        assert verdict.decision == "reject"
        assert "already at/below floor" in verdict.reason

    def test_clamps_concede_pct(self):
        engine = ProviderPolicyEngine(
            base_policy(counter_strategy="concede", concede_pct=200)
        )
        # 200 clamps to 99 → 7000000 - (2000000 * 99 / 100) = 5020000
        verdict = engine.evaluate_counter("3000000", "7000000", 0)
        assert verdict.decision == "requote"
        assert verdict.amount_base_units == "5020000"

    def test_never_requotes_below_floor(self):
        engine = ProviderPolicyEngine(
            base_policy(counter_strategy="concede", concede_pct=99)
        )
        verdict = engine.evaluate_counter("3000000", "5100000", 0)
        assert verdict.decision == "requote"
        assert int(verdict.amount_base_units) >= 5_000_000


class TestQuoteTtlSeconds:
    def test_exposes_parsed_ttl(self):
        engine = ProviderPolicyEngine(base_policy(quote_ttl="30m"))
        assert engine.quote_ttl_seconds == 1800


class TestParseTtl:
    def test_parses_s_m_h(self):
        assert parse_ttl("30s") == 30
        assert parse_ttl("15m") == 900
        assert parse_ttl("1h") == 3600

    def test_handles_whitespace(self):
        # TS regex tolerates inner space between digits and unit only via the
        # \s* between them; leading/trailing trimmed. "  15 m  " → 900.
        assert parse_ttl("  15 m  ") == 900

    def test_rejects_malformed(self):
        with pytest.raises(ValueError, match="Invalid TTL format"):
            parse_ttl("forever")
        with pytest.raises(ValueError):
            parse_ttl("15")
        with pytest.raises(ValueError):
            parse_ttl("15d")
