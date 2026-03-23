"""Tests for PolicyEngine — 5 guardrails + budget ledger."""

from __future__ import annotations

import datetime
import json
import os
import tempfile
import time

import pytest

from agirails.negotiation.policy_engine import (
    BudgetEntry,
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    PolicyEngine,
    PolicyResult,
    QuoteOffer,
    Selection,
)


# ============================================================================
# Helpers
# ============================================================================


def _make_policy(
    max_price: float = 1.0,
    max_daily: float = 10.0,
    min_reputation: float = None,
) -> BuyerPolicy:
    return BuyerPolicy(
        task="test task",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=max_price, currency="USDC", unit="request"),
            max_daily_spend=MaxDailySpend(amount=max_daily, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=3, quote_ttl="15m"),
        selection=Selection(
            prioritize=["quality", "price"],
            min_reputation=min_reputation,
        ),
    )


def _make_offer(
    unit_price: float = 0.50,
    currency: str = "USDC",
    unit: str = "request",
    reputation_score: float = 80.0,
    session_id: str = "test-session-123",
    expires_at: int = None,
) -> QuoteOffer:
    if expires_at is None:
        expires_at = int(time.time()) + 3600  # 1h from now
    return QuoteOffer(
        provider="test-provider",
        unit_price=unit_price,
        currency=currency,
        unit=unit,
        reputation_score=reputation_score,
        commerce_session_id=session_id,
        expires_at=expires_at,
    )


# ============================================================================
# Validation — 5 guardrails
# ============================================================================


class TestValidation:
    def test_happy_path(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer())
        assert result.allowed is True
        assert result.violations == []

    def test_unit_price_exceeded(self, tmp_path):
        engine = PolicyEngine(_make_policy(max_price=0.10), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(unit_price=0.50))
        assert result.allowed is False
        assert any(v.rule == "max_unit_price" for v in result.violations)

    def test_currency_mismatch(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(currency="EUR"))
        assert result.allowed is False
        assert any(v.rule == "max_unit_price" for v in result.violations)

    def test_unit_mismatch(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(unit="hour"))
        assert result.allowed is False

    def test_daily_spend_exceeded(self, tmp_path):
        engine = PolicyEngine(_make_policy(max_daily=1.0), actp_dir=str(tmp_path))
        # Reserve most of the budget
        engine.reserve("session-1", 0.80, "USDC")
        # This offer would push us over
        result = engine.validate(_make_offer(unit_price=0.50))
        assert result.allowed is False
        assert any(v.rule == "max_daily_spend" for v in result.violations)

    def test_reputation_below_minimum(self, tmp_path):
        engine = PolicyEngine(_make_policy(min_reputation=50.0), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(reputation_score=30.0))
        assert result.allowed is False
        assert any(v.rule == "min_reputation" for v in result.violations)

    def test_reputation_unknown_fails(self, tmp_path):
        engine = PolicyEngine(_make_policy(min_reputation=50.0), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(reputation_score=None))
        assert result.allowed is False
        assert any(v.rule == "min_reputation" for v in result.violations)

    def test_no_min_reputation_skips_check(self, tmp_path):
        engine = PolicyEngine(_make_policy(min_reputation=None), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(reputation_score=None))
        assert result.allowed is True

    def test_quote_expired(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(expires_at=int(time.time()) - 100))
        assert result.allowed is False
        assert any(v.rule == "quote_expired" for v in result.violations)

    def test_missing_session_id(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(session_id=None))
        assert result.allowed is False
        assert any(v.rule == "missing_session_id" for v in result.violations)

    def test_negative_price_rejected(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(unit_price=-1.0))
        assert result.allowed is False

    def test_nan_price_rejected(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(unit_price=float("nan")))
        assert result.allowed is False

    def test_inf_price_rejected(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        result = engine.validate(_make_offer(unit_price=float("inf")))
        assert result.allowed is False


# ============================================================================
# Budget ledger — reserve / commit / release
# ============================================================================


class TestBudgetLedger:
    def test_reserve_increases_committed(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        assert engine.get_committed_today() == 0.0
        engine.reserve("s1", 2.0, "USDC")
        assert engine.get_committed_today() == 2.0

    def test_reserve_exceeds_budget_raises(self, tmp_path):
        engine = PolicyEngine(_make_policy(max_daily=5.0), actp_dir=str(tmp_path))
        engine.reserve("s1", 4.0, "USDC")
        with pytest.raises(ValueError, match="Budget exceeded"):
            engine.reserve("s2", 2.0, "USDC")

    def test_release_frees_budget(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        engine.reserve("s1", 3.0, "USDC")
        engine.release("s1")
        assert engine.get_committed_today() == 0.0

    def test_commit_marks_as_committed(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        engine.reserve("s1", 2.0, "USDC")
        engine.commit("s1", "0xtx123")
        # Still counts as committed
        assert engine.get_committed_today() == 2.0

    def test_reserve_currency_mismatch_raises(self, tmp_path):
        engine = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Currency mismatch"):
            engine.reserve("s1", 1.0, "EUR")

    def test_ledger_persists_to_disk(self, tmp_path):
        engine1 = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        engine1.reserve("s1", 3.0, "USDC")

        # New engine instance reads from disk
        engine2 = PolicyEngine(_make_policy(), actp_dir=str(tmp_path))
        assert engine2.get_committed_today() == 3.0


# ============================================================================
# TTL parsing
# ============================================================================


class TestParseTtl:
    def test_seconds(self):
        assert PolicyEngine.parse_ttl("30s") == 30

    def test_minutes(self):
        assert PolicyEngine.parse_ttl("15m") == 900

    def test_hours(self):
        assert PolicyEngine.parse_ttl("2h") == 7200

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            PolicyEngine.parse_ttl("abc")

    def test_no_unit_raises(self):
        with pytest.raises(ValueError):
            PolicyEngine.parse_ttl("30")
