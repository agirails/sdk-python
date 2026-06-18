"""Tests for Level 1 pricing types."""

import pytest
from datetime import datetime, timedelta
from agirails.level1.pricing import (
    CostModel,
    PricingStrategy,
    PriceCalculation,
    calculate_price,
    DEFAULT_PRICING_STRATEGY,
)
from agirails.level1.job import Job


class TestCostModel:
    """Tests for CostModel."""

    def test_base_cost_only(self):
        """Test cost calculation with base cost only."""
        cost = CostModel(base=0.10)
        assert cost.calculate() == 0.10
        assert cost.calculate(units=100) == 0.10  # No per-unit

    def test_per_unit_cost(self):
        """Test cost calculation with per-unit pricing."""
        cost = CostModel(
            base=0.01,
            per_unit={"unit": "token", "rate": 0.0001},
        )
        assert cost.calculate(units=0) == 0.01
        assert cost.calculate(units=1000) == 0.11  # 0.01 + 1000 * 0.0001

    def test_zero_base_cost(self):
        """Test with zero base cost."""
        cost = CostModel(base=0.0, per_unit={"unit": "request", "rate": 0.05})
        assert cost.calculate(units=10) == 0.50


class TestPricingStrategy:
    """Tests for PricingStrategy."""

    def test_target_price_calculation(self):
        """Test target price with margin (TS markdown formula)."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.40,  # 40% margin = share of final price
        )
        # TS: price = cost / (1 - margin) = 0.10 / 0.6 = 0.1667
        assert strategy.calculate_target_price() == pytest.approx(0.1666667, abs=1e-4)

    def test_target_price_with_min_price(self):
        """Test minimum price enforcement."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.01),
            margin=0.20,
            min_price=0.05,
        )
        # Cost: 0.01, price = 0.01/0.8 = 0.0125, Min: 0.05 => Price: 0.05
        assert strategy.calculate_target_price() == 0.05

    def test_target_price_with_max_price(self):
        """Test maximum price enforcement."""
        strategy = PricingStrategy(
            cost=CostModel(base=1.00),
            margin=0.50,
            max_price=1.00,
        )
        # Cost: 1.00, price = 1.00/0.5 = 2.00, Max: 1.00 => Price: 1.00
        assert strategy.calculate_target_price() == 1.00

    def test_target_price_with_units(self):
        """Test target price with per-unit cost (TS markdown formula)."""
        strategy = PricingStrategy(
            cost=CostModel(
                base=0.01,
                per_unit={"unit": "token", "rate": 0.0001},
            ),
            margin=0.20,
        )
        # Cost at 1000 tokens: 0.01 + 0.10 = 0.11; price = 0.11/0.8 = 0.1375
        assert strategy.calculate_target_price(units=1000) == pytest.approx(0.1375)


class TestCalculatePrice:
    """Tests for calculate_price function."""

    def _make_job(self, budget: float) -> Job:
        """Create a test job with given budget."""
        return Job(
            id="0x123",
            service="test",
            input={},
            budget=budget,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )

    def test_accept_good_price(self):
        """Test accepting a price above target."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.20,  # Target: 0.10/0.8 = 0.125
        )
        job = self._make_job(budget=0.20)  # Offered: 0.20

        result = calculate_price(strategy, job)

        assert result.decision == "accept"
        assert result.cost == 0.10
        assert result.price == pytest.approx(0.125)
        # TS profit = price - cost = 0.125 - 0.10 = 0.025
        assert result.profit == pytest.approx(0.025)
        # TS sets a non-None reason on every branch.
        assert result.reason is not None

    def test_reject_below_cost(self):
        """Test rejecting price below cost."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            below_cost="reject",
        )
        job = self._make_job(budget=0.05)  # Below cost

        result = calculate_price(strategy, job)

        assert result.decision == "reject"
        assert "below cost" in result.reason.lower()

    def test_accept_below_cost_when_configured(self):
        """Test accepting below cost when configured."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            below_cost="accept",
        )
        job = self._make_job(budget=0.05)

        result = calculate_price(strategy, job)

        assert result.decision == "accept"
        # TS profit is the strategy's intended profit (price - cost), not
        # budget - cost. With the default 0.40 margin, price = 0.1667 > cost.
        assert result.profit == pytest.approx(0.10 / 0.6 - 0.10)

    def test_reject_below_target(self):
        """Test rejecting price below target."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.10/0.5 = 0.20
            below_price="reject",
        )
        job = self._make_job(budget=0.12)  # Above cost, below target

        result = calculate_price(strategy, job)

        assert result.decision == "reject"
        # TS reason: "below price ... but above cost".
        assert "below price" in result.reason.lower()

    def test_counter_offer(self):
        """Test counter-offer when below target."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.10/0.5 = 0.20
            below_price="counter-offer",
        )
        job = self._make_job(budget=0.12)  # Above cost, below target

        result = calculate_price(strategy, job)

        assert result.decision == "counter-offer"
        assert result.counter_offer == pytest.approx(0.20)

    def test_accept_below_target_when_configured(self):
        """Test accepting below target when configured."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.20
            below_price="accept",
        )
        job = self._make_job(budget=0.12)

        result = calculate_price(strategy, job)

        assert result.decision == "accept"

    def test_never_reject_above_max_price(self):
        """TS never rejects a too-generous budget (PriceCalculator.ts:94)."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.40,
            max_price=0.50,
        )
        job = self._make_job(budget=1.00)  # Far above price

        result = calculate_price(strategy, job)

        # price = 0.10/0.6 = 0.1667 (well under the 0.50 cap); budget 1.00 >=
        # price -> accept. The legacy "reject for being too generous" branch is
        # gone (TS never rejects a high budget).
        assert result.decision == "accept"
        assert result.price == pytest.approx(0.10 / 0.6)

    def test_max_price_clamps_high_target(self):
        """A target price above max is clamped down to max, then accepted."""
        strategy = PricingStrategy(
            cost=CostModel(base=1.00),
            margin=0.50,  # raw price = 1.00/0.5 = 2.00
            max_price=0.50,
        )
        job = self._make_job(budget=1.00)

        result = calculate_price(strategy, job)

        # price clamped to 0.50; budget 1.00 >= 0.50 -> accept.
        assert result.price == pytest.approx(0.50)
        assert result.decision == "accept"

    def test_margin_calculation(self):
        """Test margin reported as share of final price (TS PriceCalculator)."""
        strategy = PricingStrategy(cost=CostModel(base=0.10), margin=0.40)
        job = self._make_job(budget=0.20)

        result = calculate_price(strategy, job)

        # price = 0.10/0.6 = 0.1667; profit = 0.0667;
        # marginPercent = profit/price = 0.40 (the configured margin).
        assert result.margin_percent == pytest.approx(0.40, abs=1e-6)


class TestDefaultPricingStrategy:
    """Tests for default pricing strategy."""

    def test_default_strategy_values(self):
        """Test default strategy configuration (TS DEFAULT_PRICING_STRATEGY)."""
        assert DEFAULT_PRICING_STRATEGY.cost.base == 0.05
        assert DEFAULT_PRICING_STRATEGY.margin == 0.40
        assert DEFAULT_PRICING_STRATEGY.min_price == 0.05
        assert DEFAULT_PRICING_STRATEGY.below_price == "counter-offer"
        assert DEFAULT_PRICING_STRATEGY.below_cost == "reject"
        assert DEFAULT_PRICING_STRATEGY.max_negotiation_rounds == 10
