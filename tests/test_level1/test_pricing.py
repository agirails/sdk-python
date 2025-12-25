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
        """Test target price with margin."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.40,  # 40% margin
        )
        # Cost: 0.10, Margin: 40% => Price: 0.14
        assert strategy.calculate_target_price() == pytest.approx(0.14)

    def test_target_price_with_min_price(self):
        """Test minimum price enforcement."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.01),
            margin=0.20,
            min_price=0.05,
        )
        # Cost: 0.01, With margin: 0.012, Min: 0.05 => Price: 0.05
        assert strategy.calculate_target_price() == 0.05

    def test_target_price_with_max_price(self):
        """Test maximum price enforcement."""
        strategy = PricingStrategy(
            cost=CostModel(base=1.00),
            margin=0.50,
            max_price=1.00,
        )
        # Cost: 1.00, With margin: 1.50, Max: 1.00 => Price: 1.00
        assert strategy.calculate_target_price() == 1.00

    def test_target_price_with_units(self):
        """Test target price with per-unit cost."""
        strategy = PricingStrategy(
            cost=CostModel(
                base=0.01,
                per_unit={"unit": "token", "rate": 0.0001},
            ),
            margin=0.20,
        )
        # Cost at 1000 tokens: 0.01 + 0.10 = 0.11
        # With 20% margin: 0.132
        assert strategy.calculate_target_price(units=1000) == pytest.approx(0.132)


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
            margin=0.20,  # Target: 0.12
        )
        job = self._make_job(budget=0.20)  # Offered: 0.20

        result = calculate_price(strategy, job)

        assert result.decision == "accept"
        assert result.cost == 0.10
        assert result.price == pytest.approx(0.12)
        assert result.profit == 0.10  # 0.20 - 0.10
        assert result.reason is None

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
        assert result.profit < 0  # Negative profit

    def test_reject_below_target(self):
        """Test rejecting price below target."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.15
            below_price="reject",
        )
        job = self._make_job(budget=0.12)  # Above cost, below target

        result = calculate_price(strategy, job)

        assert result.decision == "reject"
        assert "below target" in result.reason.lower()

    def test_counter_offer(self):
        """Test counter-offer when below target."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.15
            below_price="counter-offer",
        )
        job = self._make_job(budget=0.12)  # Above cost, below target

        result = calculate_price(strategy, job)

        assert result.decision == "counter-offer"
        assert result.counter_offer == pytest.approx(0.15)

    def test_accept_below_target_when_configured(self):
        """Test accepting below target when configured."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            margin=0.50,  # Target: 0.15
            below_price="accept",
        )
        job = self._make_job(budget=0.12)

        result = calculate_price(strategy, job)

        assert result.decision == "accept"

    def test_reject_above_max_price(self):
        """Test rejecting price above maximum."""
        strategy = PricingStrategy(
            cost=CostModel(base=0.10),
            max_price=0.50,
        )
        job = self._make_job(budget=1.00)  # Above max

        result = calculate_price(strategy, job)

        assert result.decision == "reject"
        assert "exceeds maximum" in result.reason.lower()

    def test_margin_calculation(self):
        """Test margin percentage calculation."""
        strategy = PricingStrategy(cost=CostModel(base=0.10))
        job = self._make_job(budget=0.20)

        result = calculate_price(strategy, job)

        # Profit: 0.10, Cost: 0.10, Margin: 100%
        assert result.margin_percent == pytest.approx(100.0)


class TestDefaultPricingStrategy:
    """Tests for default pricing strategy."""

    def test_default_strategy_values(self):
        """Test default strategy configuration."""
        assert DEFAULT_PRICING_STRATEGY.cost.base == 0.05
        assert DEFAULT_PRICING_STRATEGY.margin == 0.20
        assert DEFAULT_PRICING_STRATEGY.min_price == 0.05
        assert DEFAULT_PRICING_STRATEGY.below_price == "reject"
        assert DEFAULT_PRICING_STRATEGY.below_cost == "reject"
