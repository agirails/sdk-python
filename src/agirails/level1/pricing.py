"""
Pricing strategy for AGIRAILS Level 1 API.

Provides:
- CostModel: Defines cost calculation
- PricingStrategy: Complete pricing configuration
- PriceCalculation: Result of price calculation
- calculate_price: Function to evaluate pricing for a job
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Literal, Optional

if TYPE_CHECKING:
    from agirails.level1.job import Job


@dataclass
class CostModel:
    """
    Cost model for service pricing.

    Defines how to calculate the base cost of a job.

    Attributes:
        base: Fixed base cost in USDC
        per_unit: Optional per-unit pricing (e.g., per token, per request)
            - unit: Name of the unit (e.g., "token", "request", "second")
            - rate: Cost per unit in USDC

    Example:
        >>> # Fixed cost
        >>> cost = CostModel(base=0.10)
        >>>
        >>> # Per-token pricing
        >>> cost = CostModel(base=0.01, per_unit={"unit": "token", "rate": 0.0001})
    """

    base: float
    per_unit: Optional[Dict[str, float]] = None

    def calculate(self, units: float = 0) -> float:
        """
        Calculate total cost.

        Args:
            units: Number of units consumed (if per_unit pricing)

        Returns:
            Total cost in USDC
        """
        total = self.base
        if self.per_unit is not None and units > 0:
            rate = self.per_unit.get("rate", 0)
            total += units * rate
        return total


@dataclass
class PricingStrategy:
    """
    Complete pricing strategy for a service.

    Defines cost, margin, price bounds, and behavior for edge cases.

    Attributes:
        cost: Cost model for calculating base cost
        margin: Profit margin as decimal (e.g., 0.40 for 40%)
        min_price: Minimum acceptable price in USDC
        max_price: Maximum acceptable price in USDC
        below_price: Action when offered price is below calculated price
        below_cost: Action when offered price is below cost

    Example:
        >>> strategy = PricingStrategy(
        ...     cost=CostModel(base=0.10),
        ...     margin=0.40,  # 40% margin
        ...     min_price=0.05,
        ...     below_price="counter-offer"
        ... )
    """

    cost: CostModel
    margin: float = 0.20  # 20% default margin
    min_price: Optional[float] = None
    max_price: Optional[float] = None
    below_price: Literal["reject", "accept", "counter-offer"] = "reject"
    below_cost: Literal["reject", "accept"] = "reject"

    def calculate_target_price(self, units: float = 0) -> float:
        """
        Calculate target price with margin.

        Args:
            units: Number of units for per-unit pricing

        Returns:
            Target price in USDC
        """
        cost = self.cost.calculate(units)
        price = cost * (1 + self.margin)

        # Apply bounds
        if self.min_price is not None:
            price = max(price, self.min_price)
        if self.max_price is not None:
            price = min(price, self.max_price)

        return price


@dataclass
class PriceCalculation:
    """
    Result of price calculation for a job.

    Contains all pricing information and the decision.

    Attributes:
        cost: Calculated cost in USDC
        price: Target price in USDC (cost + margin)
        profit: Expected profit (price - cost)
        margin_percent: Actual margin percentage
        decision: Whether to accept, reject, or counter-offer
        reason: Explanation for the decision
        counter_offer: Suggested counter-offer price (if decision is counter-offer)
    """

    cost: float
    price: float
    profit: float
    margin_percent: float
    decision: Literal["accept", "reject", "counter-offer"]
    reason: Optional[str] = None
    counter_offer: Optional[float] = None


# Default pricing strategy for services without custom pricing
DEFAULT_PRICING_STRATEGY = PricingStrategy(
    cost=CostModel(base=0.05),  # $0.05 base cost
    margin=0.20,  # 20% margin
    min_price=0.05,  # Minimum $0.05
    below_price="reject",
    below_cost="reject",
)


def calculate_price(
    strategy: PricingStrategy,
    job: Job,
    units: float = 0,
) -> PriceCalculation:
    """
    Calculate pricing for a job.

    Evaluates the job's budget against the pricing strategy and returns
    a decision on whether to accept, reject, or counter-offer.

    Args:
        strategy: Pricing strategy to use
        job: Job to evaluate
        units: Number of units for per-unit pricing (default: 0)

    Returns:
        PriceCalculation with decision and details

    Example:
        >>> strategy = PricingStrategy(cost=CostModel(base=0.10), margin=0.40)
        >>> calc = calculate_price(strategy, job)
        >>> if calc.decision == "accept":
        ...     # Process the job
        ...     pass
    """
    # Calculate cost and target price
    cost = strategy.cost.calculate(units)
    target_price = strategy.calculate_target_price(units)
    offered_price = job.budget

    # Calculate actual profit and margin if we accept
    actual_profit = offered_price - cost
    actual_margin = (actual_profit / cost) if cost > 0 else float("inf")

    # Determine decision
    decision: Literal["accept", "reject", "counter-offer"]
    reason: Optional[str] = None
    counter_offer: Optional[float] = None

    # Check against maximum price
    if strategy.max_price is not None and offered_price > strategy.max_price:
        decision = "reject"
        reason = f"Offered price ${offered_price:.2f} exceeds maximum ${strategy.max_price:.2f}"

    # Check against cost
    elif offered_price < cost:
        if strategy.below_cost == "accept":
            decision = "accept"
            reason = f"Accepting below cost (${offered_price:.2f} < ${cost:.2f})"
        else:
            decision = "reject"
            reason = f"Offered price ${offered_price:.2f} is below cost ${cost:.2f}"

    # Check against target price
    elif offered_price < target_price:
        if strategy.below_price == "accept":
            decision = "accept"
            reason = f"Accepting below target price (${offered_price:.2f} < ${target_price:.2f})"
        elif strategy.below_price == "counter-offer":
            decision = "counter-offer"
            reason = f"Counter-offering ${target_price:.2f} (offered ${offered_price:.2f})"
            counter_offer = target_price
        else:
            decision = "reject"
            reason = f"Offered price ${offered_price:.2f} is below target ${target_price:.2f}"

    # Price is acceptable
    else:
        decision = "accept"
        reason = None

    return PriceCalculation(
        cost=cost,
        price=target_price,
        profit=actual_profit,
        margin_percent=actual_margin * 100,
        decision=decision,
        reason=reason,
        counter_offer=counter_offer,
    )
