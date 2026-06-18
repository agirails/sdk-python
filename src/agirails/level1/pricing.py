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
    margin: float = 0.40  # 40% default margin (TS DEFAULT_PRICING_STRATEGY)
    min_price: Optional[float] = None
    max_price: Optional[float] = None
    # TS default behavior: belowPrice -> counter-offer, belowCost -> reject.
    below_price: Literal["reject", "accept", "counter-offer"] = "counter-offer"
    below_cost: Literal["reject", "accept", "counter-offer"] = "reject"
    # TS behavior.maxNegotiationRounds (PricingStrategy.ts:151). Counter-offer
    # round cap; carried for parity, enforced by the orchestrator state machine.
    max_negotiation_rounds: int = 10

    def calculate_target_price(self, units: float = 0) -> float:
        """
        Calculate target price with margin.

        Mirrors TS ``calculatePrice`` margin math (PriceCalculator.ts:76-84):
        ``price = cost / (1 - clamp(margin, 0, 1))`` — margin is the share of
        the FINAL price, not a markup over cost. For cost=$10, margin=0.40
        this yields $16.67 (TS), NOT $14.00 (legacy markup). Bounds default to
        TS [0.05, 10000] when not set.

        Args:
            units: Number of units for per-unit pricing

        Returns:
            Target price in USDC
        """
        cost = self.cost.calculate(units)
        # Clamp margin to [0, 1] like TS Math.max(0, Math.min(1, margin)).
        margin = max(0.0, min(1.0, self.margin))
        price = cost / (1 - margin) if margin < 1 else float("inf")

        # Enforce min/max bounds. Default to TS bounds (0.05 / 10000) when the
        # strategy does not set them (PriceCalculator.ts:82-84).
        minimum = self.min_price if self.min_price is not None else 0.05
        maximum = self.max_price if self.max_price is not None else 10000
        price = max(minimum, min(maximum, price))

        return price


@dataclass
class PriceCalculation:
    """
    Result of price calculation for a job.

    Contains all pricing information and the decision.

    Attributes:
        cost: Calculated cost in USDC
        price: Target price in USDC (cost / (1 - margin))
        profit: Expected profit (price - cost)
        margin_percent: Margin as the SHARE of the final price (0..1),
            matching TS marginPercent = profit / price (NOT a markup, NOT *100)
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


# Default pricing strategy for services without custom pricing.
# Mirrors TS DEFAULT_PRICING_STRATEGY (PriceCalculator.ts:233-245):
# base $0.05, 40% margin, counter-offer below price, reject below cost,
# 10 max negotiation rounds.
DEFAULT_PRICING_STRATEGY = PricingStrategy(
    cost=CostModel(base=0.05),  # ACTP protocol minimum
    margin=0.40,  # 40% profit margin
    min_price=0.05,  # Minimum $0.05
    max_price=10000,
    below_price="counter-offer",
    below_cost="reject",
    max_negotiation_rounds=10,
)


def estimate_units(job: "Job", unit: str) -> int:
    """Estimate number of units in a job's input.

    Mirrors TS ``estimateUnits`` (PriceCalculator.ts:140-198). Supports
    word / token / character / image / minute / request unit types and
    extracts the relevant field from ``job.input``.
    """
    import json as _json

    inp = job.input
    inp_dict = inp if isinstance(inp, dict) else {}
    text = inp_dict.get("text") if isinstance(inp_dict.get("text"), str) else None
    u = unit.lower()

    if u == "word":
        if text is not None:
            return len([w for w in text.split() if len(w) > 0])
        return len(_json.dumps(inp).split())

    if u == "token":
        # Rough estimate: 1 token ~ 4 characters.
        import math

        if text is not None:
            return math.ceil(len(text) / 4)
        return math.ceil(len(_json.dumps(inp)) / 4)

    if u in ("character", "char"):
        if text is not None:
            return len(text)
        return len(_json.dumps(inp))

    if u in ("image", "img"):
        images = inp_dict.get("images")
        if isinstance(images, list):
            return len(images)
        if inp_dict.get("image") or inp_dict.get("imageUrl"):
            return 1
        return 1

    if u in ("minute", "min"):
        dur = inp_dict.get("duration")
        if isinstance(dur, (int, float)) and not isinstance(dur, bool):
            return int(dur)
        dur_m = inp_dict.get("durationMinutes")
        if isinstance(dur_m, (int, float)) and not isinstance(dur_m, bool):
            return int(dur_m)
        return 1

    if u in ("request", "job"):
        return 1

    # Unknown unit type — default to 1 (TS default branch).
    return 1


def calculate_price(
    strategy: PricingStrategy,
    job: Job,
    units: Optional[float] = None,
) -> PriceCalculation:
    """
    Calculate pricing for a job.

    Mirrors TS ``calculatePrice`` (PriceCalculator.ts:54-126) byte-for-byte
    on the decision band and reported margin:

      * cost = base + per-unit (units estimated from job.input when per_unit
        is set, via :func:`estimate_units`) — NOT always zero.
      * price = clamp(cost / (1 - clamp(margin,0,1)), minimum 0.05, maximum
        10000).
      * marginPercent = profit / price (share of FINAL price, 0..1 — NOT a
        markup over cost, NOT *100).
      * decision: accept when budget >= price; below_price behavior when
        cost <= budget < price; below_cost behavior when budget < cost.
        A high budget (above max) is NEVER rejected for being too generous.

    Args:
        strategy: Pricing strategy to use
        job: Job to evaluate
        units: Optional explicit unit count override (estimated when None)

    Returns:
        PriceCalculation with decision and details
    """
    base_cost = strategy.cost.base or 0.0

    # Per-unit cost: estimate units from the job input when a per_unit model is
    # configured (TS PriceCalculator.ts:59-64). The caller may override.
    unit_cost = 0.0
    estimated_units: Optional[float] = None
    if strategy.cost.per_unit:
        unit_name = strategy.cost.per_unit.get("unit", "")
        if units is not None:
            estimated_units = units
        else:
            estimated_units = float(estimate_units(job, str(unit_name)))
        rate = strategy.cost.per_unit.get("rate", 0)
        unit_cost = estimated_units * rate

    total_cost = base_cost + unit_cost

    # Apply margin + bounds via the strategy helper (uses the estimated units
    # for the per-unit branch so the target price matches the cost).
    target_price = strategy.calculate_target_price(
        estimated_units if estimated_units is not None else 0
    )

    offered_price = job.budget

    # Actual profit + margin reported as the share of the FINAL price (TS:87-88).
    profit = target_price - total_cost
    margin_percent = (profit / target_price) if target_price > 0 else 0.0

    decision: Literal["accept", "reject", "counter-offer"]
    reason: Optional[str] = None
    counter_offer: Optional[float] = None

    if offered_price >= target_price:
        # Budget meets or exceeds our price — accept immediately.
        decision = "accept"
        reason = f"Budget ${offered_price:.2f} >= price ${target_price:.2f}"
    elif offered_price >= total_cost:
        # Budget below price but above cost (reduced profit). Use behavior.
        decision = strategy.below_price
        reason = (
            f"Budget ${offered_price:.2f} below price ${target_price:.2f} "
            f"but above cost ${total_cost:.2f}"
        )
        if decision == "counter-offer":
            counter_offer = target_price
    else:
        # Budget below cost (would lose money). Use behavior.
        decision = strategy.below_cost
        reason = (
            f"Budget ${offered_price:.2f} below cost ${total_cost:.2f} "
            f"(would lose money)"
        )
        if decision == "counter-offer":
            counter_offer = target_price

    return PriceCalculation(
        cost=total_cost,
        price=target_price,
        profit=profit,
        margin_percent=margin_percent,
        decision=decision,
        reason=reason,
        counter_offer=counter_offer,
    )
