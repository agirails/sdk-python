"""
ProviderPolicy — hard guardrails for autonomous provider quoting + counter handling.

Python port of a working subset of
``sdk-js/src/negotiation/ProviderPolicy.ts``. Only the fields the v1
``actp serve`` daemon needs to evaluate counter-offers are modeled here;
the full TS shape (currency/unit, services list, multi-round concede
strategy, etc.) will be ported incrementally.

@module server/policy
@see Protocol/aips/AIP-2.1-DRAFT.md §5.2 (provider policy)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PLATFORM_MIN_BASE_UNITS = 50_000  # $0.05 USDC


# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class PricingPolicy:
    """Provider pricing rules in USDC base units (1e6 per $1).

    Invariants enforced at load time:
      ideal_amount >= min_acceptable_amount >= PLATFORM_MIN_BASE_UNITS
    """

    min_acceptable_amount: int
    ideal_amount: int
    currency: str = "USDC"
    unit: str = "base"

    def __post_init__(self) -> None:
        if self.min_acceptable_amount < PLATFORM_MIN_BASE_UNITS:
            raise ValueError(
                f"min_acceptable_amount ({self.min_acceptable_amount}) is "
                f"below platform minimum ({PLATFORM_MIN_BASE_UNITS})"
            )
        if self.ideal_amount < self.min_acceptable_amount:
            raise ValueError(
                "ideal_amount must be >= min_acceptable_amount"
            )
        if self.currency != "USDC":
            raise ValueError("Only USDC supported in v1")


@dataclass(frozen=True)
class ProviderPolicy:
    """Minimal v1 policy for the ``actp serve`` daemon.

    Attributes:
        services: Service identifiers this provider offers. Empty list
            means "accept all services" (legacy behavior). Incoming
            counter-offers for service types NOT in this list get a
            ``REJECT`` verdict.
        pricing: Pricing rules. ``min_acceptable_amount`` is the absolute
            floor; ``ideal_amount`` is what the provider would quote if
            the buyer was willing to pay it.
        quote_ttl_seconds: How long our quotes / counter-accepts are
            valid for. Used by the orchestrator when building reply
            messages; the channel handler also rejects messages whose
            ``expiresAt`` has already passed.
        min_deadline_seconds: Minimum seconds between now and tx.deadline
            for us to commit to delivery. Tighter deadlines → REJECT.
        counter_strategy: 'walk' (reject + log; let buyer's TTL expire)
            or 'concede' (re-quote between last quote and floor by
            ``concede_pct`` for up to ``max_requotes`` rounds).
    """

    pricing: PricingPolicy
    services: List[str] = field(default_factory=list)
    quote_ttl_seconds: int = 900  # 15 min
    min_deadline_seconds: int = 60
    counter_strategy: str = "walk"  # 'walk' | 'concede'
    concede_pct: int = 30
    max_requotes: int = 2

    def __post_init__(self) -> None:
        if self.counter_strategy not in ("walk", "concede"):
            raise ValueError(
                f"counter_strategy must be 'walk' or 'concede', got "
                f"{self.counter_strategy!r}"
            )
        if not 1 <= self.concede_pct <= 99:
            raise ValueError("concede_pct must be in [1, 99]")
        if self.max_requotes < 0:
            raise ValueError("max_requotes must be >= 0")
        if self.min_deadline_seconds < 0:
            raise ValueError("min_deadline_seconds must be >= 0")


# ============================================================================
# Loaders
# ============================================================================


_DURATION_RE = re.compile(r"^(\d+)\s*([smhd])?$")


def _parse_duration(value: Any, default_seconds: int) -> int:
    """Parse '15m', '1h', '900', or int into seconds."""
    if value is None:
        return default_seconds
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        m = _DURATION_RE.match(value.strip())
        if not m:
            raise ValueError(f"Invalid duration: {value!r}")
        n = int(m.group(1))
        unit = m.group(2) or "s"
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        return n * multiplier
    raise ValueError(f"Invalid duration type: {type(value).__name__}")


def load_policy_from_dict(data: Dict[str, Any]) -> ProviderPolicy:
    """Build a :class:`ProviderPolicy` from a parsed JSON dict.

    Accepts the same JSON shape the TS daemon consumes (the operator
    writes one policy file; either SDK loads it).
    """
    pricing_raw = data.get("pricing", {})
    min_raw = pricing_raw.get("min_acceptable", {})
    ideal_raw = pricing_raw.get("ideal_price", pricing_raw.get("ideal", {}))

    pricing = PricingPolicy(
        min_acceptable_amount=int(min_raw.get("amount", 0)),
        ideal_amount=int(ideal_raw.get("amount", 0)),
        currency=str(min_raw.get("currency", "USDC")),
        unit=str(min_raw.get("unit", "base")),
    )

    return ProviderPolicy(
        pricing=pricing,
        services=list(data.get("services", [])),
        quote_ttl_seconds=_parse_duration(data.get("quote_ttl"), 900),
        min_deadline_seconds=int(data.get("min_deadline_seconds", 60)),
        counter_strategy=str(data.get("counter_strategy", "walk")),
        concede_pct=int(data.get("concede_pct", 30)),
        max_requotes=int(data.get("max_requotes", 2)),
    )


def load_policy_from_file(path: Path) -> ProviderPolicy:
    """Load a JSON policy file from disk."""
    with open(path, encoding="utf-8") as fp:
        data = json.load(fp)
    return load_policy_from_dict(data)


__all__ = [
    "PLATFORM_MIN_BASE_UNITS",
    "PricingPolicy",
    "ProviderPolicy",
    "load_policy_from_dict",
    "load_policy_from_file",
]
