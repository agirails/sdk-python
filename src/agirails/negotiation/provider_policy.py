"""
ProviderPolicy — hard guardrails for autonomous provider quoting.

Python port of ``sdk-js/src/negotiation/ProviderPolicy.ts`` (lines 1-399),
byte/semantically identical. Symmetric to BuyerPolicy. Provider configures
what they'll deliver, their price floor, and their lifecycle preferences;
:class:`ProviderPolicyEngine` enforces those invariants on every incoming
request so the provider never quotes below floor, outside their service
menu, or for a transaction they can't realistically complete before the
deadline.

This module mirrors the FULL TS field shape — human-amount fields
(``min_acceptable.amount`` / ``ideal_price.amount`` as floats), a full
:meth:`ProviderPolicyEngine.evaluate` that checks
service_not_offered / currency_mismatch / unit_mismatch /
max_price_below_floor / deadline_too_tight, and
:meth:`ProviderPolicyEngine.evaluate_counter` that enforces ``max_requotes``
with concede math.

The legacy ``server/policy.py`` ``ProviderPolicy`` dataclass (base-unit-int
fields) is retained for the v1 ``actp serve`` daemon and is NOT removed; this
module is the canonical TS-parity surface.

@module negotiation/provider_policy
@see Protocol/aips/AIP-2.1-DRAFT.md §5.2 (ProviderPolicy.ts creation)
"""

from __future__ import annotations

import inspect
import re
import time
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Union,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only import, avoids runtime coupling
    from agirails.builders.counter_offer import CounterOfferMessage

# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class PriceTerm:
    """A priced term: ``{ amount, currency, unit }`` (mirrors TS shape).

    ``amount`` is a HUMAN amount (e.g. ``5``, ``10.5``) — NOT base units —
    matching ``ProviderPolicy.ts`` ``{ amount: number; currency; unit }``.
    """

    amount: float
    currency: str
    unit: str


@dataclass(frozen=True)
class ProviderPricing:
    """Provider pricing block.

    Pricing invariant (enforced in :class:`ProviderPolicyEngine` construction):
      ``ideal_price.amount >= min_acceptable.amount >= PLATFORM_MIN_USDC``

    ``currency`` / ``unit`` must be identical across ``min_acceptable`` and
    ``ideal_price`` — we compare amounts directly, there's no FX in v1.
    """

    #: Absolute floor. Any buyer maxPrice below this → skip.
    min_acceptable: PriceTerm
    #: Preferred quote amount when buyer's maxPrice ≥ ideal.
    ideal_price: PriceTerm


@dataclass(frozen=True)
class ProviderPolicy:
    """What this agent provides + at what terms (mirrors TS ``ProviderPolicy``)."""

    #: Services this provider offers. Incoming requests for service types NOT
    #: in this list get a 'skip' decision (let the tx timeout to CANCELLED).
    services: List[str]
    #: Pricing rules (min_acceptable + ideal_price).
    pricing: ProviderPricing
    #: Quote validity window (e.g. "15m"). Governs our QuoteMessage expiresAt.
    quote_ttl: str
    #: Minimum seconds between now and tx.deadline to realistically deliver.
    #: Requests with a tighter deadline get 'skip'. Defaults to 60s if None.
    min_deadline_seconds: Optional[int] = None
    #: Multi-round counter strategy: 'walk' (default) | 'concede'.
    counter_strategy: Optional[Literal["walk", "concede"]] = None
    #: Concede percent: new = last - (last - floor) * pct/100. Default 30, bounded [1,99].
    concede_pct: Optional[int] = None
    #: Hard cap on re-quotes per (provider, txId). Default 2.
    max_requotes: Optional[int] = None


# ProviderPolicyViolation rules (TS discriminated union → rule strings).
ProviderPolicyViolationRule = Literal[
    "service_not_offered",
    "max_price_below_floor",
    "deadline_too_tight",
    "currency_mismatch",
    "unit_mismatch",
]


@dataclass(frozen=True)
class ProviderPolicyViolation:
    """A single policy violation (mirrors TS ``ProviderPolicyViolation``)."""

    rule: ProviderPolicyViolationRule
    detail: str


@dataclass(frozen=True)
class ProviderPolicyResult:
    """Result of :meth:`ProviderPolicyEngine.evaluate` (mirrors TS ``ProviderPolicyResult``)."""

    allowed: bool
    violations: List[ProviderPolicyViolation] = field(default_factory=list)
    #: When ``allowed``, the amount we SHOULD quote in USDC base units
    #: (1e6 per $1) as a decimal string. None when not allowed.
    recommended_quote_amount_base_units: Optional[str] = None


@dataclass(frozen=True)
class IncomingRequest:
    """Incoming request surface (mirrors TS ``IncomingRequest``).

    The minimum the orchestrator needs to decide whether + at what price to
    quote. Extracted from the on-chain transaction plus off-chain context.
    """

    tx_id: str
    consumer: str  # DID
    #: Buyer's offered amount in USDC base units (smallest unit, string).
    offered_amount: str
    #: Buyer's ceiling in USDC base units.
    max_price: str
    #: Unix seconds — tx.deadline from on-chain.
    deadline: int
    #: Service identifier (e.g. "code-review").
    service_type: str
    currency: str  # "USDC"
    unit: str  # "job" | whatever


CounterDecisionAction = Literal["accept", "reject", "requote"]


@dataclass(frozen=True)
class CounterEvaluation:
    """Verdict for :meth:`ProviderPolicyEngine.evaluate_counter`.

    Mirrors TS return ``{ decision, reason, amountBaseUnits? }``.
    """

    decision: CounterDecisionAction
    reason: str
    amount_base_units: Optional[str] = None


# ============================================================================
# BYO-brain counter decider hooks (TS ProviderOrchestrator.ts:107-139)
# ============================================================================


@dataclass(frozen=True)
class CounterDecision:
    """Decision for a buyer counter-offer from a provider counter-decider.

    Discriminated union flattened to a single frozen dataclass (mirrors the
    TS ``CounterDecision`` union, ProviderOrchestrator.ts:107-110):

    - ``action='accept'``  → provider accepts the buyer's counter amount.
    - ``action='reject'``  → provider walks; let the tx time out to CANCELLED.
    - ``action='requote'`` → provider sends a new quote at
      ``amount_base_units`` (>= the provider floor, else the QuoteBuilder
      rejects it deep in the re-quote path).
    """

    action: CounterDecisionAction  # 'accept' | 'reject' | 'requote'
    reason: str
    #: Set ONLY when ``action == 'requote'`` (base-unit string). None otherwise.
    amount_base_units: Optional[str] = None


@dataclass(frozen=True)
class CounterContext:
    """Context handed to a provider counter-decider.

    Surfaces everything the built-in :meth:`ProviderPolicyEngine.evaluate_counter`
    reads (floor = pricing.min_acceptable, counter_strategy, concede_pct,
    max_requotes all live on ``policy``) plus the per-tx baseline, so a BYO
    decider isn't blind. The counter is ALREADY signature/band/expiry verified
    before the decider runs. Mirrors TS ``CounterContext``
    (ProviderOrchestrator.ts:119-128).
    """

    #: Verified incoming counter (``counter.counterAmount`` = buyer's bid).
    counter: "CounterOfferMessage"
    #: Provider's most recent quote amount for this tx (base units).
    last_quote_amount_base_units: str
    #: Re-quotes already sent this tx (0 on first counter).
    requotes_used: int
    #: Provider policy (floor, counter_strategy, concede_pct, max_requotes).
    policy: ProviderPolicy


# ----------------------------------------------------------------------------
# BYO-brain hook for the accept/reject/requote decision. Sync OR async
# (awaitable). Verification is NOT part of the hook — it always runs before
# the decider. Mirrors TS ``CounterDecider`` (ProviderOrchestrator.ts:137-139).
#
# Contract: a 'requote'.amount_base_units MUST be a valid quote amount (>= the
# provider floor), else the QuoteBuilder rejects it deep in the re-quote path.
# ----------------------------------------------------------------------------
CounterDecider = Callable[
    ["CounterContext"],
    Union["CounterDecision", Awaitable["CounterDecision"]],
]


# ============================================================================
# Engine constants / helpers (mirror ProviderPolicy.ts:136-164)
# ============================================================================

#: Base units per $1 for supported currencies. USDC = 1e6 (6 decimals).
BASE_UNITS_PER_USD: Dict[str, int] = {"USDC": 1_000_000}
#: Platform minimum in base units — $0.05 × 1e6 for USDC.
PLATFORM_MIN_BASE_UNITS: Dict[str, int] = {"USDC": 50_000}
DEFAULT_MIN_DEADLINE_SECONDS = 60


def _to_base_units(amount: float, currency: str) -> int:
    """Convert a human amount (e.g. 5, 10.5) to base units (int).

    Mirror of TS ``toBaseUnits`` (ProviderPolicy.ts:146-154): string→Int
    scaling to avoid float drift on amounts that don't fit cleanly in
    double precision (e.g. 0.1).
    """
    per_usd = BASE_UNITS_PER_USD.get(currency.upper())
    if not per_usd:
        raise ValueError(f"Unsupported currency: {currency}")
    whole, _, frac = str(amount).partition(".")
    # len(str(per_usd)) - 1 == number of decimal digits (6 for USDC).
    frac_padded = (frac + "000000")[: len(str(per_usd)) - 1]
    return int(whole) * per_usd + int(frac_padded or "0")


def _format_from_base_units(base_units: int, currency: str) -> str:
    """Format base units back to a human string for error messages.

    Mirror of TS ``formatFromBaseUnits`` (ProviderPolicy.ts:157-164).
    """
    per_usd = BASE_UNITS_PER_USD.get(currency.upper())
    if not per_usd:
        return f"{base_units} base units"
    whole = base_units // per_usd
    frac = base_units % per_usd
    frac_str = str(frac).rjust(len(str(per_usd)) - 1, "0").rstrip("0")
    return f"${whole}.{frac_str}" if frac_str else f"${whole}"


def parse_ttl(ttl: str) -> int:
    """Parse a short duration string like "15m", "1h", "30s" into seconds.

    Mirror of TS ``parseTtl`` (ProviderPolicy.ts:389-399).
    """
    match = re.match(r"^(\d+)\s*([smh])$", ttl.strip(), re.IGNORECASE)
    if not match:
        raise ValueError(f'Invalid TTL format: "{ttl}" (expected e.g. "15m", "1h", "30s")')
    n = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "s":
        return n
    if unit == "m":
        return n * 60
    return n * 3600


# ============================================================================
# Engine (mirror ProviderPolicy.ts:166-382)
# ============================================================================


class ProviderPolicyEngine:
    """Enforce :class:`ProviderPolicy` invariants on incoming requests + counters.

    Byte/semantically identical to TS ``ProviderPolicyEngine``.
    """

    def __init__(
        self,
        policy: ProviderPolicy,
        counter_decider: Optional[CounterDecider] = None,
    ) -> None:
        currency = policy.pricing.min_acceptable.currency
        platform_min = PLATFORM_MIN_BASE_UNITS.get(currency.upper())
        if not platform_min:
            raise ValueError(f"Unsupported currency in policy: {currency}")

        # Enforce pricing invariants at construction — fail fast.
        floor_bu = _to_base_units(policy.pricing.min_acceptable.amount, currency)
        ideal_bu = _to_base_units(policy.pricing.ideal_price.amount, currency)

        if floor_bu < platform_min:
            raise ValueError(
                f"min_acceptable.amount ({_format_from_base_units(floor_bu, currency)}) "
                f"below platform minimum ({_format_from_base_units(platform_min, currency)})"
            )
        if ideal_bu < floor_bu:
            raise ValueError(
                f"ideal_price.amount ({_format_from_base_units(ideal_bu, currency)}) "
                f"must be >= min_acceptable.amount ({_format_from_base_units(floor_bu, currency)})"
            )
        if policy.pricing.min_acceptable.currency != policy.pricing.ideal_price.currency:
            raise ValueError("min_acceptable.currency must equal ideal_price.currency")
        if policy.pricing.min_acceptable.unit != policy.pricing.ideal_price.unit:
            raise ValueError("min_acceptable.unit must equal ideal_price.unit")

        self._policy = policy
        self._floor_base_units = floor_bu
        self._ideal_base_units = ideal_bu
        self._currency = currency
        # BYO-brain: optional injectable counter decider. When None, the
        # built-in evaluate_counter math is used (zero behavior change).
        # Mirrors TS ProviderOrchestrator's ``counterDecider`` field
        # (ProviderOrchestrator.ts:87,169,187).
        self._counter_decider: Optional[CounterDecider] = counter_decider

    def evaluate(self, req: IncomingRequest) -> ProviderPolicyResult:
        """Evaluate an incoming request against policy.

        Returns ``allowed=True`` with ``recommended_quote_amount_base_units``
        when we should quote, or ``allowed=False`` with the specific rule(s)
        violated. Mirror of TS ``evaluate`` (ProviderPolicy.ts:216-284).
        """
        violations: List[ProviderPolicyViolation] = []

        if req.service_type not in self._policy.services:
            violations.append(
                ProviderPolicyViolation(
                    rule="service_not_offered",
                    detail=(
                        f'We don\'t offer service "{req.service_type}". '
                        f"Configured: {', '.join(self._policy.services)}"
                    ),
                )
            )

        if req.currency.upper() != self._currency.upper():
            violations.append(
                ProviderPolicyViolation(
                    rule="currency_mismatch",
                    detail=f"Request in {req.currency}, we quote in {self._currency}",
                )
            )

        if req.unit != self._policy.pricing.min_acceptable.unit:
            violations.append(
                ProviderPolicyViolation(
                    rule="unit_mismatch",
                    detail=(
                        f'Request unit "{req.unit}" does not match policy unit '
                        f'"{self._policy.pricing.min_acceptable.unit}"'
                    ),
                )
            )

        try:
            max_price_bu = int(req.max_price)
        except (ValueError, TypeError):
            violations.append(
                ProviderPolicyViolation(
                    rule="max_price_below_floor",
                    detail=f"Invalid maxPrice: {req.max_price}",
                )
            )
            max_price_bu = 0
        if max_price_bu < self._floor_base_units:
            violations.append(
                ProviderPolicyViolation(
                    rule="max_price_below_floor",
                    detail=(
                        f"Buyer maxPrice {_format_from_base_units(max_price_bu, self._currency)} "
                        f"below our floor {_format_from_base_units(self._floor_base_units, self._currency)}"
                    ),
                )
            )

        now = int(time.time())
        min_deadline_seconds = (
            self._policy.min_deadline_seconds
            if self._policy.min_deadline_seconds is not None
            else DEFAULT_MIN_DEADLINE_SECONDS
        )
        if req.deadline - now < min_deadline_seconds:
            violations.append(
                ProviderPolicyViolation(
                    rule="deadline_too_tight",
                    detail=(
                        f"tx.deadline - now = {req.deadline - now}s, "
                        f"need >= {min_deadline_seconds}s"
                    ),
                )
            )

        if violations:
            return ProviderPolicyResult(allowed=False, violations=violations)

        # Recommended quote: ideal unless buyer can't afford it, in which case
        # quote at maxPrice (still above floor — validated above).
        ceiling_bu = (
            max_price_bu if max_price_bu < self._ideal_base_units else self._ideal_base_units
        )
        recommended_bu = (
            ceiling_bu if ceiling_bu > self._floor_base_units else self._floor_base_units
        )

        return ProviderPolicyResult(
            allowed=True,
            violations=[],
            recommended_quote_amount_base_units=str(recommended_bu),
        )

    def evaluate_counter(
        self,
        counter_amount_base_units: str,
        last_quote_amount_base_units: str,
        requotes_used: int,
    ) -> CounterEvaluation:
        """Decide what to do with a buyer's counter-offer (3.5.0 multi-round).

          accept  — counter ≥ floor: take the deal
          requote — counter < floor AND counter_strategy == 'concede' AND
                    requotes_used < max_requotes: send a new quote at the
                    concession price (between last quote and floor)
          reject  — anything else (walk strategy, or requote budget spent)

        Mirror of TS ``evaluateCounter`` (ProviderPolicy.ts:306-366). All
        arithmetic uses Python int (arbitrary precision) on base units — no
        float drift.
        """
        try:
            counter = int(counter_amount_base_units)
        except (ValueError, TypeError):
            return CounterEvaluation(
                decision="reject",
                reason=f"Invalid counter amount: {counter_amount_base_units}",
            )
        if counter >= self._floor_base_units:
            return CounterEvaluation(
                decision="accept",
                reason=f"Counter {_format_from_base_units(counter, self._currency)} meets our floor",
            )

        # Below floor — consider concession.
        strategy = self._policy.counter_strategy or "walk"
        if strategy == "walk":
            return CounterEvaluation(
                decision="reject",
                reason=(
                    f"Counter {_format_from_base_units(counter, self._currency)} "
                    f"below floor; counter_strategy=walk"
                ),
            )
        max_requotes = self._policy.max_requotes if self._policy.max_requotes is not None else 2
        if requotes_used >= max_requotes:
            return CounterEvaluation(
                decision="reject",
                reason=(
                    f"Counter below floor and requote budget exhausted "
                    f"({requotes_used}/{max_requotes})"
                ),
            )

        # Concede: new quote = last - (last - floor) * pct / 100.
        try:
            last_quote = int(last_quote_amount_base_units)
        except (ValueError, TypeError):
            return CounterEvaluation(
                decision="reject",
                reason=f"Invalid lastQuoteAmount: {last_quote_amount_base_units}",
            )
        if last_quote <= self._floor_base_units:
            return CounterEvaluation(
                decision="reject",
                reason=(
                    f"Cannot concede: last quote "
                    f"{_format_from_base_units(last_quote, self._currency)} already at/below floor"
                ),
            )
        pct = self._policy.concede_pct if self._policy.concede_pct is not None else 30
        safe_pct = 1 if pct < 1 else (99 if pct > 99 else pct)
        gap = last_quote - self._floor_base_units
        concession = (gap * safe_pct) // 100
        new_quote = last_quote - concession
        # Defensive: never go below floor regardless of math.
        if new_quote < self._floor_base_units:
            new_quote = self._floor_base_units
        return CounterEvaluation(
            decision="requote",
            amount_base_units=str(new_quote),
            reason=(
                f"Conceding {safe_pct}% from "
                f"{_format_from_base_units(last_quote, self._currency)} toward floor "
                f"→ {_format_from_base_units(new_quote, self._currency)} "
                f"(round {requotes_used + 1}/{max_requotes})"
            ),
        )

    async def decide_counter(
        self,
        counter: "CounterOfferMessage",
        last_quote_amount_base_units: Optional[str] = None,
        requotes_used: int = 0,
    ) -> CounterDecision:
        """Consult the installed counter decider (BYO-brain hook).

        Mirrors TS ``ProviderOrchestrator.evaluateCounter``
        (ProviderOrchestrator.ts:338-362) MINUS the signature/band/expiry
        verification, which the caller (the orchestrator / serve loop) MUST
        run BEFORE calling this — verification is intentionally NOT part of
        the hook (TS comment ProviderOrchestrator.ts:346-347: "a custom
        decider replaces ONLY the decision (verify above still ran)").

        When no custom ``counter_decider`` was injected at construction, this
        delegates verbatim to :meth:`evaluate_counter` and maps the
        :class:`CounterEvaluation` verdict to a :class:`CounterDecision` —
        zero behavior change. When a custom decider was injected (e.g. an LLM
        brain), it is invoked instead; the result is awaited if it is a
        coroutine (async-tolerant, matching the TS
        ``| Promise<CounterDecision>`` contract).

        ``last_quote_amount_base_units`` — provider's most recent quote
        amount for this tx. On the first counter pass ``counter.quoteAmount``
        (matches TS ``lastQuoteAmountBaseUnits ?? counter.quoteAmount``).
        """
        last_amount = (
            last_quote_amount_base_units
            if last_quote_amount_base_units is not None
            else counter.quoteAmount
        )

        # BYO-brain: a custom decider replaces ONLY the decision (the caller's
        # verification still ran). When absent, the built-in policy engine
        # runs verbatim.
        if self._counter_decider is not None:
            result = self._counter_decider(
                CounterContext(
                    counter=counter,
                    last_quote_amount_base_units=last_amount,
                    requotes_used=requotes_used,
                    policy=self._policy,
                )
            )
            if inspect.isawaitable(result):
                return await result
            return result

        verdict = self.evaluate_counter(
            counter.counterAmount, last_amount, requotes_used
        )
        if verdict.decision == "requote":
            return CounterDecision(
                action="requote",
                amount_base_units=verdict.amount_base_units,
                reason=verdict.reason,
            )
        return CounterDecision(action=verdict.decision, reason=verdict.reason)

    @property
    def quote_ttl_seconds(self) -> int:
        """Expose ttl as seconds for callers building QuoteMessage.expiresAt."""
        return parse_ttl(self._policy.quote_ttl)

    @property
    def policy_currency(self) -> str:
        """Expose the policy's currency for orchestrator wiring."""
        return self._currency

    @property
    def policy_unit(self) -> str:
        """Expose the policy's unit for orchestrator wiring + UI."""
        return self._policy.pricing.min_acceptable.unit


__all__ = [
    "PriceTerm",
    "ProviderPricing",
    "ProviderPolicy",
    "ProviderPolicyViolation",
    "ProviderPolicyViolationRule",
    "ProviderPolicyResult",
    "IncomingRequest",
    "CounterEvaluation",
    "CounterDecisionAction",
    "CounterDecision",
    "CounterContext",
    "CounterDecider",
    "ProviderPolicyEngine",
    "BASE_UNITS_PER_USD",
    "PLATFORM_MIN_BASE_UNITS",
    "DEFAULT_MIN_DEADLINE_SECONDS",
    "parse_ttl",
]
