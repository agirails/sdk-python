"""
Minimal AIP-2.1 counter-offer policy engine.

Given a verified :class:`CounterOfferMessage` and a :class:`ProviderPolicy`,
decide one of:

  - ``ACCEPT``  — counter is at or above ideal; provider signs a
    :class:`CounterAcceptMessage` for ``counterAmount`` and replies.
  - ``COUNTER`` — counter is between floor and ideal; provider counters
    again at a price between the previous quote and the floor, governed
    by the policy's concede strategy.
  - ``REJECT``  — counter is below the floor, or the provider's strategy
    is 'walk' for an in-band counter.

This is a deliberately small surface — the v1 ``actp serve`` daemon
runs the verdict and logs it, but does NOT auto-send replies back to
the buyer. The operator handles delivery (see AIP-2.1-DRAFT §5.3).

@module server/policy_engine
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agirails.builders.counter_offer import CounterOfferMessage
from agirails.server.policy import ProviderPolicy


class VerdictAction(str, Enum):
    ACCEPT = "ACCEPT"
    COUNTER = "COUNTER"
    REJECT = "REJECT"


@dataclass(frozen=True)
class Verdict:
    """Policy verdict for an inbound counter-offer.

    Attributes:
        action: One of ``ACCEPT``, ``COUNTER``, ``REJECT``.
        reason: Human-readable explanation; logged by the daemon.
        recommended_amount: When ``action == COUNTER``, the amount the
            provider should requote in USDC base units. ``None`` for
            ACCEPT (use counter.counterAmount) and REJECT.
    """

    action: VerdictAction
    reason: str
    recommended_amount: Optional[int] = None


def evaluate_counter(
    message: CounterOfferMessage,
    policy: ProviderPolicy,
    last_quote_amount: Optional[int] = None,
) -> Verdict:
    """Evaluate a buyer counter-offer against the provider policy.

    Args:
        message: The verified counter-offer (caller must have already
            run :meth:`CounterOfferBuilder.verify`).
        policy: Provider policy.
        last_quote_amount: Provider's most recent quote for this tx
            (USDC base units). Used by the concede strategy to compute
            the next counter. When omitted, falls back to ``policy.pricing.ideal_amount``.

    Returns:
        :class:`Verdict` with action + reason + optional recommended_amount.
    """
    counter = int(message.counterAmount)
    floor = policy.pricing.min_acceptable_amount
    ideal = policy.pricing.ideal_amount

    # Below the absolute floor — never engage.
    if counter < floor:
        return Verdict(
            action=VerdictAction.REJECT,
            reason=(
                f"counter ({counter}) below provider floor ({floor})"
            ),
        )

    # At or above ideal — accept.
    if counter >= ideal:
        return Verdict(
            action=VerdictAction.ACCEPT,
            reason=f"counter ({counter}) >= ideal ({ideal})",
            recommended_amount=counter,
        )

    # Strictly between floor and ideal — strategy decides.
    if policy.counter_strategy == "walk":
        return Verdict(
            action=VerdictAction.REJECT,
            reason=(
                f"counter ({counter}) in negotiation band [{floor}, "
                f"{ideal}) but strategy='walk' — provider declines"
            ),
        )

    # 'concede' — recommend a price between last_quote and floor by concede_pct.
    last = last_quote_amount if last_quote_amount is not None else ideal
    # next = last - (last - floor) * concede_pct / 100
    next_amount = last - (last - floor) * policy.concede_pct // 100
    # Don't undercut our own floor or our own previous quote in the wrong direction.
    next_amount = max(next_amount, floor)
    next_amount = min(next_amount, last)
    # If our concession lands at or below the buyer's counter, accept instead.
    if next_amount <= counter:
        return Verdict(
            action=VerdictAction.ACCEPT,
            reason=(
                f"concede would land at {next_amount} which is at or below "
                f"counter ({counter}) — accepting"
            ),
            recommended_amount=counter,
        )
    return Verdict(
        action=VerdictAction.COUNTER,
        reason=(
            f"concede from {last} toward floor {floor} → {next_amount}"
        ),
        recommended_amount=next_amount,
    )


__all__ = [
    "Verdict",
    "VerdictAction",
    "evaluate_counter",
]
