# PARITY: sdk-js/src/reputation/DisputeSplitIndexer.ts
# Every public symbol here has a TS twin (same name/arity) and vice-versa.
"""
DisputeSplitIndexer — per-agent dispute split-rate surfacing (PRD P2-8,
AIP-14b §3.4 / §3.5, INV-22, INV-4).

What it does
------------
Surfaces the per-agent **split rate** — the fraction of an agent's resolved
disputes that ended in a SPLIT — so systematic dispute-to-split ambiguity
griefing is visible to future counterparties (e.g. *"14% of this agent's
disputes end in splits"*). A split carries NO on-chain reputation penalty
(INV-4); the rate is the ONLY signal, which is why under-counting it would
silently re-open the griefing path.

OQ-11 (normative default — PRD §9, P2-8)
----------------------------------------
A dispute counts as a SPLIT for the HEADLINE rate when it resolved via EITHER:
    1. ``DisputeSplitRecorded`` — CompositeMediator ruling-2 (finalize /
       force_resolve_stale / UMA no-winner fallback), OR
    2. kernel ``DISPUTED → CANCELLED`` — the kernel-level split path, which
       includes **admin-CANCELLED** disputes that bypass CompositeMediator.
BOTH are counted at **IDENTICAL weight**. Counting only (1) would miss
admin-CANCELLED splits and undercount the rate (R11). The headline
``get_split_rate`` treats them as fungible; ``get_split_rate_breakdown`` exposes
the two sub-counts WITHOUT changing the headline number.

ZERO-REMAINING CONSUMER RULE (AIP-14b §6, normative — load-bearing)
-------------------------------------------------------------------
Split classification derives from **event semantics + escrow ``remaining``**,
NEVER from resolution-proof amounts. When on-chain ``remaining == 0`` the proof
carries only a phantom 1-wei sentinel; this indexer NEVER reads it as a payout.
A drained dispute (remaining==0) still counts as a split. ``classify_payout``
delegates to :func:`decode_resolution_proof`, which zeros the phantom sentinel.

PARITY: sdk-js/src/reputation/DisputeSplitIndexer.ts — the shared golden fixture
``DISPUTE SYSTEM/test-vectors/dispute-split-indexer-vectors.json`` is consumed
byte-identically by both SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from agirails.dispute.composite_mediator import (
    DecodedResolutionProof,
    DisputeSplitRecorded,
    compute_split_rate,
    decode_resolution_proof,
)

# ---------------------------------------------------------------------------
# Outcome model
# ---------------------------------------------------------------------------

# How a dispute resolved, for split-rate accounting (string literals identical
# to TS ``DisputeOutcomeKind``). Both split kinds are counted at identical weight
# (OQ-11); ``settled`` is a non-split resolution (kernel DISPUTED->SETTLED).
DisputeOutcomeKind = str  # "disputeSplitRecorded" | "kernelDisputedToCancelled" | "settled"

# The two split sources are fungible for the headline rate.
_SPLIT_KINDS = frozenset({"disputeSplitRecorded", "kernelDisputedToCancelled"})


def is_split_kind(kind: str) -> bool:
    """Return True for both split kinds (OQ-11: identical weight).

    PARITY: TS ``isSplitKind``.
    """
    return kind in _SPLIT_KINDS


@dataclass
class DisputeOutcome:
    """
    One resolved dispute, normalized for split-rate accounting.

    Assembled from ``DisputeSplitRecorded`` events + kernel
    ``StateTransitioned(DISPUTED->CANCELLED / DISPUTED->SETTLED)`` events, joined
    with the kernel transaction's ``provider``/``requester``. ``remaining`` is
    the on-chain escrow ``remaining`` at resolution time and is the ONLY thing
    (with ``kind``) that drives classification — proof amounts are never trusted
    (ZERO-REMAINING RULE).

    PARITY: TS ``DisputeOutcome`` interface.
    """

    provider: str
    requester: str
    kind: DisputeOutcomeKind
    remaining: int = 0
    split_bps: Optional[int] = None
    proof: Optional[str] = None
    tx_id: Optional[str] = None


@dataclass
class SplitRateResult:
    """Per-agent split-rate result. PARITY: TS ``SplitRateResult``."""

    agent_id: str
    split_count: int
    total_disputes: int
    split_rate: float


@dataclass
class SplitRateBreakdown(SplitRateResult):
    """
    Split-rate result WITH the OQ-11 source breakdown. The headline ``split_rate``
    is unchanged (both sources at identical weight); the sub-counts are diagnostic.

    PARITY: TS ``SplitRateBreakdown``.
    """

    mediator_split_count: int = 0
    admin_split_count: int = 0


# ---------------------------------------------------------------------------
# Address helper
# ---------------------------------------------------------------------------


def _same_address(a: str, b: str) -> bool:
    """Case-insensitive address equality (checksum-agnostic)."""
    return a.lower() == b.lower()


# ---------------------------------------------------------------------------
# Indexer
# ---------------------------------------------------------------------------


class DisputeSplitIndexer:
    """
    Aggregates :class:`DisputeOutcome` records into per-agent split rates.

    The indexer is a PURE accumulator over already-decoded outcomes — it does NOT
    hold a provider/signer. Callers feed it outcomes assembled from
    ``EventMonitor.get_dispute_events()`` (which already surfaces
    ``DisputeSplitRecorded`` AND kernel ``DISPUTED->CANCELLED``) joined with
    kernel transaction lookups. This keeps it deterministic + trivially testable
    against the shared golden fixture, and keeps the ZERO-REMAINING rule enforced
    in one place.

    PARITY: TS ``DisputeSplitIndexer``.
    """

    def __init__(self, outcomes: Optional[List[DisputeOutcome]] = None) -> None:
        """
        Args:
            outcomes: optional initial outcomes to seed the indexer.
        """
        self._outcomes: List[DisputeOutcome] = []
        if outcomes:
            self.add_outcomes(outcomes)

    def add_outcome(self, outcome: DisputeOutcome) -> None:
        """Record a single resolved dispute. PARITY: TS ``addOutcome``."""
        self._outcomes.append(outcome)

    def add_outcomes(self, outcomes: List[DisputeOutcome]) -> None:
        """Record many resolved disputes. PARITY: TS ``addOutcomes``."""
        for o in outcomes:
            self.add_outcome(o)

    def get_outcomes(self) -> List[DisputeOutcome]:
        """All recorded outcomes (defensive copy). PARITY: TS ``getOutcomes``."""
        return list(self._outcomes)

    def size(self) -> int:
        """Number of recorded outcomes. PARITY: TS ``size``."""
        return len(self._outcomes)

    def clear(self) -> None:
        """Clear all recorded outcomes. PARITY: TS ``clear``."""
        self._outcomes.clear()

    def get_split_rate(self, agent_id: str) -> SplitRateResult:
        """
        The HEADLINE split rate for an agent (OQ-11 default).

        Counts BOTH ``disputeSplitRecorded`` AND ``kernelDisputedToCancelled``
        (incl. admin-CANCELLED) at IDENTICAL weight over the agent's total
        disputes. A drained dispute (remaining==0) still counts as a split.
        PARITY: TS ``getSplitRate``.

        Args:
            agent_id: the provider address whose rate to compute.
        """
        mine = [o for o in self._outcomes if _same_address(o.provider, agent_id)]
        split_recorded = sum(1 for o in mine if o.kind == "disputeSplitRecorded")
        kernel_disputed_to_cancelled = sum(
            1 for o in mine if o.kind == "kernelDisputedToCancelled"
        )
        total_disputes = len(mine)

        # Reuse the P2-5 primitive so the headline arithmetic is identical to the
        # CompositeMediator client's compute_split_rate (OQ-11: equal weight).
        split_rate = compute_split_rate(
            split_recorded,
            kernel_disputed_to_cancelled,
            total_disputes,
        )

        return SplitRateResult(
            agent_id=agent_id,
            split_count=split_recorded + kernel_disputed_to_cancelled,
            total_disputes=total_disputes,
            split_rate=split_rate,
        )

    def get_split_rate_breakdown(self, agent_id: str) -> SplitRateBreakdown:
        """
        The split rate WITH the OQ-11 source breakdown. The headline ``split_rate``
        is identical to :meth:`get_split_rate` (both sources at equal weight); the
        sub-counts (``mediator_split_count``, ``admin_split_count``) are diagnostic
        only. PARITY: TS ``getSplitRateBreakdown``.
        """
        base = self.get_split_rate(agent_id)
        mine = [o for o in self._outcomes if _same_address(o.provider, agent_id)]
        return SplitRateBreakdown(
            agent_id=base.agent_id,
            split_count=base.split_count,
            total_disputes=base.total_disputes,
            split_rate=base.split_rate,
            mediator_split_count=sum(
                1 for o in mine if o.kind == "disputeSplitRecorded"
            ),
            admin_split_count=sum(
                1 for o in mine if o.kind == "kernelDisputedToCancelled"
            ),
        )

    def classify_payout(
        self, outcome: DisputeOutcome
    ) -> Optional[DecodedResolutionProof]:
        """
        Classify the ECONOMIC payout of one outcome under the ZERO-REMAINING
        CONSUMER RULE (AIP-14b §6). Delegates to the P2-5
        :func:`decode_resolution_proof`, which ZEROS both payouts and flags
        ``phantom_sentinel`` when ``remaining == 0``.

        Used by the drained-dispute test to assert that NO 1-wei payout is ever
        surfaced. Returns ``None`` when the outcome carried no proof (split
        counting does not need it). PARITY: TS ``classifyPayout``.
        """
        if outcome.proof is None:
            return None
        return decode_resolution_proof(outcome.proof, outcome.remaining or 0)


def outcome_from_split_recorded(
    event: DisputeSplitRecorded,
    remaining: int = 0,
    proof: Optional[str] = None,
) -> DisputeOutcome:
    """
    Build a :class:`DisputeOutcome` from a decoded ``DisputeSplitRecorded`` event.
    The ``remaining`` MUST be supplied separately (read from the escrow at
    resolution time) — it is NOT in the event. PARITY: TS
    ``outcomeFromSplitRecorded``.
    """
    return DisputeOutcome(
        provider=event.provider,
        requester=event.requester,
        kind="disputeSplitRecorded",
        remaining=remaining,
        split_bps=event.split_bps,
        proof=proof,
        tx_id=event.tx_id,
    )


__all__ = [
    # Outcome model
    "DisputeOutcomeKind",
    "DisputeOutcome",
    "SplitRateResult",
    "SplitRateBreakdown",
    "is_split_kind",
    # Indexer
    "DisputeSplitIndexer",
    "outcome_from_split_recorded",
]
