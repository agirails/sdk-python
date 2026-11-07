# PARITY: sdk-js/src/reputation/ (DisputeSplitIndexer.ts)
"""
Reputation surfacing utilities (PRD P2-8).

Exposes the :class:`DisputeSplitIndexer` — per-agent dispute split-rate
aggregation (AIP-14b §3.4/§3.5, OQ-11, INV-22). See
``dispute_split_indexer.py`` for the ZERO-REMAINING CONSUMER RULE and the
OQ-11 identical-weight semantics.
"""

from agirails.reputation.dispute_split_indexer import (
    DisputeOutcome,
    DisputeOutcomeKind,
    DisputeSplitIndexer,
    SplitRateBreakdown,
    SplitRateResult,
    is_split_kind,
    outcome_from_split_recorded,
)

__all__ = [
    "DisputeOutcome",
    "DisputeOutcomeKind",
    "DisputeSplitIndexer",
    "SplitRateBreakdown",
    "SplitRateResult",
    "is_split_kind",
    "outcome_from_split_recorded",
]
