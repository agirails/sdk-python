"""
Negotiation Module -- Autonomous buyer-side negotiation engine.

Components:
- PolicyEngine: Hard guardrails (budget, reputation, expiry)
- DecisionEngine: Weighted scoring for candidate ranking
- SessionStore: Commerce session tracking and traceability

Example:
    ```python
    from agirails.negotiation import (
        PolicyEngine,
        BuyerPolicy,
        Constraints,
        MaxUnitPrice,
        MaxDailySpend,
        Negotiation,
        Selection,
        QuoteOffer,
        DecisionEngine,
        SessionStore,
    )

    # Define policy
    policy = BuyerPolicy(
        task="Summarize document",
        constraints=Constraints(
            max_unit_price=MaxUnitPrice(amount=0.10, currency="USDC", unit="request"),
            max_daily_spend=MaxDailySpend(amount=5.0, currency="USDC"),
        ),
        negotiation=Negotiation(rounds_max=3, quote_ttl="15m"),
        selection=Selection(prioritize=["quality", "price"]),
    )

    # Validate a quote
    engine = PolicyEngine(policy)
    result = engine.validate(QuoteOffer(
        provider="summarizer-agent",
        unit_price=0.08,
        currency="USDC",
        unit="request",
        commerce_session_id="abc-123",
    ))
    assert result.allowed
    ```
"""
from __future__ import annotations

# ============================================================================
# PolicyEngine
# ============================================================================

from agirails.negotiation.policy_engine import (
    BudgetEntry,
    BudgetLedgerFile,
    BuyerPolicy,
    Constraints,
    MaxDailySpend,
    MaxUnitPrice,
    Negotiation,
    PolicyEngine,
    PolicyResult,
    PolicyViolation,
    QuoteOffer,
    Selection,
)

# ============================================================================
# DecisionEngine
# ============================================================================

from agirails.negotiation.decision_engine import (
    CandidateStats,
    DEFAULT_WEIGHTS,
    DecisionEngine,
    ScoreBreakdown,
    ScoredCandidate,
    ScoringWeights,
)

# ============================================================================
# SessionStore
# ============================================================================

from agirails.negotiation.session_store import (
    SessionMapping,
    SessionsFile,
    SessionStore,
)

# ============================================================================
# BuyerOrchestrator
# ============================================================================

from agirails.negotiation.buyer_orchestrator import (
    BuyerOrchestrator,
    CompleteEvent,
    DiscoveryEvent,
    NegotiationResult,
    OrchestratorConfig,
    ProgressEvent,
    QuoteReceivedEvent,
    RoundEndEvent,
    RoundResult,
    RoundStartEvent,
    ScoringEvent,
    WaitingQuoteEvent,
)

__all__ = [
    # PolicyEngine
    "PolicyEngine",
    "BuyerPolicy",
    "Constraints",
    "MaxUnitPrice",
    "MaxDailySpend",
    "Negotiation",
    "Selection",
    "QuoteOffer",
    "PolicyViolation",
    "PolicyResult",
    "BudgetEntry",
    "BudgetLedgerFile",
    # DecisionEngine
    "DecisionEngine",
    "ScoringWeights",
    "CandidateStats",
    "ScoredCandidate",
    "ScoreBreakdown",
    "DEFAULT_WEIGHTS",
    # SessionStore
    "SessionStore",
    "SessionMapping",
    "SessionsFile",
    # BuyerOrchestrator
    "BuyerOrchestrator",
    "NegotiationResult",
    "RoundResult",
    "OrchestratorConfig",
    "ProgressEvent",
    "DiscoveryEvent",
    "ScoringEvent",
    "RoundStartEvent",
    "WaitingQuoteEvent",
    "QuoteReceivedEvent",
    "RoundEndEvent",
    "CompleteEvent",
]
