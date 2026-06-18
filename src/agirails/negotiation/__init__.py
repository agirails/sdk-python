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
        negotiation=Negotiation(rounds_max=10, quote_ttl="15m"),
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
    BuyerQuoteDecider,
    CandidateStats,
    DEFAULT_WEIGHTS,
    DecisionEngine,
    QuoteEvaluation,
    QuoteForEvaluation,
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
    RequoteGuardViolation,
    RoundEndEvent,
    RoundResult,
    RoundStartEvent,
    ScoringEvent,
    WaitingQuoteEvent,
)

# ============================================================================
# ProviderPolicy (AIP-2.1, TS parity) — provider-side pricing/counter policy.
# NOTE: provider_policy.ProviderPolicy (human-amount shape) is namespaced here
# to avoid colliding with server.policy.ProviderPolicy (base-unit v1).
# ============================================================================

from agirails.negotiation.provider_policy import (
    CounterContext,
    CounterDecider,
    CounterDecision,
    CounterEvaluation,
    IncomingRequest,
    PriceTerm,
    ProviderPolicy,
    ProviderPolicyEngine,
    ProviderPolicyResult,
    ProviderPolicyViolation,
    ProviderPricing,
    parse_ttl as provider_parse_ttl,
)

# ============================================================================
# On-chain quote-hash verification (AIP-2.1 anchoring cross-check)
# ============================================================================

from agirails.negotiation.verify_quote_on_chain import (
    VerifyOnChainResult,
    VerifySource,
    verify_quote_hash_on_chain,
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
    "RequoteGuardViolation",
    # ProviderPolicy (AIP-2.1, TS parity)
    "ProviderPolicyEngine",
    "ProviderPolicyViolation",
    "ProviderPolicyResult",
    "IncomingRequest",
    "CounterEvaluation",
    "PriceTerm",
    "ProviderPricing",
    # On-chain quote-hash verification
    "verify_quote_hash_on_chain",
    "VerifyOnChainResult",
    "VerifySource",
    # Injectable decider hooks (BYO-brain)
    "BuyerQuoteDecider",
    "QuoteForEvaluation",
    "QuoteEvaluation",
    "CounterDecider",
    "CounterContext",
    "CounterDecision",
]
