"""
BuyerOrchestrator -- Autonomous buyer-side negotiation orchestrator.

Flow:
  1. Discover candidates (via agirails.app API)
  2. Score with DecisionEngine (weighted ranking)
  3. Validate with PolicyEngine (5 guardrails)
  4. For each candidate (up to rounds_max):
     a. createTransaction -> INITIATED
     b. Poll for QUOTED state (within quote_ttl)
     c. Validate quote against policy
     d. Accept -> linkEscrow -> COMMITTED
     e. OR reject -> try next candidate
  5. Track everything via SessionStore

Accepts IACTPRuntime for on-chain operations. Caller manages lifecycle.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Union

from agirails.api.discover import DiscoverAgent, DiscoverParams, discover_agents
from agirails.negotiation.decision_engine import CandidateStats, DecisionEngine, ScoringWeights
from agirails.negotiation.policy_engine import BuyerPolicy, PolicyEngine, QuoteOffer
from agirails.negotiation.session_store import SessionStore
from agirails.runtime.base import CreateTransactionParams, IACTPRuntime

# ============================================================================
# Types
# ============================================================================


@dataclass
class RoundResult:
    """Per-round details for traceability."""

    round: int
    provider_slug: str
    provider_address: str
    action: Literal["accepted", "rejected", "timeout", "error"]
    reason: str
    tx_id: Optional[str] = None
    quoted_price: Optional[float] = None
    """Actual quoted price from on-chain (USDC float), if quote was received."""


@dataclass
class NegotiationResult:
    """Result of a full negotiation flow."""

    success: bool
    commerce_session_id: str
    rounds_used: int
    reason: str
    """Why negotiation ended (settled, exhausted, budget_exceeded, etc.)"""
    rounds: List[RoundResult] = field(default_factory=list)
    actp_tx_id: Optional[str] = None
    selected_provider: Optional[str] = None
    deadlock_detected: bool = False
    """True if repeated identical prices were detected across rounds (price deadlock)."""


@dataclass
class DiscoveryEvent:
    type: Literal["discovery"] = "discovery"
    candidates: int = 0


@dataclass
class ScoringEvent:
    type: Literal["scoring"] = "scoring"
    ranked: int = 0


@dataclass
class RoundStartEvent:
    type: Literal["round_start"] = "round_start"
    round: int = 0
    provider: str = ""


@dataclass
class WaitingQuoteEvent:
    type: Literal["waiting_quote"] = "waiting_quote"
    tx_id: str = ""
    ttl_seconds: int = 0


@dataclass
class QuoteReceivedEvent:
    type: Literal["quote_received"] = "quote_received"
    tx_id: str = ""


@dataclass
class RoundEndEvent:
    type: Literal["round_end"] = "round_end"
    round: int = 0
    action: str = ""
    reason: str = ""


@dataclass
class CompleteEvent:
    type: Literal["complete"] = "complete"
    success: bool = False
    reason: str = ""


ProgressEvent = Union[
    DiscoveryEvent,
    ScoringEvent,
    RoundStartEvent,
    WaitingQuoteEvent,
    QuoteReceivedEvent,
    RoundEndEvent,
    CompleteEvent,
]


@dataclass
class OrchestratorConfig:
    """Configuration for the negotiation orchestrator."""

    discover: Optional[DiscoverParams] = None
    """Override discover params (search, capability, etc.)."""
    poll_interval_ms: int = 3000
    """Poll interval for checking quote state (ms). Default: 3000."""
    dry_run: bool = False
    """If true, run discovery + scoring but don't create transactions."""
    on_progress: Optional[Callable[[ProgressEvent], None]] = None
    """Callback for progress events."""


# ============================================================================
# BuyerOrchestrator
# ============================================================================


class BuyerOrchestrator:
    """Autonomous buyer-side negotiation orchestrator."""

    def __init__(
        self,
        policy: BuyerPolicy,
        runtime: IACTPRuntime,
        requester_address: str,
        actp_dir: Optional[str] = None,
    ) -> None:
        self._policy = policy
        self._runtime = runtime
        self._requester_address = requester_address
        self._policy_engine = PolicyEngine(policy, actp_dir)
        # Convert dict weights to ScoringWeights if needed
        weights = policy.selection.weights
        if isinstance(weights, dict):
            weights = ScoringWeights(**{k: v for k, v in weights.items() if k in ("quality", "price", "speed", "reliability")})
        self._decision_engine = DecisionEngine(weights)
        self._session_store = SessionStore(actp_dir)

    async def negotiate(
        self, config: Optional[OrchestratorConfig] = None
    ) -> NegotiationResult:
        """Execute the full negotiation flow."""
        if config is None:
            config = OrchestratorConfig()

        poll_interval = config.poll_interval_ms
        emit = config.on_progress or (lambda _event: None)

        # Create session
        session = self._session_store.create(self._policy.task)
        rounds: List[RoundResult] = []

        try:
            return await self._negotiate(session, rounds, config, poll_interval, emit)
        except Exception:
            # Guarantee session reaches terminal status on any uncaught throw
            current_session = self._session_store.get(session.commerce_session_id)
            if current_session and current_session.status == "active":
                self._session_store.update_status(
                    session.commerce_session_id, "failed"
                )
            raise

    async def _negotiate(
        self,
        session: Any,
        rounds: List[RoundResult],
        config: OrchestratorConfig,
        poll_interval: int,
        emit: Callable[[ProgressEvent], None],
    ) -> NegotiationResult:
        # 1. Discover candidates
        discover_params = DiscoverParams(
            search=self._policy.task,
            sort="reputation",
            limit=20,
            max_price=self._policy.constraints.max_unit_price.amount,
        )

        # Merge overrides from config.discover
        if config.discover is not None:
            override = config.discover
            if override.search is not None:
                discover_params.search = override.search
            if override.capability is not None:
                discover_params.capability = override.capability
            if override.payment_mode is not None:
                discover_params.payment_mode = override.payment_mode
            if override.sort is not None:
                discover_params.sort = override.sort
            if override.limit is not None:
                discover_params.limit = override.limit
            if override.offset is not None:
                discover_params.offset = override.offset
            if override.max_price is not None:
                discover_params.max_price = override.max_price
            if override.rank is not None:
                discover_params.rank = override.rank
            if override.priority is not None:
                discover_params.priority = override.priority

        discovered = await discover_agents(discover_params)
        emit(DiscoveryEvent(candidates=len(discovered.agents)))

        if len(discovered.agents) == 0:
            emit(CompleteEvent(success=False, reason="No candidates found"))
            self._session_store.update_status(
                session.commerce_session_id, "failed"
            )
            return NegotiationResult(
                success=False,
                commerce_session_id=session.commerce_session_id,
                rounds_used=0,
                reason="No candidates found",
                rounds=rounds,
            )

        # 2. Score candidates with DecisionEngine
        candidate_stats = self._map_to_candidate_stats(discovered.agents)
        ranked = self._decision_engine.rank(
            candidate_stats,
            self._policy.constraints.max_unit_price.amount,
        )
        emit(ScoringEvent(ranked=len(ranked)))

        if len(ranked) == 0:
            emit(
                CompleteEvent(
                    success=False, reason="No candidates within budget"
                )
            )
            self._session_store.update_status(
                session.commerce_session_id, "failed"
            )
            return NegotiationResult(
                success=False,
                commerce_session_id=session.commerce_session_id,
                rounds_used=0,
                reason="No candidates within budget after scoring",
                rounds=rounds,
            )

        # Dry-run: return ranked candidates without creating transactions
        if config.dry_run:
            self._session_store.update_status(
                session.commerce_session_id, "completed"
            )
            emit(CompleteEvent(success=True, reason="Dry run complete"))
            return NegotiationResult(
                success=True,
                commerce_session_id=session.commerce_session_id,
                rounds_used=0,
                reason=f"Dry run: {len(ranked)} candidates ranked",
                rounds=[
                    RoundResult(
                        round=i + 1,
                        provider_slug=c.slug,
                        provider_address=self._find_agent_address(
                            discovered.agents, c.slug
                        ),
                        action="accepted",
                        reason=f"Score: {c.score:.3f}",
                    )
                    for i, c in enumerate(ranked)
                ],
            )

        # 3. Try candidates up to rounds_max
        max_rounds = min(self._policy.negotiation.rounds_max, len(ranked))
        quote_ttl_seconds = PolicyEngine.parse_ttl(
            self._policy.negotiation.quote_ttl
        )

        # Price tracking for deadlock detection (PRD-5B)
        price_history: List[float] = []
        deadlock_detected = False

        for round_idx in range(max_rounds):
            candidate = ranked[round_idx]
            provider_address = self._find_agent_address(
                discovered.agents, candidate.slug
            )

            emit(
                RoundStartEvent(
                    round=round_idx + 1, provider=candidate.slug
                )
            )
            self._session_store.record_attempt(
                session.commerce_session_id, candidate.slug
            )

            # 3a. Pre-validate with PolicyEngine
            offer = QuoteOffer(
                provider=candidate.slug,
                unit_price=self._find_agent_price(
                    discovered.agents, candidate.slug
                ),
                currency=self._policy.constraints.max_unit_price.currency,
                unit=self._policy.constraints.max_unit_price.unit,
                reputation_score=self._find_agent_reputation(
                    discovered.agents, candidate.slug
                ),
                commerce_session_id=session.commerce_session_id,
                expires_at=int(time.time()) + quote_ttl_seconds,
                final_offer=deadlock_detected,
            )

            validation = self._policy_engine.validate(offer)
            if not validation.allowed:
                reason = "; ".join(
                    f"{v.rule}: {v.detail}" for v in validation.violations
                )
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="rejected",
                        reason=f"Policy violation: {reason}",
                    )
                )
                emit(
                    RoundEndEvent(
                        round=round_idx + 1,
                        action="rejected",
                        reason=reason,
                    )
                )
                continue

            # 3b. Create transaction
            tx_id: Optional[str] = None
            try:
                amount = self._to_base_units(offer.unit_price)
                tx_id = await self._runtime.create_transaction(
                    CreateTransactionParams(
                        provider=provider_address,
                        requester=self._requester_address,
                        amount=amount,
                        deadline=int(time.time())
                        + quote_ttl_seconds
                        + 3600,  # quote TTL + 1h buffer
                        service_description=json.dumps(
                            {
                                "service": self._policy.task,
                                "session": session.commerce_session_id,
                            }
                        ),
                    )
                )
            except Exception as err:
                reason = str(err)
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="error",
                        reason=f"createTransaction failed: {reason}",
                    )
                )
                emit(
                    RoundEndEvent(
                        round=round_idx + 1, action="error", reason=reason
                    )
                )
                continue

            # 3c. Wait for quote or direct commit (ACTP allows INITIATED -> COMMITTED fast path)
            emit(
                WaitingQuoteEvent(
                    tx_id=tx_id, ttl_seconds=quote_ttl_seconds
                )
            )

            reached_state = await self._wait_for_state(
                tx_id,
                ["QUOTED", "COMMITTED"],
                quote_ttl_seconds * 1000,
                poll_interval,
            )

            if reached_state is None:
                # Timeout or cancelled -- cancel and try next
                try:
                    await self._runtime.transition_state(tx_id, "CANCELLED")
                except Exception:
                    pass  # Best-effort cancel
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="timeout",
                        reason=f"No quote within {quote_ttl_seconds}s",
                        tx_id=tx_id,
                    )
                )
                emit(
                    RoundEndEvent(
                        round=round_idx + 1,
                        action="timeout",
                        reason="Quote TTL expired",
                    )
                )
                continue

            emit(QuoteReceivedEvent(tx_id=tx_id))

            # 3d. Read quoted price from on-chain for tracking (PRD-5B)
            quoted_price: Optional[float] = None
            try:
                quoted_tx = await self._runtime.get_transaction(tx_id)
                if quoted_tx and hasattr(quoted_tx, "amount") and quoted_tx.amount is not None:
                    raw_amount = float(quoted_tx.amount) if isinstance(quoted_tx.amount, str) else float(quoted_tx.amount)
                    quoted_price = raw_amount / 1_000_000  # Convert base units to USDC
                    price_history.append(quoted_price)

                    # Deadlock detection: if 2+ consecutive identical prices, flag deadlock
                    if len(price_history) >= 2 and price_history[-1] == price_history[-2]:
                        deadlock_detected = True
            except Exception:
                pass  # Non-fatal — price tracking is best-effort

            # 3e. Reserve budget and link escrow (or recognize already-committed).
            # ACTP invariant: tx.amount is immutable (set at createTransaction).
            # Policy was already validated pre-round, so offer.unit_price
            # is the correct amount for both reservation and escrow.

            if reached_state == "COMMITTED":
                # COMMITTED is terminal on-chain -- this is a success regardless of local ledger state.
                # Best-effort reserve for local budget tracking; failure is non-fatal.
                try:
                    self._policy_engine.reserve(
                        session.commerce_session_id,
                        offer.unit_price,
                        offer.currency,
                    )
                except Exception:
                    # Local ledger out of sync -- log but don't fail the already-committed tx
                    pass

                self._session_store.link_transaction(
                    session.commerce_session_id, tx_id, candidate.slug
                )

                reason = "Provider already committed, escrow recognized"
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="accepted",
                        reason=reason,
                        tx_id=tx_id,
                        quoted_price=quoted_price,
                    )
                )

                emit(
                    RoundEndEvent(
                        round=round_idx + 1, action="accepted", reason=reason
                    )
                )
                emit(
                    CompleteEvent(
                        success=True, reason="Negotiation complete"
                    )
                )

                return NegotiationResult(
                    success=True,
                    commerce_session_id=session.commerce_session_id,
                    actp_tx_id=tx_id,
                    selected_provider=candidate.slug,
                    rounds_used=round_idx + 1,
                    reason="Negotiation complete -- already committed",
                    rounds=rounds,
                    deadlock_detected=deadlock_detected,
                )

            # QUOTED path: reserve budget + link escrow (both must succeed, or try next candidate)
            escrow_amount = self._to_base_units(offer.unit_price)
            try:
                self._policy_engine.reserve(
                    session.commerce_session_id,
                    offer.unit_price,
                    offer.currency,
                )
                await self._runtime.link_escrow(tx_id, escrow_amount)

                # Success
                self._session_store.link_transaction(
                    session.commerce_session_id, tx_id, candidate.slug
                )

                reason = "Quote accepted, escrow linked"
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="accepted",
                        reason=reason,
                        tx_id=tx_id,
                        quoted_price=quoted_price,
                    )
                )

                emit(
                    RoundEndEvent(
                        round=round_idx + 1, action="accepted", reason=reason
                    )
                )
                emit(
                    CompleteEvent(
                        success=True, reason="Negotiation complete"
                    )
                )

                return NegotiationResult(
                    success=True,
                    commerce_session_id=session.commerce_session_id,
                    actp_tx_id=tx_id,
                    selected_provider=candidate.slug,
                    rounds_used=round_idx + 1,
                    reason="Negotiation complete -- escrow linked",
                    rounds=rounds,
                    deadlock_detected=deadlock_detected,
                )
            except Exception as err:
                # Reserve or linkEscrow failed -- release and try next
                self._policy_engine.release(session.commerce_session_id)
                reason = str(err)
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate.slug,
                        provider_address=provider_address,
                        action="error",
                        reason=f"Escrow failed: {reason}",
                        tx_id=tx_id,
                        quoted_price=quoted_price,
                    )
                )
                emit(
                    RoundEndEvent(
                        round=round_idx + 1, action="error", reason=reason
                    )
                )
                continue

        # All rounds exhausted
        self._session_store.update_status(
            session.commerce_session_id, "failed"
        )
        emit(
            CompleteEvent(
                success=False, reason="All candidates exhausted"
            )
        )

        exhausted_reason = (
            f"All {len(rounds)} candidates exhausted (price deadlock detected)"
            if deadlock_detected
            else f"All {len(rounds)} candidates exhausted"
        )

        return NegotiationResult(
            success=False,
            commerce_session_id=session.commerce_session_id,
            rounds_used=len(rounds),
            reason=exhausted_reason,
            rounds=rounds,
            deadlock_detected=deadlock_detected,
        )

    # ============================================================================
    # Helpers
    # ============================================================================

    async def _wait_for_state(
        self,
        tx_id: str,
        target_states: List[str],
        timeout_ms: int,
        poll_interval_ms: int,
    ) -> Optional[str]:
        """
        Poll until tx reaches one of the target states.
        Returns the reached state, or None on timeout/cancelled.
        Resilient to transient RPC errors (retries until deadline).
        """
        deadline = time.time() + (timeout_ms / 1000.0)

        while time.time() < deadline:
            try:
                tx = await self._runtime.get_transaction(tx_id)
                if tx and tx.state in target_states:
                    return tx.state
                # Exit early if CANCELLED by provider
                if tx and tx.state == "CANCELLED":
                    return None
            except Exception:
                # Transient error (RPC timeout, network blip) -- keep polling until deadline
                pass

            remaining_ms = (deadline - time.time()) * 1000.0
            sleep_ms = min(poll_interval_ms, remaining_ms)
            if sleep_ms > 0:
                await asyncio.sleep(sleep_ms / 1000.0)

        return None

    def _map_to_candidate_stats(
        self, agents: List[DiscoverAgent]
    ) -> List[CandidateStats]:
        """Map discovered agents to CandidateStats for scoring."""
        results: List[CandidateStats] = []
        for a in agents:
            if not a.wallet_address or not (
                a.published_config and a.published_config.pricing
            ):
                continue

            pricing_amount = a.published_config.pricing.amount
            if isinstance(pricing_amount, str):
                unit_price = float(pricing_amount)
            elif pricing_amount is not None:
                unit_price = float(pricing_amount)
            else:
                unit_price = 0.0

            results.append(
                CandidateStats(
                    slug=a.slug,
                    unit_price=unit_price,
                    reputation_score=(
                        a.stats.reputation_score if a.stats else 0.0
                    ),
                    success_rate=a.stats.success_rate if a.stats else 0.0,
                    avg_completion_time_seconds=(
                        a.stats.avg_completion_time_seconds if a.stats else None
                    ),
                    completed_transactions=(
                        a.stats.completed_transactions if a.stats else 0
                    ),
                )
            )
        return results

    def _find_agent_address(
        self, agents: List[DiscoverAgent], slug: str
    ) -> str:
        """Find agent wallet address by slug."""
        for a in agents:
            if a.slug == slug:
                return a.wallet_address
        return ""

    def _find_agent_price(
        self, agents: List[DiscoverAgent], slug: str
    ) -> float:
        """Find agent unit price by slug."""
        for a in agents:
            if a.slug == slug:
                if a.published_config and a.published_config.pricing:
                    amount = a.published_config.pricing.amount
                    if isinstance(amount, str):
                        return float(amount)
                    if amount is not None:
                        return float(amount)
                return 0.0
        return 0.0

    def _find_agent_reputation(
        self, agents: List[DiscoverAgent], slug: str
    ) -> Optional[float]:
        """Find agent reputation score by slug."""
        for a in agents:
            if a.slug == slug:
                if a.stats:
                    return a.stats.reputation_score
                return None
        return None

    @staticmethod
    def _to_base_units(amount: float) -> str:
        """Convert a USDC amount (e.g. 0.80) to base units string (e.g. '800000').

        Uses math.floor(x + 0.5) to match JavaScript's Math.round() semantics
        (round-half-up), since Python's built-in round() uses banker's rounding.
        """
        return str(math.floor(amount * 1_000_000 + 0.5))


__all__ = [
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
