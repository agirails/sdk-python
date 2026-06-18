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
import inspect
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.builders.quote import QuoteBuilder, QuoteMessage
from agirails.negotiation.negotiation_channel import (
    COUNTERACCEPT_ENVELOPE,
    COUNTEROFFER_ENVELOPE,
    QUOTE_ENVELOPE,
    DeliveredMessage,
    NegotiationChannel,
    NegotiationMessage,
    Subscription,
    is_counter_accept_envelope,
    is_quote_envelope,
)
from agirails.negotiation.verify_quote_on_chain import (
    VerifyOnChainResult,
    verify_quote_hash_on_chain,
)

from agirails.api.discover import DiscoverAgent, DiscoverParams, discover_agents
from agirails.negotiation.decision_engine import (
    BuyerQuoteDecider,
    CandidateStats,
    DecisionEngine,
    QuoteEvaluation,
    QuoteForEvaluation,
    ScoringWeights,
)
from agirails.negotiation.policy_engine import BuyerPolicy, PolicyEngine, QuoteOffer
from agirails.negotiation.session_store import SessionStore
from agirails.runtime.base import CreateTransactionParams, IACTPRuntime

# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class RequoteGuardViolation:
    """A re-quote anchoring violation (TS BuyerOrchestrator.ts:802-844).

    Returned by :meth:`BuyerOrchestrator.check_requote_anchors` when an
    attacker mutated ``provider`` or ``max_price`` on a re-quote relative to
    the first (on-chain-anchored) quote. The buyer must CANCEL the tx.
    """

    rule: Literal["provider_mismatch", "max_price_mismatch"]
    detail: str


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
# BuyerNegotiationContext (AIP-2.1 §6 channel-driven multi-round)
# ============================================================================


@dataclass
class BuyerNegotiationContext:
    """AIP-2.1 negotiation context: wires the orchestrator into the
    :class:`NegotiationChannel` transport. All fields optional: without them
    the orchestrator runs the legacy fixed-price / poll-only flow (no
    counters). Mirrors TS ``BuyerNegotiationContext``
    (BuyerOrchestrator.ts:104-126).

    To enable multi-round negotiation, supply ALL of:
      - ``private_key`` (signs CounterOfferMessages)
      - ``kernel_address`` (EIP-712 domain)
      - ``chain_id``
      - ``negotiation_channel`` (transport: MockChannel for tests, an HTTP
        channel in production)
    """

    #: Buyer's signer private key (hex). Signs CounterOfferMessages. (TS passes
    #: an ethers ``Signer``; Python's CounterOfferBuilder takes a private key.)
    private_key: Optional[str] = None
    #: ACTPKernel address for the chain. Required for counter signing.
    kernel_address: Optional[str] = None
    #: Chain id (84532 / 8453). Required for counter signing.
    chain_id: Optional[int] = None
    #: Nonce manager for counter messages. Defaults to an in-memory one.
    nonce_manager: Optional[MessageNonceManager] = None
    #: Transport for receiving quotes / acceptances + sending counters.
    #: Required for any negotiation feature; without it the orchestrator is
    #: fixed-price only.
    negotiation_channel: Optional[NegotiationChannel] = None
    #: BYO-brain: override the per-quote accept/counter/reject decision. When
    #: omitted, the built-in DecisionEngine is used. Only consulted on the
    #: channel negotiation path. Async-tolerant for LLM deciders.
    decide_quote: Optional[BuyerQuoteDecider] = None
    #: Buyer's signer address (lowercased into the consumer DID). When omitted,
    #: derived from ``private_key``.
    signer_address: Optional[str] = None


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
        negotiation: Optional[BuyerNegotiationContext] = None,
        client: Optional[Any] = None,
        decide_quote: Optional[BuyerQuoteDecider] = None,
    ) -> None:
        # Fail-fast on partial negotiation context. Pre-fix bug: a developer who
        # set ``negotiation_channel`` but forgot private_key / chain_id got NO
        # error — every tx silently fell through to fixed-price flow with the
        # channel subscription opened-and-immediately-closed for nothing.
        # Mirrors TS BuyerOrchestrator.ts:180-192 (P1 audit finding G).
        negotiation = negotiation or BuyerNegotiationContext()
        if negotiation.negotiation_channel is not None:
            missing: List[str] = []
            if not negotiation.private_key:
                missing.append("private_key")
            if not negotiation.kernel_address:
                missing.append("kernel_address")
            if not negotiation.chain_id:
                missing.append("chain_id")
            if missing:
                raise ValueError(
                    "BuyerNegotiationContext: negotiation_channel was provided "
                    "but the following required field(s) are missing: "
                    f"{', '.join(missing)}. Multi-round negotiation needs all "
                    "of: private_key, kernel_address, chain_id, "
                    "negotiation_channel. Omit negotiation_channel for "
                    "fixed-price-only flow."
                )

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
        self._negotiation = negotiation
        self._client = client

        # BYO-brain: the default decider delegates to the built-in
        # DecisionEngine, so when ``decide_quote`` is absent the per-quote
        # accept/counter/reject decision is byte-for-byte identical to the
        # zero-config path. ``negotiation.decide_quote`` takes precedence over
        # the legacy top-level ``decide_quote`` kwarg (back-compat). Mirrors TS
        # BuyerOrchestrator.ts:199-201.
        effective_decider = (
            negotiation.decide_quote
            if negotiation.decide_quote is not None
            else decide_quote
        )
        self._decider: BuyerQuoteDecider = (
            effective_decider
            if effective_decider is not None
            else (
                lambda q, p, r: self._decision_engine.evaluate_quote(q, p, r)
            )
        )

        # Counter builder is only wired when a signer is present.
        self._counter_builder: Optional[CounterOfferBuilder] = None
        if negotiation.private_key:
            self._counter_builder = CounterOfferBuilder(
                private_key=negotiation.private_key,
                nonce_manager=negotiation.nonce_manager or MessageNonceManager(),
            )

        # Per-txId inbound message queue + resolver + active subscriptions
        # (mirror TS inboundQueues / inboundResolvers / activeSubscriptions).
        self._inbound_queues: Dict[str, List[NegotiationMessage]] = {}
        self._inbound_resolvers: Dict[str, "asyncio.Future[NegotiationMessage]"] = {}
        self._active_subscriptions: Dict[str, Subscription] = {}

    # --------------------------------------------------------------------------
    # Channel inbound dispatch
    # --------------------------------------------------------------------------

    def _on_channel_message(self, tx_id: str, delivered: DeliveredMessage) -> None:
        """Channel delivered a verified message for ``tx_id``. If a round is
        awaiting the next message, hand it directly; otherwise queue.

        The channel has already verified EIP-712 signature + chainId before
        invoking us — this handler is concerned only with routing. Mirror of
        TS ``_onChannelMessage`` (BuyerOrchestrator.ts:225-235).
        """
        resolver = self._inbound_resolvers.get(tx_id)
        if resolver is not None and not resolver.done():
            self._inbound_resolvers.pop(tx_id, None)
            resolver.set_result(delivered.envelope)
            return
        queue = self._inbound_queues.get(tx_id, [])
        queue.append(delivered.envelope)
        self._inbound_queues[tx_id] = queue

    async def _wait_for_next_message(
        self,
        tx_id: str,
        accepted_types: Tuple[str, ...],
        timeout_ms: int,
    ) -> Optional[NegotiationMessage]:
        """Await the next inbound message matching one of ``accepted_types``.
        Returns ``None`` on timeout. Drains the queue first so messages
        buffered while we were busy processing the previous round are picked up
        immediately. Mirror of TS ``_waitForNextMessage``
        (BuyerOrchestrator.ts:245-296).
        """
        # Drain queue first — non-matching types stay queued for later.
        queue = self._inbound_queues.get(tx_id, [])
        for idx, m in enumerate(queue):
            if m.type in accepted_types:
                queue.pop(idx)
                if not queue:
                    self._inbound_queues.pop(tx_id, None)
                else:
                    self._inbound_queues[tx_id] = queue
                return m

        loop = asyncio.get_event_loop()
        while True:
            fut: "asyncio.Future[NegotiationMessage]" = loop.create_future()
            self._inbound_resolvers[tx_id] = fut
            try:
                msg = await asyncio.wait_for(
                    asyncio.shield(fut), timeout=timeout_ms / 1000.0
                )
            except asyncio.TimeoutError:
                if self._inbound_resolvers.get(tx_id) is fut:
                    self._inbound_resolvers.pop(tx_id, None)
                return None
            if msg.type in accepted_types:
                return msg
            # Wrong type — push back to queue and keep waiting. Re-drain the
            # queue BEFORE re-registering so a correct-type message that landed
            # in the same tick isn't lost (TS pre-fix race H).
            q = self._inbound_queues.get(tx_id, [])
            q.append(msg)
            for idx, m in enumerate(q):
                if m.type in accepted_types:
                    q.pop(idx)
                    if not q:
                        self._inbound_queues.pop(tx_id, None)
                    else:
                        self._inbound_queues[tx_id] = q
                    return m
            self._inbound_queues[tx_id] = q
            # loop: re-register resolver for the next message.

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
                        # PRD §5.6 / TS parity (BuyerOrchestrator.ts:444-449): put
                        # the bytes32 routing key on-chain so it matches what
                        # Agent.provide(name) registers in handlersByHash. TS sets
                        # serviceDescription = keccak256(toUtf8Bytes(policy.task));
                        # the Python BlockchainRuntime hashes service_description
                        # with w3.keccak(text=...), so passing the RAW task string
                        # here produces the SAME on-chain serviceHash =
                        # keccak(task). Pre-4.0.0 this site passed
                        # json.dumps({service, session}) — the runtime then hashed
                        # the whole JSON blob, so the on-chain serviceHash could
                        # never equal keccak(taskName) and provider routing
                        # silently missed (the exact pre-4.0.0 bug). The session_id
                        # is no longer carried on-chain; correlation uses txId.
                        service_description=self._policy.task,
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

            # Open negotiation channel subscription for this txId. All inbound
            # quote / counteraccept messages from the provider will land in our
            # internal queue (via _on_channel_message) for the negotiation round
            # loop to consume. Subscription is closed in _cleanup_tx_state.
            # Mirror of TS BuyerOrchestrator.ts:467-473.
            if self._negotiation.negotiation_channel is not None:
                captured_tx = tx_id

                def _cb(delivered: DeliveredMessage, _tx: str = captured_tx) -> None:
                    self._on_channel_message(_tx, delivered)

                sub = self._negotiation.negotiation_channel.subscribe_tx_id(
                    tx_id, _cb
                )
                self._active_subscriptions[tx_id] = sub

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
                # External caller may have pushed a quote between
                # createTransaction and timeout — clear so a long-running daemon
                # doesn't accumulate channel state.
                self._cleanup_tx_state(tx_id)
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

            # 3d-bis. AIP-2.1 negotiation branch: if the orchestrator has a
            # negotiation_channel configured, drain the inbound queue for any
            # quote that arrived via the channel and run the multi-round
            # counter-offer loop. The branch ONLY triggers when reached_state ==
            # 'QUOTED' — the COMMITTED fast-path below bypasses negotiation
            # entirely because the provider already locked the deal at buyer's
            # offered amount. Mirror of TS BuyerOrchestrator.ts:534-568.
            if (
                reached_state == "QUOTED"
                and self._negotiation.negotiation_channel is not None
            ):
                neg_done, neg_success, neg_reason = await self._run_negotiation_round(
                    tx_id=tx_id,
                    candidate_slug=candidate.slug,
                    provider_address=provider_address,
                    offer=offer,
                    round_idx=round_idx,
                    rounds=rounds,
                    emit=emit,
                )
                if neg_done:
                    # Negotiation reached a terminal decision (accept or reject)
                    # — short-circuit the existing escrow logic below.
                    if neg_success:
                        self._session_store.link_transaction(
                            session.commerce_session_id, tx_id, candidate.slug
                        )
                        neg_reason_str = neg_reason or "Negotiation complete"
                        emit(CompleteEvent(success=True, reason=neg_reason_str))
                        return NegotiationResult(
                            success=True,
                            commerce_session_id=session.commerce_session_id,
                            actp_tx_id=tx_id,
                            selected_provider=candidate.slug,
                            rounds_used=round_idx + 1,
                            reason=neg_reason_str,
                            rounds=rounds,
                            deadlock_detected=deadlock_detected,
                        )
                    # neg_success is False → candidate rejected; continue outer
                    # loop to try the next one.
                    continue

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

                # COMMITTED fast-path bypassed _run_negotiation_round (the usual
                # cleanup site) — drop any stashed channel state so daemon
                # callers don't leak across negotiations.
                self._cleanup_tx_state(tx_id)

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

                # Symmetric to the COMMITTED fast-path above — this success exit
                # also bypassed _run_negotiation_round's cleanup site.
                self._cleanup_tx_state(tx_id)

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
                # Same daemon-leak rationale as the timeout `continue` above.
                self._cleanup_tx_state(tx_id)
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
    # AIP-2.1 negotiation round
    # ============================================================================

    async def _run_negotiation_round(
        self,
        tx_id: str,
        candidate_slug: str,
        provider_address: str,
        offer: QuoteOffer,
        round_idx: int,
        rounds: List[RoundResult],
        emit: Callable[[ProgressEvent], None],
    ) -> Tuple[bool, bool, Optional[str]]:
        """Run the multi-round AIP-2.1 negotiation flow for one provider/txId.

        Channel-driven: never reads ``set_received_quote`` state; all inbound
        messages flow through the orchestrator's NegotiationChannel
        subscription (opened in ``_negotiate`` after createTransaction).

        Returns ``(done, success, reason)``:
          - ``(False, _, _)`` — channel has no quote but the tx reached QUOTED
            via raw transitionState (legacy/poll-only provider). Caller falls
            through to fixed-price flow.
          - ``(True, success, reason)`` — terminal outcome (accept/reject).

        Mirror of TS ``_runNegotiationRound`` (BuyerOrchestrator.ts:721-965).
        """

        def terminate(success: bool, reason: str) -> Tuple[bool, bool, Optional[str]]:
            # Cleanup hook fires on any done=True return — closes the channel
            # subscription opened in _negotiate so daemon callers don't leak.
            self._cleanup_tx_state(tx_id)
            return (True, success, reason)

        if (
            self._counter_builder is None
            or not self._negotiation.kernel_address
            or not self._negotiation.chain_id
        ):
            # Channel was provided but not the rest of the negotiation context.
            # Fall through to fixed-price flow rather than try to negotiate.
            self._cleanup_tx_state(tx_id)
            return (False, False, None)

        counter_ttl_sec = getattr(
            self._policy.negotiation, "counter_response_ttl_seconds", None
        )
        if counter_ttl_sec is None:
            counter_ttl_sec = PolicyEngine.parse_ttl(self._policy.negotiation.quote_ttl)
        counter_ttl_ms = counter_ttl_sec * 1000
        rounds_budget = getattr(self._policy.negotiation, "rounds_per_provider", None)
        if rounds_budget is None:
            rounds_budget = 1

        # Wait for the FIRST quote on the channel.
        first_quote_env = await self._wait_for_next_message(
            tx_id, (QUOTE_ENVELOPE,), counter_ttl_ms
        )
        if first_quote_env is None or not is_quote_envelope(first_quote_env):
            # No quote arrived on the channel within TTL — fall through to
            # fixed-price (the on-chain hash + waitForState already proved the
            # tx hit QUOTED, so this is a legacy-provider scenario).
            self._cleanup_tx_state(tx_id)
            return (False, False, None)
        first_quote: QuoteMessage = first_quote_env.message  # type: ignore[assignment]
        current_quote: QuoteMessage = first_quote

        # Multi-round inner loop.
        hash_source = "aip2"
        for counter_round in range(rounds_budget):
            if counter_round == 0:
                on_chain_tx = await self._runtime.get_transaction(tx_id)
                on_chain_hash = (
                    getattr(on_chain_tx, "quote_hash", None)
                    if on_chain_tx is not None
                    else None
                )
                if not on_chain_hash:
                    # No anchored quote — fall through to fixed-price.
                    self._cleanup_tx_state(tx_id)
                    return (False, False, None)
                verify = verify_quote_hash_on_chain(
                    current_quote,
                    on_chain_hash,
                    provider_address=provider_address,
                )
                if not verify.match:
                    rounds.append(
                        RoundResult(
                            round=round_idx + 1,
                            provider_slug=candidate_slug,
                            provider_address=provider_address,
                            action="error",
                            reason=(
                                f"Quote hash mismatch: expected "
                                f"{verify.canonical_hash}, on-chain {on_chain_hash}"
                            ),
                            tx_id=tx_id,
                        )
                    )
                    emit(
                        RoundEndEvent(
                            round=round_idx + 1,
                            action="error",
                            reason="Quote hash mismatch",
                        )
                    )
                    return terminate(False, "hash mismatch")
                hash_source = verify.source or "aip2"
            else:
                # Subsequent re-quotes: guard against two attacker-controlled
                # mutations the channel-level EIP-712 verify cannot catch:
                #   (a) provider DID switched mid-negotiation
                #   (b) maxPrice inflated mid-negotiation (P0 audit finding)
                # Both anchor to the FIRST quote (which cross-checked the
                # on-chain hash on round 0). Mirror BuyerOrchestrator.ts:802-844.
                if current_quote.provider != first_quote.provider:
                    try:
                        await self._transition_state(tx_id, "CANCELLED")
                    except Exception:
                        pass
                    rounds.append(
                        RoundResult(
                            round=round_idx + 1,
                            provider_slug=candidate_slug,
                            provider_address=provider_address,
                            action="error",
                            reason=(
                                f"Re-quote provider mismatch: {current_quote.provider} "
                                f"vs original {first_quote.provider}"
                            ),
                            tx_id=tx_id,
                        )
                    )
                    emit(
                        RoundEndEvent(
                            round=round_idx + 1,
                            action="error",
                            reason="provider mismatch on re-quote",
                        )
                    )
                    return terminate(False, "provider mismatch")
                if current_quote.max_price != first_quote.max_price:
                    try:
                        await self._transition_state(tx_id, "CANCELLED")
                    except Exception:
                        pass
                    rounds.append(
                        RoundResult(
                            round=round_idx + 1,
                            provider_slug=candidate_slug,
                            provider_address=provider_address,
                            action="error",
                            reason=(
                                f"Re-quote maxPrice mismatch: {current_quote.max_price} "
                                f"vs original {first_quote.max_price} — provider may "
                                f"not raise the ceiling mid-negotiation"
                            ),
                            tx_id=tx_id,
                        )
                    )
                    emit(
                        RoundEndEvent(
                            round=round_idx + 1,
                            action="error",
                            reason="maxPrice substitution attempt on re-quote",
                        )
                    )
                    return terminate(False, "maxPrice substitution")
                hash_source = "aip2"

            evaluation = await self._evaluate_current_quote(current_quote, counter_round)

            # ----- reject -----
            if evaluation.action == "reject":
                try:
                    await self._transition_state(tx_id, "CANCELLED")
                except Exception:
                    pass
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate_slug,
                        provider_address=provider_address,
                        action="rejected",
                        reason=(
                            f"{evaluation.reason} (round {counter_round + 1}/"
                            f"{rounds_budget}, source: {hash_source})"
                        ),
                        tx_id=tx_id,
                        quoted_price=self._base_units_for_log(
                            current_quote.quoted_amount
                        ),
                    )
                )
                emit(
                    RoundEndEvent(
                        round=round_idx + 1,
                        action="rejected",
                        reason=evaluation.reason,
                    )
                )
                return terminate(False, evaluation.reason)

            # ----- accept (at provider's quoted amount) -----
            if evaluation.action == "accept":
                result = await self._commit_at_amount(
                    tx_id,
                    current_quote.quoted_amount,
                    candidate_slug,
                    provider_address,
                    offer,
                    round_idx,
                    rounds,
                    emit,
                    hash_source,
                    counter_round,
                )
                self._cleanup_tx_state(tx_id)
                return result

            # ----- counter -----
            try:
                signer_addr = (
                    self._negotiation.signer_address
                    or _address_from_private_key(self._negotiation.private_key)
                )
                consumer_did = (
                    f"did:ethr:{self._negotiation.chain_id}:{signer_addr.lower()}"
                )
                now = int(time.time())
                # inReplyTo is the canonical hash of the quote we're countering
                # — recompute on every round (re-quotes have their own hash).
                current_quote_hash = QuoteBuilder().compute_hash(current_quote)
                counter = self._counter_builder.build(
                    CounterOfferParams(
                        txId=tx_id,
                        consumer=consumer_did,
                        provider=current_quote.provider,
                        quoteAmount=current_quote.quoted_amount,
                        counterAmount=evaluation.amount_base_units,  # type: ignore[arg-type]
                        maxPrice=current_quote.max_price,
                        inReplyTo=current_quote_hash,
                        chainId=self._negotiation.chain_id,
                        kernelAddress=self._negotiation.kernel_address,
                        expiresAt=now + counter_ttl_sec,
                    )
                )
            except Exception as err:
                reason = (
                    f"Counter build failed on round {counter_round + 1}: {err}"
                )
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate_slug,
                        provider_address=provider_address,
                        action="error",
                        reason=reason,
                        tx_id=tx_id,
                    )
                )
                emit(RoundEndEvent(round=round_idx + 1, action="error", reason=reason))
                return terminate(False, reason)

            try:
                await self._negotiation.negotiation_channel.post(  # type: ignore[union-attr]
                    tx_id,
                    NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=counter),
                )
            except Exception as err:
                reason = (
                    f"Counter post failed on round {counter_round + 1}: {err}"
                )
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate_slug,
                        provider_address=provider_address,
                        action="error",
                        reason=reason,
                        tx_id=tx_id,
                    )
                )
                emit(RoundEndEvent(round=round_idx + 1, action="error", reason=reason))
                return terminate(False, reason)

            # Await provider's response: counteraccept (deal closed) or new quote
            # (provider re-quote → next round).
            nxt = await self._wait_for_next_message(
                tx_id,
                (COUNTERACCEPT_ENVELOPE, QUOTE_ENVELOPE),
                counter_ttl_ms,
            )
            if nxt is None:
                try:
                    await self._transition_state(tx_id, "CANCELLED")
                except Exception:
                    pass
                reason = (
                    f"No response within {counter_ttl_sec}s on round "
                    f"{counter_round + 1}"
                )
                rounds.append(
                    RoundResult(
                        round=round_idx + 1,
                        provider_slug=candidate_slug,
                        provider_address=provider_address,
                        action="timeout",
                        reason=reason,
                        tx_id=tx_id,
                    )
                )
                emit(RoundEndEvent(round=round_idx + 1, action="timeout", reason=reason))
                return terminate(False, reason)

            if is_counter_accept_envelope(nxt):
                # Provider accepted our counter — bind to the counter WE sent.
                accept = nxt.message
                counter_hash = CounterOfferBuilder().compute_hash(counter)
                if (
                    accept.txId != tx_id
                    or accept.inReplyTo != counter_hash
                    or accept.acceptedAmount != counter.counterAmount
                ):
                    reason = (
                        f"CounterAccept binding mismatch on round {counter_round + 1}"
                    )
                    rounds.append(
                        RoundResult(
                            round=round_idx + 1,
                            provider_slug=candidate_slug,
                            provider_address=provider_address,
                            action="error",
                            reason=reason,
                            tx_id=tx_id,
                        )
                    )
                    emit(
                        RoundEndEvent(
                            round=round_idx + 1, action="error", reason=reason
                        )
                    )
                    return terminate(False, reason)
                result = await self._commit_at_amount(
                    tx_id,
                    accept.acceptedAmount,
                    candidate_slug,
                    provider_address,
                    offer,
                    round_idx,
                    rounds,
                    emit,
                    "counteraccept",
                    counter_round,
                )
                self._cleanup_tx_state(tx_id)
                return result

            if is_quote_envelope(nxt):
                # Provider re-quoted — replace current_quote and loop.
                current_quote = nxt.message  # type: ignore[assignment]
                continue

        # Budget exhausted without accept.
        try:
            await self._transition_state(tx_id, "CANCELLED")
        except Exception:
            pass
        reason = (
            f"Negotiation budget ({rounds_budget} rounds) exhausted without accept"
        )
        rounds.append(
            RoundResult(
                round=round_idx + 1,
                provider_slug=candidate_slug,
                provider_address=provider_address,
                action="timeout",
                reason=reason,
                tx_id=tx_id,
            )
        )
        emit(RoundEndEvent(round=round_idx + 1, action="timeout", reason=reason))
        return terminate(False, reason)

    async def _evaluate_current_quote(
        self, current_quote: QuoteMessage, counter_round: int
    ) -> QuoteEvaluation:
        """Consult the installed per-quote decider for a channel quote.

        Mirrors TS ``await this.decider(currentQuote, this.policy, counterRound)``
        (BuyerOrchestrator.ts:846), adapting the full ``QuoteMessage`` to the
        minimal ``QuoteForEvaluation`` shape the decider expects.
        """
        q = QuoteForEvaluation(
            quoted_amount=current_quote.quoted_amount,
            original_amount=current_quote.original_amount,
            max_price=current_quote.max_price,
            final_offer=False,
        )
        result = self._decider(q, self._policy, counter_round)
        if inspect.isawaitable(result):
            return await result
        return result

    async def _commit_at_amount(
        self,
        tx_id: str,
        amount_base_units: str,
        candidate_slug: str,
        provider_address: str,
        offer: QuoteOffer,
        round_idx: int,
        rounds: List[RoundResult],
        emit: Callable[[ProgressEvent], None],
        source_tag: str,
        counter_round: int,
    ) -> Tuple[bool, bool, str]:
        """Shared accept+linkEscrow with atomic rollback. Used by both the
        "accept the quote" and "accept the counter" terminal branches. Mirror
        of TS ``_commitAtAmount`` (BuyerOrchestrator.ts:971-1020).
        """
        accept_quote_succeeded = False
        try:
            await self._accept_quote(tx_id, amount_base_units)
            accept_quote_succeeded = True
            await self._link_escrow(tx_id, amount_base_units)
        except Exception as err:
            reason = str(err)
            if accept_quote_succeeded:
                try:
                    await self._transition_state(tx_id, "CANCELLED")
                except Exception:
                    pass
            rounds.append(
                RoundResult(
                    round=round_idx + 1,
                    provider_slug=candidate_slug,
                    provider_address=provider_address,
                    action="error",
                    reason=f"Commit failed (round {counter_round + 1}): {reason}",
                    tx_id=tx_id,
                )
            )
            emit(RoundEndEvent(round=round_idx + 1, action="error", reason=reason))
            return (True, False, reason)

        try:
            self._policy_engine.reserve(
                offer.commerce_session_id or "",
                self._base_units_for_log(amount_base_units),
                offer.currency,
            )
        except Exception:
            pass  # best-effort budget bookkeeping

        reason = (
            f"Committed at {amount_base_units} base units "
            f"(round {counter_round + 1}, source: {source_tag})"
        )
        rounds.append(
            RoundResult(
                round=round_idx + 1,
                provider_slug=candidate_slug,
                provider_address=provider_address,
                action="accepted",
                reason=reason,
                tx_id=tx_id,
                quoted_price=self._base_units_for_log(amount_base_units),
            )
        )
        emit(RoundEndEvent(round=round_idx + 1, action="accepted", reason=reason))
        return (True, True, reason)

    def _cleanup_tx_state(self, tx_id: str) -> None:
        """Free per-tx negotiation state at terminal outcomes. Closes the
        channel subscription too so long-running daemon callers don't leak
        inbound-message resolvers. Idempotent. Mirror of TS ``_cleanupTxState``
        (BuyerOrchestrator.ts:1029-1047).
        """
        self._inbound_queues.pop(tx_id, None)
        # Detach the resolver reference but do NOT resolve/cancel it: any
        # in-flight ``_wait_for_next_message`` holds the future locally and will
        # resolve on its own asyncio.wait_for timeout — mirrors TS, which lets
        # the setTimeout win on its own clock rather than calling the pending
        # resolver (BuyerOrchestrator.ts:1031-1041).
        self._inbound_resolvers.pop(tx_id, None)
        sub = self._active_subscriptions.pop(tx_id, None)
        if sub is not None:
            sub.unsubscribe()

    def _base_units_for_log(self, base_units_str: str) -> float:
        """Display-only downcast: USDC base-units string → float for the
        RoundResult.quoted_price log field. Mirror of TS ``_baseUnitsForLog``.
        """
        return int(base_units_str) / 1_000_000

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

    async def decide_quote(
        self,
        quote: QuoteForEvaluation,
        rounds_used_so_far: int = 0,
    ) -> QuoteEvaluation:
        """Consult the installed per-quote decider (BYO-brain hook).

        Single point that mirrors TS ``await this.decider(currentQuote,
        this.policy, counterRound)`` (BuyerOrchestrator.ts:846). When no
        custom ``decide_quote`` was injected at construction, this delegates
        verbatim to :meth:`DecisionEngine.evaluate_quote` — zero behavior
        change. When a custom decider was injected (e.g. an LLM brain), it is
        invoked instead; the result is awaited if it is a coroutine
        (async-tolerant, matching the TS ``| Promise<QuoteEvaluation>``
        contract).

        Contract the caller relies on (same as TS):
          - ``'counter'.amount_base_units`` MUST be a base-unit string,
            strictly < ``quote.quoted_amount`` and >= 50_000 ($0.05 platform
            min), or the CounterOfferBuilder rejects it.
          - ``'accept'`` commits at ``quote.quoted_amount`` without
            re-checking affordability.
        """
        result = self._decider(quote, self._policy, rounds_used_so_far)
        if inspect.isawaitable(result):
            return await result
        return result

    @staticmethod
    def verify_first_quote_on_chain(
        quote: QuoteMessage,
        on_chain_hash: str,
        provider_address: Optional[str] = None,
        actual_escrow: Optional[str] = None,
    ) -> VerifyOnChainResult:
        """Round-0 anchored MITM defense (TS BuyerOrchestrator.ts:780-801).

        On the FIRST quote received over a negotiation channel, the buyer
        MUST cross-check the off-chain :class:`QuoteMessage` against the hash
        the provider anchored on-chain at QUOTED. A mismatch means a
        man-in-the-middle substituted the quote (the channel-level EIP-712
        verify only proves the provider signed *something*, not that *this* is
        what was anchored). Callers should CANCEL the tx on ``match is False``.

        Thin wrapper over :func:`verify_quote_hash_on_chain` so the buyer path
        and tests share one anchored-hash entry point.
        """
        return verify_quote_hash_on_chain(
            quote,
            on_chain_hash,
            provider_address=provider_address,
            actual_escrow=actual_escrow,
        )

    @staticmethod
    def check_requote_anchors(
        current_quote: QuoteMessage,
        first_quote: QuoteMessage,
    ) -> Optional[RequoteGuardViolation]:
        """Re-quote MITM guards (TS BuyerOrchestrator.ts:802-844).

        On a SUBSEQUENT re-quote (round > 0) the channel-level EIP-712 verify
        cannot catch two attacker-controlled mutations — the same provider can
        sign anything, including poisoned re-quotes:

          (a) provider DID switched mid-negotiation
          (b) maxPrice inflated mid-negotiation — without this guard, the
              buyer's accept-if-affordable last-round branch would compare
              against the attacker's inflated max and commit above its own
              policy ceiling. (P0 audit finding.)

        Both anchor to the FIRST quote (which already cross-checked the
        on-chain hash on round 0 via :meth:`verify_first_quote_on_chain`).

        Returns a :class:`RequoteGuardViolation` describing the first failing
        anchor (caller should CANCEL the tx), or ``None`` if both anchors hold.
        """
        if current_quote.provider != first_quote.provider:
            return RequoteGuardViolation(
                rule="provider_mismatch",
                detail=(
                    f"Re-quote provider mismatch: {current_quote.provider} "
                    f"vs original {first_quote.provider}"
                ),
            )
        if current_quote.max_price != first_quote.max_price:
            return RequoteGuardViolation(
                rule="max_price_mismatch",
                detail=(
                    f"Re-quote maxPrice mismatch: {current_quote.max_price} "
                    f"vs original {first_quote.max_price} — provider may not "
                    f"raise the ceiling mid-negotiation"
                ),
            )
        return None

    @staticmethod
    def _to_base_units(amount: float) -> str:
        """Convert a USDC amount (e.g. 0.80) to base units string (e.g. '800000').

        Uses math.floor(x + 0.5) to match JavaScript's Math.round() semantics
        (round-half-up), since Python's built-in round() uses banker's rounding.
        """
        return str(math.floor(amount * 1_000_000 + 0.5))

    # ==========================================================================
    # AA-aware write routing helpers
    #
    # When ``self._client`` is provided, on-chain writes go through the
    # StandardAdapter which routes via the Smart Wallet when an AGIRAILS Smart
    # Wallet is active (PRD §5.6 — gasless requesters). Otherwise (legacy
    # constructors without ``client``, mock-only callers, or EOA testnet without
    # AA infra) writes fall through to the raw runtime. Mirror of TS
    # BuyerOrchestrator.ts:1132-1219.
    # ==========================================================================

    async def _transition_state(
        self, tx_id: str, new_state: str, proof: Optional[str] = None
    ) -> None:
        if self._client is not None:
            return await self._client.standard.transition_state(
                tx_id, new_state, proof
            )
        return await self._runtime.transition_state(tx_id, new_state, proof)

    async def _link_escrow(self, tx_id: str, amount: str) -> str:
        if self._client is not None:
            # StandardAdapter.link_escrow reads tx.amount from runtime and locks
            # that; by the ACTP invariant tx.amount equals the agreed amount at
            # the call sites here (createTransaction price or post-accept_quote).
            return await self._client.standard.link_escrow(tx_id)
        return await self._runtime.link_escrow(tx_id, amount)

    async def _accept_quote(self, tx_id: str, amount: str) -> None:
        if self._client is not None:
            return await self._client.standard.accept_quote(
                tx_id, self._base_units_to_human(amount)
            )
        return await self._runtime.accept_quote(tx_id, amount)

    @staticmethod
    def _base_units_to_human(base_units: str) -> str:
        """Convert a USDC base-unit string (e.g. '5000000') to a human-readable
        decimal string (e.g. '5.000000'). Inverse of :meth:`_to_base_units`,
        lossless for any non-negative integer input. Mirror of TS
        ``_baseUnitsToHuman`` (BuyerOrchestrator.ts:1213-1219).
        """
        n = int(base_units)
        if n < 0:
            raise ValueError(f'_base_units_to_human: negative input "{base_units}"')
        whole = n // 1_000_000
        frac = n % 1_000_000
        return f"{whole}.{str(frac).rjust(6, '0')}"


def _address_from_private_key(private_key: Optional[str]) -> str:
    """Derive the 0x EOA address from a hex private key (for the consumer DID).

    Returns the empty string if no key is set (the caller already gated the
    counter path on ``private_key`` being present).
    """
    if not private_key:
        return ""
    from eth_account import Account

    return Account.from_key(private_key).address


__all__ = [
    "BuyerOrchestrator",
    "BuyerNegotiationContext",
    "NegotiationResult",
    "RoundResult",
    "RequoteGuardViolation",
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
