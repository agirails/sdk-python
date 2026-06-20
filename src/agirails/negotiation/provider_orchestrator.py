"""
ProviderOrchestrator — autonomous provider-side negotiation flow.

Python port of ``sdk-js/src/negotiation/ProviderOrchestrator.ts``,
byte/semantically identical. Two responsibilities:

  1. Accept an incoming request → decide whether to quote → if yes, build +
     sign a :class:`QuoteMessage`, anchor on-chain via ``runtime.submit_quote``,
     post it on the :class:`NegotiationChannel` for the buyer.

  2. (3.5.0) Run a long-lived :meth:`start` listener on the channel: every
     counter that arrives is evaluated against :class:`ProviderPolicy` (or the
     injected :data:`CounterDecider`); based on ``counter_strategy`` we either
     auto-accept (build + post a CounterAccept), auto-requote (build + post a
     new quote with the conceded amount), or walk (log + drop).

Symmetric to :class:`BuyerOrchestrator`'s channel-driven multi-round loop —
together they implement the full AIP-2.1 §6 negotiation protocol without
either party needing to host an HTTP endpoint.

@module negotiation/provider_orchestrator
@see Protocol/aips/AIP-2.1.md §5.2 (provider quote flow)
@see Protocol/aips/AIP-2.1.md §6 (NegotiationChannel)
@see sdk-js/src/negotiation/ProviderOrchestrator.ts
"""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional

from eth_account import Account

from agirails.builders.counter_accept import CounterAcceptBuilder, CounterAcceptParams
from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferMessage,
    MessageNonceManager,
)
from agirails.builders.quote import QuoteBuilder, QuoteMessage, QuoteParams
from agirails.negotiation.negotiation_channel import (
    COUNTERACCEPT_ENVELOPE,
    QUOTE_ENVELOPE,
    DeliveredMessage,
    NegotiationChannel,
    NegotiationMessage,
    Subscription,
    is_counter_offer_envelope,
)
from agirails.negotiation.provider_policy import (
    CounterDecider,
    CounterDecision,
    IncomingRequest,
    ProviderPolicy,
    ProviderPolicyEngine,
)
from agirails.runtime.base import IACTPRuntime

# ============================================================================
# Types
# ============================================================================

LogLevel = Literal["info", "warn", "error"]
Logger = Any  # Callable[[LogLevel, str], None]


@dataclass(frozen=True)
class QuoteDecisionViolation:
    rule: str
    detail: str


@dataclass(frozen=True)
class QuoteDecision:
    """Verdict from :meth:`ProviderOrchestrator.evaluate_request`.

    Mirrors the TS ``QuoteDecision`` discriminated union flattened to a single
    frozen dataclass.

    - ``action='quote'`` → ``amount_base_units`` is the recommended quote
      amount (base units, string).
    - ``action='skip'``  → ``violations`` carries the policy rules that failed.
    """

    action: Literal["quote", "skip"]
    reason: str
    amount_base_units: Optional[str] = None
    violations: List[QuoteDecisionViolation] = field(default_factory=list)


@dataclass
class QuoteResult:
    """Result of :meth:`ProviderOrchestrator.quote`."""

    decision: QuoteDecision
    #: Set when ``action == 'quote'`` and on-chain anchoring succeeded.
    quote: Optional[QuoteMessage] = None
    #: Set when channel post failed (on-chain still succeeded).
    channel_error: Optional[str] = None


@dataclass
class _TxState:
    """Per-tx state the orchestrator tracks while listening on the channel."""

    #: Provider's most recent QuoteMessage for this tx (initial or re-quote).
    last_quote: Optional[QuoteMessage]
    #: How many re-quotes we've sent so far (0 = only initial quote).
    requotes_used: int
    #: Buyer's DID — captured from incoming counter so we can address acceptance.
    consumer_did: str


@dataclass
class ProviderOrchestratorConfig:
    """Configuration for :class:`ProviderOrchestrator` (mirrors TS config)."""

    policy: ProviderPolicy
    runtime: IACTPRuntime
    #: Provider's signer private key (hex). Signs QuoteMessages +
    #: CounterAcceptMessages. (TS passes an ethers ``Signer``; Python builders
    #: take a private key.)
    private_key: str
    #: Kernel address for the EIP-712 domain.
    kernel_address: str
    #: Chain id (84532 or 8453).
    chain_id: int
    #: Provider's DID — used for the ``subscribe_agent`` filter on the channel
    #: AND as the ``provider`` field on outbound messages. Required for start().
    provider_did: Optional[str] = None
    #: Persistent nonce manager. Defaults to an in-memory one.
    nonce_manager: Optional[MessageNonceManager] = None
    #: Negotiation channel. Required for ``start()`` long-running mode.
    negotiation_channel: Optional[NegotiationChannel] = None
    #: Logger for observability. Default: noop.
    log: Optional[Logger] = None
    #: BYO-brain: override the accept/reject/requote decision. When omitted,
    #: the built-in ProviderPolicyEngine is used. Signature verification ALWAYS
    #: runs first regardless. Async-tolerant for LLM deciders.
    counter_decider: Optional[CounterDecider] = None


# ============================================================================
# Orchestrator
# ============================================================================


class ProviderOrchestrator:
    """Autonomous provider-side negotiation orchestrator (TS-parity)."""

    def __init__(self, config: ProviderOrchestratorConfig) -> None:
        self._policy = config.policy
        # The engine carries the injected counter_decider so decide_counter
        # routes through it (mirrors TS: counterDecider lives on the
        # orchestrator and is consulted inside evaluateCounter).
        self._policy_engine = ProviderPolicyEngine(
            config.policy, counter_decider=config.counter_decider
        )
        self._runtime = config.runtime
        self._private_key = config.private_key
        self._account = Account.from_key(config.private_key)
        self._kernel_address = config.kernel_address
        self._chain_id = config.chain_id
        self._provider_did = config.provider_did
        self._nonce_manager = config.nonce_manager or MessageNonceManager()
        self._negotiation_channel = config.negotiation_channel
        self._log: Logger = config.log or (lambda _level, _msg: None)
        self._counter_decider = config.counter_decider

        self._quote_builder = QuoteBuilder(
            account=self._account, nonce_manager=_QuoteNonceAdapter(self._nonce_manager)
        )
        self._counter_verifier = CounterOfferBuilder()  # verify-only
        self._counter_accept_builder = CounterAcceptBuilder(
            private_key=self._private_key, nonce_manager=self._nonce_manager
        )

        # Per-tx state for the multi-round counter listener.
        self._tx_states: dict[str, _TxState] = {}
        # Active channel subscription opened by start().
        self._channel_subscription: Optional[Subscription] = None

    # --------------------------------------------------------------------------
    # One-shot quote (caller-driven)
    # --------------------------------------------------------------------------

    def evaluate_request(self, req: IncomingRequest) -> QuoteDecision:
        """Decide whether to quote. Pure policy — no chain, no channel.

        Mirror of TS ``evaluateRequest`` (ProviderOrchestrator.ts:200-214).
        """
        result = self._policy_engine.evaluate(req)
        if not result.allowed:
            return QuoteDecision(
                action="skip",
                reason="; ".join(f"{v.rule}: {v.detail}" for v in result.violations),
                violations=[
                    QuoteDecisionViolation(rule=v.rule, detail=v.detail)
                    for v in result.violations
                ],
            )
        return QuoteDecision(
            action="quote",
            amount_base_units=result.recommended_quote_amount_base_units,
            reason=(
                "Policy passed; recommended quote "
                f"{result.recommended_quote_amount_base_units} base units"
            ),
        )

    async def quote(self, req: IncomingRequest, provider_did: str) -> QuoteResult:
        """Full quote flow: evaluate → build signed QuoteMessage → submit
        on-chain → post on negotiation_channel.

        Channel post failure is non-fatal: on-chain anchor succeeded so the
        buyer can still observe the quote, just won't see the off-chain signed
        body. Mirror of TS ``quote`` (ProviderOrchestrator.ts:224-264).
        """
        decision = self.evaluate_request(req)
        if decision.action == "skip":
            return QuoteResult(decision=decision)

        now = int(time.time())
        currency = self._policy_engine.policy_currency
        decimals = 6  # USDC; TS hardcodes 6 for both branches
        quote = self._quote_builder.build(
            QuoteParams(
                tx_id=req.tx_id,
                provider=provider_did,
                consumer=req.consumer,
                quoted_amount=decision.amount_base_units,  # type: ignore[arg-type]
                original_amount=req.offered_amount,
                max_price=req.max_price,
                currency=currency,
                decimals=decimals,
                expires_at=now + self._policy_engine.quote_ttl_seconds,
                chain_id=self._chain_id,
                kernel_address=self._kernel_address,
            )
        )

        await self._runtime.submit_quote(req.tx_id, quote)

        if self._negotiation_channel is not None:
            try:
                await self._negotiation_channel.post(
                    req.tx_id,
                    NegotiationMessage(type=QUOTE_ENVELOPE, message=quote),
                )
            except Exception as err:  # noqa: BLE001 — channel post is non-fatal
                return QuoteResult(
                    decision=decision, quote=quote, channel_error=str(err)
                )

        # Seed per-tx state so a follow-up counter is evaluated with the right
        # last_quote baseline if the listener is running.
        self._tx_states[req.tx_id] = _TxState(
            last_quote=quote,
            requotes_used=0,
            consumer_did=req.consumer,
        )

        return QuoteResult(decision=decision, quote=quote)

    # --------------------------------------------------------------------------
    # Long-running listener (channel-driven, multi-round)
    # --------------------------------------------------------------------------

    async def start(self) -> Subscription:
        """Subscribe to the negotiation channel and auto-respond to incoming
        counter-offers per ``counter_strategy``. Idempotent — calling start()
        twice replaces the previous subscription.

        Mirror of TS ``start`` (ProviderOrchestrator.ts:279-309).

        Raises:
            ValueError: if ``negotiation_channel`` or ``provider_did`` is unset.
        """
        if self._negotiation_channel is None:
            raise ValueError(
                "ProviderOrchestrator.start() requires negotiation_channel in config"
            )
        if not self._provider_did:
            raise ValueError(
                "ProviderOrchestrator.start() requires provider_did in config"
            )

        # Replace any prior subscription.
        if self._channel_subscription is not None:
            self._channel_subscription.unsubscribe()

        async def on_message(tx_id: str, delivered: DeliveredMessage) -> None:
            if not is_counter_offer_envelope(delivered.envelope):
                return
            try:
                await self._handle_incoming_counter(tx_id, delivered.envelope.message)
            except Exception as err:  # noqa: BLE001
                self._log(
                    "error",
                    f"Counter handler crashed for tx {tx_id[:12]}…: {err}",
                )

        sub = self._negotiation_channel.subscribe_agent(self._provider_did, on_message)
        self._channel_subscription = sub
        self._log(
            "info",
            f"ProviderOrchestrator listening on channel for {self._provider_did}",
        )

        outer = self

        def _unsub() -> None:
            sub.unsubscribe()
            outer._channel_subscription = None
            outer._log("info", "ProviderOrchestrator stopped")

        return Subscription(unsubscribe=_unsub)

    def stop(self) -> None:
        """Stop the active channel subscription if any. Idempotent.

        Mirror of TS ``stop`` (ProviderOrchestrator.ts:314-319).
        """
        if self._channel_subscription is not None:
            self._channel_subscription.unsubscribe()
            self._channel_subscription = None

    # --------------------------------------------------------------------------
    # Single-shot counter evaluation
    # --------------------------------------------------------------------------

    async def evaluate_counter(
        self,
        counter: CounterOfferMessage,
        last_quote_amount_base_units: Optional[str] = None,
        requotes_used: int = 0,
    ) -> CounterDecision:
        """Verify + evaluate a buyer counter-offer. Returns the decision
        (accept / reject / requote with concession amount). Does NOT send any
        response — caller drives the next step. Use ``start()`` for autonomous
        operation.

        Verification (signature / band / expiry) ALWAYS runs first; a custom
        ``counter_decider`` replaces ONLY the decision. Mirror of TS
        ``evaluateCounter`` (ProviderOrchestrator.ts:338-362).

        Raises:
            Exception: if the counter signature / band / expiry fails verify.
        """
        # Verification is mandatory and runs before any decision logic.
        self._counter_verifier.verify(counter, self._kernel_address)
        last_amount = (
            last_quote_amount_base_units
            if last_quote_amount_base_units is not None
            else counter.quoteAmount
        )

        # BYO-brain routing + built-in policy math both live in the engine's
        # decide_counter (Wave-5 provider_policy.py). It already handles the
        # injected counter_decider and maps CounterEvaluation → CounterDecision.
        result = self._policy_engine.decide_counter(
            counter,
            last_quote_amount_base_units=last_amount,
            requotes_used=requotes_used,
        )
        if inspect.isawaitable(result):
            return await result
        return result

    def get_policy(self) -> ProviderPolicy:
        """Read-only policy accessor for UIs and tests."""
        return self._policy

    # --------------------------------------------------------------------------
    # Internals
    # --------------------------------------------------------------------------

    async def _handle_incoming_counter(
        self, tx_id: str, counter: CounterOfferMessage
    ) -> None:
        """Mirror of TS ``_handleIncomingCounter`` (ProviderOrchestrator.ts:373-453)."""
        if not self._provider_did or self._negotiation_channel is None:
            return

        # Look up per-tx state. If we never quoted (counter arrived without a
        # prior quote() call), still process — counter.quoteAmount is the
        # provider's quote per buyer's view, so we use it as baseline.
        state = self._tx_states.get(tx_id) or _TxState(
            last_quote=None,
            requotes_used=0,
            consumer_did=counter.consumer,
        )
        last_amount = (
            state.last_quote.quoted_amount
            if state.last_quote is not None
            else counter.quoteAmount
        )

        try:
            decision = await self.evaluate_counter(
                counter, last_amount, state.requotes_used
            )
        except Exception as err:  # noqa: BLE001 — verify failed → drop
            self._log(
                "warn",
                f"[counter] tx={tx_id[:12]}… verify failed: {err}",
            )
            return

        self._log(
            "info",
            f"[counter] tx={tx_id[:12]}… counter={counter.counterAmount} "
            f"→ {decision.action}: {decision.reason}",
        )

        if decision.action == "accept":
            accept = self._counter_accept_builder.build(
                CounterAcceptParams(
                    txId=tx_id,
                    provider=self._provider_did,
                    consumer=counter.consumer,
                    acceptedAmount=counter.counterAmount,
                    inReplyTo=CounterOfferBuilder().compute_hash(counter),
                    chainId=self._chain_id,
                    kernelAddress=self._kernel_address,
                )
            )
            await self._negotiation_channel.post(
                tx_id,
                NegotiationMessage(type=COUNTERACCEPT_ENVELOPE, message=accept),
            )
            self._tx_states.pop(tx_id, None)  # terminal
            return

        if decision.action == "requote":
            now = int(time.time())
            currency = self._policy_engine.policy_currency
            decimals = 6
            # QuoteBuilder enforces quoted_amount >= original_amount (AIP-2
            # invariant). For re-quotes the buyer's original amount lives
            # on-chain as tx.amount (immutable until acceptQuote). Fall back to
            # counter.counterAmount if the read fails.
            original_amount = counter.counterAmount
            try:
                on_chain_tx = await self._runtime.get_transaction(tx_id)
                if on_chain_tx is not None and getattr(on_chain_tx, "amount", None):
                    original_amount = str(on_chain_tx.amount)
            except Exception:  # noqa: BLE001 — fall back to counter.counterAmount
                pass

            new_quote = self._quote_builder.build(
                QuoteParams(
                    tx_id=tx_id,
                    provider=self._provider_did,
                    consumer=counter.consumer,
                    quoted_amount=decision.amount_base_units,  # type: ignore[arg-type]
                    original_amount=original_amount,
                    max_price=counter.maxPrice,
                    currency=currency,
                    decimals=decimals,
                    expires_at=now + self._policy_engine.quote_ttl_seconds,
                    chain_id=self._chain_id,
                    kernel_address=self._kernel_address,
                )
            )
            # Re-quotes are off-chain only — kernel forbids QUOTED → QUOTED.
            await self._negotiation_channel.post(
                tx_id,
                NegotiationMessage(type=QUOTE_ENVELOPE, message=new_quote),
            )
            self._tx_states[tx_id] = _TxState(
                last_quote=new_quote,
                requotes_used=state.requotes_used + 1,
                consumer_did=counter.consumer,
            )
            return

        # reject — let buyer's TTL expire to CANCELLED. Drop state.
        self._tx_states.pop(tx_id, None)


# ----------------------------------------------------------------------------
# Nonce adapter — QuoteBuilder expects get_next_nonce / record_nonce; the
# AIP-2.1 MessageNonceManager already exposes exactly that interface, so this
# is a transparent pass-through kept explicit for clarity + future-proofing.
# ----------------------------------------------------------------------------


class _QuoteNonceAdapter:
    def __init__(self, nm: MessageNonceManager) -> None:
        self._nm = nm

    def get_next_nonce(self, message_type: str) -> int:
        return self._nm.get_next_nonce(message_type)

    def record_nonce(self, message_type: str, nonce: int) -> None:
        self._nm.record_nonce(message_type, nonce)


__all__ = [
    "ProviderOrchestrator",
    "ProviderOrchestratorConfig",
    "QuoteDecision",
    "QuoteDecisionViolation",
    "QuoteResult",
]
