"""
NegotiationChannel — single transport abstraction for AIP-2.1 messages.

Python port of ``sdk-js/src/negotiation/NegotiationChannel.ts`` +
``MockChannel.ts``, byte/semantically identical.

All negotiation message flow — buyer↔provider, both directions, all
message types — funnels through ONE interface so:

  1. Verification + binding live in ONE place (every signed message is
     verified at the channel boundary; orchestrators never see unverified
     payloads).
  2. Transport is pluggable (RelayChannel for prod, MockChannel for tests).
  3. Test surface collapses (in-memory MockChannel = no HTTP mocks).

The wire envelope is a ``NegotiationMessage`` discriminated union:
  - ``agirails.quote.v1``        → :class:`QuoteMessage`
  - ``agirails.counteroffer.v1`` → :class:`CounterOfferMessage`
  - ``agirails.counteraccept.v1``→ :class:`CounterAcceptMessage`

@module negotiation/negotiation_channel
@see Protocol/aips/AIP-2.1.md §6 (Negotiation Relay Protocol)
@see sdk-js/src/negotiation/NegotiationChannel.ts
@see sdk-js/src/negotiation/MockChannel.ts
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Protocol,
    Set,
    Union,
    runtime_checkable,
)

from agirails.builders.counter_accept import CounterAcceptBuilder, CounterAcceptMessage
from agirails.builders.counter_offer import CounterOfferBuilder, CounterOfferMessage
from agirails.builders.quote import QuoteBuilder, QuoteMessage

# ============================================================================
# Wire types
# ============================================================================

# Discriminator strings for the three signed message envelopes.
QUOTE_ENVELOPE = "agirails.quote.v1"
COUNTEROFFER_ENVELOPE = "agirails.counteroffer.v1"
COUNTERACCEPT_ENVELOPE = "agirails.counteraccept.v1"

NegotiationMessageType = Literal[
    "agirails.quote.v1",
    "agirails.counteroffer.v1",
    "agirails.counteraccept.v1",
]

_InnerMessage = Union[QuoteMessage, CounterOfferMessage, CounterAcceptMessage]


@dataclass(frozen=True)
class NegotiationMessage:
    """One signed envelope on the channel.

    Mirrors the TS discriminated union ``NegotiationMessage`` — ``type``
    selects which builder verifies ``message``.
    """

    type: NegotiationMessageType
    message: _InnerMessage


@dataclass(frozen=True)
class DeliveredMessage:
    """Per-message metadata the channel attaches when delivering.

    Mirrors TS ``DeliveredMessage``. ``cursor`` lets a subscriber persist a
    resume-point; ``received_at`` is the channel's perspective of when it
    learned about the message (NOT the message's signed timestamp).
    """

    cursor: str
    received_at: int
    envelope: NegotiationMessage


@dataclass
class Subscription:
    """Unsubscribe handle (mirrors TS ``Subscription``).

    ``unsubscribe()`` MUST be idempotent.
    """

    unsubscribe: Callable[[], None]


# ============================================================================
# Type guards (parity with TS isQuoteEnvelope / isCounterOfferEnvelope / …)
# ============================================================================


def is_quote_envelope(e: NegotiationMessage) -> bool:
    return e.type == QUOTE_ENVELOPE


def is_counter_offer_envelope(e: NegotiationMessage) -> bool:
    return e.type == COUNTEROFFER_ENVELOPE


def is_counter_accept_envelope(e: NegotiationMessage) -> bool:
    return e.type == COUNTERACCEPT_ENVELOPE


def envelope_tx_id(e: NegotiationMessage) -> str:
    """Extract the txId carried inside the envelope's signed message.

    Python ``QuoteMessage`` uses ``tx_id``; the counter/accept messages use
    ``txId``. Mirror TS ``envelopeTxId`` (reads ``message.txId``).
    """
    return _msg_tx_id(e.message)


def envelope_chain_id(e: NegotiationMessage) -> int:
    """Extract the chainId carried inside the envelope's signed message."""
    return _msg_chain_id(e.message)


# ----------------------------------------------------------------------------
# Field-access shims — Python QuoteMessage is snake_case (tx_id / chain_id);
# CounterOfferMessage + CounterAcceptMessage are camelCase (txId / chainId).
# These normalize the difference so the channel + orchestrators stay simple.
# ----------------------------------------------------------------------------


def _msg_tx_id(m: _InnerMessage) -> str:
    return getattr(m, "tx_id", None) or m.txId  # type: ignore[union-attr]


def _msg_chain_id(m: _InnerMessage) -> int:
    cid = getattr(m, "chain_id", None)
    return cid if cid is not None else m.chainId  # type: ignore[union-attr]


def _msg_signature(m: _InnerMessage) -> str:
    return m.signature


def _msg_provider(m: _InnerMessage) -> Optional[str]:
    return getattr(m, "provider", None)


def _msg_consumer(m: _InnerMessage) -> Optional[str]:
    return getattr(m, "consumer", None)


# ============================================================================
# Channel interface
# ============================================================================

TxIdCallback = Callable[[DeliveredMessage], Union[None, Awaitable[None]]]
AgentCallback = Callable[[str, DeliveredMessage], Union[None, Awaitable[None]]]


@runtime_checkable
class NegotiationChannel(Protocol):
    """Transport-agnostic AIP-2.1 message bus (mirrors TS ``NegotiationChannel``).

    Implementations are responsible for EIP-712 signature verification BEFORE
    invoking the subscriber callback, dedup, liveness, and error isolation.
    """

    async def post(self, tx_id: str, envelope: NegotiationMessage) -> None:
        ...

    def subscribe_tx_id(self, tx_id: str, on_message: TxIdCallback) -> Subscription:
        ...

    def subscribe_agent(self, agent_did: str, on_message: AgentCallback) -> Subscription:
        ...


# ============================================================================
# MockChannel — in-memory NegotiationChannel for unit tests
# ============================================================================


@dataclass
class _StoredMessage:
    cursor: str
    tx_id: str
    envelope: NegotiationMessage
    received_at: int


@dataclass
class _TxIdSubscriber:
    tx_id: str
    callback: TxIdCallback
    delivered: Set[str] = field(default_factory=set)
    cancelled: bool = False
    kind: str = "txId"


@dataclass
class _AgentSubscriber:
    agent_did: str
    callback: AgentCallback
    delivered: Set[str] = field(default_factory=set)
    cancelled: bool = False
    kind: str = "agent"


@dataclass
class MockChannelConfig:
    """Configuration for :class:`MockChannel` (mirrors TS ``MockChannelConfig``)."""

    #: Kernel address per chainId — used by the channel's EIP-712 verify step.
    #: If missing for a chainId, the message is dropped silently (matches
    #: RelayChannel behavior).
    kernel_address_by_chain_id: Optional[Dict[int, str]] = None
    #: If True, skip signature verification (useful for tests that want to
    #: inject malformed messages). Default: False.
    skip_verify: bool = False


class MockChannel:
    """In-memory :class:`NegotiationChannel`. Mirrors TS ``MockChannel``.

    Two parties can share the same instance to simulate "both parties on the
    same relay". Messages POSTed are delivered asynchronously to all matching
    subscribers on the next event-loop tick (mirrors RelayChannel's poll-tick
    boundary and the TS ``queueMicrotask`` fan-out). Same EIP-712 verifiers as
    the real channel — security regression tests work identically.
    """

    def __init__(self, config: Optional[MockChannelConfig] = None) -> None:
        cfg = config or MockChannelConfig()
        self._subscribers: List[Union[_TxIdSubscriber, _AgentSubscriber]] = []
        self._messages: List[_StoredMessage] = []
        self._cursor_counter = 0
        self._kernels: Dict[int, str] = dict(cfg.kernel_address_by_chain_id or {})
        self._skip_verify = cfg.skip_verify
        self._quote_verifier = QuoteBuilder()
        self._counter_verifier = CounterOfferBuilder()
        self._counter_accept_verifier = CounterAcceptBuilder()
        # Background fan-out tasks we keep references to (so they aren't GC'd
        # mid-flight) — mirrors TS queueMicrotask scheduling.
        self._tasks: Set[asyncio.Task[Any]] = set()

    # -- NegotiationChannel API ---------------------------------------------

    async def post(self, tx_id: str, envelope: NegotiationMessage) -> None:
        """Store + schedule async fan-out (mirrors TS ``post``).

        Returns before any subscriber callback runs — the fan-out is scheduled
        on the event loop so ``post`` always completes first, mirroring the TS
        ``queueMicrotask`` boundary.
        """
        stored = _StoredMessage(
            cursor=str(self._next_cursor()),
            tx_id=tx_id,
            envelope=envelope,
            received_at=int(_now_seconds()),
        )
        self._messages.append(stored)
        self._schedule(self._fanout(stored))

    def subscribe_tx_id(self, tx_id: str, on_message: TxIdCallback) -> Subscription:
        sub = _TxIdSubscriber(tx_id=tx_id, callback=on_message)
        self._subscribers.append(sub)

        async def replay() -> None:
            for m in list(self._messages):
                if sub.cancelled:
                    break
                if m.tx_id == tx_id:
                    await self._deliver_to_sub(sub, m)

        self._schedule(replay())

        def _unsub() -> None:
            sub.cancelled = True
            self._remove_subscriber(sub)

        return Subscription(unsubscribe=_unsub)

    def subscribe_agent(self, agent_did: str, on_message: AgentCallback) -> Subscription:
        sub = _AgentSubscriber(agent_did=agent_did, callback=on_message)
        self._subscribers.append(sub)

        async def replay() -> None:
            for m in list(self._messages):
                if sub.cancelled:
                    break
                if self._envelope_addresses_agent(m.envelope, agent_did):
                    await self._deliver_to_sub(sub, m)

        self._schedule(replay())

        def _unsub() -> None:
            sub.cancelled = True
            self._remove_subscriber(sub)

        return Subscription(unsubscribe=_unsub)

    async def close(self) -> None:
        for s in self._subscribers:
            s.cancelled = True
        self._subscribers.clear()
        # Drain any in-flight fan-out tasks so close() is deterministic.
        pending = [t for t in self._tasks if not t.done()]
        for t in pending:
            try:
                await t
            except Exception:  # noqa: BLE001 — fan-out errors are swallowed by design
                pass
        self._tasks.clear()

    # -- test introspection helpers (NOT part of NegotiationChannel) --------

    def get_all_messages(self) -> List[_StoredMessage]:
        """All messages ever posted, in order."""
        return list(self._messages)

    def get_messages_for_tx_id(self, tx_id: str) -> List[_StoredMessage]:
        """Filter messages by txId."""
        return [m for m in self._messages if m.tx_id == tx_id]

    def active_subscription_count(self) -> int:
        """Number of currently-active subscriptions. Useful for leak tests."""
        return len(self._subscribers)

    async def drain(self) -> None:
        """Await all currently-scheduled fan-out / replay tasks.

        Python has no synchronous microtask queue like JS ``queueMicrotask``;
        tests that want to assert on delivered state after a ``post`` can
        ``await channel.drain()`` to flush pending callbacks deterministically.
        """
        while True:
            pending = [t for t in self._tasks if not t.done()]
            if not pending:
                return
            await asyncio.gather(*pending, return_exceptions=True)

    # -- internals ----------------------------------------------------------

    def _next_cursor(self) -> int:
        self._cursor_counter += 1
        return self._cursor_counter

    def _schedule(self, coro: Awaitable[None]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _remove_subscriber(self, sub: Union[_TxIdSubscriber, _AgentSubscriber]) -> None:
        try:
            self._subscribers.remove(sub)
        except ValueError:
            pass

    async def _fanout(self, stored: _StoredMessage) -> None:
        for sub in list(self._subscribers):
            if sub.cancelled:
                continue
            if isinstance(sub, _TxIdSubscriber) and sub.tx_id == stored.tx_id:
                await self._deliver_to_sub(sub, stored)
            elif isinstance(sub, _AgentSubscriber) and self._envelope_addresses_agent(
                stored.envelope, sub.agent_did
            ):
                await self._deliver_to_sub(sub, stored)

    def _envelope_addresses_agent(
        self, envelope: NegotiationMessage, agent_did: str
    ) -> bool:
        lc = agent_did.lower()
        m = envelope.message
        provider = _msg_provider(m)
        consumer = _msg_consumer(m)
        return (provider is not None and provider.lower() == lc) or (
            consumer is not None and consumer.lower() == lc
        )

    async def _deliver_to_sub(
        self, sub: Union[_TxIdSubscriber, _AgentSubscriber], stored: _StoredMessage
    ) -> None:
        # Same dedup-after-verify ordering as RelayChannel: a tampered message
        # with a reused signature must NOT poison the dedup-set and silently
        # drop the subsequent legitimate message.
        sig = _msg_signature(stored.envelope.message)
        if sig in sub.delivered:
            return

        if not self._skip_verify:
            chain_id = _msg_chain_id(stored.envelope.message)
            kernel_address = self._kernels.get(chain_id)
            if not kernel_address:
                return  # silently drop unknown chain
            try:
                if is_quote_envelope(stored.envelope):
                    self._quote_verifier.verify(stored.envelope.message, kernel_address)
                elif is_counter_offer_envelope(stored.envelope):
                    self._counter_verifier.verify(
                        stored.envelope.message, kernel_address
                    )
                elif is_counter_accept_envelope(stored.envelope):
                    self._counter_accept_verifier.verify(
                        stored.envelope.message, kernel_address
                    )
            except Exception:  # noqa: BLE001 — verify failure → drop, mirror RelayChannel
                return

        # Verify passed (or was skipped) → safe to dedup.
        sub.delivered.add(sig)

        delivered = DeliveredMessage(
            cursor=stored.cursor,
            received_at=stored.received_at,
            envelope=stored.envelope,
        )
        try:
            if isinstance(sub, _TxIdSubscriber):
                result = sub.callback(delivered)
            else:
                result = sub.callback(stored.tx_id, delivered)
            if asyncio.iscoroutine(result):
                await result
        except Exception:  # noqa: BLE001 — channel must not propagate subscriber errors
            pass


def _now_seconds() -> float:
    import time as _time

    return _time.time()


__all__ = [
    "QUOTE_ENVELOPE",
    "COUNTEROFFER_ENVELOPE",
    "COUNTERACCEPT_ENVELOPE",
    "NegotiationMessageType",
    "NegotiationMessage",
    "DeliveredMessage",
    "Subscription",
    "NegotiationChannel",
    "MockChannel",
    "MockChannelConfig",
    "is_quote_envelope",
    "is_counter_offer_envelope",
    "is_counter_accept_envelope",
    "envelope_tx_id",
    "envelope_chain_id",
]
