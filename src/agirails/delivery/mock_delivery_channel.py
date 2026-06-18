"""
AIP-16 Delivery Surface — MockDeliveryChannel (Python port).

Mirrors sdk-js/src/delivery/MockDeliveryChannel.ts. In-process loopback
:class:`DeliveryChannel` for unit tests and MockRuntime flows. Verification is
performed in-channel using the same builder ``verify()`` methods that
:class:`RelayDeliveryChannel` consumers run on read.

Security invariants (TS MockDeliveryChannel.ts:15):
  1. Dedup AFTER verify.
  2. Subscriber error isolation (callbacks wrapped; errors swallowed+logged).
  3. Replay on subscribe (full historical set delivered first).
  4. Address comparison case-insensitivity (txId lowercased for store keys).

Async model: TS uses ``queueMicrotask`` to defer fan-out/replay until after
``publish``/``subscribe`` returns. Python uses ``asyncio.ensure_future`` /
``loop.call_soon`` deferral so ``publish_*`` resolves before any callback
runs, matching the TS poll-tick boundary.

Cite: sdk-js/src/delivery/MockDeliveryChannel.ts.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from agirails.delivery.channel import (
    DeliveryChannel,
    DeliverySubscription,
    EnvelopeCallback,
    SetupCallback,
)
from agirails.delivery.channel_log import LogFn, noop_log
from agirails.delivery.envelope_builder import DeliveryEnvelopeBuilder
from agirails.delivery.setup_builder import DeliverySetupBuilder
from agirails.delivery.types import DeliveryEnvelopeWireV1, DeliverySetupWireV1


# ============================================================================
# Public options (TS MockDeliveryChannel.ts:95)
# ============================================================================


@dataclass
class MockDeliveryChannelOptions:
    """Construction options for :class:`MockDeliveryChannel` (TS:95)."""

    log: LogFn = noop_log
    skip_verify_for_tests: bool = False
    expected_kernel_address: Optional[str] = None
    expected_chain_id: Optional[int] = None
    now: Optional[object] = None  # callable returning Unix seconds


# ============================================================================
# Internal state (TS MockDeliveryChannel.ts:147-173)
# ============================================================================


@dataclass
class _SetupStore:
    setups: List[DeliverySetupWireV1] = field(default_factory=list)
    dedup: Set[str] = field(default_factory=set)


@dataclass
class _EnvelopeStore:
    envelopes: List[DeliveryEnvelopeWireV1] = field(default_factory=list)
    dedup: Set[str] = field(default_factory=set)


# eq=False → identity-based hashing so subscribers can live in a ``set`` even
# though they carry mutable fields (delivered set, cancelled flag).
@dataclass(eq=False)
class _SetupSubscriber:
    callback: SetupCallback
    delivered: Set[str] = field(default_factory=set)
    cancelled: bool = False


@dataclass(eq=False)
class _EnvelopeSubscriber:
    callback: EnvelopeCallback
    delivered: Set[str] = field(default_factory=set)
    cancelled: bool = False


class _MockSubscription(DeliverySubscription):
    """Subscription handle returned from ``subscribe_*`` (TS:370 close())."""

    def __init__(self, on_close) -> None:
        self._on_close = on_close
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._on_close()


# ============================================================================
# MockDeliveryChannel (TS MockDeliveryChannel.ts:204)
# ============================================================================


class MockDeliveryChannel(DeliveryChannel):
    """In-process loopback delivery channel (TS MockDeliveryChannel.ts:204)."""

    def __init__(self, opts: Optional[MockDeliveryChannelOptions] = None) -> None:
        opts = opts or MockDeliveryChannelOptions()
        self._log: LogFn = opts.log or noop_log
        self._skip_verify = opts.skip_verify_for_tests
        self._expected_kernel_address = opts.expected_kernel_address
        self._expected_chain_id = opts.expected_chain_id
        self._now_fn = opts.now

        self._setup_store_by_tx: Dict[str, _SetupStore] = {}
        self._envelope_store_by_tx: Dict[str, _EnvelopeStore] = {}
        self._setup_subs_by_tx: Dict[str, Set[_SetupSubscriber]] = {}
        self._envelope_subs_by_tx: Dict[str, Set[_EnvelopeSubscriber]] = {}

        self._closed = False

    # ------------------------------------------------------------------
    # publish (TS MockDeliveryChannel.ts:230 / :283)
    # ------------------------------------------------------------------

    async def publish_setup(self, setup: DeliverySetupWireV1) -> None:
        if self._closed:
            raise RuntimeError("MockDeliveryChannel: channel is closed")

        # Step 1: verify (unless disabled for tests). TS:236.
        if not self._skip_verify:
            verify_result = DeliverySetupBuilder.verify(
                setup,
                expected_kernel_address=(
                    self._expected_kernel_address or setup["signed"]["kernelAddress"]
                ),
                expected_chain_id=(
                    self._expected_chain_id
                    if self._expected_chain_id is not None
                    else setup["signed"]["chainId"]
                ),
                now=self._now(),
            )
            if not verify_result.ok:
                self._log(
                    "warn",
                    "MockDeliveryChannel: setup verify failed",
                    {
                        "code": verify_result.code,
                        "error": verify_result.error,
                        "txId": setup["signed"]["txId"],
                    },
                )
                err = RuntimeError(
                    f"MockDeliveryChannel: setup verify failed: "
                    f"{verify_result.code}: {verify_result.error}"
                )
                err.code = verify_result.code  # type: ignore[attr-defined]
                raise err

        # Step 2: dedup hash AFTER verify (security invariant #1, TS:259).
        h = DeliverySetupBuilder.compute_hash(setup)

        tx_id = setup["signed"]["txId"].lower()
        store = self._setup_store_by_tx.get(tx_id)
        if store is None:
            store = _SetupStore()
            self._setup_store_by_tx[tx_id] = store

        if h in store.dedup:
            return  # idempotent re-publish (TS:268)

        store.dedup.add(h)
        store.setups.append(setup)

        # Step 3: fan out deferred so publish() resolves first (TS:280).
        self._fanout_setup(tx_id, setup)

    async def publish_envelope(self, envelope: DeliveryEnvelopeWireV1) -> None:
        if self._closed:
            raise RuntimeError("MockDeliveryChannel: channel is closed")

        if not self._skip_verify:
            verify_result = DeliveryEnvelopeBuilder.verify(
                envelope,
                expected_kernel_address=(
                    self._expected_kernel_address or envelope["signed"]["kernelAddress"]
                ),
                expected_chain_id=(
                    self._expected_chain_id
                    if self._expected_chain_id is not None
                    else envelope["signed"]["chainId"]
                ),
                now=self._now(),
            )
            if not verify_result.ok:
                self._log(
                    "warn",
                    "MockDeliveryChannel: envelope verify failed",
                    {
                        "code": verify_result.code,
                        "error": verify_result.error,
                        "txId": envelope["signed"]["txId"],
                    },
                )
                err = RuntimeError(
                    f"MockDeliveryChannel: envelope verify failed: "
                    f"{verify_result.code}: {verify_result.error}"
                )
                err.code = verify_result.code  # type: ignore[attr-defined]
                raise err

        h = DeliveryEnvelopeBuilder.compute_hash(envelope)

        tx_id = envelope["signed"]["txId"].lower()
        store = self._envelope_store_by_tx.get(tx_id)
        if store is None:
            store = _EnvelopeStore()
            self._envelope_store_by_tx[tx_id] = store

        if h in store.dedup:
            return

        store.dedup.add(h)
        store.envelopes.append(envelope)

        self._fanout_envelope(tx_id, envelope)

    # ------------------------------------------------------------------
    # subscribe (TS MockDeliveryChannel.ts:332 / :384)
    # ------------------------------------------------------------------

    async def subscribe_setups(
        self, tx_id: str, callback: SetupCallback
    ) -> DeliverySubscription:
        if self._closed:
            raise RuntimeError("MockDeliveryChannel: channel is closed")

        tx_id_lc = tx_id.lower()
        sub = _SetupSubscriber(callback=callback)

        subs = self._setup_subs_by_tx.get(tx_id_lc)
        if subs is None:
            subs = set()
            self._setup_subs_by_tx[tx_id_lc] = subs
        subs.add(sub)

        # Replay-on-subscribe deferred so subscribe() returns the handle
        # before any callback fires (TS MockDeliveryChannel.ts:358).
        store = self._setup_store_by_tx.get(tx_id_lc)
        if store is not None:
            snapshot = list(store.setups)

            def replay() -> None:
                if sub.cancelled:
                    return
                for wire in snapshot:
                    if sub.cancelled:
                        break
                    self._deliver_setup(sub, wire)

            _defer(replay)

        def on_close() -> None:
            sub.cancelled = True
            current = self._setup_subs_by_tx.get(tx_id_lc)
            if current is not None:
                current.discard(sub)
                if len(current) == 0:
                    self._setup_subs_by_tx.pop(tx_id_lc, None)

        return _MockSubscription(on_close)

    async def subscribe_envelopes(
        self, tx_id: str, callback: EnvelopeCallback
    ) -> DeliverySubscription:
        if self._closed:
            raise RuntimeError("MockDeliveryChannel: channel is closed")

        tx_id_lc = tx_id.lower()
        sub = _EnvelopeSubscriber(callback=callback)

        subs = self._envelope_subs_by_tx.get(tx_id_lc)
        if subs is None:
            subs = set()
            self._envelope_subs_by_tx[tx_id_lc] = subs
        subs.add(sub)

        store = self._envelope_store_by_tx.get(tx_id_lc)
        if store is not None:
            snapshot = list(store.envelopes)

            def replay() -> None:
                if sub.cancelled:
                    return
                for wire in snapshot:
                    if sub.cancelled:
                        break
                    self._deliver_envelope(sub, wire)

            _defer(replay)

        def on_close() -> None:
            sub.cancelled = True
            current = self._envelope_subs_by_tx.get(tx_id_lc)
            if current is not None:
                current.discard(sub)
                if len(current) == 0:
                    self._envelope_subs_by_tx.pop(tx_id_lc, None)

        return _MockSubscription(on_close)

    # ------------------------------------------------------------------
    # snapshot accessors (TS MockDeliveryChannel.ts:436 / :440)
    # ------------------------------------------------------------------

    async def get_setups(self, tx_id: Optional[str] = None) -> List[DeliverySetupWireV1]:
        return self.get_all_setups(tx_id)

    async def get_envelopes(
        self, tx_id: Optional[str] = None
    ) -> List[DeliveryEnvelopeWireV1]:
        return self.get_all_envelopes(tx_id)

    # ------------------------------------------------------------------
    # test helpers (TS MockDeliveryChannel.ts:453 / :470 / :486 / :497)
    # ------------------------------------------------------------------

    def get_all_setups(self, tx_id: Optional[str] = None) -> List[DeliverySetupWireV1]:
        """Synchronous snapshot of setups (defensive copy) — TS:453."""
        if tx_id is None:
            out: List[DeliverySetupWireV1] = []
            for store in self._setup_store_by_tx.values():
                out.extend(store.setups)
            return out
        store = self._setup_store_by_tx.get(tx_id.lower())
        return list(store.setups) if store else []

    def get_all_envelopes(
        self, tx_id: Optional[str] = None
    ) -> List[DeliveryEnvelopeWireV1]:
        """Synchronous snapshot of envelopes (defensive copy) — TS:470."""
        if tx_id is None:
            out: List[DeliveryEnvelopeWireV1] = []
            for store in self._envelope_store_by_tx.values():
                out.extend(store.envelopes)
            return out
        store = self._envelope_store_by_tx.get(tx_id.lower())
        return list(store.envelopes) if store else []

    def active_subscription_count(self) -> int:
        """Count of active subscriptions (setup + envelope) — TS:486."""
        n = 0
        for subs in self._setup_subs_by_tx.values():
            n += len(subs)
        for subs in self._envelope_subs_by_tx.values():
            n += len(subs)
        return n

    def clear(self) -> None:
        """Reset stored state (subscriber lists preserved) — TS:497."""
        self._setup_store_by_tx.clear()
        self._envelope_store_by_tx.clear()

    async def close(self) -> None:
        """Cancel + drop all subscriptions; preserve storage (TS:507)."""
        if self._closed:
            return
        self._closed = True
        for subs in self._setup_subs_by_tx.values():
            for s in subs:
                s.cancelled = True
        for subs in self._envelope_subs_by_tx.values():
            for s in subs:
                s.cancelled = True
        self._setup_subs_by_tx.clear()
        self._envelope_subs_by_tx.clear()

    # ------------------------------------------------------------------
    # internals — fan-out (TS MockDeliveryChannel.ts:524 / :538)
    # ------------------------------------------------------------------

    def _fanout_setup(self, tx_id_lc: str, wire: DeliverySetupWireV1) -> None:
        subs = self._setup_subs_by_tx.get(tx_id_lc)
        if not subs:
            return
        snapshot = list(subs)

        def run() -> None:
            for sub in snapshot:
                if sub.cancelled:
                    continue
                self._deliver_setup(sub, wire)

        _defer(run)

    def _fanout_envelope(self, tx_id_lc: str, wire: DeliveryEnvelopeWireV1) -> None:
        subs = self._envelope_subs_by_tx.get(tx_id_lc)
        if not subs:
            return
        snapshot = list(subs)

        def run() -> None:
            for sub in snapshot:
                if sub.cancelled:
                    continue
                self._deliver_envelope(sub, wire)

        _defer(run)

    # ------------------------------------------------------------------
    # internals — deliver (TS MockDeliveryChannel.ts:560 / :576)
    # ------------------------------------------------------------------

    def _deliver_setup(self, sub: _SetupSubscriber, wire: DeliverySetupWireV1) -> None:
        sig = wire["requesterSig"]
        if sig in sub.delivered:
            return
        sub.delivered.add(sig)
        self._invoke(sub.callback, wire, "setup", wire["signed"]["txId"])

    def _deliver_envelope(
        self, sub: _EnvelopeSubscriber, wire: DeliveryEnvelopeWireV1
    ) -> None:
        sig = wire["providerSig"]
        if sig in sub.delivered:
            return
        sub.delivered.add(sig)
        self._invoke(sub.callback, wire, "envelope", wire["signed"]["txId"])

    def _invoke(self, callback, wire, kind: str, tx_id: str) -> None:
        """Invoke a subscriber callback with error isolation (TS invariant #2).

        Sync callbacks run inline; coroutine results are scheduled as tasks.
        Any error is caught, logged at ``warn``, and swallowed so one bad
        subscriber cannot halt fan-out.
        """
        try:
            result = callback(wire)
        except Exception as e:  # noqa: BLE001
            self._log(
                "warn",
                f"MockDeliveryChannel: {kind} subscriber threw",
                {"error": str(e), "txId": tx_id},
            )
            return

        if inspect.isawaitable(result):
            async def _await_isolated() -> None:
                try:
                    await result
                except Exception as e:  # noqa: BLE001
                    self._log(
                        "warn",
                        f"MockDeliveryChannel: {kind} subscriber threw",
                        {"error": str(e), "txId": tx_id},
                    )

            try:
                asyncio.ensure_future(_await_isolated())
            except RuntimeError:
                # No running loop (sync test context) — run to completion.
                asyncio.get_event_loop().run_until_complete(_await_isolated())

    def _now(self) -> Optional[int]:
        if self._now_fn is None:
            return None
        return self._now_fn()


# ============================================================================
# Deferral helper — TS ``queueMicrotask`` analogue
# ============================================================================


def _defer(fn) -> None:
    """Schedule ``fn`` to run after the current call returns.

    Mirrors TS ``queueMicrotask`` (fan-out / replay run on the next tick so
    ``publish_*`` / ``subscribe_*`` resolve before any callback fires). When a
    running event loop exists we use ``loop.call_soon``; otherwise (a fully
    synchronous test context with no loop) we run inline — the callbacks
    themselves are still error-isolated.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon(fn)
    except RuntimeError:
        # No running loop — execute inline (sync test path).
        fn()


__all__ = [
    "MockDeliveryChannel",
    "MockDeliveryChannelOptions",
]
