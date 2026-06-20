"""
AIP-16 Delivery Surface — Channel Abstraction (Python port).

Mirrors sdk-js/src/delivery/channel.ts. Transport-agnostic interface for
posting and observing delivery setup + envelope wire objects between
requester and provider. The channel does NOT perform cryptographic
verification — its only job is to transport already-signed wire objects.

Security invariants binding on all implementations (TS channel.ts:26):
  1. Dedup AFTER verify.
  2. Subscriber error isolation (catch + swallow).
  3. No verification at the channel layer (delegated to the builders).
  4. Address comparison case-insensitivity.

Callbacks may be sync or async (``Callable[..., Optional[Awaitable[None]]]``),
mirroring TS's ``void | Promise<void>`` (channel.ts:129/:138).

Cite: sdk-js/src/delivery/channel.ts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Awaitable, Callable, List, Optional, Union

from agirails.delivery.types import DeliveryEnvelopeWireV1, DeliverySetupWireV1

# ============================================================================
# Callback shapes (TS channel.ts:129 SetupCallback, :138 EnvelopeCallback)
# ============================================================================

# A callback returns either None (sync) or an awaitable (async). The channel
# implementation awaits the result iff it is awaitable.
SetupCallback = Callable[[DeliverySetupWireV1], Union[None, Awaitable[None]]]
EnvelopeCallback = Callable[[DeliveryEnvelopeWireV1], Union[None, Awaitable[None]]]


# ============================================================================
# Subscription handle (TS channel.ts:103 DeliverySubscription)
# ============================================================================


class DeliverySubscription(ABC):
    """Handle returned from a ``subscribe_*`` call (TS channel.ts:103).

    Calling :meth:`close` cancels the subscription. ``close()`` is idempotent
    and MAY be awaited (it can return an awaitable when the implementation
    needs to tear down an in-flight poll).
    """

    @abstractmethod
    def close(self) -> Union[None, Awaitable[None]]:
        """Cancel this subscription (idempotent). TS channel.ts:109."""
        raise NotImplementedError


# ============================================================================
# Channel interface (TS channel.ts:199 DeliveryChannel)
# ============================================================================


class DeliveryChannel(ABC):
    """Transport-agnostic delivery channel (TS channel.ts:199).

    Concrete implementations: :class:`MockDeliveryChannel`,
    :class:`RelayDeliveryChannel`. ``get_setups`` / ``get_envelopes`` /
    ``close`` are OPTIONAL in TS (channel.ts:287/:296/:312); here they have
    default no-op / empty-list implementations so subclasses may override
    only what they support.
    """

    @abstractmethod
    async def publish_setup(self, setup: DeliverySetupWireV1) -> None:
        """Post a fully-signed setup wire object (TS channel.ts:219)."""
        raise NotImplementedError

    @abstractmethod
    async def publish_envelope(self, envelope: DeliveryEnvelopeWireV1) -> None:
        """Post a fully-signed envelope wire object (TS channel.ts:232)."""
        raise NotImplementedError

    @abstractmethod
    async def subscribe_setups(
        self, tx_id: str, callback: SetupCallback
    ) -> DeliverySubscription:
        """Subscribe to setups for ``tx_id`` (TS channel.ts:251)."""
        raise NotImplementedError

    @abstractmethod
    async def subscribe_envelopes(
        self, tx_id: str, callback: EnvelopeCallback
    ) -> DeliverySubscription:
        """Subscribe to envelopes for ``tx_id`` (TS channel.ts:265)."""
        raise NotImplementedError

    # ---- Optional methods (TS channel.ts:287 / :296 / :312) ----

    async def get_setups(self, tx_id: Optional[str] = None) -> List[DeliverySetupWireV1]:
        """Optional: all known setups for ``tx_id`` (TS channel.ts:287)."""
        return []

    async def get_envelopes(
        self, tx_id: Optional[str] = None
    ) -> List[DeliveryEnvelopeWireV1]:
        """Optional: all known envelopes for ``tx_id`` (TS channel.ts:296)."""
        return []

    async def close(self) -> None:
        """Optional: release channel-level resources (TS channel.ts:312)."""
        return None


__all__ = [
    "DeliveryChannel",
    "DeliverySubscription",
    "SetupCallback",
    "EnvelopeCallback",
]
