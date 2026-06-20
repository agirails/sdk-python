"""
AIP-16 Delivery Surface — RelayDeliveryChannel (Python port).

Mirrors sdk-js/src/delivery/RelayDeliveryChannel.ts. HTTP-backed
:class:`DeliveryChannel` that talks to the AGIRAILS relay (or any compatible
relay implementing the same REST surface) for posting + observing delivery
setup / envelope wire objects.

Mirrors the TS design:
  - POST/GET endpoints under ``/api/v1/delivery/...`` (same shapes as TS).
  - Subscriptions poll on a fixed interval (1000ms default).
  - Cursor pagination on GETs (``?after=<cursor>``).
  - SSRF guard on ``base_url`` via :func:`validate_endpoint_url`
    (``allow_private_hosts=True`` bypasses for dev/test, matching TS's
    ``allowPrivateHosts``).
  - Request timeout on every POST + GET (8s default).
  - Dedup-after-verify on read (an unverified item never poisons the dedup
    set).
  - Subscriber errors caught + logged so one bad subscriber cannot halt the
    poll loop.

HTTP via ``httpx.AsyncClient`` (an existing dependency). Polling uses
``asyncio`` background tasks instead of TS ``setTimeout``.

Cite: sdk-js/src/delivery/RelayDeliveryChannel.ts.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote as url_quote

import httpx

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
from agirails.utils.validation import validate_endpoint_url

# ============================================================================
# Constants (TS RelayDeliveryChannel.ts:62 / :70 / :73)
# ============================================================================

# TS RelayDeliveryChannel.ts:62 — POLL_INTERVAL_MS (seconds in Python)
POLL_INTERVAL_MS = 1000
# TS RelayDeliveryChannel.ts:70 — REQUEST_TIMEOUT_MS
REQUEST_TIMEOUT_MS = 8000
# TS RelayDeliveryChannel.ts:73 — DEFAULT_BASE_URL
_DEFAULT_BASE_URL = "https://agirails.app"


# ============================================================================
# Public options (TS RelayDeliveryChannel.ts:85)
# ============================================================================


@dataclass
class RelayDeliveryChannelOptions:
    """Construction options for :class:`RelayDeliveryChannel` (TS:85)."""

    base_url: Optional[str] = None
    poll_interval_ms: Optional[int] = None
    request_timeout_ms: Optional[int] = None
    http_client: Optional[httpx.AsyncClient] = None  # TS fetchImpl analogue
    log: LogFn = noop_log
    allow_private_hosts: bool = False
    expected_kernel_address: Optional[str] = None
    expected_chain_id: Optional[int] = None
    now: Optional[object] = None  # callable returning Unix seconds


# ============================================================================
# Internal poll state (TS RelayDeliveryChannel.ts:176)
# ============================================================================


# eq=False → identity-based hashing so poll states can live in a ``set``.
@dataclass(eq=False)
class _PollState:
    cursor: Optional[str] = None
    delivered: Set[str] = field(default_factory=set)
    cancelled: bool = False
    task: Optional[asyncio.Task] = None


class _RelaySubscription(DeliverySubscription):
    """Subscription handle for the polling loop (TS:335 close())."""

    def __init__(self, state: _PollState, channel: "RelayDeliveryChannel") -> None:
        self._state = state
        self._channel = channel
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._state.cancelled = True
        if self._state.task is not None:
            self._state.task.cancel()
        self._channel._poll_states.discard(self._state)


# ============================================================================
# RelayDeliveryChannel (TS RelayDeliveryChannel.ts:206)
# ============================================================================


class RelayDeliveryChannel(DeliveryChannel):
    """HTTP relay-backed delivery channel (TS RelayDeliveryChannel.ts:206)."""

    def __init__(self, opts: Optional[RelayDeliveryChannelOptions] = None) -> None:
        opts = opts or RelayDeliveryChannelOptions()
        base = (opts.base_url or _DEFAULT_BASE_URL).rstrip("/")

        # SSRF guard (TS RelayDeliveryChannel.ts:221 assertSafePeerUrl).
        # allow_private_hosts=True fully bypasses the guard (dev/test only),
        # matching TS where ``allowPrivateHosts`` short-circuits assertSafePeerUrl
        # before any host check. Otherwise enforce the full SSRF policy
        # (scheme, localhost aliases, private-IP literals, cloud metadata,
        # and DNS-rebinding resolution).
        if not opts.allow_private_hosts:
            validate_endpoint_url(base, field_name="baseUrl", resolve_dns=True)

        self._base_url = base
        self._poll_interval_ms = (
            opts.poll_interval_ms if opts.poll_interval_ms is not None else POLL_INTERVAL_MS
        )
        self._request_timeout_ms = (
            opts.request_timeout_ms
            if opts.request_timeout_ms is not None
            else REQUEST_TIMEOUT_MS
        )
        self._owns_client = opts.http_client is None
        self._client = opts.http_client or httpx.AsyncClient(
            timeout=self._request_timeout_ms / 1000.0
        )
        self._log: LogFn = opts.log or noop_log
        self._expected_kernel_address = opts.expected_kernel_address
        self._expected_chain_id = opts.expected_chain_id
        self._now_fn = opts.now

        self._poll_states: Set[_PollState] = set()
        self._closed = False

    # ------------------------------------------------------------------
    # publish (TS RelayDeliveryChannel.ts:235 / :243)
    # ------------------------------------------------------------------

    async def publish_setup(self, setup: DeliverySetupWireV1) -> None:
        if self._closed:
            raise RuntimeError("RelayDeliveryChannel: channel is closed")
        url = f"{self._base_url}/api/v1/delivery/setup"
        await self._post_json(url, setup)

    async def publish_envelope(self, envelope: DeliveryEnvelopeWireV1) -> None:
        if self._closed:
            raise RuntimeError("RelayDeliveryChannel: channel is closed")
        url = f"{self._base_url}/api/v1/delivery"
        await self._post_json(url, envelope)

    # ------------------------------------------------------------------
    # get (TS RelayDeliveryChannel.ts:255 / :269)
    # ------------------------------------------------------------------

    async def get_setups(
        self, tx_id: Optional[str] = None, after: Optional[str] = None
    ) -> List[DeliverySetupWireV1]:
        if tx_id is None:
            return []
        url = f"{self._base_url}/api/v1/delivery/setup/{url_quote(tx_id, safe='')}"
        if after:
            url += f"?after={url_quote(after, safe='')}"
        body = await self._get_json(url)
        return [item["wire"] for item in (body.get("items") or [])]

    async def get_envelopes(
        self, tx_id: Optional[str] = None, after: Optional[str] = None
    ) -> List[DeliveryEnvelopeWireV1]:
        if tx_id is None:
            return []
        url = f"{self._base_url}/api/v1/delivery/{url_quote(tx_id, safe='')}"
        if after:
            url += f"?after={url_quote(after, safe='')}"
        body = await self._get_json(url)
        return [item["wire"] for item in (body.get("items") or [])]

    # ------------------------------------------------------------------
    # subscribe (TS RelayDeliveryChannel.ts:287 / :344)
    # ------------------------------------------------------------------

    async def subscribe_setups(
        self, tx_id: str, callback: SetupCallback
    ) -> DeliverySubscription:
        if self._closed:
            raise RuntimeError("RelayDeliveryChannel: channel is closed")
        state = _PollState()
        self._poll_states.add(state)

        async def poll_loop() -> None:
            # First tick immediate (TS uses setTimeout(pollOnce, 0)).
            while not state.cancelled:
                try:
                    url = (
                        f"{self._base_url}/api/v1/delivery/setup/"
                        f"{url_quote(tx_id, safe='')}"
                    )
                    if state.cursor:
                        url += f"?after={url_quote(state.cursor, safe='')}"
                    body = await self._get_json(url)
                    for item in body.get("items") or []:
                        if state.cancelled:
                            break
                        await self._deliver_setup(item, state, callback)
                        state.cursor = item.get("cursor")
                except asyncio.CancelledError:
                    raise
                except Exception as err:  # noqa: BLE001
                    self._log(
                        "warn",
                        "RelayDeliveryChannel: setup poll error",
                        {"txId": tx_id, "error": str(err)},
                    )
                if state.cancelled:
                    break
                await asyncio.sleep(self._poll_interval_ms / 1000.0)

        state.task = asyncio.ensure_future(poll_loop())
        return _RelaySubscription(state, self)

    async def subscribe_envelopes(
        self, tx_id: str, callback: EnvelopeCallback
    ) -> DeliverySubscription:
        if self._closed:
            raise RuntimeError("RelayDeliveryChannel: channel is closed")
        state = _PollState()
        self._poll_states.add(state)

        async def poll_loop() -> None:
            while not state.cancelled:
                try:
                    url = (
                        f"{self._base_url}/api/v1/delivery/"
                        f"{url_quote(tx_id, safe='')}"
                    )
                    if state.cursor:
                        url += f"?after={url_quote(state.cursor, safe='')}"
                    body = await self._get_json(url)
                    for item in body.get("items") or []:
                        if state.cancelled:
                            break
                        await self._deliver_envelope(item, state, callback)
                        state.cursor = item.get("cursor")
                except asyncio.CancelledError:
                    raise
                except Exception as err:  # noqa: BLE001
                    self._log(
                        "warn",
                        "RelayDeliveryChannel: envelope poll error",
                        {"txId": tx_id, "error": str(err)},
                    )
                if state.cancelled:
                    break
                await asyncio.sleep(self._poll_interval_ms / 1000.0)

        state.task = asyncio.ensure_future(poll_loop())
        return _RelaySubscription(state, self)

    # ------------------------------------------------------------------
    # close (TS RelayDeliveryChannel.ts:404)
    # ------------------------------------------------------------------

    async def close(self) -> None:
        self._closed = True
        for state in list(self._poll_states):
            state.cancelled = True
            if state.task is not None:
                state.task.cancel()
        self._poll_states.clear()
        if self._owns_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # internals — deliver (TS RelayDeliveryChannel.ts:421 / :462)
    # ------------------------------------------------------------------

    async def _deliver_setup(
        self, item: Dict[str, Any], state: _PollState, callback: SetupCallback
    ) -> None:
        wire = item["wire"]
        # Verify FIRST — dedup AFTER verify (TS:428).
        verify_result = DeliverySetupBuilder.verify(
            wire,
            expected_kernel_address=(
                self._expected_kernel_address or wire["signed"]["kernelAddress"]
            ),
            expected_chain_id=(
                self._expected_chain_id
                if self._expected_chain_id is not None
                else wire["signed"]["chainId"]
            ),
            now=self._now(),
        )
        if not verify_result.ok:
            self._log(
                "warn",
                "RelayDeliveryChannel: dropping unverified setup",
                {
                    "code": verify_result.code,
                    "error": verify_result.error,
                    "txId": wire["signed"]["txId"],
                },
            )
            return

        h = DeliverySetupBuilder.compute_hash(wire)
        if h in state.delivered:
            return
        state.delivered.add(h)

        await self._invoke(callback, wire, "setup", wire["signed"]["txId"])

    async def _deliver_envelope(
        self, item: Dict[str, Any], state: _PollState, callback: EnvelopeCallback
    ) -> None:
        wire = item["wire"]
        verify_result = DeliveryEnvelopeBuilder.verify(
            wire,
            expected_kernel_address=(
                self._expected_kernel_address or wire["signed"]["kernelAddress"]
            ),
            expected_chain_id=(
                self._expected_chain_id
                if self._expected_chain_id is not None
                else wire["signed"]["chainId"]
            ),
            now=self._now(),
        )
        if not verify_result.ok:
            self._log(
                "warn",
                "RelayDeliveryChannel: dropping unverified envelope",
                {
                    "code": verify_result.code,
                    "error": verify_result.error,
                    "txId": wire["signed"]["txId"],
                },
            )
            return

        h = DeliveryEnvelopeBuilder.compute_hash(wire)
        if h in state.delivered:
            return
        state.delivered.add(h)

        await self._invoke(callback, wire, "envelope", wire["signed"]["txId"])

    async def _invoke(self, callback, wire, kind: str, tx_id: str) -> None:
        """Invoke a subscriber callback, isolating its errors (TS:447 / :486)."""
        try:
            result = callback(wire)
            if inspect.isawaitable(result):
                await result
        except Exception as err:  # noqa: BLE001
            self._log(
                "warn",
                f"RelayDeliveryChannel: {kind} subscriber threw",
                {"error": str(err), "txId": tx_id},
            )

    # ------------------------------------------------------------------
    # internals — HTTP (TS RelayDeliveryChannel.ts:502 / :531)
    # ------------------------------------------------------------------

    async def _post_json(self, url: str, body: Any) -> None:
        """POST JSON; resolve on 2xx, raise on non-2xx (TS:502)."""
        timeout = self._request_timeout_ms / 1000.0
        try:
            res = await self._client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
        except httpx.HTTPError as err:
            raise RuntimeError(f"RelayDeliveryChannel POST failed: {err}") from err
        if res.status_code < 200 or res.status_code >= 300:
            text = ""
            try:
                text = res.text
            except Exception:  # noqa: BLE001
                text = ""
            self._log(
                "warn",
                "RelayDeliveryChannel: POST non-2xx",
                {"url": url, "status": res.status_code, "body": text[:256]},
            )
            raise RuntimeError(
                f"RelayDeliveryChannel POST {res.status_code}: {text[:200]}"
            )

    async def _get_json(self, url: str) -> Dict[str, Any]:
        """GET + decode JSON, raise on non-2xx (TS:531)."""
        timeout = self._request_timeout_ms / 1000.0
        res = await self._client.get(url, timeout=timeout)
        if res.status_code < 200 or res.status_code >= 300:
            text = ""
            try:
                text = res.text
            except Exception:  # noqa: BLE001
                text = ""
            raise RuntimeError(
                f"RelayDeliveryChannel GET {res.status_code}: {text[:200]}"
            )
        return res.json()

    def _now(self) -> Optional[int]:
        if self._now_fn is None:
            return None
        return self._now_fn()


__all__ = [
    "RelayDeliveryChannel",
    "RelayDeliveryChannelOptions",
    "POLL_INTERVAL_MS",
    "REQUEST_TIMEOUT_MS",
]
