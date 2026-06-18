"""
QuoteChannelHandler — receive-side handler for AIP-2.1 counter-offer messages.

Python port of a working subset of
``sdk-js/src/transport/QuoteChannel.ts``. Framework-agnostic verifier
that callers wire into FastAPI / Starlette / aiohttp routes via the
:func:`build_channel_path` helper.

Enforces the AIP-2.1 §8 security model:

  - URL path binding: ``/quote-channel/{chainId}/{txId}`` must match
    ``message.chainId`` / ``message.txId``.
  - EIP-712 signature verification via :class:`CounterOfferBuilder`.
  - TTL + grace window so stale traffic is shed cheaply before the
    (expensive) signature recovery step.
  - Nonce dedup so the same signed counter can't be replayed.

Rate limiting is deliberately out of scope — that belongs at the
framework / proxy level (nginx, fastapi-limiter, Cloudflare).

@module server/quote_channel
@see Protocol/aips/AIP-2.1-DRAFT.md §8 (threat model + mitigations)
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferJustification,
    CounterOfferMessage,
)
from agirails.builders.quote import QuoteMessage
from agirails.errors import SignatureVerificationError


# ============================================================================
# Constants
# ============================================================================

TTL_GRACE_SECONDS = 30
DEDUP_TTL_SECONDS = 90_000  # 25h covers max quote TTL + grace


def build_channel_path(chain_id: int, tx_id: str) -> str:
    """Canonical URL path for AIP-2.1 quote channel POSTs."""
    return f"/quote-channel/{chain_id}/{tx_id}"


# ============================================================================
# Client (send side) — mirror of TS QuoteChannelClient
# ============================================================================


def _strip_trailing_slash(url: str) -> str:
    return url[:-1] if url.endswith("/") else url


def assert_safe_peer_url(url: str, allow_insecure_targets: bool) -> None:
    """Reject peer URLs that could SSRF into local / internal infrastructure.

    Python port of TS ``assertSafePeerUrl`` (QuoteChannel.ts:385-469),
    semantically identical. Rules (default, ``allow_insecure_targets=False``):

      - scheme MUST be https
      - hostname MUST NOT be ``localhost`` (or ``*.localhost``)
      - hostname MUST NOT be loopback (127.x, ::1)
      - hostname MUST NOT be link-local (169.254.x, fe80::/10) — covers AWS
        metadata at 169.254.169.254
      - hostname MUST NOT be RFC1918 private (10.x, 172.16-31.x, 192.168.x)
        or IPv6 ULA (fc00::/7)

    Dev mode (``allow_insecure_targets=True``): no restrictions.

    Raises ``ValueError`` if the URL fails the checks (deliberately specific
    messages so callers / tests can assert on them).
    """
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"Invalid peer URL: {url}") from exc
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Invalid peer URL: {url}")

    if allow_insecure_targets:
        return

    if parsed.scheme != "https":
        raise ValueError(
            f"Peer URL must use https:// (got {parsed.scheme}://). "
            "Set allow_insecure_targets=True on the QuoteChannelClient "
            "for dev/test only."
        )

    # urlsplit().hostname already strips IPv6 brackets and lowercases.
    host = parsed.hostname

    # IPv4-mapped IPv6 (::ffff:127.0.0.1 / ::ffff:7f00:1) folds to its v4 form
    # via ipaddress; re-extract so the dotted-quad rules below catch it.
    mapped_dotted = re.match(
        r"^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", host
    )
    mapped_hex = re.match(r"^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$", host)
    if mapped_dotted:
        host = mapped_dotted.group(1)
    elif mapped_hex:
        hi = int(mapped_hex.group(1), 16)
        lo = int(mapped_hex.group(2), 16)
        host = f"{(hi >> 8) & 0xFF}.{hi & 0xFF}.{(lo >> 8) & 0xFF}.{lo & 0xFF}"

    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError(
            f"Peer URL points at localhost ({host}) — refusing (SSRF guard)"
        )

    # IPv4 literals
    ipv4 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", host)
    if ipv4:
        a, b = int(ipv4.group(1)), int(ipv4.group(2))
        if a == 127:
            raise ValueError(
                f"Peer URL points at loopback IP ({host}) — refusing (SSRF guard)"
            )
        if a == 169 and b == 254:
            raise ValueError(
                f"Peer URL points at link-local / cloud-metadata IP ({host}) "
                "— refusing (SSRF guard)"
            )
        if a == 10:
            raise ValueError(
                f"Peer URL points at RFC1918 10.x.x.x ({host}) — refusing (SSRF guard)"
            )
        if a == 192 and b == 168:
            raise ValueError(
                f"Peer URL points at RFC1918 192.168.x.x ({host}) — refusing (SSRF guard)"
            )
        if a == 172 and 16 <= b <= 31:
            raise ValueError(
                f"Peer URL points at RFC1918 172.16-31.x ({host}) — refusing (SSRF guard)"
            )

    # IPv6 literals
    if host == "::1":
        raise ValueError(
            f"Peer URL points at IPv6 loopback ({host}) — refusing (SSRF guard)"
        )
    if host.startswith("fe80:") or host.startswith("fe80::"):
        raise ValueError(
            f"Peer URL points at IPv6 link-local ({host}) — refusing (SSRF guard)"
        )
    if host.startswith("fc") or host.startswith("fd"):
        if re.match(r"^(fc|fd)[0-9a-f]{0,2}:", host):
            raise ValueError(
                f"Peer URL points at IPv6 ULA ({host}) — refusing (SSRF guard)"
            )


@dataclass
class QuoteChannelClientConfig:
    """Configuration for :class:`QuoteChannelClient` (mirrors TS config)."""

    #: Per-request timeout in seconds. Default 10s (TS uses ms; we use s).
    timeout_seconds: float = 10.0
    #: Allow insecure targets (http://, localhost, RFC1918, link-local).
    #: Default False (production hardening). True ONLY for local dev / tests.
    allow_insecure_targets: bool = False


class QuoteChannelClient:
    """HTTPS transport for sending AIP-2.1 quote + counter-offer messages.

    Python port of TS ``QuoteChannelClient`` (QuoteChannel.ts:159-222). Used
    by buyers (posting counter-offers to the provider) and providers (posting
    quotes to the buyer). SSRF-guarded + timeout-bounded.

    Async (``httpx.AsyncClient``) so it composes with the orchestrators'
    asyncio negotiation loops.
    """

    def __init__(self, config: Optional[QuoteChannelClientConfig] = None) -> None:
        cfg = config or QuoteChannelClientConfig()
        self._timeout = cfg.timeout_seconds
        self._allow_insecure = cfg.allow_insecure_targets

    async def send_quote(self, peer_endpoint: str, quote: QuoteMessage) -> None:
        """POST a provider quote to the buyer's endpoint."""
        await self._post(
            peer_endpoint,
            quote.chain_id,
            quote.tx_id,
            {"type": "agirails.quote.v1", "message": quote.to_dict()},
        )

    async def send_counter(
        self, peer_endpoint: str, counter: CounterOfferMessage
    ) -> None:
        """POST a buyer counter-offer to the provider's endpoint."""
        await self._post(
            peer_endpoint,
            counter.chainId,
            counter.txId,
            {"type": "agirails.counteroffer.v1", "message": counter.to_dict()},
        )

    async def _post(
        self,
        peer_endpoint: str,
        chain_id: int,
        tx_id: str,
        payload: Dict[str, Any],
    ) -> None:
        url = f"{_strip_trailing_slash(peer_endpoint)}{build_channel_path(chain_id, tx_id)}"

        # SSRF guard. Peer endpoints come from on-chain AgentRegistry / the
        # agirails.app DB — both technically adversary-writable. Fail fast.
        assert_safe_peer_url(url, self._allow_insecure)

        import httpx

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            res = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if res.status_code >= 400:
                text = ""
                try:
                    text = res.text
                except Exception:  # noqa: BLE001
                    text = ""
                suffix = f" — {text}" if text else ""
                raise RuntimeError(
                    f"Quote channel POST failed: {res.status_code} "
                    f"{res.reason_phrase}{suffix}"
                )


# ============================================================================
# Dedup store
# ============================================================================


class InMemoryDedupStore:
    """Single-process in-memory LRU dedup store.

    Atomic ``record_once`` based on a process-wide lock — concurrent
    workers within the same process see exactly one ``recorded`` per
    key. Multi-worker deployments MUST replace this with a distributed
    store (Redis ``SET NX EX``, etc.).
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._entries: Dict[str, float] = {}
        self._max_size = max_size
        self._lock = threading.Lock()

    def record_once(self, key: str, ttl_ms: int) -> str:
        """Atomic record-if-absent.

        Returns ``"recorded"`` when the key is fresh (caller proceeds
        with side effects) or ``"duplicate"`` when the key was already
        present and unexpired (caller returns idempotent cached
        response).
        """
        now_ms = time.time() * 1000.0
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None and existing > now_ms:
                return "duplicate"
            # Evict expired entries opportunistically when over cap.
            if len(self._entries) >= self._max_size:
                self._entries = {
                    k: exp
                    for k, exp in self._entries.items()
                    if exp > now_ms
                }
                if len(self._entries) >= self._max_size:
                    # Still over cap: drop the oldest entry.
                    oldest = min(self._entries.items(), key=lambda kv: kv[1])
                    self._entries.pop(oldest[0], None)
            self._entries[key] = now_ms + ttl_ms
            return "recorded"


# ============================================================================
# Handler
# ============================================================================


@dataclass(frozen=True)
class HandlerContext:
    """Per-request context derived from the URL path."""

    path_chain_id: int
    path_tx_id: str


@dataclass(frozen=True)
class HandlerResult:
    """Outcome of :meth:`QuoteChannelHandler.handle`.

    ``status`` is the HTTP status code the caller should return.
    ``body`` is a JSON-serializable dict.
    ``parsed_message`` is the typed message when verification succeeded
    (caller may pass it to the policy engine); ``None`` otherwise.
    """

    status: int
    body: Dict[str, Any]
    parsed_message: Optional[CounterOfferMessage] = None


class QuoteChannelHandler:
    """Verifies + dedups incoming AIP-2.1 counter-offer messages.

    Currently only ``agirails.counteroffer.v1`` is supported on the
    Python side — the forward channel (``agirails.quote.v1``) is
    handled by the buyer SDK once the Python ``QuoteBuilder`` gains
    EIP-712 sign/verify symmetry.
    """

    def __init__(
        self,
        kernel_address_by_chain_id: Dict[int, str],
        dedup_store: Optional[InMemoryDedupStore] = None,
        ttl_grace_seconds: int = TTL_GRACE_SECONDS,
    ) -> None:
        self._kernels = dict(kernel_address_by_chain_id)
        self._dedup = dedup_store or InMemoryDedupStore()
        self._ttl_grace = ttl_grace_seconds
        # Verify-only — no signer, no nonce manager.
        self._counter_verifier = CounterOfferBuilder()

    def handle(self, payload: Any, ctx: HandlerContext) -> HandlerResult:
        """Validate, verify, and dedup an incoming POST body.

        Caller is responsible for parsing the request body to JSON and
        parsing the URL path into ``ctx``. The result's ``status`` and
        ``body`` map directly to the HTTP response.
        """
        # 1. Wire shape check.
        if not isinstance(payload, dict):
            return HandlerResult(
                status=400,
                body={"accepted": False, "reason": "Invalid payload shape"},
            )
        if payload.get("type") != "agirails.counteroffer.v1":
            return HandlerResult(
                status=400,
                body={
                    "accepted": False,
                    "reason": (
                        "Only agirails.counteroffer.v1 is supported by "
                        "this handler in v1"
                    ),
                },
            )
        msg_raw = payload.get("message")
        if not isinstance(msg_raw, dict):
            return HandlerResult(
                status=400,
                body={"accepted": False, "reason": "Missing message field"},
            )

        # 2. Parse the counter-offer dict into the typed dataclass.
        try:
            message = _parse_counter_offer(msg_raw)
        except (ValueError, KeyError, TypeError) as exc:
            return HandlerResult(
                status=400,
                body={
                    "accepted": False,
                    "reason": f"Malformed CounterOffer: {exc}",
                },
            )

        # 3. Path binding — URL chainId/txId MUST match message.
        if message.chainId != ctx.path_chain_id:
            return HandlerResult(
                status=400,
                body={
                    "accepted": False,
                    "reason": "chainId mismatch between URL and message",
                },
            )
        if message.txId.lower() != ctx.path_tx_id.lower():
            return HandlerResult(
                status=400,
                body={
                    "accepted": False,
                    "reason": "txId mismatch between URL and message",
                },
            )

        # 4. Kernel address must be configured for this chain.
        kernel_address = self._kernels.get(message.chainId)
        if not kernel_address:
            return HandlerResult(
                status=400,
                body={
                    "accepted": False,
                    "reason": (
                        f"Unsupported chainId: {message.chainId}"
                    ),
                },
            )

        # 5. TTL + grace. Cheap reject BEFORE signature recovery.
        now = int(time.time())
        if message.expiresAt + self._ttl_grace < now:
            return HandlerResult(
                status=410,
                body={"accepted": False, "reason": "Message expired"},
            )

        # 6. EIP-712 signature + business rules (delegated to builder).
        try:
            self._counter_verifier.verify(message, kernel_address)
        except SignatureVerificationError as exc:
            return HandlerResult(
                status=401,
                body={"accepted": False, "reason": str(exc)},
            )
        except ValueError as exc:
            return HandlerResult(
                status=422,
                body={"accepted": False, "reason": str(exc)},
            )

        # 7. Dedup. Key = (type, signerDID, nonce).
        dedup_key = (
            f"{payload['type']}:{message.consumer}:{message.nonce}"
        )
        outcome = self._dedup.record_once(dedup_key, DEDUP_TTL_SECONDS * 1000)
        if outcome == "duplicate":
            return HandlerResult(
                status=200,
                body={"accepted": True, "duplicate": True},
                parsed_message=message,
            )

        return HandlerResult(
            status=201,
            body={"accepted": True, "duplicate": False},
            parsed_message=message,
        )


# ============================================================================
# Internal: dict → dataclass
# ============================================================================


def _parse_counter_offer(raw: Dict[str, Any]) -> CounterOfferMessage:
    """Parse a wire-format counter-offer dict into the dataclass."""
    just_raw = raw.get("justification")
    justification: Optional[CounterOfferJustification] = None
    if isinstance(just_raw, dict) and just_raw:
        justification = CounterOfferJustification(
            reason=just_raw.get("reason"),
            market_rate=just_raw.get("marketRate"),
            breakdown=just_raw.get("breakdown") or {},
        )

    return CounterOfferMessage(
        txId=str(raw["txId"]),
        consumer=str(raw["consumer"]),
        provider=str(raw["provider"]),
        quoteAmount=str(raw["quoteAmount"]),
        counterAmount=str(raw["counterAmount"]),
        maxPrice=str(raw["maxPrice"]),
        inReplyTo=str(raw["inReplyTo"]),
        counteredAt=int(raw["counteredAt"]),
        expiresAt=int(raw["expiresAt"]),
        chainId=int(raw["chainId"]),
        nonce=int(raw["nonce"]),
        signature=str(raw["signature"]),
        type=str(raw.get("type", "agirails.counteroffer.v1")),
        version=str(raw.get("version", "1.0.0")),
        currency=str(raw.get("currency", "USDC")),
        decimals=int(raw.get("decimals", 6)),
        justification=justification,
    )


__all__ = [
    "DEDUP_TTL_SECONDS",
    "HandlerContext",
    "HandlerResult",
    "InMemoryDedupStore",
    "QuoteChannelHandler",
    "QuoteChannelClient",
    "QuoteChannelClientConfig",
    "assert_safe_peer_url",
    "TTL_GRACE_SECONDS",
    "build_channel_path",
]
