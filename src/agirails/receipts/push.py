"""
Buyer-visible settlement receipt — SDK push path.

Python port of ``sdk-js/src/receipts/push.ts`` (TS 4.8.0, source of truth).

On SETTLED state transition, the SDK posts a V2-signed receipt to the
AGIRAILS Platform. The response includes a clickable receipt URL which the
CLI prints to the terminal — the wow moment.

Integration points:
  1. Import this module from wherever lifecycle reaches SETTLED.
  2. After the on-chain state advances to SETTLED, call::

        result = await push_receipt_on_settled(...)

  3. Surface ``result.receipt_url`` on the public RequestResult and to CLI
     commands (pay, test, serve) so they print it.

Non-goals:
  - This module does NOT change the lifecycle itself.
  - Failure is non-fatal: settlement already happened on-chain; the Platform
    indexer cron is the backstop for cases where this POST fails.

Auth: V2 EIP-712 signature, requester wallet (when SDK acts as requester) or
  provider wallet (when SDK acts as provider). The Platform's POST handler
  verifies the signer matches participantRole, AND independently verifies
  on-chain that the tx really exists with claimed values. Forgery is not
  possible without on-chain truth.

@module receipts/push
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

import httpx
from eth_account.messages import encode_typed_data

_LOG = logging.getLogger("agirails.receipts")

# ──────────────────────────────────────────────────────────────────────────
# EIP-712 V2 — must match Platform/agirails.app/web/lib/receipts/eip712.ts
# and sdk-js/src/receipts/push.ts:34-55
# ──────────────────────────────────────────────────────────────────────────

#: TS push.ts:34-37 — RECEIPT_WRITE_DOMAIN_V2 (chainId added at signing time).
RECEIPT_WRITE_DOMAIN_V2: Dict[str, str] = {
    "name": "AGIRAILS Receipts",
    "version": "2",
}

#: TS push.ts:39-55 — RECEIPT_WRITE_TYPES_V2. Field order is IMMUTABLE: any
#: reordering/type drift produces a different typeHash → signatures become
#: unverifiable cross-SDK.
RECEIPT_WRITE_TYPES_V2: Dict[str, List[Dict[str, str]]] = {
    "ReceiptWriteV2": [
        {"name": "signerAddress", "type": "address"},
        {"name": "participantRole", "type": "string"},
        {"name": "providerAddress", "type": "address"},
        {"name": "requesterAddress", "type": "address"},
        {"name": "kernelAddress", "type": "address"},
        {"name": "txId", "type": "bytes32"},
        {"name": "network", "type": "string"},
        {"name": "amountWei", "type": "uint256"},
        {"name": "feeWei", "type": "uint256"},
        {"name": "netWei", "type": "uint256"},
        {"name": "serviceHash", "type": "bytes32"},
        {"name": "nonce", "type": "string"},
        {"name": "issuedAt", "type": "uint64"},
    ],
}

#: TS push.ts:57 — ZERO_BYTES32 used as the serviceHash fallback.
ZERO_BYTES32 = "0x" + "0" * 64

ParticipantRole = Literal["provider", "requester"]

Network = Literal["base-sepolia", "base-mainnet"]


def chain_id_for_network(network: str) -> int:
    """TS push.ts:63-65 — chainIdForNetwork."""
    return 8453 if network == "base-mainnet" else 84532


# ──────────────────────────────────────────────────────────────────────────
# Signer abstraction
#
# TS uses an ethers ``Signer`` with ``getAddress()`` + ``signTypedData``. The
# Python analog is either an ``eth_account`` ``LocalAccount`` (has ``.address``
# and signs an ``encode_typed_data`` ``SignableMessage``) or an SDK
# ``IWalletProvider`` (has ``sign_typed_data(full_message)`` and an address via
# ``get_wallet_info().address``). ``_resolve_signer_address`` and
# ``_sign_typed_data`` accept both, mirroring ``signer.getAddress()`` /
# ``signer.signTypedData(domain, types, payload)`` (push.ts:121,155).
# ──────────────────────────────────────────────────────────────────────────


def _resolve_signer_address(signer: Any) -> str:
    """Mirror TS ``await signer.getAddress()`` (push.ts:121).

    Resolution order:
      1. ``signer.address`` (LocalAccount, or any object with an address attr)
      2. ``signer.get_wallet_info().address`` (IWalletProvider)
      3. ``signer.get_address()`` (sync or callable returning str)
    """
    addr = getattr(signer, "address", None)
    if isinstance(addr, str) and addr:
        return addr

    get_info = getattr(signer, "get_wallet_info", None)
    if callable(get_info):
        info = get_info()
        info_addr = getattr(info, "address", None)
        if isinstance(info_addr, str) and info_addr:
            return info_addr

    get_address = getattr(signer, "get_address", None)
    if callable(get_address):
        resolved = get_address()
        if isinstance(resolved, str) and resolved:
            return resolved

    raise ValueError("signer has no resolvable address")


def _sign_typed_data(signer: Any, full_message: Dict[str, Any]) -> str:
    """Mirror TS ``await signer.signTypedData(domain, types, payload)``.

    Accepts an SDK ``IWalletProvider`` (``sign_typed_data(full_message) -> str``)
    or an ``eth_account`` ``LocalAccount``/``Account``. The ``eth_account`` path is
    preferred when available: a raw account exposes ``sign_message`` (and its own
    ``sign_typed_data`` has an INCOMPATIBLE positional signature), whereas an
    ``IWalletProvider`` has no ``sign_message`` and is reached via its
    ``sign_typed_data`` wrapper. Returns a 0x-prefixed hex signature.
    """
    sign_message = getattr(signer, "sign_message", None)
    if callable(sign_message):
        signable = encode_typed_data(full_message=full_message)
        signed = sign_message(signable)
        sig_hex = signed.signature.hex()
        return sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex

    provider_sign = getattr(signer, "sign_typed_data", None)
    if callable(provider_sign):
        sig = provider_sign(full_message)
        return sig if isinstance(sig, str) and sig.startswith("0x") else "0x" + str(sig)

    raise ValueError("signer cannot sign typed data")


# ──────────────────────────────────────────────────────────────────────────
# push_receipt_on_settled — fire-and-recover at lifecycle SETTLED
# ──────────────────────────────────────────────────────────────────────────


@dataclass
class PushReceiptArgs:
    """Mirror TS ``PushReceiptArgs`` (push.ts:71-97)."""

    #: Signer for this side — provider wallet (provider push) or requester
    #: wallet (requester push). LocalAccount or IWalletProvider.
    signer: Any
    #: Role the signer is claiming. Provider for earn pushes, requester for
    #: buyer pushes.
    participant_role: ParticipantRole
    #: On-chain participants. Same values ACTPKernel.getTransaction returns.
    provider_address: str
    requester_address: str
    kernel_address: str
    tx_id: str
    network: Network
    amount_wei: str
    fee_wei: str
    net_wei: str
    #: Human-readable service slug (for receipt display).
    service: str = ""
    #: Milliseconds from INITIATED to SETTLED (CLI lifecycle timer).
    duration_ms: int = 0
    #: Platform base URL — defaults to production. Override for staging tests.
    api_base: Optional[str] = None
    #: Optional — zero bytes32 if not yet emitted by the service descriptor.
    service_hash: Optional[str] = None
    #: Optional — when the SDK can compute it cheaply. Indexer fills otherwise.
    eth_tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    log_index: Optional[int] = None
    #: Optional injected transport (tests). When set, used instead of a fresh
    #: httpx.AsyncClient — lets respx/httpx MockTransport intercept the flow.
    transport: Optional[httpx.AsyncBaseTransport] = None


@dataclass
class PushReceiptResult:
    """Mirror TS ``PushReceiptResult`` (push.ts:99-113)."""

    #: Absolute URL the CLI prints. None when POST failed (indexer backstop).
    receipt_url: Optional[str]
    #: Receipt PK on the Platform, when known.
    receipt_id: Optional[str]
    #: True when the server confirmed on-chain match before minting.
    verified_on_chain: bool
    #: Why the push failed, when it did (``post_failed:<status> <error>: <detail>``
    #: or ``prepare_failed:<status>``), else None. A missing-field 400 and an
    #: on-chain 422 both surface as a null URL — without this, the reason is lost
    #: and the two are indistinguishable to the caller.
    reason: Optional[str] = None


_TRAILING_SLASHES = re.compile(r"/+$")


async def push_receipt_on_settled(args: PushReceiptArgs) -> PushReceiptResult:
    """Mirror TS ``pushReceiptOnSettled`` (push.ts:115-233).

    Resolution priority for the base URL: explicit arg > ``AGIRAILS_BASE_URL``
    env > prod default. Trailing slashes are stripped.

    Returns a :class:`PushReceiptResult`; never raises (receipt POST failure is
    non-fatal — settlement already happened on-chain, and the indexer cron
    backfills rows within ~5min). The failure reason rides on ``reason``.
    """
    # push.ts:118-120 — apiBase resolution + trailing-slash strip.
    api_base = _TRAILING_SLASHES.sub(
        "",
        args.api_base
        or os.environ.get("AGIRAILS_BASE_URL")
        or "https://agirails.app",
    )
    signer_address = _resolve_signer_address(args.signer)

    try:
        async with httpx.AsyncClient(
            timeout=10.0, transport=args.transport
        ) as client:
            # 1) Fetch a single-use nonce bound to the signer wallet (push.ts:124-131).
            prep_res = await client.post(
                f"{api_base}/api/v1/receipts/prepare",
                headers={"Content-Type": "application/json"},
                json={"signerAddress": signer_address},
            )
            if not _is_ok(prep_res):
                raise _PushError(f"prepare_failed:{prep_res.status_code}")
            nonce = str(prep_res.json()["nonce"])

            issued_at = int(time.time())  # push.ts:133 — Math.floor(Date.now()/1000)
            payload = {
                "signerAddress": signer_address,
                "participantRole": args.participant_role,
                "providerAddress": args.provider_address,
                "requesterAddress": args.requester_address,
                "kernelAddress": args.kernel_address,
                "txId": args.tx_id,
                "network": args.network,
                "amountWei": args.amount_wei,
                "feeWei": args.fee_wei,
                "netWei": args.net_wei,
                "serviceHash": args.service_hash
                if args.service_hash is not None
                else ZERO_BYTES32,
                "nonce": nonce,
                "issuedAt": issued_at,
            }

            # 2) EIP-712 V2 sign — domain chainId is part of the binding
            #    (push.ts:151-155).
            signature = _sign_receipt_write_v2(args.signer, payload, args.network)

            # 3) POST receipt. Body fields match the payload; server reconstructs
            #    and verifies them against the signature (push.ts:159-188).
            body = {
                "participantRole": args.participant_role,
                "signerAddress": signer_address,
                "agentAddress": args.provider_address,
                "requesterAddress": args.requester_address,
                "kernelAddress": args.kernel_address,
                "txId": args.tx_id,
                "network": args.network,
                "amountWei": args.amount_wei,
                "feeWei": args.fee_wei,
                "netWei": args.net_wei,
                "serviceHash": args.service_hash,
                "ethTxHash": args.eth_tx_hash,
                "blockNumber": args.block_number,
                "logIndex": args.log_index,
                "service": args.service,
                "durationMs": args.duration_ms,
                "agentSignature": signature,
                "agentSignatureAlgorithm": "EIP712-ReceiptV2",
                "nonce": nonce,
                "issuedAt": issued_at,
            }
            post_res = await client.post(
                f"{api_base}/api/v1/receipts",
                headers={
                    "X-Agent-Address": signer_address,
                    "X-Agent-Signature": signature,
                    "Content-Type": "application/json",
                },
                json=body,
            )

            if not _is_ok(post_res):
                # push.ts:190-208 — read the server's {error, detail} so the
                # reason rides up instead of collapsing to a bare status code.
                detail = ""
                try:
                    b = post_res.json()
                    if isinstance(b, dict):
                        detail = ": ".join(
                            str(b[k]) for k in ("error", "detail") if b.get(k)
                        )
                except Exception:
                    detail = ""
                raise _PushError(
                    f"post_failed:{post_res.status_code}"
                    + (f" {detail}" if detail else "")
                )

            data = post_res.json()
            return PushReceiptResult(
                receipt_url=data.get("url"),
                receipt_id=data.get("id"),
                verified_on_chain=bool(data.get("verified_on_chain")),
            )
    except Exception as err:  # noqa: BLE001 — push.ts:221-232, non-fatal
        # Receipt POST failure is non-fatal — settlement already happened
        # on-chain, and the indexer cron backfills rows within ~5min. But DON'T
        # swallow the reason: a 400 (missing field) and a 422 (RPC desync) both
        # surface as a null URL, and conflating them has cost real debug time.
        reason = str(err)
        _LOG.warning("[receipts] push failed (non-fatal): %s", reason)
        return PushReceiptResult(
            receipt_url=None,
            receipt_id=None,
            verified_on_chain=False,
            reason=reason,
        )


class _PushError(Exception):
    """Internal sentinel carrying the structured failure reason string."""


def _is_ok(res: httpx.Response) -> bool:
    """Mirror the JS ``Response.ok`` predicate (status in [200, 300))."""
    return 200 <= res.status_code < 300


def _sign_receipt_write_v2(
    signer: Any, payload: Dict[str, Any], network: str
) -> str:
    """Build the V2 typed data and EIP-712 sign it (push.ts:150-155).

    The domain spreads ``RECEIPT_WRITE_DOMAIN_V2`` and adds ``chainId``; there is
    no ``verifyingContract`` so the EIP712Domain type is [name, version, chainId].
    uint256/uint64 fields are passed as ints; address/bytes32 as 0x-hex strings.
    """
    domain = {
        "name": RECEIPT_WRITE_DOMAIN_V2["name"],
        "version": RECEIPT_WRITE_DOMAIN_V2["version"],
        "chainId": chain_id_for_network(network),
    }
    message = {
        "signerAddress": payload["signerAddress"],
        "participantRole": payload["participantRole"],
        "providerAddress": payload["providerAddress"],
        "requesterAddress": payload["requesterAddress"],
        "kernelAddress": payload["kernelAddress"],
        "txId": payload["txId"],
        "network": payload["network"],
        "amountWei": int(payload["amountWei"]),
        "feeWei": int(payload["feeWei"]),
        "netWei": int(payload["netWei"]),
        "serviceHash": payload["serviceHash"],
        "nonce": payload["nonce"],
        "issuedAt": int(payload["issuedAt"]),
    }
    full_message = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            **RECEIPT_WRITE_TYPES_V2,
        },
        "primaryType": "ReceiptWriteV2",
        "domain": domain,
        "message": message,
    }
    return _sign_typed_data(signer, full_message)


# ──────────────────────────────────────────────────────────────────────────
# CLI helper — what to print at SETTLED
# ──────────────────────────────────────────────────────────────────────────


@dataclass
class FormatSettledLineArgs:
    """Mirror TS ``FormatSettledLineArgs`` (push.ts:239-249)."""

    participant_role: ParticipantRole
    #: Net to provider (their earnings) — already formatted (e.g. "$4.95").
    net_display: str
    #: Gross from requester (what they paid) — already formatted.
    gross_display: str
    #: Counterparty slug or short address.
    counterparty_display: str
    #: Result URL from push_receipt_on_settled.
    receipt_url: Optional[str]


def format_settled_line(args: FormatSettledLineArgs) -> str:
    """Mirror TS ``formatSettledLine`` (push.ts:256-264).

    Format the one-line CLI summary the buyer or provider sees at SETTLED.
    Returns the line as a string; the CLI prints it. URL is omitted if None
    (indexer backstop will eventually mint a receipt but we have no PK for it).
    """
    action = (
        f"Earned {args.net_display} from {args.counterparty_display}"
        if args.participant_role == "provider"
        else f"Paid {args.gross_display} to {args.counterparty_display}"
    )
    if args.receipt_url:
        return f"[SETTLED] {action}\n           Receipt: {args.receipt_url}"
    return f"[SETTLED] {action}"


# ──────────────────────────────────────────────────────────────────────────
# renderReceiptV3 — FIX-5 wow-path framed ceremonial receipt
#
# Python port of sdk-js/src/cli/commands/receipt.ts ``renderReceiptV3``
# (TS 4.8.0, source of truth). The TS renderer pushes lines through an
# ``Output`` object wrapped in ANSI ``fmt`` colours; the Python SDK's receipt
# convention (cli/commands/receipt.py ``render_receipt``) is a plain
# string-returning function, so this port returns the full receipt as a string
# with the SAME structure/geometry/copy/perspective semantics but WITHOUT the
# cosmetic ANSI colour wrappers (colour is non-load-bearing — it carries no
# information a test or a buyer reads). Callers print the returned string.
# ──────────────────────────────────────────────────────────────────────────


@dataclass
class ReceiptTimingV3:
    """Per-stage timing. ``total_ms`` renders as the "Duration" row.

    Mirrors TS ``ReceiptTiming`` (receipt.ts:24-28).
    """

    total_ms: int
    escrow_lock_ms: int = 0
    settlement_ms: int = 0


@dataclass
class ReceiptDataV3:
    """Input shape for :func:`render_receipt_v3` (mirror TS ``ReceiptDataV3``).

    Superset of the V2 receipt data with two optional blocks (reflection,
    receipt_url), a direction-aware ``perspective``, and an injectable
    ``now_fn`` for deterministic test rendering.
    """

    #: Local agent name / slug (rendered on the "To" line by default).
    agent: str
    #: Service name (e.g. "onboarding").
    service: str
    #: Amount in USDC wei (6 decimals).
    amount_wei: int
    #: Network identifier: 'base-sepolia' | 'base-mainnet' | 'mock' | ...
    network: str
    #: ACTP transaction id (bytes32 hex).
    tx_id: str
    #: Counterparty display label (e.g. "Sentinel"). Falls back to a truncated
    #: ``requester`` address, then to the sentinel string "requester-agent".
    counterparty: Optional[str] = None
    #: Per-stage timing. ``total_ms`` is rendered as the "Duration" row.
    timing: Optional[ReceiptTimingV3] = None
    #: Reflection text. Suppressed when None OR empty string.
    reflection: Optional[str] = None
    #: Absolute public receipt URL. Suppressed when None.
    receipt_url: Optional[str] = None
    #: Optional requester wallet address (truncated when displayed).
    requester: Optional[str] = None
    #: Optional Ethereum on-chain settlement tx hash.
    eth_tx_hash: Optional[str] = None
    #: Injectable clock. Defaults to ``datetime.now(UTC)``. Tests pass a
    #: fixed-clock callable so the "Time" row is byte-stable.
    now_fn: Optional[Any] = None
    #: Receipt perspective — 'buyer' (local agent paid) or 'provider' (local
    #: agent earned, legacy default).
    perspective: Optional[Literal["buyer", "provider"]] = None


def _v3_format_usdc(wei: int) -> str:
    """Mirror TS ``formatUsdc`` (receipt.ts:48-51)."""
    dollars = wei / 1_000_000
    return f"${dollars:.2f} USDC"


def _v3_short_addr(addr: str) -> str:
    """Mirror TS ``shortAddr`` (receipt.ts:275-278)."""
    if len(addr) <= 14:
        return addr
    return f"{addr[:8]}...{addr[-4:]}"


def _v3_format_eth_hash(h: str) -> str:
    """Mirror TS ``formatEthHash`` (receipt.ts:58-61)."""
    if len(h) <= 14:
        return h
    return f"{h[:8]}...{h[-4:]}"


def _v3_format_time_utc(d: Any) -> str:
    """Mirror TS ``formatTimeUtc`` (receipt.ts:284-286): ``YYYY-MM-DD HH:MM:SS UTC``."""
    return f"{d.isoformat().replace('T', ' ')[:19]} UTC"


def _v3_wrap_text(text: str, max_width: int) -> List[str]:
    """Word-aware wrap (mirror TS ``wrapText`` receipt.ts:293-322).

    Words longer than ``max_width`` are hard-split so output stays bounded.
    """
    if max_width <= 0:
        return [text]
    words = [w for w in text.split() if len(w) > 0]
    lines: List[str] = []
    current = ""
    for w in words:
        if len(w) > max_width:
            if len(current) > 0:
                lines.append(current)
                current = ""
            for i in range(0, len(w), max_width):
                lines.append(w[i : i + max_width])
            continue
        if len(current) == 0:
            current = w
        elif len(current) + 1 + len(w) <= max_width:
            current = f"{current} {w}"
        else:
            lines.append(current)
            current = w
    if len(current) > 0:
        lines.append(current)
    return lines if len(lines) > 0 else [""]


def render_receipt_v3(data: ReceiptDataV3) -> str:
    """Render the FIX-5 ceremonial framed receipt (mirror TS ``renderReceiptV3``).

    Returns the full human-mode receipt as a newline-joined string. JSON / quiet
    modes are the caller's concern in the Python SDK (the CLI already emits the
    structured payload before calling this), matching the existing
    ``render_receipt`` split.

    Geometry, field order, network/perspective-variant copy, the reflection
    block (direction-aware label) and the receipt-URL block all mirror the TS
    source byte-for-byte modulo the omitted ANSI colour wrappers.
    """
    import datetime as _dt

    from agirails.cli.commands.receipt import compute_display_fee

    network_raw = (data.network or "mock").lower()
    is_testnet = "testnet" in network_raw or "sepolia" in network_raw
    is_mainnet = network_raw in ("mainnet", "base-mainnet")

    # Defensive zero-amount handling: keep fee at 0 so net is never negative
    # (TS receipt.ts:344-348 — computeDisplayFee returns MIN_FEE for amount=0).
    fee = 0 if data.amount_wei == 0 else compute_display_fee(data.amount_wei)
    net = data.amount_wei - fee
    fee_percent = (
        f"{round((fee / data.amount_wei) * 100)}" if data.amount_wei > 0 else "0"
    )

    is_buyer = data.perspective == "buyer"
    counterparty_label = data.counterparty or (
        _v3_short_addr(data.requester) if data.requester else "requester-agent"
    )
    from_label = data.agent if is_buyer else counterparty_label
    to_label = counterparty_label if is_buyer else data.agent

    out: List[str] = []

    # ----- Human mode: framed ceremonial receipt -----
    outer_width = 54
    inner_width = outer_width - 11  # 43

    def outer_pad(s: str) -> str:
        return s + " " * max(0, outer_width - len(s))

    def inner_pad(s: str) -> str:
        return s + " " * max(0, inner_width - len(s))

    def outer_line(s: str) -> None:
        out.append(f"║  {outer_pad(s)}║")

    def outer_empty() -> None:
        outer_line("")

    def inner_line(s: str) -> None:
        out.append(f"║   │  {inner_pad(s)}│      ║")

    horiz = "═" * (outer_width + 2)

    header_text = (
        "FIRST MAINNET SETTLEMENT" if is_mainnet else "FIRST TRANSACTION RECEIPT"
    )
    if is_mainnet:
        tagline_line1 = "This is real money. On a real blockchain."
    elif is_buyer:
        tagline_line1 = "Your agent just made its first payment."
    else:
        tagline_line1 = "Your agent just earned its first payment."
    tagline_line2 = (
        "Your agent is in the economy."
        if is_mainnet
        else "Autonomously. Trustlessly. In under 60 seconds."
    )

    # Top frame
    out.append(f"╔{horiz}╗")
    outer_empty()
    outer_line(f"◬  {header_text}")
    outer_empty()
    if is_buyer:
        outer_line(f"{data.agent} paid {_v3_format_usdc(data.amount_wei)}")
    else:
        outer_line(f"{data.agent} earned {_v3_format_usdc(net)}")
    outer_empty()

    # Inner card top
    out.append(f"║   ┌{'─' * (inner_width + 2)}┐      ║")

    # Inner card content
    inner_line(f"From       {from_label}")
    inner_line(f"To         {to_label}")
    inner_line(f"Amount     {_v3_format_usdc(data.amount_wei)}")
    inner_line(f"Fee        {_v3_format_usdc(fee)} ({fee_percent}%)")
    inner_line(f"Net        {_v3_format_usdc(net)}")
    inner_line(f"Service    {data.service}")
    inner_line("Status     SETTLED ✓")
    if data.timing is not None:
        inner_line(f"Duration   {data.timing.total_ms}ms")
    inner_line(f"Network    {data.network}")

    # On-chain proof rows (testnet + mainnet only).
    if (is_testnet or is_mainnet) and data.eth_tx_hash:
        inner_line(f"Eth Tx     {_v3_format_eth_hash(data.eth_tx_hash)}")
        scan_base = "basescan.org" if is_mainnet else "sepolia.basescan.org"
        inner_line(f"Verify     {scan_base}/tx/{data.eth_tx_hash[:8]}...")

    # Time row — uses injected now_fn so tests can pin the clock.
    now = (data.now_fn or (lambda: _dt.datetime.now(_dt.timezone.utc)))()
    inner_line(f"Time       {_v3_format_time_utc(now)}")

    # Inner card bottom
    out.append(f"║   └{'─' * (inner_width + 2)}┘      ║")

    # Reflection / service-delivered block (direction-aware label).
    if isinstance(data.reflection, str) and len(data.reflection) > 0:
        outer_empty()
        if is_buyer:
            provided_by = (
                f"  (from {counterparty_label})"
                if counterparty_label and counterparty_label != "requester-agent"
                else ""
            )
            outer_line(f"Service delivered{provided_by}")
        else:
            outer_line("Reflection")
        for ln in _v3_wrap_text(data.reflection, outer_width - 2):
            outer_line(f"  {ln}")

    # Receipt URL block — only when present. Label + URL on separate lines.
    if data.receipt_url:
        outer_empty()
        outer_line("Receipt URL")
        for ln in _v3_wrap_text(data.receipt_url, outer_width - 2):
            outer_line(f"  {ln}")

    outer_empty()
    outer_line(tagline_line1)
    outer_line(tagline_line2)
    outer_empty()
    out.append(f"╚{horiz}╝")

    return "\n".join(out)


__all__ = [
    "RECEIPT_WRITE_DOMAIN_V2",
    "RECEIPT_WRITE_TYPES_V2",
    "ZERO_BYTES32",
    "ParticipantRole",
    "Network",
    "chain_id_for_network",
    "PushReceiptArgs",
    "PushReceiptResult",
    "push_receipt_on_settled",
    "FormatSettledLineArgs",
    "format_settled_line",
    "ReceiptDataV3",
    "ReceiptTimingV3",
    "render_receipt_v3",
]
