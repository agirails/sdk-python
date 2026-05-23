"""
Upload a settled receipt to the agirails.app public receipt endpoint.

Python port of ``sdk-js/src/cli/receiptUpload.ts``.

Auth:
  - **Mock network**: API key required (``AGIRAILS_API_KEY`` env or
    ``options.api_key``).
  - **On-chain (testnet/mainnet)**: API key OR EIP-712 wallet signature.
    Wallet path is preferred since the agent already has a signer
    available (the same EOA that issued state transitions).

Failure mode: best-effort. A network error never fails the settlement
flow. The receipt's canonical source of truth is the kernel's on-chain
log; the web receipt is a cosmetic, shareable artifact.

@module receipts/web_receipt
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Literal, Optional, Union

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

# ============================================================================
# Constants
# ============================================================================

DEFAULT_BASE_URL = os.environ.get("AGIRAILS_BASE_URL", "https://agirails.app")
EIP712_DOMAIN_NAME = "AGIRAILS Receipts"
EIP712_DOMAIN_VERSION = "1"

NetworkName = Literal["mock", "base-sepolia", "base-mainnet"]


def _chain_id_for(network: str) -> int:
    if network == "base-mainnet":
        return 8453
    if network == "base-sepolia":
        return 84532
    raise ValueError(f"No chain ID for network: {network}")


# ============================================================================
# Types
# ============================================================================


@dataclass
class ReceiptUploadPayload:
    """Public receipt payload uploaded to agirails.app.

    Field names match the TS schema (camelCase on the wire). ``txId``
    is the ACTP bytes32 transaction id; ``ethTxHash`` is the on-chain
    settlement tx hash. ``serviceHash`` and ``kernelAddress`` are
    optional in mock mode and required for on-chain receipts.
    """

    agentAddress: str
    service: str
    amountWei: str
    feeWei: str
    netWei: str
    txId: str
    network: str  # NetworkName at runtime, str for 3.9 typing compat
    requesterAddress: str
    durationMs: int
    serviceHash: Optional[str] = None
    kernelAddress: Optional[str] = None
    ethTxHash: Optional[str] = None
    logIndex: Optional[int] = None
    blockNumber: Optional[int] = None
    ownerCaption: Optional[str] = None

    def to_wire(self) -> Dict[str, Any]:
        """Serialize to the JSON shape the server consumes (omits None)."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ReceiptUploadOptions:
    """Caller-supplied auth + endpoint overrides."""

    base_url: Optional[str] = None
    private_key: Optional[str] = None  # 0x-prefixed hex — preferred over signer
    api_key: Optional[str] = None
    timeout_seconds: float = 10.0


@dataclass(frozen=True)
class ReceiptUploadSuccess:
    ok: Literal[True]
    id: str
    url: str
    milestone: Optional[str]


@dataclass(frozen=True)
class ReceiptUploadFailure:
    ok: Literal[False]
    reason: str


ReceiptUploadResult = Union[ReceiptUploadSuccess, ReceiptUploadFailure]


# ============================================================================
# Public API
# ============================================================================


async def upload_receipt(
    payload: ReceiptUploadPayload,
    options: Optional[ReceiptUploadOptions] = None,
) -> ReceiptUploadResult:
    """Upload a settled receipt to agirails.app.

    Args:
        payload: Receipt fields. ``network`` selects the endpoint
            (``/api/v1/receipts/mock`` vs ``/api/v1/receipts``).
        options: Auth + transport overrides. When ``api_key`` is
            present (or ``AGIRAILS_API_KEY`` env), Bearer-auth is used;
            otherwise on-chain networks fall back to EIP-712 wallet
            signature flow (requires ``private_key``).

    Returns:
        :class:`ReceiptUploadSuccess` on 2xx (with the server-issued
        ``id`` and shareable ``url``), or :class:`ReceiptUploadFailure`
        on any network / auth / HTTP error. Never raises.
    """
    opts = options or ReceiptUploadOptions()
    base_url = opts.base_url or DEFAULT_BASE_URL

    endpoint = (
        f"{base_url}/api/v1/receipts/mock"
        if payload.network == "mock"
        else f"{base_url}/api/v1/receipts"
    )

    api_key = opts.api_key or os.environ.get("AGIRAILS_API_KEY")

    headers: Dict[str, str] = {"content-type": "application/json"}
    body: Dict[str, Any] = payload.to_wire()

    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    elif payload.network != "mock" and opts.private_key:
        # Wallet-sig auth path:
        #   1. POST /receipts/prepare → server-issued nonce bound to signer.
        #   2. Sign EIP-712 ReceiptWrite over (commitment, nonce, issuedAt).
        #   3. POST signed body to /receipts; server atomically consumes nonce.
        try:
            signer_address, nonce, issued_at, signature = await _wallet_sig_prepare(
                payload, opts.private_key, base_url, opts.timeout_seconds
            )
        except _UploadFailed as exc:
            return ReceiptUploadFailure(ok=False, reason=str(exc))

        headers["x-agent-address"] = signer_address
        headers["x-agent-signature"] = signature
        body = {**body, "nonce": nonce, "issuedAt": issued_at}
    else:
        return ReceiptUploadFailure(
            ok=False,
            reason="No credentials: set AGIRAILS_API_KEY or pass private_key",
        )

    try:
        # follow_redirects: agirails.app responds with 308 → www.agirails.app
        # (apex → www canonical redirect). Without this, the POST is sent
        # to the apex once, gets 308, and httpx returns the 308 as an
        # error response. We follow redirects on both prepare (below) and
        # the main receipts upload.
        async with httpx.AsyncClient(
            timeout=opts.timeout_seconds, follow_redirects=True
        ) as client:
            res = await client.post(endpoint, headers=headers, json=body)
    except httpx.HTTPError as exc:
        return ReceiptUploadFailure(ok=False, reason=str(exc) or "network error")

    if res.status_code < 200 or res.status_code >= 300:
        reason = f"HTTP {res.status_code}"
        try:
            err_json = res.json()
            if isinstance(err_json, dict) and isinstance(err_json.get("error"), str):
                reason = err_json["error"]
        except Exception:
            pass
        return ReceiptUploadFailure(ok=False, reason=reason)

    try:
        data = res.json()
    except Exception as exc:
        return ReceiptUploadFailure(
            ok=False, reason=f"Invalid JSON in response: {exc}"
        )

    if not isinstance(data, dict) or "id" not in data or "url" not in data:
        return ReceiptUploadFailure(
            ok=False, reason="Malformed response (missing id/url)"
        )

    url_field = data["url"]
    if not isinstance(url_field, str):
        return ReceiptUploadFailure(
            ok=False, reason="Malformed response (url is not a string)"
        )
    full_url = url_field if url_field.startswith("http") else f"{base_url}{url_field}"

    return ReceiptUploadSuccess(
        ok=True,
        id=str(data["id"]),
        url=full_url,
        milestone=data.get("milestone"),
    )


# ============================================================================
# Internals
# ============================================================================


class _UploadFailed(Exception):
    """Internal sentinel for the wallet-sig prepare step."""


async def _wallet_sig_prepare(
    payload: ReceiptUploadPayload,
    private_key: str,
    base_url: str,
    timeout_seconds: float,
) -> "tuple[str, str, int, str]":
    """Run the EIP-712 wallet-sig prepare handshake.

    Returns ``(signer_address, nonce, issued_at, signature_hex)``.

    Raises :class:`_UploadFailed` with a stable human-readable message
    so the caller can wrap it into a :class:`ReceiptUploadFailure`.
    """
    account = Account.from_key(private_key)
    signer_address = account.address

    prepare_url = f"{base_url}/api/v1/receipts/prepare"
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds, follow_redirects=True
        ) as client:
            prep_res = await client.post(
                prepare_url, json={"signerAddress": signer_address}
            )
    except httpx.HTTPError as exc:
        raise _UploadFailed(
            f"Nonce prepare error: {exc or 'network error'}"
        ) from exc

    if prep_res.status_code < 200 or prep_res.status_code >= 300:
        raise _UploadFailed(
            f"Nonce prepare failed: HTTP {prep_res.status_code}"
        )

    try:
        prepared = prep_res.json()
    except Exception as exc:
        raise _UploadFailed(
            f"Nonce prepare returned invalid JSON: {exc}"
        ) from exc

    if (
        not isinstance(prepared, dict)
        or "nonce" not in prepared
        or "issuedAt" not in prepared
    ):
        raise _UploadFailed("Nonce prepare returned malformed payload")

    nonce = str(prepared["nonce"])
    try:
        issued_at = int(prepared["issuedAt"])
    except (TypeError, ValueError) as exc:
        raise _UploadFailed("Nonce prepare returned non-integer issuedAt") from exc

    typed_data = _build_receipt_write_typed_data(
        payload=payload,
        nonce=nonce,
        issued_at=issued_at,
    )
    signable = encode_typed_data(full_message=typed_data)
    signed = account.sign_message(signable)
    sig_hex = signed.signature.hex()
    if not sig_hex.startswith("0x"):
        sig_hex = "0x" + sig_hex

    return signer_address, nonce, issued_at, sig_hex


def _build_receipt_write_typed_data(
    payload: ReceiptUploadPayload, nonce: str, issued_at: int
) -> Dict[str, Any]:
    """Build the EIP-712 typed-data payload for ReceiptWrite.

    Matches the TS shape exactly so signatures verify on the server:

        domain:  { name="AGIRAILS Receipts", version="1", chainId }
        type:    ReceiptWrite(
                    address agentAddress,
                    bytes32 txId,
                    string  network,
                    string  amountWei,
                    string  netWei,
                    string  nonce,
                    uint64  issuedAt,
                 )
    """
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "ReceiptWrite": [
                {"name": "agentAddress", "type": "address"},
                {"name": "txId", "type": "bytes32"},
                {"name": "network", "type": "string"},
                {"name": "amountWei", "type": "string"},
                {"name": "netWei", "type": "string"},
                {"name": "nonce", "type": "string"},
                {"name": "issuedAt", "type": "uint64"},
            ],
        },
        "primaryType": "ReceiptWrite",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": _chain_id_for(payload.network),
        },
        "message": {
            "agentAddress": payload.agentAddress,
            "txId": payload.txId,
            "network": payload.network,
            "amountWei": payload.amountWei,
            "netWei": payload.netWei,
            "nonce": nonce,
            "issuedAt": issued_at,
        },
    }


__all__ = [
    "DEFAULT_BASE_URL",
    "EIP712_DOMAIN_NAME",
    "EIP712_DOMAIN_VERSION",
    "ReceiptUploadPayload",
    "ReceiptUploadOptions",
    "ReceiptUploadResult",
    "ReceiptUploadSuccess",
    "ReceiptUploadFailure",
    "upload_receipt",
]
