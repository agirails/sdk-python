"""
EIP-3009 ``transferWithAuthorization`` signing for x402 v2 (exact scheme).

1:1 port of @x402/evm exact-scheme client EIP-3009 path
(node_modules/@x402/evm/dist/cjs/exact/client/index.js — createEIP3009Payload /
signEIP3009Authorization / createNonce / getEvmChainId).

The signing primitive (`sign_eip3009_authorization`) produces a signature
BYTE-IDENTICAL to @x402/evm given the same domain/authorization/key, proven by
the cross-SDK oracle in tests/fixtures/cross_sdk/wave3_x402.json.

TS reference:
- authorizationTypes.TransferWithAuthorization  (constants.ts)
- createEIP3009Payload / signEIP3009Authorization (exact/client/eip3009.ts)

@module adapters/x402/eip3009
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:  # pragma: no cover
    from typing_extensions import TypedDict

from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

# ============================================================================
# Typed-data schema — IMMUTABLE field order/types (must match TS exactly)
# ============================================================================

# @x402/evm constants.ts authorizationTypes.TransferWithAuthorization
# Any reordering / type drift produces a different EIP-712 typeHash → the
# signature would be unverifiable by the facilitator and cross-SDK.
AUTHORIZATION_TYPES: Dict[str, Any] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

# The EIP712Domain entry eth_account requires when signing with full_message.
# (viem injects this implicitly; eth_account requires it explicitly.)
_EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


# ============================================================================
# CAIP-2 <-> chainId / network-name helpers (mirror @x402/evm getEvmChainId)
# ============================================================================

# CAIP-2 network id -> EVM chainId. Mirrors getEvmChainId() which parses
# "eip155:CHAIN_ID". We accept either CAIP-2 ("eip155:84532") or the AGIRAILS
# network alias ("base-sepolia"/"base-mainnet") for convenience.
_NETWORK_ALIAS_TO_CAIP2: Dict[str, str] = {
    "base-mainnet": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "base": "eip155:8453",
}

_CAIP2_TO_NETWORK_NAME: Dict[str, str] = {
    "eip155:8453": "base-mainnet",
    "eip155:84532": "base-sepolia",
}


def chain_id_for_network(network: str) -> int:
    """Resolve a CAIP-2 (``eip155:8453``) or alias (``base-sepolia``) to chainId.

    1:1 with @x402/evm ``getEvmChainId`` for the ``eip155:`` form; additionally
    accepts AGIRAILS network aliases.

    Raises:
        ValueError: If the network format is unsupported / chain id is invalid.
    """
    caip2 = _NETWORK_ALIAS_TO_CAIP2.get(network, network)
    if not caip2.startswith("eip155:"):
        raise ValueError(
            f"Unsupported network format: {network} (expected eip155:CHAIN_ID)"
        )
    id_str = caip2.split(":", 1)[1]
    try:
        return int(id_str, 10)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid CAIP-2 chain ID: {network}")


def network_name_for_caip2(network: str) -> str:
    """Map a CAIP-2 network id to its x402 network name for the X-PAYMENT header.

    The X-PAYMENT header carries the human network string (e.g. "base-sepolia"),
    matching the TS X402Adapter which emits the same shape the facilitator reads.
    Passes through unknown values unchanged.
    """
    return _CAIP2_TO_NETWORK_NAME.get(network, network)


# ============================================================================
# Data classes
# ============================================================================


class EIP3009Domain(TypedDict):
    """EIP-712 domain for USDC ``transferWithAuthorization``.

    Built exactly as @x402/evm ``signEIP3009Authorization``:
    ``{ name, version (from paymentRequirements.extra), chainId, verifyingContract = asset }``.
    """

    name: str
    version: str
    chainId: int
    verifyingContract: str


@dataclass
class EIP3009Authorization:
    """An EIP-3009 ``TransferWithAuthorization`` authorization.

    Field names mirror the x402 wire payload (camelCase strings on the wire).
    """

    from_address: str
    to: str
    value: str  # uint256 as decimal string
    valid_after: str  # uint256 as decimal string
    valid_before: str  # uint256 as decimal string
    nonce: str  # bytes32 as 0x-hex

    def to_wire(self) -> Dict[str, str]:
        """Serialize to the camelCase wire shape used in the x402 payload."""
        return {
            "from": self.from_address,
            "to": self.to,
            "value": self.value,
            "validAfter": self.valid_after,
            "validBefore": self.valid_before,
            "nonce": self.nonce,
        }


# ============================================================================
# Nonce
# ============================================================================


def create_nonce() -> str:
    """Random 32-byte nonce as 0x-hex.

    1:1 with @x402/evm ``createNonce`` = ``toHex(randomValues(32))``.
    """
    return "0x" + os.urandom(32).hex()


# ============================================================================
# Signing
# ============================================================================


def sign_eip3009_authorization(
    account: Any,
    authorization: EIP3009Authorization,
    domain: EIP3009Domain,
) -> str:
    """Sign an EIP-3009 ``TransferWithAuthorization`` over EIP-712.

    BYTE-EXACT with @x402/evm ``signEIP3009Authorization``. ``account`` is an
    ``eth_account.Account`` (LocalAccount) — its ``sign_message`` over the
    EIP-712 ``encode_typed_data`` is proven equal to ethers/viem signing.

    Args:
        account: eth_account LocalAccount (the buyer/signer).
        authorization: The EIP-3009 authorization to sign.
        domain: EIP-712 domain (name, version, chainId, verifyingContract).

    Returns:
        0x-prefixed 65-byte signature hex string.
    """
    message = {
        "from": to_checksum_address(authorization.from_address),
        "to": to_checksum_address(authorization.to),
        "value": int(authorization.value),
        "validAfter": int(authorization.valid_after),
        "validBefore": int(authorization.valid_before),
        # bytes32 — eth_account accepts the raw 32-byte value
        "nonce": _bytes32(authorization.nonce),
    }
    types = dict(AUTHORIZATION_TYPES, EIP712Domain=_EIP712_DOMAIN_TYPE)
    full_message = {
        "domain": dict(domain),
        "types": types,
        "primaryType": "TransferWithAuthorization",
        "message": message,
    }

    # Wallet-provider path: mirror the TS walletProviderToClientEvmSigner bridge —
    # hand the typed-data dict straight to the provider's signer. Gated on a
    # sentinel so plain eth_account accounts (which DO expose sign_typed_data
    # with a different signature) stay on the byte-exact sign_message path.
    typed_signer = getattr(account, "_x402_sign_typed_data", None)
    if callable(typed_signer):
        return _normalize_sig(typed_signer(full_message))

    signable = encode_typed_data(full_message=full_message)
    signed = account.sign_message(signable)
    return _normalize_sig(signed.signature.hex())


def _bytes32(value: str) -> bytes:
    """Decode a 0x-prefixed (or bare) 32-byte hex string to bytes."""
    h = value[2:] if value.startswith("0x") else value
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(b)}")
    return b


def _normalize_sig(sig: str) -> str:
    """Ensure a 0x-prefixed signature hex string."""
    s = sig if isinstance(sig, str) else "0x" + bytes(sig).hex()
    return s if s.startswith("0x") else "0x" + s


# ============================================================================
# Payload + X-PAYMENT header
# ============================================================================


@dataclass
class PaymentRequirements:
    """Subset of x402 PaymentRequirements needed for EIP-3009 signing.

    Mirrors the fields @x402/evm ``createEIP3009Payload`` /
    ``signEIP3009Authorization`` read.
    """

    pay_to: str  # recipient (USDC `to`)
    amount: str  # uint256 base-units string
    asset: str  # USDC token contract (EIP-712 verifyingContract)
    network: str  # CAIP-2 or alias
    max_timeout_seconds: int  # validity window
    extra_name: str  # domain name (EIP-712)
    extra_version: str  # domain version (EIP-712)


def build_eip3009_payload(
    account: Any,
    requirements: PaymentRequirements,
    x402_version: int = 2,
    now: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a signed x402 EIP-3009 payment payload.

    1:1 with @x402/evm ``createEIP3009Payload``:
      validAfter = now - 600; validBefore = now + maxTimeoutSeconds;
      nonce = random 32 bytes; domain from requirements.extra + asset.

    Returns:
        ``{"x402Version": <int>, "payload": {"authorization": {...}, "signature": "0x..."}}``
    """
    import time

    if now is None:
        now = int(time.time())
    if nonce is None:
        nonce = create_nonce()

    authorization = EIP3009Authorization(
        from_address=account.address,
        to=to_checksum_address(requirements.pay_to),
        value=requirements.amount,
        valid_after=str(now - 600),
        valid_before=str(now + requirements.max_timeout_seconds),
        nonce=nonce,
    )

    if not requirements.extra_name or not requirements.extra_version:
        raise ValueError(
            "EIP-712 domain parameters (name, version) are required in payment "
            f"requirements for asset {requirements.asset}"
        )

    domain: EIP3009Domain = {
        "name": requirements.extra_name,
        "version": requirements.extra_version,
        "chainId": chain_id_for_network(requirements.network),
        "verifyingContract": to_checksum_address(requirements.asset),
    }

    signature = sign_eip3009_authorization(account, authorization, domain)

    return {
        "x402Version": x402_version,
        "payload": {
            "authorization": authorization.to_wire(),
            "signature": signature,
        },
    }


def encode_x_payment_header(
    payload: Dict[str, Any],
    network: str,
    scheme: str = "exact",
    x402_version: int = 2,
) -> str:
    """Encode the X-PAYMENT header value: base64(JSON of envelope).

    1:1 with the TS X402Adapter wire: the header is
    ``base64(JSON({x402Version, scheme, network, payload}))`` with compact
    JSON separators (no whitespace) so it matches Node ``JSON.stringify`` and
    the cross-SDK oracle byte-for-byte.

    The ``payload`` here is the inner ``payload`` object (``{authorization,
    signature}``), i.e. ``build_eip3009_payload(...)["payload"]``.
    """
    envelope = {
        "x402Version": x402_version,
        "scheme": scheme,
        "network": network_name_for_caip2(network),
        "payload": payload,
    }
    raw = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")
