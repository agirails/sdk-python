"""
AIP-16 Delivery Surface — Type Definitions (Python port).

Mirrors sdk-js/src/delivery/types.ts. The signed/wire shapes carry the exact
field names the EIP-712 core (``eip712.py``) and the cross-SDK fixtures rely
on; field *order* in the EIP-712 type hash is fixed in ``eip712.py`` and is
NOT re-derived here.

Two privacy modes (TS types.ts:94 ``DeliveryScheme``):

  - ``public-v1``            — body is plaintext UTF-8 JSON.
  - ``x25519-aes256gcm-v1``  — body is AES-256-GCM ciphertext (0x-hex on wire).

Both objects use a *signed projection* + *wire envelope* split. We model the
signed projections and wire envelopes as ``TypedDict`` so they round-trip
through plain ``dict``/JSON exactly like the TS interfaces (the EIP-712 signer
in ``eip712.py`` already consumes plain dicts).

Cite: sdk-js/src/delivery/types.ts.
"""

from __future__ import annotations

from typing import Any, List, Literal, Optional, TypedDict, Union

# ============================================================================
# Discriminator unions (TS types.ts:94-154)
# ============================================================================

# TS types.ts:94 — DeliveryScheme
DeliveryScheme = Literal["x25519-aes256gcm-v1", "public-v1"]

# TS types.ts:111 — DeliveryMode
DeliveryMode = Literal["channel", "none"]

# TS types.ts:127 — DeliveryPrivacy
DeliveryPrivacy = Literal["encrypted", "public"]

# TS types.ts:139 — ParticipantRole
ParticipantRole = Literal["provider", "requester"]

# TS types.ts:154 — DeliveryNetwork
DeliveryNetwork = Literal["base-sepolia", "base-mainnet", "mock"]

# Scheme string constants (convenience; not in TS but referenced as literals).
SCHEME_PUBLIC_V1 = "public-v1"
SCHEME_ENCRYPTED_V1 = "x25519-aes256gcm-v1"


# ============================================================================
# Server metadata (TS types.ts:358 / :597 — serverMeta)
# ============================================================================


class DeliveryServerMeta(TypedDict):
    """Relay-added metadata (set on read, never signed). TS types.ts:358."""

    receivedAt: str
    relayId: str


# ============================================================================
# Buyer Setup (TS types.ts:218 DeliverySetupSignedV1, :341 DeliverySetupWireV1)
# ============================================================================


class DeliverySetupSignedV1(TypedDict, total=False):
    """Canonical EIP-712 payload signed by the requester (buyer).

    Mirrors TS ``DeliverySetupSignedV1`` (types.ts:218). ``smartWalletNonce``
    is optional (H4, appended at END of the EIP-712 field list); absent → the
    signer normalizes it to 0 (see eip712.py ``_normalize``). ``total=False``
    so ``smartWalletNonce`` may be omitted on pre-H4 fixtures.
    """

    version: Literal[1]
    txId: str
    chainId: int
    kernelAddress: str
    requesterAddress: str
    signerAddress: str
    buyerEphemeralPubkey: str
    acceptedChannels: List[str]
    expectedPrivacy: str  # DeliveryPrivacy
    createdAt: int
    expiresAt: int
    smartWalletNonce: int  # optional (H4)


class DeliverySetupWireV1(TypedDict, total=False):
    """Wire envelope wrapping a signed setup (TS types.ts:341).

    ``serverMeta`` is optional (relay-decorated on read).
    """

    signed: DeliverySetupSignedV1
    requesterSig: str
    serverMeta: DeliveryServerMeta  # optional


# ============================================================================
# Provider Envelope (TS types.ts:412 / :557)
# ============================================================================


class DeliveryEnvelopeSignedV1(TypedDict, total=False):
    """Canonical EIP-712 payload signed by the provider (TS types.ts:412).

    Canonical-empty rule for ``public-v1``: ``providerEphemeralPubkey`` =
    ``CANONICAL_EMPTY_BYTES32``, ``nonce`` = ``CANONICAL_EMPTY_BYTES12``,
    ``tag`` = ``CANONICAL_EMPTY_BYTES16`` (TS types.ts:404-407).
    """

    version: Literal[1]
    txId: str
    chainId: int
    kernelAddress: str
    providerAddress: str
    signerAddress: str
    scheme: str  # DeliveryScheme
    providerEphemeralPubkey: str
    nonce: str
    payloadHash: str
    tag: str
    createdAt: int
    smartWalletNonce: int  # optional (H4)


class DeliveryEnvelopeWireV1(TypedDict, total=False):
    """Wire envelope around a signed envelope (TS types.ts:557).

    ``body`` encoding is scheme-dependent (FIX-1, TS types.ts:533):
      - ``public-v1``: plaintext UTF-8 JSON string (NOT hex).
      - ``x25519-aes256gcm-v1``: 0x-prefixed lowercase hex of raw ciphertext.
    """

    signed: DeliveryEnvelopeSignedV1
    body: str
    providerSig: str
    serverMeta: DeliveryServerMeta  # optional


# ============================================================================
# Builder result types (TS types.ts:617 / :645)
# ============================================================================


class BuildSetupResult(TypedDict):
    """Result of building a delivery setup (TS types.ts:617)."""

    wire: DeliverySetupWireV1
    nonceManagerKey: str


class BuildEnvelopeResult(TypedDict, total=False):
    """Result of building a delivery envelope (TS types.ts:645).

    ``blobKey`` present ONLY for the encrypted scheme; ``bodyBytes`` is the
    exact bytes ``payloadHash`` was computed over (TS types.ts:655/:663).
    """

    wire: DeliveryEnvelopeWireV1
    blobKey: bytes  # optional (encrypted only)
    bodyBytes: bytes


# ============================================================================
# Structured error codes (TS types.ts:690 DeliveryErrorCode)
# ============================================================================

# Kept as a frozenset of stable identifiers; mirrors the TS union exactly.
DELIVERY_ERROR_CODES = frozenset(
    {
        # Envelope verification failures
        "envelope_signature_invalid",
        "envelope_decrypt_failed",
        "envelope_payload_hash_mismatch",
        "envelope_participant_mismatch",
        "envelope_signer_role_mismatch",
        "envelope_chain_mismatch",
        "envelope_kernel_mismatch",
        "envelope_timestamp_skew",
        "envelope_no_envelope_at_relay",
        # Setup verification failures
        "setup_post_failed",
        "setup_signature_invalid",
        "setup_participant_mismatch",
        "setup_signer_role_mismatch",
        "setup_chain_mismatch",
        "setup_kernel_mismatch",
        "setup_timestamp_skew",
        "setup_expired",
        # Cryptographic primitive failures
        "crypto_keygen_failed",
        "crypto_shared_secret_failed",
        "crypto_hkdf_failed",
        "crypto_encrypt_failed",
        "crypto_decrypt_failed",
        # Channel / transport failures
        "channel_post_failed",
        "channel_get_failed",
        "channel_unreachable",
        "envelope_missing",
        "envelope_late",
    }
)

DeliveryErrorCode = str  # alias; validity is checked against DELIVERY_ERROR_CODES


class DeliveryError(TypedDict, total=False):
    """Structured error payload (TS types.ts:748)."""

    code: str
    message: str
    details: dict


# ============================================================================
# Canonical empty value constants (TS types.ts:787 / :807 / :823)
# ============================================================================

# 32 zero bytes — TS types.ts:787 CANONICAL_EMPTY_BYTES32
CANONICAL_EMPTY_BYTES32 = "0x" + "00" * 32
# 12 zero bytes — TS types.ts:807 CANONICAL_EMPTY_BYTES12
CANONICAL_EMPTY_BYTES12 = "0x" + "00" * 12
# 16 zero bytes — TS types.ts:823 CANONICAL_EMPTY_BYTES16
CANONICAL_EMPTY_BYTES16 = "0x" + "00" * 16


__all__ = [
    # Discriminator unions
    "DeliveryScheme",
    "DeliveryMode",
    "DeliveryPrivacy",
    "ParticipantRole",
    "DeliveryNetwork",
    "SCHEME_PUBLIC_V1",
    "SCHEME_ENCRYPTED_V1",
    # Server meta
    "DeliveryServerMeta",
    # Setup
    "DeliverySetupSignedV1",
    "DeliverySetupWireV1",
    # Envelope
    "DeliveryEnvelopeSignedV1",
    "DeliveryEnvelopeWireV1",
    # Builder results
    "BuildSetupResult",
    "BuildEnvelopeResult",
    # Errors
    "DeliveryError",
    "DeliveryErrorCode",
    "DELIVERY_ERROR_CODES",
    # Canonical empty constants
    "CANONICAL_EMPTY_BYTES32",
    "CANONICAL_EMPTY_BYTES12",
    "CANONICAL_EMPTY_BYTES16",
]
