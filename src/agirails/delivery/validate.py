"""
AIP-16 Delivery Surface — Runtime Validation (Python port).

Mirrors sdk-js/src/delivery/validate.ts. Pure, dependency-light validators
for the delivery wire and signed shapes. Validators do NOT throw and do NOT
perform I/O; they return a :class:`ValidationResult` so callers branch
cleanly. On the first failure the validator returns (no error accumulation),
coarse -> fine, exactly like TS (validate.ts:24).

The error string is a stable, machine-actionable identifier (snake_case),
byte-identical to the TS labels so cross-SDK / Platform code maps the same.

Cite: sdk-js/src/delivery/validate.ts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from eth_utils import is_checksum_address, is_hex_address

from agirails.delivery.types import (
    CANONICAL_EMPTY_BYTES12,
    CANONICAL_EMPTY_BYTES16,
    CANONICAL_EMPTY_BYTES32,
)

# ============================================================================
# Result type (TS validate.ts:88 ValidationResult)
# ============================================================================


@dataclass(frozen=True)
class ValidationResult:
    """Discriminated result of every validator (TS validate.ts:88).

    ``ok=True`` -> valid; ``ok=False`` -> ``error`` is a stable snake_case id.
    """

    ok: bool
    error: Optional[str] = None


def _fail(error: str) -> ValidationResult:
    """TS validate.ts:347 — fail()."""
    return ValidationResult(ok=False, error=error)


# Singleton success result (TS validate.ts:356 OK).
_OK = ValidationResult(ok=True)


# ============================================================================
# Internal constants (TS validate.ts:107-164)
# ============================================================================

_BYTES32_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")  # TS validate.ts:107
_BYTES16_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{32}$")  # TS validate.ts:108
_BYTES12_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{24}$")  # TS validate.ts:109
_UINT_STRING_RE = re.compile(r"^(0|[1-9][0-9]*)$")  # TS validate.ts:110
_SIGNATURE_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")  # TS validate.ts:749

_ALLOWED_SCHEMES = frozenset({"x25519-aes256gcm-v1", "public-v1"})  # TS validate.ts:117
_ALLOWED_PRIVACY = frozenset({"encrypted", "public"})  # TS validate.ts:126
_ALLOWED_ROLES = frozenset({"provider", "requester"})  # TS validate.ts:135

# Lowercased canonical-empty (TS validate.ts:145-147).
_CANONICAL_EMPTY_BYTES32_LC = CANONICAL_EMPTY_BYTES32.lower()
_CANONICAL_EMPTY_BYTES12_LC = CANONICAL_EMPTY_BYTES12.lower()
_CANONICAL_EMPTY_BYTES16_LC = CANONICAL_EMPTY_BYTES16.lower()

_MAX_ACCEPTED_CHANNELS = 32  # TS validate.ts:156
_MAX_CHANNEL_ID_LENGTH = 256  # TS validate.ts:164


# ============================================================================
# Primitive validators (TS validate.ts:178-248)
# ============================================================================


def is_valid_bytes32(s: Any) -> bool:
    """TS validate.ts:178 — bytes32 hex (case-insensitive)."""
    return isinstance(s, str) and bool(_BYTES32_HEX_RE.match(s))


def is_valid_bytes12(s: Any) -> bool:
    """TS validate.ts:187 — bytes12 hex (AES-GCM nonce length)."""
    return isinstance(s, str) and bool(_BYTES12_HEX_RE.match(s))


def is_valid_bytes16(s: Any) -> bool:
    """TS validate.ts:196 — bytes16 hex (AES-GCM tag length)."""
    return isinstance(s, str) and bool(_BYTES16_HEX_RE.match(s))


def is_valid_address(s: Any) -> bool:
    """TS validate.ts:211 — ``ethers.isAddress`` equivalent.

    Accepts all-lowercase or all-uppercase hex bodies (no checksum), and
    mixed-case ONLY if the EIP-55 checksum is valid — exactly mirroring
    ``ethers.isAddress`` (which rejects bad-checksum mixed-case addresses).
    ``eth_utils.is_address`` alone is too lenient (accepts bad checksums).
    """
    if not isinstance(s, str) or not is_hex_address(s):
        return False
    body = s[2:]
    if body == body.lower() or body == body.upper():
        return True
    return is_checksum_address(s)


def is_valid_uint_string(s: Any) -> bool:
    """TS validate.ts:223 — decimal non-negative integer string."""
    return isinstance(s, str) and bool(_UINT_STRING_RE.match(s))


def is_valid_scheme(s: Any) -> bool:
    """TS validate.ts:232 — one of DeliveryScheme."""
    return isinstance(s, str) and s in _ALLOWED_SCHEMES


def is_valid_privacy(s: Any) -> bool:
    """TS validate.ts:239 — one of DeliveryPrivacy."""
    return isinstance(s, str) and s in _ALLOWED_PRIVACY


def is_valid_role(s: Any) -> bool:
    """TS validate.ts:246 — one of ParticipantRole."""
    return isinstance(s, str) and s in _ALLOWED_ROLES


# ============================================================================
# Canonical-empty checks (TS validate.ts:265-285)
# ============================================================================


def is_canonical_empty_bytes32(s: Any) -> bool:
    """TS validate.ts:265 — canonical empty bytes32."""
    return isinstance(s, str) and s.lower() == _CANONICAL_EMPTY_BYTES32_LC


def is_canonical_empty_bytes12(s: Any) -> bool:
    """TS validate.ts:274 — canonical empty bytes12."""
    return isinstance(s, str) and s.lower() == _CANONICAL_EMPTY_BYTES12_LC


def is_canonical_empty_bytes16(s: Any) -> bool:
    """TS validate.ts:283 — canonical empty bytes16."""
    return isinstance(s, str) and s.lower() == _CANONICAL_EMPTY_BYTES16_LC


# ============================================================================
# Internal helpers (TS validate.ts:297-341)
# ============================================================================


def _is_object_like(x: Any) -> bool:
    """TS validate.ts:297 — non-null dict (excludes lists). In Python: a dict."""
    return isinstance(x, dict)


def _is_positive_integer(n: Any) -> bool:
    """TS validate.ts:306 — finite positive integer.

    ``bool`` is a Python ``int`` subclass; reject it (a stray ``True`` is not
    a valid timestamp) to match JS's ``typeof n === 'number'``.
    """
    return isinstance(n, int) and not isinstance(n, bool) and n > 0


def _is_valid_accepted_channels(arr: Any) -> bool:
    """TS validate.ts:325 — non-empty bounded array of bounded strings."""
    if not isinstance(arr, list):
        return False
    if len(arr) == 0 or len(arr) > _MAX_ACCEPTED_CHANNELS:
        return False
    for c in arr:
        if not isinstance(c, str):
            return False
        if len(c) == 0 or len(c) > _MAX_CHANNEL_ID_LENGTH:
            return False
    return True


def _is_valid_signature_hex(s: Any) -> bool:
    """TS validate.ts:745 — 0x + 130 hex chars (65-byte secp256k1 sig)."""
    return isinstance(s, str) and len(s) == 132 and bool(_SIGNATURE_HEX_RE.match(s))


def _is_int_chain_id(v: Any) -> bool:
    """Positive integer chainId; reject bool (JS ``typeof === 'number'``)."""
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


# ============================================================================
# Setup signed validator (TS validate.ts:392)
# ============================================================================


def validate_setup_signed(obj: Any) -> ValidationResult:
    """TS validate.ts:392 — structure + field-level invariants for a setup."""
    if not _is_object_like(obj):
        return _fail("setup_signed_not_object")

    if obj.get("version") != 1:
        return _fail("setup_version_invalid")

    if not is_valid_bytes32(obj.get("txId")):
        return _fail("setup_txid_invalid")

    if not _is_int_chain_id(obj.get("chainId")):
        return _fail("setup_chain_id_invalid")

    if not is_valid_address(obj.get("kernelAddress")):
        return _fail("setup_kernel_address_invalid")

    if not is_valid_address(obj.get("requesterAddress")):
        return _fail("setup_requester_address_invalid")

    if not is_valid_address(obj.get("signerAddress")):
        return _fail("setup_signer_address_invalid")

    if not is_valid_bytes32(obj.get("buyerEphemeralPubkey")):
        return _fail("setup_buyer_pubkey_invalid")

    if not _is_valid_accepted_channels(obj.get("acceptedChannels")):
        return _fail("setup_accepted_channels_invalid")

    if not is_valid_privacy(obj.get("expectedPrivacy")):
        return _fail("setup_expected_privacy_invalid")

    if not _is_positive_integer(obj.get("createdAt")):
        return _fail("setup_created_at_invalid")

    if not _is_positive_integer(obj.get("expiresAt")):
        return _fail("setup_expires_at_invalid")

    if obj["expiresAt"] <= obj["createdAt"]:
        return _fail("expiresAt_before_createdAt")

    return _OK


# ============================================================================
# Setup wire validator (TS validate.ts:477)
# ============================================================================


def validate_setup_wire(obj: Any) -> ValidationResult:
    """TS validate.ts:477 — structure of a setup wire object."""
    if not _is_object_like(obj):
        return _fail("setup_wire_not_object")

    signed_result = validate_setup_signed(obj.get("signed"))
    if not signed_result.ok:
        return signed_result

    if not _is_valid_signature_hex(obj.get("requesterSig")):
        return _fail("setup_requester_sig_invalid")

    server_meta = obj.get("serverMeta")
    if server_meta is not None:
        if not _is_object_like(server_meta):
            return _fail("setup_server_meta_invalid")
        received_at = server_meta.get("receivedAt")
        if not isinstance(received_at, str) or len(received_at) == 0:
            return _fail("setup_server_meta_received_at_invalid")
        relay_id = server_meta.get("relayId")
        if not isinstance(relay_id, str) or len(relay_id) == 0:
            return _fail("setup_server_meta_relay_id_invalid")

    return _OK


# ============================================================================
# Envelope signed validator (TS validate.ts:538)
# ============================================================================


def validate_envelope_signed(obj: Any) -> ValidationResult:
    """TS validate.ts:538 — structure + scheme/canonical-empty consistency."""
    if not _is_object_like(obj):
        return _fail("envelope_signed_not_object")

    if obj.get("version") != 1:
        return _fail("envelope_version_invalid")

    if not is_valid_bytes32(obj.get("txId")):
        return _fail("envelope_txid_invalid")

    if not _is_int_chain_id(obj.get("chainId")):
        return _fail("envelope_chain_id_invalid")

    if not is_valid_address(obj.get("kernelAddress")):
        return _fail("envelope_kernel_address_invalid")

    if not is_valid_address(obj.get("providerAddress")):
        return _fail("envelope_provider_address_invalid")

    if not is_valid_address(obj.get("signerAddress")):
        return _fail("envelope_signer_address_invalid")

    if not is_valid_scheme(obj.get("scheme")):
        return _fail("envelope_scheme_invalid")

    if not is_valid_bytes32(obj.get("providerEphemeralPubkey")):
        return _fail("envelope_provider_pubkey_invalid")

    if not is_valid_bytes12(obj.get("nonce")):
        return _fail("envelope_nonce_invalid")

    if not is_valid_bytes32(obj.get("payloadHash")):
        return _fail("envelope_payload_hash_invalid")

    if not is_valid_bytes16(obj.get("tag")):
        return _fail("envelope_tag_invalid")

    if not _is_positive_integer(obj.get("createdAt")):
        return _fail("envelope_created_at_invalid")

    # Cross-field: scheme <-> canonical-empty (TS validate.ts:598).
    return validate_scheme_consistency(obj)


# ============================================================================
# Envelope wire validator (TS validate.ts:625)
# ============================================================================


def validate_envelope_wire(obj: Any) -> ValidationResult:
    """TS validate.ts:625 — structure of an envelope wire object."""
    if not _is_object_like(obj):
        return _fail("envelope_wire_not_object")

    signed_result = validate_envelope_signed(obj.get("signed"))
    if not signed_result.ok:
        return signed_result

    body = obj.get("body")
    if not isinstance(body, str) or len(body) == 0:
        return _fail("envelope_body_invalid")

    if not _is_valid_signature_hex(obj.get("providerSig")):
        return _fail("envelope_provider_sig_invalid")

    server_meta = obj.get("serverMeta")
    if server_meta is not None:
        if not _is_object_like(server_meta):
            return _fail("envelope_server_meta_invalid")
        received_at = server_meta.get("receivedAt")
        if not isinstance(received_at, str) or len(received_at) == 0:
            return _fail("envelope_server_meta_received_at_invalid")
        relay_id = server_meta.get("relayId")
        if not isinstance(relay_id, str) or len(relay_id) == 0:
            return _fail("envelope_server_meta_relay_id_invalid")

    return _OK


# ============================================================================
# Scheme consistency / canonical-empty rule (TS validate.ts:692)
# ============================================================================


def validate_scheme_consistency(env: Any) -> ValidationResult:
    """TS validate.ts:692 — enforce the AIP-16 canonical-empty rule.

    Assumes field types/lengths are already correct (run
    :func:`validate_envelope_signed` first, which invokes this automatically).
    """
    scheme = env.get("scheme") if isinstance(env, dict) else None

    if scheme == "public-v1":
        if not is_canonical_empty_bytes32(env.get("providerEphemeralPubkey")):
            return _fail("envelope_public_pubkey_not_canonical_empty")
        if not is_canonical_empty_bytes12(env.get("nonce")):
            return _fail("envelope_public_nonce_not_canonical_empty")
        if not is_canonical_empty_bytes16(env.get("tag")):
            return _fail("envelope_public_tag_not_canonical_empty")
        return _OK

    if scheme == "x25519-aes256gcm-v1":
        if is_canonical_empty_bytes32(env.get("providerEphemeralPubkey")):
            return _fail("envelope_encrypted_pubkey_is_canonical_empty")
        if is_canonical_empty_bytes12(env.get("nonce")):
            return _fail("envelope_encrypted_nonce_is_canonical_empty")
        if is_canonical_empty_bytes16(env.get("tag")):
            return _fail("envelope_encrypted_tag_is_canonical_empty")
        return _OK

    # Unreachable if validate_envelope_signed has run (TS validate.ts:723).
    return _fail("envelope_scheme_invalid")


__all__ = [
    "ValidationResult",
    # Primitive validators
    "is_valid_bytes32",
    "is_valid_bytes12",
    "is_valid_bytes16",
    "is_valid_address",
    "is_valid_uint_string",
    "is_valid_scheme",
    "is_valid_privacy",
    "is_valid_role",
    # Canonical-empty checks
    "is_canonical_empty_bytes32",
    "is_canonical_empty_bytes12",
    "is_canonical_empty_bytes16",
    # Schema validators
    "validate_setup_signed",
    "validate_setup_wire",
    "validate_envelope_signed",
    "validate_envelope_wire",
    # Cross-field consistency
    "validate_scheme_consistency",
]
