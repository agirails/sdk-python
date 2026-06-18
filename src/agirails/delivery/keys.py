"""
AIP-16 Delivery Surface — X25519 keys, ECDH, HKDF (Python port).

Byte-exact parity with the TS delivery layer (sdk-js/src/delivery/keys.ts) for
the ``x25519-aes256gcm-v1`` scheme:

    1. ephemeral X25519 keypair
    2. ECDH shared secret (X25519, reject all-zero / low-order peers)
    3. HKDF-SHA256 stretch to a 32-byte session key, with the on-chain
       ``txId`` as the salt and ``"agirails-delivery-v1"`` as the info string.

Crypto via pyca/cryptography (X25519, HKDF), matching Node's ``crypto`` +
``@noble/curves`` byte-for-byte (both implement RFC 7748 / RFC 5869).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================================================
# Constants
# ============================================================================

X25519_PUBLIC_KEY_LENGTH = 32
X25519_PRIVATE_KEY_LENGTH = 32
X25519_SHARED_SECRET_LENGTH = 32
DELIVERY_SESSION_KEY_LENGTH = 32
TX_ID_BYTES = 32

# HKDF `info` string for v1 delivery session-key derivation (UTF-8 bytes).
DELIVERY_HKDF_INFO_V1 = "agirails-delivery-v1"


class DeliveryCryptoError(Exception):
    """Structured error for the delivery crypto layer (mirrors TS).

    ``code`` is a stable machine-actionable identifier; ``details`` carries
    optional debugging context.
    """

    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


# ============================================================================
# Hex helpers (lowercase, 0x-prefixed) — byte-identical to TS
# ============================================================================

_HEX = "0123456789abcdef"


def bytes_to_hex(b: bytes) -> str:
    """Encode raw bytes to a lowercase 0x-prefixed hex string."""
    if not isinstance(b, (bytes, bytearray)):
        raise DeliveryCryptoError("crypto_keygen_failed", f"bytes_to_hex expected bytes, got {type(b).__name__}")
    out = ["0x"]
    for byte in b:
        out.append(_HEX[(byte >> 4) & 0x0F])
        out.append(_HEX[byte & 0x0F])
    return "".join(out)


def bytes_from_hex(hex_str: str, *, expected_length: Optional[int] = None, field: str = "value") -> bytes:
    """Decode a 0x-prefixed even-length hex string to bytes."""
    if not isinstance(hex_str, str):
        raise DeliveryCryptoError("crypto_keygen_failed", f"{field} must be a string, got {type(hex_str).__name__}")
    if len(hex_str) < 2 or hex_str[0] != "0" or hex_str[1] not in ("x", "X"):
        raise DeliveryCryptoError("crypto_keygen_failed", f"{field} requires a 0x-prefixed string")
    body = hex_str[2:]
    if len(body) % 2 != 0:
        raise DeliveryCryptoError("crypto_keygen_failed", f"{field} requires an even number of hex digits")
    try:
        out = bytes.fromhex(body)
    except ValueError as exc:
        raise DeliveryCryptoError("crypto_keygen_failed", f"{field} contains non-hex characters") from exc
    if expected_length is not None and len(out) != expected_length:
        raise DeliveryCryptoError(
            "crypto_keygen_failed",
            f"{field} must be exactly {expected_length} bytes (got {len(out)})",
            {"field": field, "expectedLength": expected_length, "actualLength": len(out)},
        )
    return out


def _assert_byte_length(value: bytes, expected: int, code: str, field: str) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise DeliveryCryptoError(code, f"{field} must be bytes, got {type(value).__name__}", {"field": field})
    if len(value) != expected:
        raise DeliveryCryptoError(
            code,
            f"{field} must be exactly {expected} bytes (got {len(value)})",
            {"field": field, "expectedLength": expected, "actualLength": len(value)},
        )


# ============================================================================
# X25519 keypair + ECDH
# ============================================================================


@dataclass
class EphemeralKeyPair:
    """A freshly generated X25519 ephemeral keypair (32 raw bytes each)."""

    public_key: bytes
    secret_key: bytes


def generate_ephemeral_key_pair() -> EphemeralKeyPair:
    """Generate a fresh X25519 ephemeral keypair using the system CSPRNG."""
    try:
        priv = X25519PrivateKey.generate()
        secret = priv.private_bytes_raw()
        public = priv.public_key().public_bytes_raw()
    except Exception as err:  # noqa: BLE001
        raise DeliveryCryptoError("crypto_keygen_failed", f"X25519 keygen failed: {err}") from err
    _assert_byte_length(public, X25519_PUBLIC_KEY_LENGTH, "crypto_keygen_failed", "publicKey")
    _assert_byte_length(secret, X25519_PRIVATE_KEY_LENGTH, "crypto_keygen_failed", "secretKey")
    return EphemeralKeyPair(public_key=public, secret_key=secret)


def public_key_from_private(private_key: bytes) -> bytes:
    """Derive the 32-byte X25519 public key from a 32-byte private scalar."""
    _assert_byte_length(private_key, X25519_PRIVATE_KEY_LENGTH, "crypto_keygen_failed", "privateKey")
    try:
        return X25519PrivateKey.from_private_bytes(bytes(private_key)).public_key().public_bytes_raw()
    except Exception as err:  # noqa: BLE001
        raise DeliveryCryptoError("crypto_keygen_failed", f"X25519 public-key derivation failed: {err}") from err


def derive_shared_secret(private_key: bytes, peer_pubkey: bytes) -> bytes:
    """X25519 ECDH. Rejects the all-zero shared secret (low-order peer)."""
    _assert_byte_length(private_key, X25519_PRIVATE_KEY_LENGTH, "crypto_keygen_failed", "privateKey")
    _assert_byte_length(peer_pubkey, X25519_PUBLIC_KEY_LENGTH, "crypto_keygen_failed", "peerPubkey")
    try:
        shared = X25519PrivateKey.from_private_bytes(bytes(private_key)).exchange(
            X25519PublicKey.from_public_bytes(bytes(peer_pubkey))
        )
    except Exception as err:  # noqa: BLE001
        # cryptography raises on some low-order points — treat as degenerate.
        raise DeliveryCryptoError(
            "crypto_ecdh_failed",
            "X25519 ECDH produced an all-zero shared secret (peer pubkey is a "
            "low-order Curve25519 point); rejecting degenerate key agreement.",
            {"cause": str(err)},
        ) from err
    # OR-fold all bytes; all-zero => degenerate.
    acc = 0
    for byte in shared:
        acc |= byte
    if acc == 0:
        raise DeliveryCryptoError(
            "crypto_ecdh_failed",
            "X25519 ECDH produced an all-zero shared secret (peer pubkey is a "
            "low-order Curve25519 point); rejecting degenerate key agreement.",
        )
    return shared


# ============================================================================
# HKDF-SHA256 session-key derivation
# ============================================================================


def derive_session_key(shared_secret: bytes, tx_id: str, info: str = DELIVERY_HKDF_INFO_V1) -> bytes:
    """HKDF-SHA256(ikm=shared_secret, salt=txId bytes, info=utf8(info), L=32).

    Byte-exact with Node ``hkdfSync('sha256', shared, txIdBytes, utf8(info), 32)``.
    """
    _assert_byte_length(shared_secret, X25519_SHARED_SECRET_LENGTH, "crypto_hkdf_failed", "sharedSecret")
    try:
        salt = bytes_from_hex(tx_id, expected_length=TX_ID_BYTES, field="txId")
    except DeliveryCryptoError as err:
        raise DeliveryCryptoError("crypto_hkdf_failed", f"txId is malformed: {err}") from err
    if not isinstance(info, str):
        raise DeliveryCryptoError("crypto_hkdf_failed", f"info must be a string, got {type(info).__name__}")
    try:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=DELIVERY_SESSION_KEY_LENGTH,
            salt=salt,
            info=info.encode("utf-8"),
        ).derive(bytes(shared_secret))
    except Exception as err:  # noqa: BLE001
        raise DeliveryCryptoError("crypto_hkdf_failed", f"HKDF-SHA256 failed: {err}") from err
    if len(derived) != DELIVERY_SESSION_KEY_LENGTH:
        raise DeliveryCryptoError("crypto_hkdf_failed", f"HKDF produced {len(derived)} bytes, expected {DELIVERY_SESSION_KEY_LENGTH}")
    return derived


# ============================================================================
# Pubkey hex helpers
# ============================================================================


def pubkey_to_hex(pubkey: bytes) -> str:
    _assert_byte_length(pubkey, X25519_PUBLIC_KEY_LENGTH, "crypto_keygen_failed", "pubkey")
    return bytes_to_hex(pubkey)


def pubkey_from_hex(hex_str: str) -> bytes:
    return bytes_from_hex(hex_str, expected_length=X25519_PUBLIC_KEY_LENGTH, field="pubkey")
