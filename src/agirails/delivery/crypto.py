"""
AIP-16 Delivery Surface — AES-256-GCM AEAD + body hashing (Python port).

Byte-exact parity with sdk-js/src/delivery/crypto.ts for the
``x25519-aes256gcm-v1`` scheme:

- :func:`encrypt_body` / :func:`decrypt_body`: AES-256-GCM seal/open with a
  12-byte nonce and 16-byte tag, optional 52-byte AAD = ``txId(32) ||
  signerAddress(20)`` (H5 misrouting defense).
- :func:`body_hash`: ``keccak256(bodyBytes)`` for the EIP-712 ``payloadHash``
  field — plaintext bytes for ``public-v1``, ciphertext bytes for the
  encrypted scheme.

Crypto via pyca/cryptography ``AESGCM`` (OpenSSL), matching Node's
``createCipheriv('aes-256-gcm', …)`` byte-for-byte.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_hash.auto import keccak

from agirails.delivery.keys import (
    DELIVERY_SESSION_KEY_LENGTH,
    DeliveryCryptoError,
    bytes_from_hex,
    bytes_to_hex,
)

AES_GCM_NONCE_LENGTH = 12
AES_GCM_TAG_LENGTH = 16
AES_KEY_LENGTH = DELIVERY_SESSION_KEY_LENGTH  # 32


@dataclass
class EncryptResult:
    """Ciphertext + 12-byte nonce + 16-byte tag (raw bytes)."""

    ciphertext: bytes
    nonce: bytes
    tag: bytes


def _to_bytes(value: Union[str, bytes], field: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise DeliveryCryptoError(
        "crypto_encrypt_failed",
        f"{field} must be a string or bytes, got {type(value).__name__}",
        {"field": field, "type": type(value).__name__},
    )


def seal_with_nonce(
    plaintext: Union[str, bytes],
    session_key: bytes,
    nonce: bytes,
    aad: Optional[bytes] = None,
) -> EncryptResult:
    """Deterministic AES-256-GCM seal with a caller-supplied nonce.

    The byte-exact core used by :func:`encrypt_body`; exposed so callers (and
    cross-SDK vector tests) can reproduce a known ciphertext/tag.
    """
    if not isinstance(session_key, (bytes, bytearray)) or len(session_key) != AES_KEY_LENGTH:
        raise DeliveryCryptoError(
            "crypto_encrypt_failed",
            f"sessionKey must be exactly {AES_KEY_LENGTH} bytes",
            {"field": "sessionKey"},
        )
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != AES_GCM_NONCE_LENGTH:
        raise DeliveryCryptoError(
            "crypto_encrypt_failed",
            f"nonce must be exactly {AES_GCM_NONCE_LENGTH} bytes",
            {"field": "nonce"},
        )
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise DeliveryCryptoError("crypto_encrypt_failed", "aad must be bytes when supplied", {"field": "aad"})
    pt = _to_bytes(plaintext, "plaintext")
    try:
        sealed = AESGCM(bytes(session_key)).encrypt(bytes(nonce), pt, bytes(aad) if aad is not None else None)
    except Exception as err:  # noqa: BLE001
        raise DeliveryCryptoError("crypto_encrypt_failed", f"AES-256-GCM encryption failed: {err}") from err
    # cryptography appends the 16-byte tag to the ciphertext; split to match TS.
    ciphertext = sealed[:-AES_GCM_TAG_LENGTH]
    tag = sealed[-AES_GCM_TAG_LENGTH:]
    return EncryptResult(ciphertext=ciphertext, nonce=bytes(nonce), tag=tag)


def encrypt_body(
    plaintext: Union[str, bytes],
    session_key: bytes,
    aad: Optional[bytes] = None,
) -> EncryptResult:
    """Encrypt a delivery body with AES-256-GCM (fresh random 12-byte nonce)."""
    nonce = os.urandom(AES_GCM_NONCE_LENGTH)
    return seal_with_nonce(plaintext, session_key, nonce, aad)


def decrypt_body(
    ciphertext: bytes,
    session_key: bytes,
    nonce: bytes,
    tag: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Verify the GCM tag and return the plaintext (raises on any mismatch)."""
    for name, val, length in (
        ("ciphertext", ciphertext, None),
        ("sessionKey", session_key, AES_KEY_LENGTH),
        ("nonce", nonce, AES_GCM_NONCE_LENGTH),
        ("tag", tag, AES_GCM_TAG_LENGTH),
    ):
        if not isinstance(val, (bytes, bytearray)):
            raise DeliveryCryptoError("crypto_decrypt_failed", f"{name} must be bytes", {"field": name})
        if length is not None and len(val) != length:
            raise DeliveryCryptoError(
                "crypto_decrypt_failed",
                f"{name} must be exactly {length} bytes (got {len(val)})",
                {"field": name},
            )
    if aad is not None and not isinstance(aad, (bytes, bytearray)):
        raise DeliveryCryptoError("crypto_decrypt_failed", "aad must be bytes when supplied", {"field": "aad"})
    try:
        return AESGCM(bytes(session_key)).decrypt(
            bytes(nonce), bytes(ciphertext) + bytes(tag), bytes(aad) if aad is not None else None
        )
    except Exception as err:  # noqa: BLE001
        raise DeliveryCryptoError(
            "crypto_decrypt_failed", f"AES-256-GCM decryption / authentication failed: {err}"
        ) from err


def body_hash(body: Union[str, bytes]) -> str:
    """keccak256 of the body bytes, as a 0x-prefixed lowercase 66-char hex.

    For ``public-v1`` pass the plaintext; for the encrypted scheme pass the
    ciphertext bytes (commits the signer to the exact wire bytes).
    """
    data = _to_bytes(body, "body")
    return "0x" + keccak(data).hex()


__all__ = [
    "AES_GCM_NONCE_LENGTH",
    "AES_GCM_TAG_LENGTH",
    "AES_KEY_LENGTH",
    "EncryptResult",
    "encrypt_body",
    "decrypt_body",
    "seal_with_nonce",
    "body_hash",
    "bytes_to_hex",
    "bytes_from_hex",
]
