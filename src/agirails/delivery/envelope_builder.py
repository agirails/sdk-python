"""
AIP-16 Delivery Surface — Provider Envelope Builder + Verifier + Decryptor
(Python port).

Mirrors sdk-js/src/delivery/envelopeBuilder.ts. Constructs and verifies the
provider-signed ``DeliveryEnvelopeV1`` payload, and decrypts encrypted
payloads on the buyer side. Reuses the verified crypto + EIP-712 core
(``encrypt_body`` / ``decrypt_body`` / ``body_hash`` / ``derive_shared_secret``
/ ``derive_session_key`` / ``sign_envelope`` / ``recover_envelope_signer``).
NO crypto is reimplemented here.

FIX-1 body encoding (TS envelopeBuilder.ts:25):
  - ``public-v1``: ``wire.body`` = plaintext UTF-8 JSON string (NOT hex);
    ``payloadHash`` = ``body_hash(bodyString)`` (utf-8 bytes).
  - ``x25519-aes256gcm-v1``: ``wire.body`` = 0x-hex of ciphertext;
    ``payloadHash`` = ``body_hash(ciphertext)`` (raw bytes).

H5 AAD (TS envelopeBuilder.ts:189): AAD = ``txId(32) || signerAddress(20) =
52 bytes``, bound inside the GCM tag both on encrypt and decrypt.

Cite: sdk-js/src/delivery/envelopeBuilder.ts.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from agirails.delivery.crypto import (
    body_hash,
    bytes_from_hex,
    bytes_to_hex,
    decrypt_body,
    encrypt_body,
)
from agirails.delivery.eip712 import (
    DeliveryEip712Error,
    recover_envelope_signer,
    sign_envelope,
)
from agirails.delivery.keys import (
    DeliveryCryptoError,
    derive_session_key,
    derive_shared_secret,
    generate_ephemeral_key_pair,
    pubkey_from_hex,
    pubkey_to_hex,
)
from agirails.delivery.types import (
    CANONICAL_EMPTY_BYTES12,
    CANONICAL_EMPTY_BYTES16,
    CANONICAL_EMPTY_BYTES32,
    BuildEnvelopeResult,
    DeliveryEnvelopeSignedV1,
    DeliveryEnvelopeWireV1,
)
from agirails.delivery.validate import (
    validate_envelope_wire,
    validate_scheme_consistency,
)
from agirails.utils.canonical_json import canonical_json_dumps

from eth_hash.auto import keccak

# ============================================================================
# Constants (TS envelopeBuilder.ts:172 / :189)
# ============================================================================

# TS envelopeBuilder.ts:172 — ENVELOPE_TIMESTAMP_SKEW_SEC
ENVELOPE_TIMESTAMP_SKEW_SEC = 900

# TS envelopeBuilder.ts:189 — ENVELOPE_AAD_LENGTH (txId 32 + signer 20)
ENVELOPE_AAD_LENGTH = 52


def build_envelope_aad(tx_id: str, signer_address: str) -> bytes:
    """Construct the AES-256-GCM AAD: ``txId(32) || signerAddress(20)`` (TS:213).

    Both build and decrypt sides call this with the SAME txId/signerAddress so
    the GCM tag commits to identical AAD bytes. ``bytes_from_hex`` is
    case-insensitive, so checksum vs lowercase inputs yield the same 20 bytes.
    """
    tx_id_bytes = bytes_from_hex(tx_id)
    if len(tx_id_bytes) != 32:
        raise DeliveryEip712Error(
            "BUILDER_AAD_TXID_INVALID_LENGTH",
            f"txId must decode to 32 bytes, got {len(tx_id_bytes)}",
            {"actualLength": len(tx_id_bytes)},
        )
    signer_bytes = bytes_from_hex(signer_address)
    if len(signer_bytes) != 20:
        raise DeliveryEip712Error(
            "BUILDER_AAD_SIGNER_INVALID_LENGTH",
            f"signerAddress must decode to 20 bytes, got {len(signer_bytes)}",
            {"actualLength": len(signer_bytes)},
        )
    aad = bytearray(ENVELOPE_AAD_LENGTH)
    aad[0:32] = tx_id_bytes
    aad[32:52] = signer_bytes
    return bytes(aad)


# ============================================================================
# Injectable clock (TS envelopeBuilder.ts:252-296)
# ============================================================================

_seconds_now_impl = lambda: int(time.time())  # noqa: E731


def _seconds_now() -> int:
    """Current wall clock in Unix seconds (TS envelopeBuilder.ts:267)."""
    return _seconds_now_impl()


def set_seconds_now_for_tests(impl: Optional[Any]) -> None:
    """TEST-ONLY: replace the wall-clock impl (TS envelopeBuilder.ts:281)."""
    global _seconds_now_impl
    if impl is None:
        reset_seconds_now_for_tests()
        return
    _seconds_now_impl = impl


def reset_seconds_now_for_tests() -> None:
    """TEST-ONLY: restore the real wall clock (TS envelopeBuilder.ts:294)."""
    global _seconds_now_impl
    _seconds_now_impl = lambda: int(time.time())  # noqa: E731


# ============================================================================
# Public parameter types (TS envelopeBuilder.ts:310 / :380)
# ============================================================================


@dataclass
class BuildPublicEnvelopeParams:
    """Parameters for :meth:`DeliveryEnvelopeBuilder.build_public` (TS:310)."""

    tx_id: str
    chain_id: int
    kernel_address: str
    provider_address: str
    signer_address: str
    payload: Any
    created_at: Optional[int] = None
    smart_wallet_nonce: Optional[int] = None


@dataclass
class BuildEncryptedEnvelopeParams:
    """Parameters for :meth:`DeliveryEnvelopeBuilder.build_encrypted` (TS:380).

    ``provider_ephemeral_key_pair`` is a TEST-ONLY override (an
    ``EphemeralKeyPair``); production callers omit it so a fresh keypair is
    generated and the private key never crosses a call boundary.
    """

    tx_id: str
    chain_id: int
    kernel_address: str
    provider_address: str
    signer_address: str
    payload: Any
    buyer_ephemeral_pubkey: str
    provider_ephemeral_key_pair: Optional[Any] = None
    created_at: Optional[int] = None
    smart_wallet_nonce: Optional[int] = None


@dataclass
class EnvelopeVerifyResult:
    """Result of :meth:`DeliveryEnvelopeBuilder.verify` (TS:837)."""

    ok: bool
    signed: Optional[DeliveryEnvelopeSignedV1] = None
    code: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VerifyAndDecryptResult:
    """Result of :meth:`verify_and_decrypt` (TS envelopeBuilder.ts:1077)."""

    ok: bool
    payload: Any = None
    code: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# Envelope builder (TS envelopeBuilder.ts:486 DeliveryEnvelopeBuilder)
# ============================================================================


class DeliveryEnvelopeBuilder:
    """Builder + verifier + decryptor for AIP-16 delivery envelopes (TS:486).

    :meth:`verify`, :meth:`decrypt_payload`, :meth:`verify_and_decrypt`, and
    :meth:`compute_hash` are ``staticmethod`` — call without an instance.
    The signer is an ``eth_account`` ``LocalAccount``.
    """

    def __init__(self, signer: Optional[Any] = None) -> None:
        """TS envelopeBuilder.ts:497 — constructor(signer?)."""
        self._signer = signer

    # ------------------------------------------------------------------
    # build_public (TS envelopeBuilder.ts:534)
    # ------------------------------------------------------------------

    def build_public(self, params: BuildPublicEnvelopeParams) -> BuildEnvelopeResult:
        """Build + sign a ``public-v1`` envelope (TS envelopeBuilder.ts:534)."""
        if self._signer is None:
            raise DeliveryEip712Error(
                "BUILDER_NO_SIGNER",
                "DeliveryEnvelopeBuilder.build_public requires a signer; construct "
                "the builder with a LocalAccount to sign envelopes.",
            )

        # ----- Timestamps (TS envelopeBuilder.ts:545) -----
        created_at = params.created_at if params.created_at is not None else _seconds_now()
        if not _is_int(created_at) or created_at <= 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_CREATED_AT",
                f"createdAt must be a positive integer, got {created_at}",
                {"createdAt": created_at},
            )

        # ----- Signer-address binding (TS envelopeBuilder.ts:559) -----
        actual_signer = self._signer.address
        if actual_signer.lower() != params.signer_address.lower():
            raise DeliveryEip712Error(
                "BUILDER_SIGNER_ADDRESS_MISMATCH",
                "params.signerAddress does not match signer.address",
                {"expected": actual_signer.lower(), "got": params.signer_address.lower()},
            )

        # ----- Smart-wallet nonce (H4, TS envelopeBuilder.ts:572) -----
        smart_wallet_nonce = (
            params.smart_wallet_nonce if params.smart_wallet_nonce is not None else 0
        )
        if not _is_int(smart_wallet_nonce) or smart_wallet_nonce < 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_SMART_WALLET_NONCE",
                f"smartWalletNonce must be a non-negative integer, got {smart_wallet_nonce}",
                {"smartWalletNonce": smart_wallet_nonce},
            )

        # ----- Encode body (FIX-1, TS envelopeBuilder.ts:597) -----
        # JSON.stringify equivalent: compact separators, non-ASCII preserved.
        # NOT canonical JSON — the body is a user payload and the buyer must
        # recover the exact structure the provider wrote.
        body_string = _json_stringify(params.payload)
        plaintext_bytes = body_string.encode("utf-8")
        wire_body = body_string  # plaintext UTF-8 JSON, NOT hex
        payload_hash = body_hash(body_string)  # body_hash(str) -> utf-8 bytes

        # ----- Build signed projection (TS envelopeBuilder.ts:608) -----
        signed: DeliveryEnvelopeSignedV1 = {
            "version": 1,
            "txId": params.tx_id,
            "chainId": params.chain_id,
            "kernelAddress": params.kernel_address,
            "providerAddress": params.provider_address,
            "signerAddress": params.signer_address,
            "scheme": "public-v1",
            "providerEphemeralPubkey": CANONICAL_EMPTY_BYTES32,
            "nonce": CANONICAL_EMPTY_BYTES12,
            "payloadHash": payload_hash,
            "tag": CANONICAL_EMPTY_BYTES16,
            "createdAt": created_at,
            "smartWalletNonce": smart_wallet_nonce,
        }

        # ----- Sign (TS envelopeBuilder.ts:625) -----
        provider_sig = sign_envelope(self._signer, signed, params.kernel_address)

        wire: DeliveryEnvelopeWireV1 = {
            "signed": signed,
            "body": wire_body,
            "providerSig": provider_sig,
        }

        # blobKey intentionally omitted for the public scheme.
        return {"wire": wire, "bodyBytes": plaintext_bytes}

    # ------------------------------------------------------------------
    # build_encrypted (TS envelopeBuilder.ts:683)
    # ------------------------------------------------------------------

    def build_encrypted(
        self, params: BuildEncryptedEnvelopeParams
    ) -> BuildEnvelopeResult:
        """Build + sign an ``x25519-aes256gcm-v1`` envelope (TS:683)."""
        if self._signer is None:
            raise DeliveryEip712Error(
                "BUILDER_NO_SIGNER",
                "DeliveryEnvelopeBuilder.build_encrypted requires a signer; construct "
                "the builder with a LocalAccount to sign envelopes.",
            )

        # ----- Buyer pubkey canonical-empty rejection (TS:694) -----
        if params.buyer_ephemeral_pubkey.lower() == CANONICAL_EMPTY_BYTES32.lower():
            raise DeliveryEip712Error(
                "BUILDER_ENCRYPTED_BUYER_PUBKEY_IS_CANONICAL_EMPTY",
                "x25519-aes256gcm-v1 requires a non-zero X25519 buyer pubkey "
                "(RFC 7748 §6.1).",
                {"buyerEphemeralPubkey": params.buyer_ephemeral_pubkey},
            )

        # ----- Timestamps (TS envelopeBuilder.ts:706) -----
        created_at = params.created_at if params.created_at is not None else _seconds_now()
        if not _is_int(created_at) or created_at <= 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_CREATED_AT",
                f"createdAt must be a positive integer, got {created_at}",
                {"createdAt": created_at},
            )

        # ----- Signer-address binding (TS envelopeBuilder.ts:716) -----
        actual_signer = self._signer.address
        if actual_signer.lower() != params.signer_address.lower():
            raise DeliveryEip712Error(
                "BUILDER_SIGNER_ADDRESS_MISMATCH",
                "params.signerAddress does not match signer.address",
                {"expected": actual_signer.lower(), "got": params.signer_address.lower()},
            )

        # ----- Ephemeral keypair (generate or accept, TS:733) -----
        provider_kp = (
            params.provider_ephemeral_key_pair
            if params.provider_ephemeral_key_pair is not None
            else generate_ephemeral_key_pair()
        )
        provider_priv, provider_pub = _kp_priv_pub(provider_kp)

        # ----- ECDH + HKDF (TS envelopeBuilder.ts:737) -----
        peer_pubkey = pubkey_from_hex(params.buyer_ephemeral_pubkey)
        shared = derive_shared_secret(provider_priv, peer_pubkey)
        session_key = derive_session_key(shared, params.tx_id)

        # ----- Encrypt with H5 AAD binding (TS envelopeBuilder.ts:749) -----
        aad = build_envelope_aad(params.tx_id, params.signer_address)
        body_string = _json_stringify(params.payload)
        plaintext_bytes = body_string.encode("utf-8")
        enc = encrypt_body(plaintext_bytes, session_key, aad)

        # ----- Wire body + payloadHash over CIPHERTEXT (TS:759) -----
        wire_body_hex = bytes_to_hex(enc.ciphertext)
        payload_hash = body_hash(enc.ciphertext)

        # ----- Smart-wallet nonce (H4, TS envelopeBuilder.ts:763) -----
        smart_wallet_nonce = (
            params.smart_wallet_nonce if params.smart_wallet_nonce is not None else 0
        )
        if not _is_int(smart_wallet_nonce) or smart_wallet_nonce < 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_SMART_WALLET_NONCE",
                f"smartWalletNonce must be a non-negative integer, got {smart_wallet_nonce}",
                {"smartWalletNonce": smart_wallet_nonce},
            )

        # ----- Build signed projection (TS envelopeBuilder.ts:773) -----
        signed: DeliveryEnvelopeSignedV1 = {
            "version": 1,
            "txId": params.tx_id,
            "chainId": params.chain_id,
            "kernelAddress": params.kernel_address,
            "providerAddress": params.provider_address,
            "signerAddress": params.signer_address,
            "scheme": "x25519-aes256gcm-v1",
            "providerEphemeralPubkey": pubkey_to_hex(provider_pub),
            "nonce": bytes_to_hex(enc.nonce),
            "payloadHash": payload_hash,
            "tag": bytes_to_hex(enc.tag),
            "createdAt": created_at,
            "smartWalletNonce": smart_wallet_nonce,
        }

        # ----- Sign (TS envelopeBuilder.ts:790) -----
        provider_sig = sign_envelope(self._signer, signed, params.kernel_address)

        wire: DeliveryEnvelopeWireV1 = {
            "signed": signed,
            "body": wire_body_hex,
            "providerSig": provider_sig,
        }

        return {"wire": wire, "bodyBytes": enc.ciphertext, "blobKey": session_key}

    # ------------------------------------------------------------------
    # verify (static, TS envelopeBuilder.ts:829)
    # ------------------------------------------------------------------

    @staticmethod
    def verify(
        wire: DeliveryEnvelopeWireV1,
        *,
        expected_kernel_address: str,
        expected_chain_id: int,
        now: Optional[int] = None,
    ) -> EnvelopeVerifyResult:
        """Verify an envelope wire object received from the relay (TS:829).

        Order: shape -> scheme-consistency -> chainId -> kernel ->
        payloadHash -> signature -> timestamp skew (skew LAST so a forged
        signature surfaces first).
        """
        # Step 1: structural / shape validation (TS envelopeBuilder.ts:843).
        shape_result = validate_envelope_wire(wire)
        if not shape_result.ok:
            return EnvelopeVerifyResult(
                ok=False, code="envelope_signature_invalid", error=shape_result.error
            )

        signed = wire["signed"]

        # Step 2: defense-in-depth scheme/canonical-empty re-check (TS:859).
        consistency_result = validate_scheme_consistency(signed)
        if not consistency_result.ok:
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_signature_invalid",
                error=consistency_result.error,
            )

        # Step 3: chainId match (TS envelopeBuilder.ts:869).
        if signed["chainId"] != expected_chain_id:
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_chain_mismatch",
                error=f"expected chainId {expected_chain_id}, got {signed['chainId']}",
            )

        # Step 4: kernel-address match (TS envelopeBuilder.ts:878).
        expected_kernel_lc = expected_kernel_address.lower()
        payload_kernel_lc = signed["kernelAddress"].lower()
        if payload_kernel_lc != expected_kernel_lc:
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_kernel_mismatch",
                error=f"expected kernel {expected_kernel_lc}, got {payload_kernel_lc}",
            )

        # Step 5: payloadHash binding, scheme-aware (FIX-1, TS:888).
        try:
            if signed["scheme"] == "public-v1":
                recomputed_hash = body_hash(wire["body"])
            else:
                body_bytes = bytes_from_hex(wire["body"])
                recomputed_hash = body_hash(body_bytes)
        except Exception as e:  # noqa: BLE001
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_payload_hash_mismatch",
                error=f"failed to decode wire.body for payloadHash recomputation: {e}",
            )

        if recomputed_hash.lower() != signed["payloadHash"].lower():
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_payload_hash_mismatch",
                error=(
                    f"recomputed {recomputed_hash.lower()} does not match "
                    f"signed.payloadHash {signed['payloadHash'].lower()}"
                ),
            )

        # Step 6: signature recovery (TS envelopeBuilder.ts:928).
        try:
            recovered = recover_envelope_signer(
                signed, wire["providerSig"], expected_kernel_address
            )
        except Exception as e:  # noqa: BLE001
            return EnvelopeVerifyResult(
                ok=False, code="envelope_signature_invalid", error=str(e)
            )

        if recovered.lower() != signed["signerAddress"].lower():
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_signature_invalid",
                error=(
                    f"recovered signer {recovered.lower()} does not match "
                    f"signed.signerAddress {signed['signerAddress'].lower()}"
                ),
            )

        # Step 7: timestamp skew — symmetric, checked LAST (TS:956).
        now_v = now if now is not None else _seconds_now()
        if abs(now_v - signed["createdAt"]) > ENVELOPE_TIMESTAMP_SKEW_SEC:
            return EnvelopeVerifyResult(
                ok=False,
                code="envelope_timestamp_skew",
                error=(
                    f"|now ({now_v}) - createdAt ({signed['createdAt']})| > "
                    f"{ENVELOPE_TIMESTAMP_SKEW_SEC}s"
                ),
            )

        return EnvelopeVerifyResult(ok=True, signed=signed)

    # ------------------------------------------------------------------
    # decrypt_payload (static, TS envelopeBuilder.ts:998)
    # ------------------------------------------------------------------

    @staticmethod
    def decrypt_payload(
        wire: DeliveryEnvelopeWireV1, buyer_ephemeral_priv_key: bytes
    ) -> Any:
        """Decrypt an encrypted envelope using the buyer's X25519 priv key (TS:998).

        Does NOT verify the signature / chain / kernel / payloadHash. Use
        :meth:`verify_and_decrypt` if those have not already been checked.
        """
        signed = wire["signed"]
        if signed["scheme"] != "x25519-aes256gcm-v1":
            raise DeliveryEip712Error(
                "BUILDER_PUBLIC_DECRYPT_NOT_APPLICABLE",
                f"decryptPayload requires scheme=x25519-aes256gcm-v1; got {signed['scheme']}",
                {"scheme": signed["scheme"]},
            )

        # ECDH + HKDF -> session key (TS envelopeBuilder.ts:1012).
        provider_pubkey = pubkey_from_hex(signed["providerEphemeralPubkey"])
        shared = derive_shared_secret(buyer_ephemeral_priv_key, provider_pubkey)
        session_key = derive_session_key(shared, signed["txId"])

        # Decode wire-form ciphertext / nonce / tag (TS envelopeBuilder.ts:1017).
        ciphertext = bytes_from_hex(wire["body"])
        nonce = bytes_from_hex(signed["nonce"])
        tag = bytes_from_hex(signed["tag"])

        # H5 binding: reconstruct the same AAD the encrypt side used (TS:1029).
        aad = build_envelope_aad(signed["txId"], signed["signerAddress"])

        # Authenticated decrypt — raises crypto_decrypt_failed on tag mismatch.
        plaintext_bytes = decrypt_body(ciphertext, session_key, nonce, tag, aad)

        # UTF-8 decode (fatal) + JSON parse (TS envelopeBuilder.ts:1037).
        text = plaintext_bytes.decode("utf-8")  # strict by default in Python
        return json.loads(text)

    # ------------------------------------------------------------------
    # verify_and_decrypt (static, TS envelopeBuilder.ts:1068)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_and_decrypt(
        wire: DeliveryEnvelopeWireV1,
        buyer_ephemeral_priv_key: bytes,
        *,
        expected_kernel_address: str,
        expected_chain_id: int,
        now: Optional[int] = None,
    ) -> VerifyAndDecryptResult:
        """Combined verify + payload extraction (TS envelopeBuilder.ts:1068)."""
        verify_result = DeliveryEnvelopeBuilder.verify(
            wire,
            expected_kernel_address=expected_kernel_address,
            expected_chain_id=expected_chain_id,
            now=now,
        )
        if not verify_result.ok:
            return VerifyAndDecryptResult(
                ok=False, code=verify_result.code, error=verify_result.error
            )

        signed = verify_result.signed
        assert signed is not None  # narrowed by ok=True

        if signed["scheme"] == "public-v1":
            # FIX-1: wire.body IS the plaintext UTF-8 JSON string (TS:1088).
            try:
                payload = json.loads(wire["body"])
                return VerifyAndDecryptResult(ok=True, payload=payload)
            except Exception as e:  # noqa: BLE001
                return VerifyAndDecryptResult(
                    ok=False,
                    code="envelope_decrypt_failed",
                    error=f"failed to parse public-v1 body as JSON: {e}",
                )

        # Encrypted scheme — run decrypt helper, surface crypto errors as
        # envelope_decrypt_failed (TS envelopeBuilder.ts:1107).
        try:
            payload = DeliveryEnvelopeBuilder.decrypt_payload(
                wire, buyer_ephemeral_priv_key
            )
            return VerifyAndDecryptResult(ok=True, payload=payload)
        except (DeliveryCryptoError, DeliveryEip712Error, Exception) as e:  # noqa: BLE001
            return VerifyAndDecryptResult(
                ok=False, code="envelope_decrypt_failed", error=str(e)
            )

    # ------------------------------------------------------------------
    # compute_hash (static, TS envelopeBuilder.ts:1145)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_hash(wire: DeliveryEnvelopeWireV1) -> str:
        """keccak256(utf8(canonicalJson(wire.signed))) (TS envelopeBuilder.ts:1145).

        Hashes the SIGNED projection only (excludes signature, body,
        serverMeta) — stable across relay decoration + signature malleability.
        """
        canonical = canonical_json_dumps(wire["signed"])
        return "0x" + keccak(canonical.encode("utf-8")).hex()


# ============================================================================
# Internal helpers
# ============================================================================


def _is_int(v: Any) -> bool:
    """Integer that is not a bool (JS ``Number.isInteger`` mirror)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _json_stringify(payload: Any) -> str:
    """``JSON.stringify(payload)`` equivalent (TS envelopeBuilder.ts:597).

    Compact separators (no whitespace) and non-ASCII preserved, matching V8's
    default ``JSON.stringify`` output for the common JSON value shapes the
    delivery payload carries. NOT canonical (keys are NOT sorted) — the buyer
    must recover the exact object the provider serialized.
    """
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _kp_priv_pub(kp: Any) -> tuple[bytes, bytes]:
    """Extract (private 32B, public 32B) from an ephemeral keypair object.

    Accepts the Python core's :class:`EphemeralKeyPair` (``secret_key`` /
    ``public_key``) and is tolerant of a TS-style ``private_key`` / ``privateKey``
    / ``publicKey`` shape passed by cross-SDK callers.
    """
    priv = (
        getattr(kp, "secret_key", None)
        or getattr(kp, "private_key", None)
        or getattr(kp, "privateKey", None)
    )
    pub = getattr(kp, "public_key", None) or getattr(kp, "publicKey", None)
    if priv is None or pub is None:
        raise DeliveryEip712Error(
            "BUILDER_INVALID_EPHEMERAL_KEYPAIR",
            "providerEphemeralKeyPair must expose private and public key bytes.",
        )
    return bytes(priv), bytes(pub)


__all__ = [
    "ENVELOPE_TIMESTAMP_SKEW_SEC",
    "ENVELOPE_AAD_LENGTH",
    "build_envelope_aad",
    "BuildPublicEnvelopeParams",
    "BuildEncryptedEnvelopeParams",
    "EnvelopeVerifyResult",
    "VerifyAndDecryptResult",
    "DeliveryEnvelopeBuilder",
    "set_seconds_now_for_tests",
    "reset_seconds_now_for_tests",
]
