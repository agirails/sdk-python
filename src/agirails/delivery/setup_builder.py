"""
AIP-16 Delivery Surface — Buyer Setup Builder + Verifier (Python port).

Mirrors sdk-js/src/delivery/setupBuilder.ts. Constructs and verifies the
buyer-signed ``DeliverySetupV1`` payload. Reuses the verified EIP-712 core
(``sign_setup`` / ``recover_setup_signer`` from ``eip712.py``) — no crypto is
reimplemented here.

Signer model: where TS uses an ethers ``Signer`` (``getAddress()`` +
``signTypedData()``), the Python builder takes an ``eth_account``
``LocalAccount``; ``account.address`` provides the signer-address binding and
``sign_setup(account, ...)`` produces the EIP-712 signature. This matches the
existing Python builder convention (e.g. ``builders/quote.py``).

Cite: sdk-js/src/delivery/setupBuilder.ts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, List, Optional, Union

from agirails.delivery.eip712 import (
    DeliveryEip712Error,
    recover_setup_signer,
    sign_setup,
)
from agirails.delivery.nonce_keys import DELIVERY_NONCE_KEY_SETUP
from agirails.delivery.types import (
    CANONICAL_EMPTY_BYTES32,
    BuildSetupResult,
    DeliverySetupSignedV1,
    DeliverySetupWireV1,
)
from agirails.delivery.validate import validate_setup_wire
from agirails.utils.canonical_json import canonical_json_dumps

from eth_hash.auto import keccak

# ============================================================================
# Constants (TS setupBuilder.ts:121 / :132 / :141)
# ============================================================================

# TS setupBuilder.ts:121 — DEFAULT_SETUP_EXPIRY_SEC
DEFAULT_SETUP_EXPIRY_SEC = 3600

# TS setupBuilder.ts:132 — SETUP_TIMESTAMP_SKEW_SEC
SETUP_TIMESTAMP_SKEW_SEC = 900

# TS setupBuilder.ts:141 — DEFAULT_ACCEPTED_CHANNELS
DEFAULT_ACCEPTED_CHANNELS: List[str] = ["agirails-relay-v1"]


# ============================================================================
# Injectable clock (TS setupBuilder.ts:167-227)
# ============================================================================
#
# All wall-clock reads flow through ``_seconds_now()``. Tests inject a
# deterministic clock via ``set_seconds_now_for_tests``; production falls
# through to the real wall clock. Single seam, mirroring the TS file.

_seconds_now_impl = lambda: int(time.time())  # noqa: E731


def _seconds_now() -> int:
    """Current wall clock in Unix seconds (TS setupBuilder.ts:182)."""
    return _seconds_now_impl()


def set_seconds_now_for_tests(impl: Optional[Any]) -> None:
    """TEST-ONLY: replace the wall-clock impl (TS setupBuilder.ts:211).

    Pass ``None`` to restore the real clock.
    """
    global _seconds_now_impl
    if impl is None:
        reset_seconds_now_for_tests()
        return
    _seconds_now_impl = impl


def reset_seconds_now_for_tests() -> None:
    """TEST-ONLY: restore the real wall clock (TS setupBuilder.ts:225)."""
    global _seconds_now_impl
    _seconds_now_impl = lambda: int(time.time())  # noqa: E731


# ============================================================================
# Public parameter type (TS setupBuilder.ts:241 BuildSetupParams)
# ============================================================================


@dataclass
class BuildSetupParams:
    """Parameters accepted by :meth:`DeliverySetupBuilder.build`.

    Mirrors TS ``BuildSetupParams`` (setupBuilder.ts:241). ``requester_address``
    and ``signer_address`` are passed separately (no implicit derivation —
    smart-wallet two-step auth, DEC-10).
    """

    tx_id: str
    chain_id: int
    kernel_address: str
    requester_address: str
    signer_address: str
    buyer_ephemeral_pubkey: str
    expected_privacy: str  # DeliveryPrivacy
    accepted_channels: Optional[List[str]] = None
    expires_in_sec: Optional[int] = None
    created_at: Optional[int] = None
    smart_wallet_nonce: Optional[int] = None


# Result of static verify(): mirrors the TS discriminated union shape.
@dataclass
class SetupVerifyResult:
    """Result of :meth:`DeliverySetupBuilder.verify` (TS setupBuilder.ts:630)."""

    ok: bool
    signed: Optional[DeliverySetupSignedV1] = None
    code: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# Setup builder (TS setupBuilder.ts:370 DeliverySetupBuilder)
# ============================================================================


class DeliverySetupBuilder:
    """Builder + verifier for AIP-16 delivery setup messages (TS:370).

    Instances are cheap and have no I/O side effects. :meth:`verify` and
    :meth:`compute_hash` are ``staticmethod`` — call without an instance.
    """

    def __init__(self, signer: Optional[Any] = None, nonce_manager: Optional[Any] = None) -> None:
        """TS setupBuilder.ts:386 — constructor(signer?, nonceManager?).

        ``signer`` is an ``eth_account`` ``LocalAccount`` (required for
        :meth:`build`). ``nonce_manager`` is an optional audit hook; the v1
        schema has no signed nonce field, so a missing manager is tolerated.
        """
        self._signer = signer
        self._nonce_manager = nonce_manager

    # ------------------------------------------------------------------
    # build (TS setupBuilder.ts:426)
    # ------------------------------------------------------------------

    def build(self, params: BuildSetupParams) -> BuildSetupResult:
        """Construct, sign, and return a setup wire object (TS:426).

        Synchronous because ``eth_account`` signing is synchronous (the TS
        method is ``async`` only because real wallets sign asynchronously).
        """
        if self._signer is None:
            raise DeliveryEip712Error(
                "BUILDER_NO_SIGNER",
                "DeliverySetupBuilder.build requires a signer; construct the builder "
                "with a LocalAccount to sign setups.",
            )

        # ----- Privacy / pubkey consistency (TS setupBuilder.ts:441) -----
        pubkey_is_empty = (
            params.buyer_ephemeral_pubkey.lower() == CANONICAL_EMPTY_BYTES32.lower()
        )

        if params.expected_privacy == "public" and not pubkey_is_empty:
            raise DeliveryEip712Error(
                "BUILDER_PUBLIC_PUBKEY_NOT_CANONICAL_EMPTY",
                'expectedPrivacy="public" requires buyerEphemeralPubkey === '
                "CANONICAL_EMPTY_BYTES32 (32 zero bytes).",
                {
                    "expectedPrivacy": params.expected_privacy,
                    "buyerEphemeralPubkey": params.buyer_ephemeral_pubkey,
                },
            )

        if params.expected_privacy == "encrypted" and pubkey_is_empty:
            raise DeliveryEip712Error(
                "BUILDER_ENCRYPTED_PUBKEY_IS_CANONICAL_EMPTY",
                'expectedPrivacy="encrypted" requires a non-zero X25519 pubkey in '
                "buyerEphemeralPubkey (RFC 7748 §6.1).",
                {"expectedPrivacy": params.expected_privacy},
            )

        # ----- Expiry window (TS setupBuilder.ts:461) -----
        expires_in_sec = (
            params.expires_in_sec
            if params.expires_in_sec is not None
            else DEFAULT_SETUP_EXPIRY_SEC
        )
        if not _is_int(expires_in_sec) or expires_in_sec <= 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_EXPIRES_IN",
                f"expiresInSec must be a positive integer, got {expires_in_sec}",
                {"expiresInSec": expires_in_sec},
            )

        # ----- Smart-wallet nonce (H4, TS setupBuilder.ts:475) -----
        smart_wallet_nonce = (
            params.smart_wallet_nonce if params.smart_wallet_nonce is not None else 0
        )
        if not _is_int(smart_wallet_nonce) or smart_wallet_nonce < 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_SMART_WALLET_NONCE",
                f"smartWalletNonce must be a non-negative integer, got {smart_wallet_nonce}",
                {"smartWalletNonce": smart_wallet_nonce},
            )

        # ----- Timestamps (TS setupBuilder.ts:485) -----
        created_at = params.created_at if params.created_at is not None else _seconds_now()
        if not _is_int(created_at) or created_at <= 0:
            raise DeliveryEip712Error(
                "BUILDER_INVALID_CREATED_AT",
                f"createdAt must be a positive integer, got {created_at}",
                {"createdAt": created_at},
            )
        expires_at = created_at + expires_in_sec

        # ----- Signer-address binding (TS setupBuilder.ts:500) -----
        actual_signer = self._signer.address
        if actual_signer.lower() != params.signer_address.lower():
            raise DeliveryEip712Error(
                "BUILDER_SIGNER_ADDRESS_MISMATCH",
                "params.signerAddress does not match signer.address",
                {"expected": actual_signer.lower(), "got": params.signer_address.lower()},
            )

        # ----- Nonce-manager hook (audit / future-compat, TS:519) -----
        if self._nonce_manager is not None:
            # Mirror TS: call the manager's counter advance. We probe for a
            # synchronous ``get_next_nonce``/``getNextNonce`` taking a key.
            _advance_nonce(self._nonce_manager, DELIVERY_NONCE_KEY_SETUP)

        # ----- Build signed projection (TS setupBuilder.ts:532) -----
        accepted_channels = (
            list(params.accepted_channels)
            if params.accepted_channels is not None
            else list(DEFAULT_ACCEPTED_CHANNELS)
        )

        signed: DeliverySetupSignedV1 = {
            "version": 1,
            "txId": params.tx_id,
            "chainId": params.chain_id,
            "kernelAddress": params.kernel_address,
            "requesterAddress": params.requester_address,
            "signerAddress": params.signer_address,
            "buyerEphemeralPubkey": params.buyer_ephemeral_pubkey,
            "acceptedChannels": accepted_channels,
            "expectedPrivacy": params.expected_privacy,
            "createdAt": created_at,
            "expiresAt": expires_at,
            "smartWalletNonce": smart_wallet_nonce,
        }

        # ----- Sign (TS setupBuilder.ts:550) -----
        requester_sig = sign_setup(self._signer, signed, params.kernel_address)

        wire: DeliverySetupWireV1 = {"signed": signed, "requesterSig": requester_sig}

        return {"wire": wire, "nonceManagerKey": DELIVERY_NONCE_KEY_SETUP}

    # ------------------------------------------------------------------
    # verify (static, TS setupBuilder.ts:623)
    # ------------------------------------------------------------------

    @staticmethod
    def verify(
        wire: DeliverySetupWireV1,
        *,
        expected_kernel_address: str,
        expected_chain_id: int,
        now: Optional[int] = None,
    ) -> SetupVerifyResult:
        """Verify a setup wire object received from the relay (TS:623).

        Check order (first failure short-circuits): shape -> chainId ->
        kernel -> signature -> timestamp skew -> expiry.
        """
        # Step 1: structural / shape validation (TS setupBuilder.ts:638).
        shape_result = validate_setup_wire(wire)
        if not shape_result.ok:
            return SetupVerifyResult(
                ok=False, code="setup_signature_invalid", error=shape_result.error
            )

        signed = wire["signed"]

        # Step 2: chainId match (TS setupBuilder.ts:650).
        if signed["chainId"] != expected_chain_id:
            return SetupVerifyResult(
                ok=False,
                code="setup_chain_mismatch",
                error=f"expected chainId {expected_chain_id}, got {signed['chainId']}",
            )

        # Step 3: kernel-address match (allowlist anchor, TS:659).
        expected_kernel_lc = expected_kernel_address.lower()
        payload_kernel_lc = signed["kernelAddress"].lower()
        if payload_kernel_lc != expected_kernel_lc:
            return SetupVerifyResult(
                ok=False,
                code="setup_kernel_mismatch",
                error=f"expected kernel {expected_kernel_lc}, got {payload_kernel_lc}",
            )

        # Step 4: signature recovery (TS setupBuilder.ts:673).
        try:
            recovered = recover_setup_signer(
                signed, wire["requesterSig"], expected_kernel_address
            )
        except Exception as e:  # noqa: BLE001
            return SetupVerifyResult(
                ok=False, code="setup_signature_invalid", error=str(e)
            )

        if recovered.lower() != signed["signerAddress"].lower():
            return SetupVerifyResult(
                ok=False,
                code="setup_signature_invalid",
                error=(
                    f"recovered signer {recovered.lower()} does not match "
                    f"signed.signerAddress {signed['signerAddress'].lower()}"
                ),
            )

        # Step 5: timestamp skew (symmetric, TS setupBuilder.ts:698).
        now_v = now if now is not None else _seconds_now()
        if abs(now_v - signed["createdAt"]) > SETUP_TIMESTAMP_SKEW_SEC:
            return SetupVerifyResult(
                ok=False,
                code="setup_timestamp_skew",
                error=(
                    f"|now ({now_v}) - createdAt ({signed['createdAt']})| > "
                    f"{SETUP_TIMESTAMP_SKEW_SEC}s"
                ),
            )

        # Step 6: expiry — strict greater-than (TS setupBuilder.ts:709).
        if not (signed["expiresAt"] > now_v):
            return SetupVerifyResult(
                ok=False,
                code="setup_expired",
                error=f"expiresAt ({signed['expiresAt']}) <= now ({now_v})",
            )

        return SetupVerifyResult(ok=True, signed=signed)

    # ------------------------------------------------------------------
    # compute_hash (static, TS setupBuilder.ts:746)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_hash(wire: DeliverySetupWireV1) -> str:
        """keccak256(utf8(canonicalJson(wire.signed))) (TS setupBuilder.ts:746).

        Hashes the SIGNED projection only (excludes signature + serverMeta) so
        the id is stable across relay decoration and signature malleability.
        """
        canonical = canonical_json_dumps(wire["signed"])
        return "0x" + keccak(canonical.encode("utf-8")).hex()


# ============================================================================
# Internal helpers
# ============================================================================


def _is_int(v: Any) -> bool:
    """Integer that is not a bool (JS ``Number.isInteger`` mirror)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _advance_nonce(manager: Any, key: str) -> None:
    """Best-effort call into a caller-supplied nonce manager (TS:519).

    The v1 schema does not sign the counter, so this is an audit hook. We try
    the snake_case and camelCase synchronous getters; anything else is a
    no-op (a missing/incompatible manager must not break ``build``).
    """
    for attr in ("get_next_nonce", "getNextNonce"):
        fn = getattr(manager, attr, None)
        if callable(fn):
            try:
                fn(key)
            except TypeError:
                # Manager signature differs (e.g. takes no key) — ignore;
                # the value is never signed.
                pass
            return


__all__ = [
    "DEFAULT_SETUP_EXPIRY_SEC",
    "SETUP_TIMESTAMP_SKEW_SEC",
    "DEFAULT_ACCEPTED_CHANNELS",
    "BuildSetupParams",
    "SetupVerifyResult",
    "DeliverySetupBuilder",
    "set_seconds_now_for_tests",
    "reset_seconds_now_for_tests",
]
