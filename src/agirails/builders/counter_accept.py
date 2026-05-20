"""
CounterAcceptBuilder — AIP-2.1 provider's signed acceptance of a buyer's
counter-offer (Python port).

Closes the non-repudiation gap noted in AIP-2.1-DRAFT §8: the
counter itself is signed by the buyer; the on-chain ``acceptQuote``
call by the buyer pins the price; but until now there was no
signed surface for the provider to *commit* to the counter
off-chain. Without this, a buyer who calls ``acceptQuote(counter)``
has no cryptographic record of provider agreement, only "they
didn't reject within TTL".

Mirrors :class:`CounterOfferBuilder` shape — same EIP-712 domain, same
canonical JSON hashing, signer-independent verification.

@module builders/counter_accept
@see Protocol/aips/AIP-2.1-DRAFT.md §8 (acceptance signal)
@see sdk-js/src/builders/CounterAcceptBuilder.ts (sibling TS port)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_hash.auto import keccak

from agirails.builders.counter_offer import (
    MessageNonceManager,
    PLATFORM_MIN_BASE_UNITS,
    TIMESTAMP_GRACE_SECONDS,
    VALID_CHAIN_IDS,
)
from agirails.errors import SignatureVerificationError
from agirails.utils.canonical_json import canonical_json_dumps

# ============================================================================
# Constants
# ============================================================================

MESSAGE_TYPE = "agirails.counteraccept.v1"

AIP21_COUNTER_ACCEPT_TYPES: Dict[str, Any] = {
    "CounterAccept": [
        {"name": "txId", "type": "bytes32"},
        {"name": "provider", "type": "string"},
        {"name": "consumer", "type": "string"},
        {"name": "acceptedAmount", "type": "string"},
        {"name": "inReplyTo", "type": "bytes32"},
        {"name": "acceptedAt", "type": "uint256"},
        {"name": "chainId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
    ],
}

_BYTES32_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_SIGNATURE_RE = re.compile(r"^0x[a-fA-F0-9]{130}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_DIGITS_RE = re.compile(r"^\d+$")


# ============================================================================
# Types
# ============================================================================


@dataclass
class CounterAcceptMessage:
    """Provider-signed acceptance of a buyer's counter-offer.

    Carries the counter hash this is responding to (``inReplyTo``) so the
    buyer's verifier can cryptographically link the acceptance to the
    exact counter it sent. ``acceptedAmount`` MUST equal the counter's
    ``counterAmount`` — verifier rejects mismatches.
    """

    txId: str
    provider: str
    consumer: str
    acceptedAmount: str
    inReplyTo: str
    acceptedAt: int
    chainId: int
    nonce: int
    signature: str
    type: str = MESSAGE_TYPE
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "version": self.version,
            "txId": self.txId,
            "provider": self.provider,
            "consumer": self.consumer,
            "acceptedAmount": self.acceptedAmount,
            "inReplyTo": self.inReplyTo,
            "acceptedAt": self.acceptedAt,
            "chainId": self.chainId,
            "nonce": self.nonce,
            "signature": self.signature,
        }


@dataclass
class CounterAcceptParams:
    """Parameters to build a counter-accept message."""

    txId: str
    provider: str
    consumer: str
    acceptedAmount: str
    inReplyTo: str
    chainId: int
    kernelAddress: str


# ============================================================================
# Builder
# ============================================================================


class CounterAcceptBuilder:
    """Build and verify AIP-2.1 counter-accept messages.

    ``private_key`` and ``nonce_manager`` are only required for ``build()``.
    ``verify()`` and ``compute_hash()`` are signer-independent — construct
    with ``private_key=None`` for verify-only use (buyer orchestrator side
    validating provider acceptance).
    """

    def __init__(
        self,
        private_key: Optional[str] = None,
        nonce_manager: Optional[MessageNonceManager] = None,
    ) -> None:
        self._private_key = private_key
        self._nonce_manager = nonce_manager
        self._account = (
            Account.from_key(private_key) if private_key else None
        )

    # ----------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------

    def build(self, params: CounterAcceptParams) -> CounterAcceptMessage:
        """Build and sign a counter-accept message."""
        if self._account is None or self._nonce_manager is None:
            raise ValueError(
                "CounterAcceptBuilder.build requires private_key + nonce_manager"
            )
        self._validate_params(params)

        accepted_at = int(time.time())
        nonce = self._nonce_manager.get_next_nonce(MESSAGE_TYPE)

        message = CounterAcceptMessage(
            txId=params.txId,
            provider=params.provider,
            consumer=params.consumer,
            acceptedAmount=params.acceptedAmount,
            inReplyTo=params.inReplyTo,
            acceptedAt=accepted_at,
            chainId=params.chainId,
            nonce=nonce,
            signature="",
        )

        message.signature = self._sign_message(message, params.kernelAddress)
        self._nonce_manager.record_nonce(MESSAGE_TYPE, nonce)
        return message

    def verify(
        self, message: CounterAcceptMessage, kernel_address: str
    ) -> bool:
        """Verify provider acceptance:

          1. Schema well-formed
          2. EIP-712 signature recovers to provider DID's address
          3. acceptedAmount ≥ platform minimum (defense)
          4. acceptedAt within skew tolerance (one-sided future check)

        Caller is responsible for additionally checking
        ``acceptedAmount == counter.counterAmount`` and
        ``inReplyTo == CounterOfferBuilder.compute_hash(counter)`` —
        those bind the acceptance to the buyer's specific counter.
        """
        self._validate_message_schema(message)

        recovered = self._recover_signer(message, kernel_address)
        expected = self._extract_address_from_did(message.provider)
        if recovered.lower() != expected.lower():
            raise SignatureVerificationError(
                "Counter-accept signature does not recover to provider DID",
                expected_signer=expected,
                actual_signer=recovered,
            )

        accepted = int(message.acceptedAmount)
        if accepted < PLATFORM_MIN_BASE_UNITS:
            raise ValueError("acceptedAmount below platform minimum ($0.05)")

        now = int(time.time())
        if message.acceptedAt > now + TIMESTAMP_GRACE_SECONDS:
            raise ValueError(
                "acceptedAt is in the future beyond skew tolerance"
            )

        return True

    def compute_hash(self, message: CounterAcceptMessage) -> str:
        """Compute keccak256 of canonical JSON (signature stripped)."""
        body = message.to_dict()
        body.pop("signature", None)
        encoded = canonical_json_dumps(body)
        return "0x" + keccak(encoded.encode("utf-8")).hex()

    # ----------------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------------

    def _sign_message(
        self, message: CounterAcceptMessage, kernel_address: str
    ) -> str:
        typed_data = self._build_typed_data(message, kernel_address)
        signable = encode_typed_data(full_message=typed_data)
        signed = self._account.sign_message(signable)  # type: ignore[union-attr]
        hex_sig = signed.signature.hex()
        return hex_sig if hex_sig.startswith("0x") else "0x" + hex_sig

    def _recover_signer(
        self, message: CounterAcceptMessage, kernel_address: str
    ) -> str:
        typed_data = self._build_typed_data(message, kernel_address)
        signable = encode_typed_data(full_message=typed_data)
        try:
            return Account.recover_message(signable, signature=message.signature)
        except Exception as exc:
            raise SignatureVerificationError(
                "Failed to recover signer from counter-accept signature",
                expected_signer=self._extract_address_from_did(message.provider),
            ) from exc

    def _build_typed_data(
        self, message: CounterAcceptMessage, kernel_address: str
    ) -> Dict[str, Any]:
        return {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                **AIP21_COUNTER_ACCEPT_TYPES,
            },
            "primaryType": "CounterAccept",
            "domain": {
                "name": "AGIRAILS",
                "version": "1",
                "chainId": message.chainId,
                "verifyingContract": kernel_address,
            },
            "message": {
                "txId": message.txId,
                "provider": message.provider,
                "consumer": message.consumer,
                "acceptedAmount": message.acceptedAmount,
                "inReplyTo": message.inReplyTo,
                "acceptedAt": message.acceptedAt,
                "chainId": message.chainId,
                "nonce": message.nonce,
            },
        }

    @staticmethod
    def _extract_address_from_did(did: str) -> str:
        if not did.startswith("did:ethr:"):
            raise ValueError(f"Invalid DID format: {did}")
        parts = did[len("did:ethr:") :].split(":")
        address = parts[1] if len(parts) == 2 else parts[0]
        if not _ADDRESS_RE.match(address):
            raise ValueError(f"Invalid DID format: {did}")
        return address

    def _validate_params(self, params: CounterAcceptParams) -> None:
        if not _BYTES32_RE.match(params.txId):
            raise ValueError("txId must be valid bytes32 hex string")
        if not _BYTES32_RE.match(params.inReplyTo):
            raise ValueError(
                "inReplyTo must be valid bytes32 hex string (the counter hash)"
            )
        if not _ADDRESS_RE.match(params.kernelAddress):
            raise ValueError("kernelAddress must be valid Ethereum address")
        if not params.provider.startswith("did:ethr:"):
            raise ValueError("provider must be valid did:ethr format")
        if not params.consumer.startswith("did:ethr:"):
            raise ValueError("consumer must be valid did:ethr format")
        if params.chainId not in VALID_CHAIN_IDS:
            raise ValueError(
                "chainId must be 84532 (Base Sepolia) or 8453 (Base Mainnet)"
            )

        try:
            accepted = int(params.acceptedAmount)
        except (TypeError, ValueError) as exc:
            raise ValueError("acceptedAmount must be a numeric string") from exc
        if accepted < PLATFORM_MIN_BASE_UNITS:
            raise ValueError("acceptedAmount below platform minimum ($0.05)")

    def _validate_message_schema(self, message: CounterAcceptMessage) -> None:
        if message.type != MESSAGE_TYPE:
            raise ValueError(
                f"Invalid message type (expected {MESSAGE_TYPE}, got {message.type})"
            )
        if not _VERSION_RE.match(message.version):
            raise ValueError("Invalid version format")
        if not _BYTES32_RE.match(message.txId):
            raise ValueError("Invalid txId format")
        if not _BYTES32_RE.match(message.inReplyTo):
            raise ValueError("Invalid inReplyTo format")
        if not message.provider.startswith("did:ethr:"):
            raise ValueError("Invalid provider DID format")
        if not message.consumer.startswith("did:ethr:"):
            raise ValueError("Invalid consumer DID format")
        if not _DIGITS_RE.match(message.acceptedAmount):
            raise ValueError("Invalid acceptedAmount format")
        if message.chainId not in VALID_CHAIN_IDS:
            raise ValueError("Invalid chainId")
        if not _SIGNATURE_RE.match(message.signature):
            raise ValueError("Invalid signature format")


__all__ = [
    "MESSAGE_TYPE",
    "AIP21_COUNTER_ACCEPT_TYPES",
    "CounterAcceptMessage",
    "CounterAcceptParams",
    "CounterAcceptBuilder",
]
