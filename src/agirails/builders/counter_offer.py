"""
CounterOfferBuilder — AIP-2.1 counter-offer message construction (Python port).

AIP-2 covers the provider's first quote (``agirails.quote.v1``). AIP-2.1
adds the buyer's reply: a signed counter-offer message that proposes a
different price than what the provider quoted. The buyer can ping-pong
counter-offers with the provider off-chain; the final agreed amount is
pinned on-chain when the buyer eventually calls ``acceptQuote(txId, amount)``
followed by ``linkEscrow``.

Mirrors QuoteBuilder (provider side) and the TS ``CounterOfferBuilder`` so
the verification path is symmetric:
 - EIP-712 signed message (buyer signs)
 - Canonical JSON hash (deterministic across implementations)
 - Same DID extraction + signature recovery pattern

@module builders/counter_offer
@see Protocol/aips/AIP-2.1-DRAFT.md §8 (security model + transport)
@see sdk-js/src/builders/CounterOfferBuilder.ts (sibling TS port)
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_hash.auto import keccak

from agirails.errors import SignatureVerificationError
from agirails.utils.canonical_json import canonical_json_dumps

# ============================================================================
# Constants
# ============================================================================

MESSAGE_TYPE = "agirails.counteroffer.v1"
DEFAULT_TTL_SECONDS = 3600  # 1 hour
MAX_TTL_SECONDS = 86_400  # 24 hours
TIMESTAMP_GRACE_SECONDS = 300  # 5 minutes (matches QuoteBuilder post-audit)
PLATFORM_MIN_BASE_UNITS = 50_000  # $0.05 USDC
ZERO_HASH = "0x" + "0" * 64
VALID_CHAIN_IDS = {84_532, 8_453}

# EIP-712 type definitions for `agirails.counteroffer.v1`.
# justification is hashed (single bytes32 field) instead of inlined.
AIP21_COUNTER_OFFER_TYPES: Dict[str, Any] = {
    "CounterOffer": [
        {"name": "txId", "type": "bytes32"},
        {"name": "consumer", "type": "string"},
        {"name": "provider", "type": "string"},
        {"name": "quoteAmount", "type": "string"},
        {"name": "counterAmount", "type": "string"},
        {"name": "maxPrice", "type": "string"},
        {"name": "currency", "type": "string"},
        {"name": "decimals", "type": "uint8"},
        {"name": "inReplyTo", "type": "bytes32"},
        {"name": "counteredAt", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "justificationHash", "type": "bytes32"},
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
class CounterOfferJustification:
    """Optional human-readable reasoning + market data."""

    reason: Optional[str] = None
    market_rate: Optional[float] = None
    breakdown: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.reason is not None:
            out["reason"] = self.reason
        if self.market_rate is not None:
            out["marketRate"] = self.market_rate
        if self.breakdown:
            out["breakdown"] = self.breakdown
        return out


@dataclass
class CounterOfferMessage:
    """Counter-offer message: buyer's reply to a provider quote.

    Field shape mirrors the TS CounterOfferMessage. quoteAmount is
    preserved verbatim from the provider's quote for unambiguous
    binding; verifier can confirm the counter is in response to the
    exact quote it claims to be.
    """

    txId: str
    consumer: str
    provider: str
    quoteAmount: str
    counterAmount: str
    maxPrice: str
    inReplyTo: str
    counteredAt: int
    expiresAt: int
    chainId: int
    nonce: int
    signature: str
    type: str = MESSAGE_TYPE
    version: str = "1.0.0"
    currency: str = "USDC"
    decimals: int = 6
    justification: Optional[CounterOfferJustification] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "type": self.type,
            "version": self.version,
            "txId": self.txId,
            "consumer": self.consumer,
            "provider": self.provider,
            "quoteAmount": self.quoteAmount,
            "counterAmount": self.counterAmount,
            "maxPrice": self.maxPrice,
            "currency": self.currency,
            "decimals": self.decimals,
            "inReplyTo": self.inReplyTo,
            "counteredAt": self.counteredAt,
            "expiresAt": self.expiresAt,
            "chainId": self.chainId,
            "nonce": self.nonce,
            "signature": self.signature,
        }
        if self.justification is not None:
            justification_dict = self.justification.to_dict()
            if justification_dict:
                out["justification"] = justification_dict
        return out


@dataclass
class CounterOfferParams:
    """Parameters to build a counter-offer.

    ``counteredAt``, ``nonce``, and ``signature`` are filled by the builder.
    """

    txId: str
    consumer: str
    provider: str
    quoteAmount: str
    counterAmount: str
    maxPrice: str
    inReplyTo: str
    chainId: int
    kernelAddress: str
    expiresAt: Optional[int] = None
    justification: Optional[CounterOfferJustification] = None


# ============================================================================
# Minimal NonceManager — per-message-type monotonic counter
# ============================================================================


class MessageNonceManager:
    """Thread-safe per-message-type monotonic nonce counter.

    Used by AIP-2.1 builders to assign monotonically-increasing nonces
    per message type so receivers can detect replays. Mirrors the TS
    ``NonceManager`` shape (getNextNonce / recordNonce).
    """

    def __init__(self) -> None:
        self._nonces: Dict[str, int] = {}
        self._lock = threading.RLock()

    def get_next_nonce(self, message_type: str) -> int:
        with self._lock:
            return self._nonces.get(message_type, 0) + 1

    def record_nonce(self, message_type: str, nonce: int) -> None:
        with self._lock:
            current = self._nonces.get(message_type, 0)
            if nonce <= current:
                raise ValueError(
                    f"Nonce {nonce} not monotonic for {message_type} "
                    f"(current high-water mark: {current})"
                )
            self._nonces[message_type] = nonce


# ============================================================================
# Builder
# ============================================================================


class CounterOfferBuilder:
    """Build and verify AIP-2.1 counter-offer messages.

    ``private_key`` and ``nonce_manager`` are only required for ``build()``.
    ``verify()`` and ``compute_hash()`` are signer-independent — construct
    with ``private_key=None`` for verify-only use (orchestrator side).
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

    def build(self, params: CounterOfferParams) -> CounterOfferMessage:
        """Build and sign a counter-offer message."""
        if self._account is None or self._nonce_manager is None:
            raise ValueError(
                "CounterOfferBuilder.build requires private_key + nonce_manager"
            )
        self._validate_params(params)

        countered_at = int(time.time())
        expires_at = params.expiresAt or (countered_at + DEFAULT_TTL_SECONDS)

        if expires_at <= countered_at:
            raise ValueError("expiresAt must be after counteredAt")
        if expires_at > countered_at + MAX_TTL_SECONDS:
            raise ValueError(
                f"expiresAt cannot exceed {MAX_TTL_SECONDS}s from counteredAt"
            )

        nonce = self._nonce_manager.get_next_nonce(MESSAGE_TYPE)
        message = CounterOfferMessage(
            txId=params.txId,
            consumer=params.consumer,
            provider=params.provider,
            quoteAmount=params.quoteAmount,
            counterAmount=params.counterAmount,
            maxPrice=params.maxPrice,
            inReplyTo=params.inReplyTo,
            counteredAt=countered_at,
            expiresAt=expires_at,
            chainId=params.chainId,
            nonce=nonce,
            signature="",
            justification=params.justification,
        )

        message.signature = self._sign_message(message, params.kernelAddress)
        self._nonce_manager.record_nonce(MESSAGE_TYPE, nonce)
        return message

    def verify(
        self, message: CounterOfferMessage, kernel_address: str
    ) -> bool:
        """Verify a counter-offer:

          1. Schema is well-formed
          2. EIP-712 signature recovers to the consumer DID's address
          3. Amount band: counterAmount within [platformMin, maxPrice],
             and strictly less than quoteAmount
          4. Not expired (with TIMESTAMP_GRACE_SECONDS slack on counteredAt)

        Returns ``True`` on success; raises otherwise.
        """
        self._validate_message_schema(message)

        recovered = self._recover_signer(message, kernel_address)
        expected = self._extract_address_from_did(message.consumer)
        if recovered.lower() != expected.lower():
            raise SignatureVerificationError(
                "Counter-offer signature does not recover to consumer DID",
                expected_signer=expected,
                actual_signer=recovered,
            )

        counter_amount = int(message.counterAmount)
        quote_amount = int(message.quoteAmount)
        max_price = int(message.maxPrice)

        if counter_amount < PLATFORM_MIN_BASE_UNITS:
            raise ValueError("counterAmount below platform minimum ($0.05)")
        # A counter ≥ existing quote is not a counter — accept the quote instead.
        if counter_amount >= quote_amount:
            raise ValueError(
                "counterAmount must be less than quoteAmount "
                "(otherwise just accept the quote)"
            )
        if counter_amount > max_price:
            raise ValueError("counterAmount exceeds maxPrice")

        now = int(time.time())
        if message.expiresAt < now:
            raise ValueError("Counter-offer expired")
        # One-sided skew check — only reject timestamps claiming the future.
        # The "too old" side is bounded by expiresAt (checked above).
        if message.counteredAt > now + TIMESTAMP_GRACE_SECONDS:
            raise ValueError(
                "counteredAt is in the future beyond skew tolerance"
            )

        return True

    def compute_hash(self, message: CounterOfferMessage) -> str:
        """Compute keccak256 of canonical JSON (signature stripped).

        This is the value that should be used for any on-chain anchoring
        or off-chain dedup keys. Identical content → identical hash on
        any implementation using canonical-JSON encoding.
        """
        body = message.to_dict()
        body.pop("signature", None)
        encoded = canonical_json_dumps(body)
        return "0x" + keccak(encoded.encode("utf-8")).hex()

    # ----------------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------------

    def _sign_message(
        self, message: CounterOfferMessage, kernel_address: str
    ) -> str:
        domain = {
            "name": "AGIRAILS",
            "version": "1",
            "chainId": message.chainId,
            "verifyingContract": kernel_address,
        }
        signed_shape = self._to_signed_shape(message)
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                **AIP21_COUNTER_OFFER_TYPES,
            },
            "primaryType": "CounterOffer",
            "domain": domain,
            "message": signed_shape,
        }
        signable = encode_typed_data(full_message=typed_data)
        signed = self._account.sign_message(signable)  # type: ignore[union-attr]
        return "0x" + signed.signature.hex() if not signed.signature.hex().startswith("0x") else signed.signature.hex()

    def _recover_signer(
        self, message: CounterOfferMessage, kernel_address: str
    ) -> str:
        domain = {
            "name": "AGIRAILS",
            "version": "1",
            "chainId": message.chainId,
            "verifyingContract": kernel_address,
        }
        signed_shape = self._to_signed_shape(message)
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                **AIP21_COUNTER_OFFER_TYPES,
            },
            "primaryType": "CounterOffer",
            "domain": domain,
            "message": signed_shape,
        }
        signable = encode_typed_data(full_message=typed_data)
        try:
            return Account.recover_message(signable, signature=message.signature)
        except Exception as exc:
            raise SignatureVerificationError(
                "Failed to recover signer from counter-offer signature",
                expected_signer=self._extract_address_from_did(message.consumer),
            ) from exc

    def _to_signed_shape(
        self, message: CounterOfferMessage
    ) -> Dict[str, Any]:
        return {
            "txId": message.txId,
            "consumer": message.consumer,
            "provider": message.provider,
            "quoteAmount": message.quoteAmount,
            "counterAmount": message.counterAmount,
            "maxPrice": message.maxPrice,
            "currency": message.currency,
            "decimals": message.decimals,
            "inReplyTo": message.inReplyTo,
            "counteredAt": message.counteredAt,
            "expiresAt": message.expiresAt,
            "justificationHash": self._compute_justification_hash(
                message.justification
            ),
            "chainId": message.chainId,
            "nonce": message.nonce,
        }

    def _compute_justification_hash(
        self, justification: Optional[CounterOfferJustification]
    ) -> str:
        if justification is None:
            return ZERO_HASH
        body = justification.to_dict()
        if not body:
            return ZERO_HASH
        encoded = canonical_json_dumps(body)
        return "0x" + keccak(encoded.encode("utf-8")).hex()

    @staticmethod
    def _extract_address_from_did(did: str) -> str:
        if not did.startswith("did:ethr:"):
            raise ValueError(f"Invalid DID format: {did}")
        parts = did[len("did:ethr:") :].split(":")
        address = parts[1] if len(parts) == 2 else parts[0]
        if not _ADDRESS_RE.match(address):
            raise ValueError(f"Invalid DID format: {did}")
        return address

    def _validate_params(self, params: CounterOfferParams) -> None:
        if not _BYTES32_RE.match(params.txId):
            raise ValueError("txId must be valid bytes32 hex string")
        if not _BYTES32_RE.match(params.inReplyTo):
            raise ValueError(
                "inReplyTo must be valid bytes32 hex string (the quote hash)"
            )
        if not _ADDRESS_RE.match(params.kernelAddress):
            raise ValueError("kernelAddress must be valid Ethereum address")
        if not params.consumer.startswith("did:ethr:"):
            raise ValueError("consumer must be valid did:ethr format")
        if not params.provider.startswith("did:ethr:"):
            raise ValueError("provider must be valid did:ethr format")
        if params.chainId not in VALID_CHAIN_IDS:
            raise ValueError(
                "chainId must be 84532 (Base Sepolia) or 8453 (Base Mainnet)"
            )

        try:
            counter = int(params.counterAmount)
            quote = int(params.quoteAmount)
            max_price = int(params.maxPrice)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "counterAmount, quoteAmount, maxPrice must be numeric strings"
            ) from exc

        if counter < PLATFORM_MIN_BASE_UNITS:
            raise ValueError("counterAmount below platform minimum ($0.05)")
        if counter >= quote:
            raise ValueError(
                "counterAmount must be strictly less than quoteAmount"
            )
        if counter > max_price:
            raise ValueError("counterAmount exceeds maxPrice")

        if params.expiresAt is not None:
            now = int(time.time())
            if params.expiresAt <= now:
                raise ValueError("expiresAt must be in the future")
            if params.expiresAt > now + MAX_TTL_SECONDS:
                raise ValueError(
                    f"expiresAt cannot be more than {MAX_TTL_SECONDS}s "
                    "in the future"
                )

    def _validate_message_schema(self, message: CounterOfferMessage) -> None:
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
        if not message.consumer.startswith("did:ethr:"):
            raise ValueError("Invalid consumer DID format")
        if not message.provider.startswith("did:ethr:"):
            raise ValueError("Invalid provider DID format")
        if not _DIGITS_RE.match(message.counterAmount):
            raise ValueError("Invalid counterAmount format")
        if not _DIGITS_RE.match(message.quoteAmount):
            raise ValueError("Invalid quoteAmount format")
        if not _DIGITS_RE.match(message.maxPrice):
            raise ValueError("Invalid maxPrice format")
        if message.currency != "USDC":
            raise ValueError("Only USDC currency is supported")
        if message.decimals != 6:
            raise ValueError("USDC must use 6 decimals")
        if message.chainId not in VALID_CHAIN_IDS:
            raise ValueError("Invalid chainId")
        if not _SIGNATURE_RE.match(message.signature):
            raise ValueError("Invalid signature format")


__all__ = [
    "MESSAGE_TYPE",
    "AIP21_COUNTER_OFFER_TYPES",
    "PLATFORM_MIN_BASE_UNITS",
    "ZERO_HASH",
    "VALID_CHAIN_IDS",
    "CounterOfferJustification",
    "CounterOfferMessage",
    "CounterOfferParams",
    "CounterOfferBuilder",
    "MessageNonceManager",
]
