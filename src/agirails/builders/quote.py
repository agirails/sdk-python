"""
Quote Builder for AGIRAILS SDK (AIP-2).

The canonical ``QuoteBuilder`` is the AIP-2 price-quote builder: it produces an
``agirails.quote.v1`` message, EIP-712 signs it (``AGIRAILS`` domain, version
``1``), verifies signatures, and computes the on-chain anchor hash as
``keccak256(canonicalJson(quoteWithoutSig))`` — byte-for-byte identical to the
TypeScript SDK's ``QuoteBuilder`` (``builders/QuoteBuilder.ts``).

A Python-side signer with no TS analog also exists: :class:`LegacyQuoteBuilder`
(a fluent local builder returning :class:`Quote`). It is retained for backward
compatibility and is NOT a cross-SDK / on-chain hashing path.

Example (AIP-2 signed quote)::

    from eth_account import Account
    from agirails.builders import QuoteBuilder, QuoteParams

    qb = QuoteBuilder(account=Account.from_key(pk), nonce_manager=nm)
    quote = qb.build(QuoteParams(
        tx_id="0x...", provider="did:ethr:84532:0x...",
        consumer="did:ethr:84532:0x...", quoted_amount="7500000",
        original_amount="5000000", max_price="10000000",
        chain_id=84532, kernel_address="0x...",
    ))
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_hash.auto import keccak

from agirails.errors import SignatureVerificationError
from agirails.utils.canonical_json import canonical_json_dumps
from agirails.utils.canonical_json import canonical_json_dumps as canonical_json_serialize

ZERO_HASH = "0x" + "0" * 64

# EIP-712 types for AIP-2 quote messages (mirrors TS AIP2QuoteTypes exactly).
AIP2_QUOTE_TYPES: Dict[str, list] = {
    "PriceQuote": [
        {"name": "txId", "type": "bytes32"},
        {"name": "provider", "type": "string"},
        {"name": "consumer", "type": "string"},
        {"name": "quotedAmount", "type": "string"},
        {"name": "originalAmount", "type": "string"},
        {"name": "maxPrice", "type": "string"},
        {"name": "currency", "type": "string"},
        {"name": "decimals", "type": "uint8"},
        {"name": "quotedAt", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "justificationHash", "type": "bytes32"},
        {"name": "chainId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
    ]
}
# Alias matching the TS export name.
AIP2QuoteTypes = AIP2_QUOTE_TYPES

_EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


@dataclass
class QuoteMessage:
    """AIP-2 ``agirails.quote.v1`` message (mirrors TS ``QuoteMessage``).

    ``quoted_amount`` / ``original_amount`` / ``max_price`` are base-unit
    strings (USDC, 6 decimals) to avoid integer overflow across languages.
    """

    tx_id: str
    provider: str  # DID
    consumer: str  # DID
    quoted_amount: str
    original_amount: str
    max_price: str
    chain_id: int
    nonce: int
    currency: str = "USDC"
    decimals: int = 6
    quoted_at: int = 0
    expires_at: int = 0
    justification: Optional[Dict[str, Any]] = None
    type: str = "agirails.quote.v1"
    version: str = "1.0.0"
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Full message dict (camelCase) including signature."""
        d = self._hash_dict()
        d["signature"] = self.signature
        return d

    def _hash_dict(self) -> Dict[str, Any]:
        """Quote dict used for ``compute_hash`` — signature stripped and the
        optional ``justification`` object omitted when absent (matching TS,
        where an undefined ``justification`` is dropped by ``JSON.stringify``).
        """
        d: Dict[str, Any] = {
            "type": self.type,
            "version": self.version,
            "txId": self.tx_id,
            "provider": self.provider,
            "consumer": self.consumer,
            "quotedAmount": self.quoted_amount,
            "originalAmount": self.original_amount,
            "maxPrice": self.max_price,
            "currency": self.currency,
            "decimals": self.decimals,
            "quotedAt": self.quoted_at,
            "expiresAt": self.expires_at,
            "chainId": self.chain_id,
            "nonce": self.nonce,
        }
        if self.justification is not None:
            d["justification"] = self.justification
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QuoteMessage":
        return cls(
            tx_id=data.get("txId", data.get("tx_id", "")),
            provider=data.get("provider", ""),
            consumer=data.get("consumer", ""),
            quoted_amount=str(data.get("quotedAmount", data.get("quoted_amount", "0"))),
            original_amount=str(data.get("originalAmount", data.get("original_amount", "0"))),
            max_price=str(data.get("maxPrice", data.get("max_price", "0"))),
            currency=data.get("currency", "USDC"),
            decimals=data.get("decimals", 6),
            quoted_at=data.get("quotedAt", data.get("quoted_at", 0)),
            expires_at=data.get("expiresAt", data.get("expires_at", 0)),
            justification=data.get("justification"),
            chain_id=data.get("chainId", data.get("chain_id", 84532)),
            nonce=data.get("nonce", 0),
            type=data.get("type", "agirails.quote.v1"),
            version=data.get("version", "1.0.0"),
            signature=data.get("signature", ""),
        )


@dataclass
class QuoteParams:
    """Parameters for :meth:`QuoteBuilder.build` (mirrors TS ``QuoteParams``)."""

    tx_id: str
    provider: str
    consumer: str
    quoted_amount: str
    original_amount: str
    max_price: str
    chain_id: int
    kernel_address: str
    currency: str = "USDC"
    decimals: int = 6
    expires_at: Optional[int] = None
    justification: Optional[Dict[str, Any]] = None


class _SimpleNonceManager:
    """Minimal nonce manager (per message-type) used when none is supplied."""

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}

    def get_next_nonce(self, message_type: str) -> int:
        return self._counters.get(message_type, 0) + 1

    def record_nonce(self, message_type: str, nonce: int) -> None:
        self._counters[message_type] = nonce


class QuoteBuilder:
    """AIP-2 price-quote builder (EIP-712 signed). Mirrors TS ``QuoteBuilder``.

    ``account`` and ``nonce_manager`` are only required for :meth:`build`;
    :meth:`verify` and :meth:`compute_hash` are signer-independent — construct
    with no arguments for a verify-only instance.
    """

    def __init__(
        self,
        account: Optional[Any] = None,
        nonce_manager: Optional[Any] = None,
        ipfs: Optional[Any] = None,
    ) -> None:
        self._account = account
        self._nonce_manager = nonce_manager
        self._ipfs = ipfs

    # -- public API -------------------------------------------------------
    def build(self, params: QuoteParams) -> QuoteMessage:
        if self._account is None:
            raise ValueError("QuoteBuilder.build requires an account")
        nonce_manager = self._nonce_manager or _SimpleNonceManager()

        self._validate_params(params)

        quoted_at = int(time.time())
        expires_at = params.expires_at or (quoted_at + 3600)
        if expires_at <= quoted_at:
            raise ValueError("expires_at must be after quoted_at")
        if expires_at > quoted_at + 86400:
            raise ValueError("expires_at cannot exceed 24 hours from quoted_at")

        nonce = nonce_manager.get_next_nonce("agirails.quote.v1")
        quote = QuoteMessage(
            tx_id=params.tx_id,
            provider=params.provider,
            consumer=params.consumer,
            quoted_amount=params.quoted_amount,
            original_amount=params.original_amount,
            max_price=params.max_price,
            currency=params.currency,
            decimals=params.decimals,
            quoted_at=quoted_at,
            expires_at=expires_at,
            justification=params.justification,
            chain_id=params.chain_id,
            nonce=nonce,
        )
        quote.signature = self.sign_quote(quote, params.kernel_address)
        nonce_manager.record_nonce("agirails.quote.v1", nonce)
        return quote

    def verify(self, quote: QuoteMessage, kernel_address: str) -> bool:
        self._validate_quote_schema(quote)

        recovered = self._recover_quote_signer(quote, kernel_address)
        expected = self._extract_address_from_did(quote.provider)
        if recovered.lower() != expected.lower():
            raise SignatureVerificationError(
                "Invalid signature: recovered address does not match provider",
                expected_signer=expected,
            )

        quoted_amount = int(quote.quoted_amount)
        original_amount = int(quote.original_amount)
        max_price = int(quote.max_price)
        if quoted_amount < original_amount:
            raise ValueError("Quoted amount below original amount")
        if quoted_amount > max_price:
            raise ValueError("Quoted amount exceeds maxPrice")
        if quoted_amount < 50000:
            raise ValueError("Quoted amount below platform minimum ($0.05)")

        now = int(time.time())
        if quote.expires_at < now:
            raise ValueError("Quote expired")
        if quote.quoted_at > now + 300:
            raise ValueError("Quote timestamp is in the future beyond skew tolerance")
        return True

    def compute_hash(self, quote: QuoteMessage) -> str:
        """keccak256 of canonical JSON (signature stripped) — on-chain anchor."""
        encoded = canonical_json_dumps(quote._hash_dict())
        return "0x" + keccak(encoded.encode("utf-8")).hex()

    def compute_justification_hash(self, justification: Optional[Dict[str, Any]]) -> str:
        if not justification:
            return ZERO_HASH
        encoded = canonical_json_dumps(justification)
        return "0x" + keccak(encoded.encode("utf-8")).hex()

    async def upload_to_ipfs(self, quote: QuoteMessage) -> str:
        if self._ipfs is None:
            raise ValueError("IPFS client not configured")
        import json as _json

        cid = await self._ipfs.add(_json.dumps(quote.to_dict()))
        await self._ipfs.pin(cid)
        return cid

    # -- internals --------------------------------------------------------
    def sign_quote(self, quote: QuoteMessage, kernel_address: str) -> str:
        if self._account is None:
            raise ValueError("QuoteBuilder.sign_quote requires an account")
        typed_data = self._typed_data(quote, kernel_address)
        signable = encode_typed_data(full_message=typed_data)
        signed = self._account.sign_message(signable)
        sig = signed.signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig

    def _recover_quote_signer(self, quote: QuoteMessage, kernel_address: str) -> str:
        typed_data = self._typed_data(quote, kernel_address)
        signable = encode_typed_data(full_message=typed_data)
        try:
            return Account.recover_message(signable, signature=quote.signature)
        except Exception as exc:  # noqa: BLE001
            raise SignatureVerificationError(
                "Failed to recover signer from quote signature",
                expected_signer=self._extract_address_from_did(quote.provider),
            ) from exc

    def _typed_data(self, quote: QuoteMessage, kernel_address: str) -> Dict[str, Any]:
        domain = {
            "name": "AGIRAILS",
            "version": "1",
            "chainId": quote.chain_id,
            "verifyingContract": kernel_address,
        }
        message = {
            "txId": quote.tx_id,
            "provider": quote.provider,
            "consumer": quote.consumer,
            "quotedAmount": quote.quoted_amount,
            "originalAmount": quote.original_amount,
            "maxPrice": quote.max_price,
            "currency": quote.currency,
            "decimals": quote.decimals,
            "quotedAt": quote.quoted_at,
            "expiresAt": quote.expires_at,
            "justificationHash": self.compute_justification_hash(quote.justification),
            "chainId": quote.chain_id,
            "nonce": quote.nonce,
        }
        return {
            "types": {"EIP712Domain": _EIP712_DOMAIN_TYPE, **AIP2_QUOTE_TYPES},
            "primaryType": "PriceQuote",
            "domain": domain,
            "message": message,
        }

    def _validate_params(self, params: QuoteParams) -> None:
        quoted_amount = int(params.quoted_amount)
        original_amount = int(params.original_amount)
        max_price = int(params.max_price)
        if quoted_amount < original_amount:
            raise ValueError("quoted_amount must be >= original_amount")
        if quoted_amount > max_price:
            raise ValueError("quoted_amount must be <= max_price")
        if quoted_amount < 50000:
            raise ValueError("quoted_amount must be >= $0.05 (50000 base units)")
        if not params.provider.startswith("did:ethr:"):
            raise ValueError("provider must be valid did:ethr format")
        if not params.consumer.startswith("did:ethr:"):
            raise ValueError("consumer must be valid did:ethr format")
        if params.chain_id not in (84532, 8453):
            raise ValueError("chain_id must be 84532 (Base Sepolia) or 8453 (Base Mainnet)")

    def _validate_quote_schema(self, quote: QuoteMessage) -> None:
        if quote.type != "agirails.quote.v1":
            raise ValueError("Invalid message type")
        if not quote.provider.startswith("did:ethr:"):
            raise ValueError("Invalid provider DID format")
        if not quote.consumer.startswith("did:ethr:"):
            raise ValueError("Invalid consumer DID format")
        if quote.currency != "USDC":
            raise ValueError("Only USDC currency is supported")
        if quote.decimals != 6:
            raise ValueError("USDC must use 6 decimals")
        if quote.chain_id not in (84532, 8453):
            raise ValueError("Invalid chainId")

    @staticmethod
    def _extract_address_from_did(did: str) -> str:
        parts = did.replace("did:ethr:", "").split(":")
        address = parts[1] if len(parts) == 2 else parts[0]
        if not address.startswith("0x") or len(address) != 42:
            raise ValueError(f"Invalid DID format: {did}")
        return address


# ---------------------------------------------------------------------------
# Legacy fluent builder (Python-only; no TS analog). Retained for backward
# compatibility. NOT a cross-SDK / on-chain hashing path.
# ---------------------------------------------------------------------------
@dataclass
class Quote:
    """Legacy local service quote (Python-only)."""

    transaction_id: str
    provider: str
    price: int
    estimated_time: int
    valid_until: int
    terms: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    created_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def price_usdc(self) -> float:
        return self.price / 1_000_000

    @property
    def is_valid(self) -> bool:
        return int(time.time()) < self.valid_until

    @property
    def valid_until_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.valid_until)

    @property
    def estimated_time_formatted(self) -> str:
        if self.estimated_time < 60:
            return f"{self.estimated_time}s"
        if self.estimated_time < 3600:
            return f"{self.estimated_time // 60}m {self.estimated_time % 60}s"
        hours = self.estimated_time // 3600
        minutes = (self.estimated_time % 3600) // 60
        return f"{hours}h {minutes}m"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transactionId": self.transaction_id,
            "provider": self.provider,
            "price": self.price,
            "priceUSDC": self.price_usdc,
            "estimatedTime": self.estimated_time,
            "validUntil": self.valid_until,
            "terms": self.terms,
            "metadata": self.metadata,
            "signature": self.signature,
            "createdAt": self.created_at,
            "isValid": self.is_valid,
        }

    def compute_hash(self) -> str:
        """Legacy local hash (sha256). NOT a cross-SDK / on-chain hash."""
        data = {
            "transactionId": self.transaction_id,
            "provider": self.provider.lower(),
            "price": self.price,
            "estimatedTime": self.estimated_time,
            "validUntil": self.valid_until,
        }
        encoded = canonical_json_serialize(data)
        hash_bytes = hashlib.sha256(encoded.encode("utf-8")).digest()
        return "0x" + hash_bytes.hex()


class LegacyQuoteBuilder:
    """Fluent builder for :class:`Quote` (Python-only, legacy)."""

    def __init__(self) -> None:
        self._transaction_id: Optional[str] = None
        self._provider: Optional[str] = None
        self._price: Optional[int] = None
        self._estimated_time: int = 60
        self._valid_until: Optional[int] = None
        self._validity_period: int = 3600
        self._terms: Optional[str] = None
        self._metadata: Dict[str, Any] = {}

    def for_transaction(self, transaction_id: str) -> "LegacyQuoteBuilder":
        self._transaction_id = transaction_id
        return self

    def from_provider(self, provider: str) -> "LegacyQuoteBuilder":
        self._provider = provider
        return self

    def with_price(self, amount: int, unit: str = "raw") -> "LegacyQuoteBuilder":
        self._price = int(amount * 1_000_000) if unit == "usdc" else amount
        return self

    def with_price_usdc(self, usdc_amount: float) -> "LegacyQuoteBuilder":
        self._price = int(usdc_amount * 1_000_000)
        return self

    def with_estimated_time(self, seconds: int) -> "LegacyQuoteBuilder":
        self._estimated_time = seconds
        return self

    def with_estimated_time_minutes(self, minutes: int) -> "LegacyQuoteBuilder":
        self._estimated_time = minutes * 60
        return self

    def valid_for(self, seconds: int) -> "LegacyQuoteBuilder":
        self._validity_period = seconds
        return self

    def valid_until(self, timestamp: int) -> "LegacyQuoteBuilder":
        self._valid_until = timestamp
        return self

    def with_terms(self, terms: str) -> "LegacyQuoteBuilder":
        self._terms = terms
        return self

    def with_metadata(self, key: str, value: Any) -> "LegacyQuoteBuilder":
        self._metadata[key] = value
        return self

    def build(self) -> Quote:
        if not self._transaction_id:
            raise ValueError("transaction_id is required")
        if not self._provider:
            raise ValueError("provider is required")
        if self._price is None:
            raise ValueError("price is required")
        valid_until = self._valid_until
        if valid_until is None:
            valid_until = int(time.time()) + self._validity_period
        return Quote(
            transaction_id=self._transaction_id,
            provider=self._provider,
            price=self._price,
            estimated_time=self._estimated_time,
            valid_until=valid_until,
            terms=self._terms,
            metadata=self._metadata,
        )

    def reset(self) -> "LegacyQuoteBuilder":
        self.__init__()
        return self


def create_quote(
    transaction_id: str,
    provider: str,
    price: int,
    estimated_time: int = 60,
    validity_seconds: int = 3600,
) -> Quote:
    """Create a legacy :class:`Quote` with minimal parameters."""
    return (
        LegacyQuoteBuilder()
        .for_transaction(transaction_id)
        .from_provider(provider)
        .with_price(price)
        .with_estimated_time(estimated_time)
        .valid_for(validity_seconds)
        .build()
    )


__all__ = [
    # AIP-2 signed quote (TS parity)
    "QuoteBuilder",
    "QuoteMessage",
    "QuoteParams",
    "AIP2_QUOTE_TYPES",
    "AIP2QuoteTypes",
    "ZERO_HASH",
    # Legacy fluent (Python-only)
    "Quote",
    "LegacyQuoteBuilder",
    "create_quote",
]
