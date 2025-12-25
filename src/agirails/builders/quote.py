"""
Quote Builder for AGIRAILS SDK.

Provides a fluent builder pattern for constructing service quotes (AIP-2).
Quotes are price proposals from providers before committing to work.

Example:
    >>> from agirails.builders import QuoteBuilder
    >>> quote = (
    ...     QuoteBuilder()
    ...     .for_transaction("0x...")
    ...     .with_price(1_000_000)  # $1.00 USDC
    ...     .with_estimated_time(60)  # 60 seconds
    ...     .with_validity(3600)  # 1 hour
    ...     .build()
    ... )
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from agirails.types.message import EIP712Domain, ServiceResponse
from agirails.utils.canonical_json import canonical_json_dumps as canonical_json_serialize


@dataclass
class Quote:
    """
    Service quote from a provider.

    Attributes:
        transaction_id: Associated transaction ID
        provider: Provider address
        price: Quoted price in USDC (6 decimals)
        estimated_time: Estimated completion time in seconds
        valid_until: Quote validity deadline (Unix timestamp)
        terms: Optional service terms
        metadata: Additional metadata
        signature: Optional EIP-712 signature
        created_at: Quote creation time
    """

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
        """Get price in human-readable USDC."""
        return self.price / 1_000_000

    @property
    def is_valid(self) -> bool:
        """Check if quote is still valid."""
        return int(time.time()) < self.valid_until

    @property
    def valid_until_datetime(self) -> datetime:
        """Get validity deadline as datetime."""
        return datetime.fromtimestamp(self.valid_until)

    @property
    def estimated_time_formatted(self) -> str:
        """Get estimated time as formatted string."""
        if self.estimated_time < 60:
            return f"{self.estimated_time}s"
        if self.estimated_time < 3600:
            return f"{self.estimated_time // 60}m {self.estimated_time % 60}s"
        hours = self.estimated_time // 3600
        minutes = (self.estimated_time % 3600) // 60
        return f"{hours}h {minutes}m"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
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
        """Compute hash of the quote for signing."""
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


class QuoteBuilder:
    """
    Fluent builder for constructing quotes.

    Example:
        >>> quote = (
        ...     QuoteBuilder()
        ...     .for_transaction("0x123...")
        ...     .from_provider("0xabc...")
        ...     .with_price(1_000_000)
        ...     .with_estimated_time(60)
        ...     .build()
        ... )
    """

    def __init__(self) -> None:
        """Initialize empty builder."""
        self._transaction_id: Optional[str] = None
        self._provider: Optional[str] = None
        self._price: Optional[int] = None
        self._estimated_time: int = 60
        self._valid_until: Optional[int] = None
        self._validity_period: int = 3600  # 1 hour default
        self._terms: Optional[str] = None
        self._metadata: Dict[str, Any] = {}

    def for_transaction(self, transaction_id: str) -> "QuoteBuilder":
        """
        Set the transaction ID this quote is for.

        Args:
            transaction_id: ACTP transaction ID

        Returns:
            Self for chaining
        """
        self._transaction_id = transaction_id
        return self

    def from_provider(self, provider: str) -> "QuoteBuilder":
        """
        Set the provider address.

        Args:
            provider: Provider's Ethereum address

        Returns:
            Self for chaining
        """
        self._provider = provider
        return self

    def with_price(
        self,
        amount: int,
        unit: str = "raw",
    ) -> "QuoteBuilder":
        """
        Set the quoted price.

        Args:
            amount: Price amount
            unit: Unit of amount ("raw" for 6 decimals, "usdc" for human-readable)

        Returns:
            Self for chaining
        """
        if unit == "usdc":
            self._price = int(amount * 1_000_000)
        else:
            self._price = amount
        return self

    def with_price_usdc(self, usdc_amount: float) -> "QuoteBuilder":
        """
        Set price in human-readable USDC.

        Args:
            usdc_amount: Amount in USDC (e.g., 1.50 for $1.50)

        Returns:
            Self for chaining
        """
        self._price = int(usdc_amount * 1_000_000)
        return self

    def with_estimated_time(self, seconds: int) -> "QuoteBuilder":
        """
        Set estimated completion time.

        Args:
            seconds: Estimated time in seconds

        Returns:
            Self for chaining
        """
        self._estimated_time = seconds
        return self

    def with_estimated_time_minutes(self, minutes: int) -> "QuoteBuilder":
        """
        Set estimated completion time in minutes.

        Args:
            minutes: Estimated time in minutes

        Returns:
            Self for chaining
        """
        self._estimated_time = minutes * 60
        return self

    def valid_for(self, seconds: int) -> "QuoteBuilder":
        """
        Set quote validity period.

        Args:
            seconds: Validity period in seconds

        Returns:
            Self for chaining
        """
        self._validity_period = seconds
        return self

    def valid_until(self, timestamp: int) -> "QuoteBuilder":
        """
        Set quote validity deadline.

        Args:
            timestamp: Unix timestamp deadline

        Returns:
            Self for chaining
        """
        self._valid_until = timestamp
        return self

    def with_terms(self, terms: str) -> "QuoteBuilder":
        """
        Set service terms.

        Args:
            terms: Service terms text

        Returns:
            Self for chaining
        """
        self._terms = terms
        return self

    def with_metadata(self, key: str, value: Any) -> "QuoteBuilder":
        """
        Add metadata key-value pair.

        Args:
            key: Metadata key
            value: Metadata value

        Returns:
            Self for chaining
        """
        self._metadata[key] = value
        return self

    def build(self) -> Quote:
        """
        Build the Quote object.

        Returns:
            Constructed Quote

        Raises:
            ValueError: If required fields are missing
        """
        if not self._transaction_id:
            raise ValueError("transaction_id is required")
        if not self._provider:
            raise ValueError("provider is required")
        if self._price is None:
            raise ValueError("price is required")

        # Calculate valid_until
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

    def reset(self) -> "QuoteBuilder":
        """
        Reset builder to initial state.

        Returns:
            Self for chaining
        """
        self.__init__()
        return self


def create_quote(
    transaction_id: str,
    provider: str,
    price: int,
    estimated_time: int = 60,
    validity_seconds: int = 3600,
) -> Quote:
    """
    Create a quote with minimal parameters.

    Args:
        transaction_id: ACTP transaction ID
        provider: Provider address
        price: Price in USDC (6 decimals)
        estimated_time: Estimated time in seconds
        validity_seconds: Quote validity in seconds

    Returns:
        Quote object
    """
    return (
        QuoteBuilder()
        .for_transaction(transaction_id)
        .from_provider(provider)
        .with_price(price)
        .with_estimated_time(estimated_time)
        .valid_for(validity_seconds)
        .build()
    )


__all__ = [
    "Quote",
    "QuoteBuilder",
    "create_quote",
]
