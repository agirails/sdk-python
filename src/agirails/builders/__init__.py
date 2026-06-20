"""
Builder patterns for AGIRAILS SDK.

Provides fluent builders for constructing protocol objects:
- QuoteBuilder: For service quotes (AIP-2)
- DeliveryProofBuilder: For delivery proofs (AIP-4)
- CounterOfferBuilder: For AIP-2.1 buyer counter-offers
- CounterAcceptBuilder: For AIP-2.1 provider acceptance

Example:
    >>> from agirails.builders import QuoteBuilder, DeliveryProofBuilder
    >>>
    >>> quote = (
    ...     QuoteBuilder()
    ...     .for_transaction("0x...")
    ...     .with_price_usdc(1.50)
    ...     .build()
    ... )
    >>>
    >>> proof = (
    ...     DeliveryProofBuilder()
    ...     .for_transaction("0x...")
    ...     .with_output(result)
    ...     .build()
    ... )
"""

from agirails.builders.quote import (
    AIP2_QUOTE_TYPES,
    AIP2QuoteTypes,
    LegacyQuoteBuilder,
    Quote,
    QuoteBuilder,
    QuoteMessage,
    QuoteParams,
    create_quote,
)
from agirails.builders.delivery_proof import (
    DeliveryProof,
    DeliveryProofBuilder,
    BatchDeliveryProofBuilder,
    create_delivery_proof,
    compute_output_hash,
)
from agirails.builders.counter_offer import (
    AIP21_COUNTER_OFFER_TYPES,
    CounterOfferBuilder,
    CounterOfferJustification,
    CounterOfferMessage,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.builders.counter_accept import (
    AIP21_COUNTER_ACCEPT_TYPES,
    CounterAcceptBuilder,
    CounterAcceptMessage,
    CounterAcceptParams,
)

__all__ = [
    # Quote (AIP-2 signed — TS parity)
    "QuoteBuilder",
    "QuoteMessage",
    "QuoteParams",
    "AIP2_QUOTE_TYPES",
    "AIP2QuoteTypes",
    # Quote (legacy fluent — Python-only)
    "Quote",
    "LegacyQuoteBuilder",
    "create_quote",
    # Delivery Proof
    "DeliveryProof",
    "DeliveryProofBuilder",
    "BatchDeliveryProofBuilder",
    "create_delivery_proof",
    "compute_output_hash",
    # Counter-offer (AIP-2.1)
    "AIP21_COUNTER_OFFER_TYPES",
    "CounterOfferBuilder",
    "CounterOfferJustification",
    "CounterOfferMessage",
    "CounterOfferParams",
    "MessageNonceManager",
    # Counter-accept (AIP-2.1)
    "AIP21_COUNTER_ACCEPT_TYPES",
    "CounterAcceptBuilder",
    "CounterAcceptMessage",
    "CounterAcceptParams",
]
