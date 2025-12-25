"""
Builder patterns for AGIRAILS SDK.

Provides fluent builders for constructing protocol objects:
- QuoteBuilder: For service quotes (AIP-2)
- DeliveryProofBuilder: For delivery proofs (AIP-4)

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
    Quote,
    QuoteBuilder,
    create_quote,
)
from agirails.builders.delivery_proof import (
    DeliveryProof,
    DeliveryProofBuilder,
    BatchDeliveryProofBuilder,
    create_delivery_proof,
    compute_output_hash,
)

__all__ = [
    # Quote
    "Quote",
    "QuoteBuilder",
    "create_quote",
    # Delivery Proof
    "DeliveryProof",
    "DeliveryProofBuilder",
    "BatchDeliveryProofBuilder",
    "create_delivery_proof",
    "compute_output_hash",
]
