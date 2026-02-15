"""
Adapter types for the ACTP SDK adapter routing system.

This module defines types for:
- AdapterMetadata: Capabilities and configuration for each adapter
- UnifiedPayParams: Common payment parameters across adapters
- AdapterSelectionResult: Result of adapter selection with resolution info

1:1 port of TypeScript SDK types/adapter.ts.

@module adapters/types
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict


# ============================================================================
# AdapterMetadata - Describes adapter capabilities
# ============================================================================


@dataclass(frozen=True)
class AdapterMetadata:
    """
    Metadata describing an adapter's capabilities.

    CRITICAL: All adapters must respect ACTP state machine:
    - No skipping IN_PROGRESS state
    - DELIVERED requires proof
    - releaseEscrow must be called explicitly (NO auto-settle)

    Attributes:
        id: Unique adapter identifier.
        priority: Priority for auto-selection (higher = preferred).
        uses_escrow: Whether adapter uses escrow.
        supports_disputes: Whether adapter supports dispute resolution.
        release_required: Whether explicit release is needed after delivery.
    """

    id: str
    priority: int
    uses_escrow: bool
    supports_disputes: bool
    release_required: bool


# ============================================================================
# PaymentIdentity - Identity info for adapter selection
# ============================================================================


@dataclass
class PaymentIdentity:
    """
    Identity information for adapter selection.

    Attributes:
        type: Identity type (erc8004, did, ens, address).
        value: Identity value.
    """

    type: str  # 'erc8004' | 'did' | 'ens' | 'address'
    value: str


# ============================================================================
# PaymentMetadata - Request-level hints for adapter selection
# ============================================================================


class PaymentMetadata(TypedDict, total=False):
    """
    Payment request metadata for adapter selection.

    Attributes:
        preferred_adapter: Explicitly request a specific adapter by ID.
        requires_escrow: Require escrow protection.
        requires_dispute: Require dispute resolution capability.
        identity: Identity information for routing.
        payment_method: Payment method hint (x402, actp, auto).
    """

    preferred_adapter: str
    requires_escrow: bool
    requires_dispute: bool
    identity: PaymentIdentity
    payment_method: str  # 'x402' | 'actp' | 'auto'


# ============================================================================
# UnifiedPayParams - Common payment parameters
# ============================================================================


@dataclass
class UnifiedPayParams:
    """
    Unified payment parameters accepted by all adapters.

    Attributes:
        to: Recipient - address, HTTP endpoint, or ERC-8004 agent ID.
        amount: Amount in human-readable format.
        deadline: Optional deadline (relative like '+24h' or unix timestamp).
        description: Optional service description.
        service_hash: Optional service hash for ACTP.
        metadata: Optional adapter selection metadata.
        erc8004_agent_id: ERC-8004 agent ID (set when 'to' was resolved).
    """

    to: str
    amount: Union[int, float, str, Decimal]
    deadline: Optional[Union[int, str]] = None
    description: Optional[str] = None
    service_hash: Optional[str] = None
    metadata: Optional[PaymentMetadata] = None
    erc8004_agent_id: Optional[str] = None


# ============================================================================
# AdapterSelectionResult - Result from selectAndResolve
# ============================================================================


@dataclass
class AdapterSelectionResult:
    """
    Result of adapter selection with potential ERC-8004 resolution.

    Attributes:
        adapter: The selected adapter instance.
        resolved_params: Resolved payment parameters (with wallet instead of agentId).
        was_agent_id_resolved: Whether an ERC-8004 agent ID was resolved.
    """

    adapter: Any  # IAdapter - using Any to avoid circular imports
    resolved_params: UnifiedPayParams
    was_agent_id_resolved: bool
