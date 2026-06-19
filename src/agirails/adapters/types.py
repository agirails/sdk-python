"""
Adapter types for the ACTP SDK adapter routing system.

This module defines types for:
- AdapterMetadata: Capabilities and configuration for each adapter
- PaymentMetadata: Request-level hints for adapter selection
- UnifiedPayParams: Common payment parameters across adapters
- UnifiedPayResult: Common result type for all adapters
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
# Dispute window bounds (mirror TS types/adapter.ts:181-187)
# ============================================================================

#: Minimum dispute window in seconds (1 hour). Mirrors TS ``MIN_DISPUTE_WINDOW``
#: (types/adapter.ts:181). Ensures requesters have time to dispute.
MIN_DISPUTE_WINDOW = 3600

#: Maximum dispute window in seconds (30 days). Mirrors TS ``MAX_DISPUTE_WINDOW``
#: (types/adapter.ts:187). Prevents excessively long fund locks.
MAX_DISPUTE_WINDOW = 30 * 24 * 3600


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

    Mirrors TS ``AdapterMetadata`` (types/adapter.ts:28-57) field-for-field.

    Attributes:
        id: Unique adapter identifier.
        priority: Priority for auto-selection (higher = preferred).
        uses_escrow: Whether adapter uses escrow.
        supports_disputes: Whether adapter supports dispute resolution.
        release_required: Whether explicit release is needed after delivery
            (Python-specific convenience; TS derives this from settlement_mode).
        name: Human-readable adapter name (TS parity, types/adapter.ts:33).
        requires_identity: Whether adapter requires on-chain identity
            (TS parity, types/adapter.ts:42).
        settlement_mode: Settlement mode — ``'explicit'`` (caller must call
            release, REQUIRED for ACTP compliance), ``'timed'`` (auto-release
            after dispute window, future), or ``'atomic'`` (instant settlement,
            no escrow — x402). TS parity, types/adapter.ts:53.
        supported_identity_types: Supported identity types (erc8004, did, ens).
            TS parity, types/adapter.ts:45.
    """

    id: str
    priority: int
    uses_escrow: bool
    supports_disputes: bool
    release_required: bool
    # --- TS-parity fields (optional with safe defaults for back-compat) ---
    name: str = ""
    requires_identity: bool = False
    settlement_mode: str = "explicit"  # 'explicit' | 'timed' | 'atomic'
    supported_identity_types: Optional[List[str]] = None


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

    Mirrors TS ``UnifiedPayParams`` (types/adapter.ts:131-175).

    Attributes:
        to: Recipient - address, HTTP endpoint, or ERC-8004 agent ID.
        amount: Amount in human-readable format. Required for ACTP adapters
            (basic/standard); optional for x402 URL targets (server specifies).
        deadline: Optional deadline (relative like '+24h' or unix timestamp).
        description: Optional service description.
        service_hash: Optional service hash for ACTP (Python convenience).
        metadata: Optional adapter selection metadata.
        erc8004_agent_id: ERC-8004 agent ID (set when 'to' was resolved).
        dispute_window: Optional dispute window in seconds (min 3600, max
            30 days). Validated in ``__post_init__``. TS parity,
            types/adapter.ts:149.
        http_method: HTTP method for x402 paid requests (GET/POST/PUT/PATCH/
            DELETE). Ignored by ACTP adapters. TS parity, types/adapter.ts:168.
        http_body: HTTP body for x402 paid requests (POST/PUT/PATCH). Ignored
            by ACTP adapters. TS parity, types/adapter.ts:171.
        http_headers: Extra HTTP headers for x402 paid requests. Ignored by
            ACTP adapters. TS parity, types/adapter.ts:174.
    """

    to: str
    amount: Optional[Union[int, float, str, Decimal]] = None
    deadline: Optional[Union[int, str]] = None
    description: Optional[str] = None
    service_hash: Optional[str] = None
    metadata: Optional[PaymentMetadata] = None
    erc8004_agent_id: Optional[str] = None
    # --- TS-parity fields ---
    dispute_window: Optional[int] = None
    http_method: Optional[str] = None  # 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'
    http_body: Optional[Union[str, bytes, bytearray]] = None
    http_headers: Optional[Dict[str, str]] = None

    def __post_init__(self) -> None:
        """Validate dispute_window bounds (mirrors TS Zod schema,
        types/adapter.ts:198-203: int, min 3600, max 30 days)."""
        if self.dispute_window is not None:
            dw = self.dispute_window
            # bool is an int subclass — reject it explicitly (TS .int()).
            if isinstance(dw, bool) or not isinstance(dw, int):
                raise ValueError(
                    f"Invalid dispute_window: must be an integer, got {dw!r}"
                )
            if dw < MIN_DISPUTE_WINDOW:
                raise ValueError(
                    f"Invalid dispute_window: must be at least "
                    f"{MIN_DISPUTE_WINDOW} seconds (1 hour), got {dw}"
                )
            if dw > MAX_DISPUTE_WINDOW:
                raise ValueError(
                    f"Invalid dispute_window: must be at most "
                    f"{MAX_DISPUTE_WINDOW} seconds (30 days), got {dw}"
                )


# ============================================================================
# UnifiedPayResult - Common result type for all adapters
# ============================================================================


@dataclass
class UnifiedPayResult:
    """
    Unified payment result returned by all adapters.

    Mirrors TS ``UnifiedPayResult`` (types/adapter.ts:232-288) field-for-field.

    For escrow adapters (basic/standard), ``success=True`` means payment
    initiated and the caller must later call ``release()`` after delivery
    verification. For atomic adapters (x402), ``success=True`` means settlement
    is final and ``release_required=False``.

    Attributes:
        tx_id: Transaction identifier (ACTP txId or x402 settlement tx hash).
        escrow_id: Escrow ID (for release); ``None`` for non-escrow adapters.
        adapter: ID of the adapter that handled the payment.
        state: Current state — ``'COMMITTED'`` or ``'IN_PROGRESS'`` (NOT
            ``'SETTLED'``).
        success: Whether payment initiation succeeded.
        amount: Amount locked, in human-readable (formatted) USDC.
        release_required: ``True`` for ACTP-compliant escrow adapters — payment
            is NOT complete until ``client.release(escrow_id)`` is called.
        provider: Provider address (normalized to lowercase).
        requester: Requester address (normalized to lowercase).
        deadline: Deadline as an ISO 8601 timestamp string.
        response: For x402: the HTTP response (``httpx.Response``). ``None``
            for ACTP adapters.
        error: Error message if the payment failed.
        erc8004_agent_id: ERC-8004 agent ID, if the transaction involved an
            ERC-8004 agent (for reputation reporting).
        fee_breakdown: Deprecated legacy x402 relay fee breakdown — never
            populated on the current x402 path. Retained for API back-compat.
    """

    tx_id: str
    escrow_id: Optional[str]
    adapter: str
    state: str  # 'COMMITTED' | 'IN_PROGRESS'
    success: bool
    amount: str
    release_required: bool
    provider: str
    requester: str
    deadline: str
    response: Optional[Any] = None
    error: Optional[str] = None
    erc8004_agent_id: Optional[str] = None
    fee_breakdown: Optional[Any] = None


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
