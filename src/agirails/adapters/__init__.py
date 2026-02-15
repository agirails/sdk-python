"""
AGIRAILS SDK Adapters.

Provides different API levels for ACTP transactions:

- BasicAdapter: Simple pay() method for quick transactions
- StandardAdapter: Full lifecycle control with separate methods
- X402Adapter: HTTP 402 Payment Required atomic payments
- BaseAdapter: Shared utilities (not for direct use)
- AdapterRegistry: Central registry for managing adapters
- AdapterRouter: Intelligent adapter selection with guard-rails
- IAdapter: Common protocol interface for all adapters

Usage:
    >>> from agirails import ACTPClient
    >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
    >>>
    >>> # Basic API (simplest)
    >>> result = await client.basic.pay({"to": "0x...", "amount": 100})
    >>>
    >>> # Standard API (more control)
    >>> tx_id = await client.standard.create_transaction(...)
    >>> escrow_id = await client.standard.link_escrow(tx_id)
    >>>
    >>> # X402 API (atomic HTTP payments)
    >>> from agirails.adapters import X402Adapter, X402AdapterConfig
    >>> adapter = X402Adapter("0x...", X402AdapterConfig(...))
    >>> result = await adapter.pay(UnifiedPayParams(to="https://...", amount="10"))
"""

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
    MIN_AMOUNT_WEI,
    MAX_DEADLINE_HOURS,
    MAX_DEADLINE_DAYS,
)
from agirails.adapters.basic import (
    BasicAdapter,
    BasicPayParams,
    BasicPayResult,
    CheckStatusResult,
)
from agirails.adapters.standard import (
    StandardAdapter,
    StandardTransactionParams,
    TransactionDetails,
)
from agirails.adapters.x402_adapter import (
    X402Adapter,
    X402AdapterConfig,
    X402PayParams,
    X402PayResult,
)
from agirails.adapters.types import (
    AdapterMetadata,
    AdapterSelectionResult,
    PaymentIdentity,
    PaymentMetadata,
    UnifiedPayParams,
)
from agirails.adapters.i_adapter import IAdapter
from agirails.adapters.adapter_registry import AdapterRegistry
from agirails.adapters.adapter_router import AdapterRouter

__all__ = [
    # Base
    "BaseAdapter",
    "DEFAULT_DEADLINE_SECONDS",
    "DEFAULT_DISPUTE_WINDOW_SECONDS",
    "MIN_AMOUNT_WEI",
    "MAX_DEADLINE_HOURS",
    "MAX_DEADLINE_DAYS",
    # Basic
    "BasicAdapter",
    "BasicPayParams",
    "BasicPayResult",
    "CheckStatusResult",
    # Standard
    "StandardAdapter",
    "StandardTransactionParams",
    "TransactionDetails",
    # X402
    "X402Adapter",
    "X402AdapterConfig",
    "X402PayParams",
    "X402PayResult",
    # Types
    "AdapterMetadata",
    "AdapterSelectionResult",
    "PaymentIdentity",
    "PaymentMetadata",
    "UnifiedPayParams",
    # Interface
    "IAdapter",
    # Registry & Router
    "AdapterRegistry",
    "AdapterRouter",
]
