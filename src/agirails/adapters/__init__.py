"""
AGIRAILS SDK Adapters.

Provides different API levels for ACTP transactions:

- BeginnerAdapter: Simple pay() method for quick transactions
- IntermediateAdapter: Full lifecycle control with separate methods
- BaseAdapter: Shared utilities (not for direct use)

Usage:
    >>> from agirails import ACTPClient
    >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
    >>>
    >>> # Beginner API (simplest)
    >>> result = await client.beginner.pay({"to": "0x...", "amount": 100})
    >>>
    >>> # Intermediate API (more control)
    >>> tx_id = await client.intermediate.create_transaction(...)
    >>> escrow_id = await client.intermediate.link_escrow(tx_id)
"""

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
    MIN_AMOUNT_WEI,
    MAX_DEADLINE_HOURS,
    MAX_DEADLINE_DAYS,
)
from agirails.adapters.beginner import (
    BeginnerAdapter,
    BeginnerPayParams,
    BeginnerPayResult,
)
from agirails.adapters.intermediate import (
    IntermediateAdapter,
    IntermediateTransactionParams,
    TransactionDetails,
)

__all__ = [
    # Base
    "BaseAdapter",
    "DEFAULT_DEADLINE_SECONDS",
    "DEFAULT_DISPUTE_WINDOW_SECONDS",
    "MIN_AMOUNT_WEI",
    "MAX_DEADLINE_HOURS",
    "MAX_DEADLINE_DAYS",
    # Beginner
    "BeginnerAdapter",
    "BeginnerPayParams",
    "BeginnerPayResult",
    # Intermediate
    "IntermediateAdapter",
    "IntermediateTransactionParams",
    "TransactionDetails",
]
