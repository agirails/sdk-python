"""
AGIRAILS SDK Adapters.

Provides different API levels for ACTP transactions:

- BasicAdapter: Simple pay() method for quick transactions
- StandardAdapter: Full lifecycle control with separate methods
- BaseAdapter: Shared utilities (not for direct use)

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
]
