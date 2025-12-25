"""
AGIRAILS Runtime Layer.

This module provides runtime implementations for the ACTP protocol:
- MockRuntime: For local development and testing
- BlockchainRuntime: For testnet/mainnet interactions

Example:
    >>> from agirails.runtime import MockRuntime, State
    >>> runtime = MockRuntime()
    >>> await runtime.create_transaction(...)

    >>> from agirails.runtime import BlockchainRuntime
    >>> runtime = await BlockchainRuntime.create(private_key, network="base-sepolia")
"""

from agirails.runtime.types import (
    State,
    TransactionStateValue,
    MockTransaction,
    MockEscrow,
    MockAccount,
    MockBlockchain,
    MockEvent,
    MockState,
    STATE_TRANSITIONS,
    is_valid_transition,
    is_terminal_state,
    MOCK_STATE_DEFAULTS,
)
from agirails.runtime.base import (
    CreateTransactionParams,
    TimeInterface,
    IACTPRuntime,
    IMockRuntime,
    is_mock_runtime,
)
from agirails.runtime.mock_state_manager import MockStateManager
from agirails.runtime.mock_runtime import MockRuntime

# BlockchainRuntime requires web3 which may not be installed
# Import it lazily to avoid breaking tests that don't need it
try:
    from agirails.runtime.blockchain_runtime import BlockchainRuntime
except ImportError:
    BlockchainRuntime = None  # type: ignore[misc, assignment]

__all__ = [
    # Types
    "State",
    "TransactionStateValue",
    "MockTransaction",
    "MockEscrow",
    "MockAccount",
    "MockBlockchain",
    "MockEvent",
    "MockState",
    "STATE_TRANSITIONS",
    "is_valid_transition",
    "is_terminal_state",
    "MOCK_STATE_DEFAULTS",
    # Interfaces
    "CreateTransactionParams",
    "TimeInterface",
    "IACTPRuntime",
    "IMockRuntime",
    "is_mock_runtime",
    # Implementations
    "MockStateManager",
    "MockRuntime",
    "BlockchainRuntime",
]
