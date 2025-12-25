"""
Runtime interfaces for ACTP protocol.

Defines the Protocol interfaces that all runtime implementations must follow,
enabling adapters to work with both mock and real blockchain backends.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol, Union, runtime_checkable

try:
    from typing import TypeGuard
except ImportError:
    from typing_extensions import TypeGuard

from agirails.runtime.types import MockTransaction, State


@dataclass
class CreateTransactionParams:
    """
    Parameters for creating a new transaction.

    Attributes:
        provider: Provider's Ethereum address.
        requester: Requester's Ethereum address.
        amount: Transaction amount in USDC wei (string for BigNumber precision).
        deadline: Unix timestamp deadline for transaction acceptance.
        dispute_window: Dispute window duration in seconds (default: 172800 = 2 days).
        service_description: Optional service description or metadata hash.
    """

    provider: str
    requester: str
    amount: str
    deadline: int
    dispute_window: int = 172800
    service_description: Optional[str] = None


class TimeInterface(Protocol):
    """
    Time management interface for runtime.

    Provides access to current blockchain time.
    """

    def now(self) -> int:
        """
        Get current timestamp in seconds.

        Returns:
            Current Unix timestamp.
        """
        ...


class MockTimeInterface(Protocol):
    """
    Extended time interface for mock runtime.

    Provides time manipulation methods for testing.
    """

    def now(self) -> int:
        """Get current timestamp in seconds."""
        ...

    async def advance_time(self, seconds: int) -> None:
        """
        Advance time by specified seconds.

        Args:
            seconds: Number of seconds to advance.
        """
        ...

    async def advance_blocks(self, blocks: int) -> None:
        """
        Advance time by specified number of blocks.

        Args:
            blocks: Number of blocks to advance.
        """
        ...

    async def set_time(self, timestamp: int) -> None:
        """
        Set exact timestamp (must be >= current time).

        Args:
            timestamp: New Unix timestamp.

        Raises:
            ValueError: If timestamp is less than current time.
        """
        ...


@runtime_checkable
class IACTPRuntime(Protocol):
    """
    Runtime interface for ACTP protocol operations.

    Implemented by:
    - MockRuntime (for local development and testing)
    - BlockchainRuntime (for testnet/mainnet)

    This abstraction allows adapters to work with any runtime implementation,
    enabling seamless transition from mock mode to production blockchain mode.

    Example:
        >>> # Using with MockRuntime
        >>> runtime: IACTPRuntime = MockRuntime()
        >>>
        >>> # Adapters work with either implementation
        >>> adapter = BasicAdapter(runtime, requester_address)
    """

    @property
    def time(self) -> TimeInterface:
        """Time management interface."""
        ...

    async def create_transaction(self, params: CreateTransactionParams) -> str:
        """
        Create a new transaction.

        Args:
            params: Transaction creation parameters.

        Returns:
            Transaction ID (bytes32 hex string).

        Raises:
            DeadlinePassedError: If deadline is in the past.
            InvalidAmountError: If amount is zero or negative.
        """
        ...

    async def link_escrow(self, tx_id: str, amount: str) -> str:
        """
        Link an escrow to a transaction and lock funds.

        Automatically transitions INITIATED or QUOTED -> COMMITTED (per ACTP spec).

        Args:
            tx_id: Transaction ID.
            amount: Amount to lock (must match transaction amount).

        Returns:
            Escrow ID.

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If not in INITIATED or QUOTED state.
            InsufficientBalanceError: If requester has insufficient funds.
        """
        ...

    async def transition_state(
        self, tx_id: str, new_state: Union[State, str], proof: Optional[str] = None
    ) -> None:
        """
        Transition a transaction to a new state.

        Validates the transition against the ACTP 8-state machine.

        Args:
            tx_id: Transaction ID.
            new_state: Target state.
            proof: Optional proof data (required for DELIVERED).

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If transition is not valid.
            DeadlinePassedError: If deadline passed (for CANCELLED transition).
        """
        ...

    async def get_transaction(self, tx_id: str) -> Optional[MockTransaction]:
        """
        Get a transaction by ID.

        Args:
            tx_id: Transaction ID.

        Returns:
            Transaction object or None if not found.
        """
        ...

    async def get_all_transactions(self) -> List[MockTransaction]:
        """
        Get all transactions.

        Returns:
            List of all transactions.
        """
        ...

    async def release_escrow(self, escrow_id: str, attestation_uid: Optional[str] = None) -> None:
        """
        Release escrow funds to the provider and settle the transaction.

        Can only be called when transaction is in DELIVERED state
        and dispute window has expired.

        Args:
            escrow_id: Escrow ID.
            attestation_uid: Optional attestation UID for verification.

        Raises:
            EscrowNotFoundError: If escrow doesn't exist.
            TransactionNotFoundError: If linked transaction doesn't exist.
            InvalidStateTransitionError: If transaction not in DELIVERED state.
            DisputeWindowActiveError: If dispute window still active.
        """
        ...

    async def get_escrow_balance(self, escrow_id: str) -> str:
        """
        Get the balance of an escrow.

        Args:
            escrow_id: Escrow ID.

        Returns:
            Balance as string in wei.

        Raises:
            EscrowNotFoundError: If escrow doesn't exist.
        """
        ...


@runtime_checkable
class IMockRuntime(IACTPRuntime, Protocol):
    """
    Extended runtime interface for mock mode.

    Includes testing utilities not available in production runtimes.
    Only implemented by MockRuntime, not by blockchain runtimes.

    Example:
        >>> if is_mock_runtime(client.runtime):
        ...     await client.runtime.reset()
        ...     await client.runtime.time.advance_time(3600)
    """

    @property
    def time(self) -> MockTimeInterface:
        """Extended time interface with manipulation methods."""
        ...

    async def reset(self) -> None:
        """
        Reset state to default.

        Clears all transactions, escrows, balances, and events.
        Only available in mock mode for testing.
        """
        ...

    async def mint_tokens(self, address: str, amount: str) -> None:
        """
        Mint tokens to an address.

        Only available in mock mode. Useful for funding test accounts.

        Args:
            address: Address to mint tokens to.
            amount: Amount to mint in USDC wei.
        """
        ...

    async def get_balance(self, address: str) -> str:
        """
        Get balance of an address.

        Args:
            address: Address to check.

        Returns:
            Balance in USDC wei.
        """
        ...

    async def get_transactions_by_provider(
        self,
        provider: str,
        state: Optional[Union[State, str]] = None,
        limit: int = 100,
    ) -> List[MockTransaction]:
        """
        Get transactions for a specific provider.

        Security measure (H-1) - uses filtered queries with limit to prevent DoS.

        Args:
            provider: Provider address to filter by.
            state: Optional state to filter by.
            limit: Maximum number of results (default 100, max 1000).

        Returns:
            List of matching transactions.
        """
        ...


def is_mock_runtime(runtime: IACTPRuntime) -> TypeGuard[IMockRuntime]:
    """
    Type guard to check if runtime is MockRuntime.

    Use this to safely access mock-only methods.

    Args:
        runtime: Runtime instance to check.

    Returns:
        True if runtime is a MockRuntime instance.

    Example:
        >>> if is_mock_runtime(runtime):
        ...     await runtime.reset()  # Safe to call
    """
    return hasattr(runtime, "reset") and hasattr(runtime, "mint_tokens")
