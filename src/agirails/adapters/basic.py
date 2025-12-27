"""
Basic adapter for AGIRAILS SDK.

Provides the simplest API for ACTP transactions:
- Single `pay()` method that handles everything
- `check_status()` for transaction status with action hints
- Automatic escrow creation and linking
- Sensible defaults for deadline and dispute window

Use this adapter when you want a "just works" experience.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Optional, Union

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
)
from agirails.runtime.base import CreateTransactionParams
from agirails.utils.helpers import ServiceHash, ServiceMetadata

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime


class CheckStatusResult(TypedDict):
    """
    Result from check_status() method.

    PARITY: Matches TypeScript SDK's BasicAdapter.checkStatus() return type.

    Attributes:
        state: Current transaction state string.
        can_accept: Whether provider can accept (INITIATED state, before deadline).
        can_complete: Whether provider can mark as delivered (COMMITTED/IN_PROGRESS).
        can_dispute: Whether requester can dispute (DELIVERED state, within window).
    """

    state: str
    can_accept: bool
    can_complete: bool
    can_dispute: bool


@dataclass
class BasicPayParams:
    """
    Parameters for basic pay() method.

    Args:
        to: Provider address to pay
        amount: Amount in USDC (string, int, or float)
        deadline: Optional deadline (default: 24 hours)
        description: Optional service description
    """

    to: str
    amount: Union[str, int, float]
    deadline: Optional[Union[str, int]] = None
    description: Optional[str] = None


@dataclass
class BasicPayResult:
    """
    Result from basic pay() method.

    Args:
        tx_id: Transaction ID (bytes32)
        escrow_id: Escrow ID (bytes32)
        state: Current transaction state
        amount: Amount in wei (string)
        deadline: Deadline timestamp
    """

    tx_id: str
    escrow_id: str
    state: str
    amount: str
    deadline: int


class BasicAdapter(BaseAdapter):
    """
    Basic-level adapter for ACTP transactions.

    Provides a simple `pay()` method that:
    1. Creates a transaction
    2. Links escrow automatically
    3. Returns a simple result

    Example:
        >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
        >>> result = await client.basic.pay(BasicPayParams(
        ...     to="0x...",
        ...     amount="100.50",
        ...     description="Text generation service"
        ... ))
        >>> print(f"Transaction: {result.tx_id}")
    """

    async def pay(self, params: Union[BasicPayParams, dict]) -> BasicPayResult:
        """
        Create and fund a transaction in one call.

        This is the simplest way to start an ACTP transaction:
        1. Validates inputs
        2. Creates transaction
        3. Links escrow (locks funds)
        4. Returns result with all details

        Args:
            params: Payment parameters (BasicPayParams or dict)

        Returns:
            BasicPayResult with transaction details

        Raises:
            ValidationError: If inputs are invalid
            InsufficientBalanceError: If requester has insufficient funds
            InvalidAddressError: If provider address is invalid

        Example:
            >>> result = await client.basic.pay({
            ...     "to": "0x123...",
            ...     "amount": 100,  # $100 USDC
            ...     "deadline": "24h"  # 24 hours from now
            ... })
        """
        # Convert dict to dataclass if needed
        if isinstance(params, dict):
            params = BasicPayParams(**params)

        # Validate provider address
        provider = self.validate_address(params.to, "to")

        # Parse amount
        amount_wei = self.parse_amount(params.amount)

        # Parse deadline
        deadline = self.parse_deadline(params.deadline)

        # Parse dispute window (use default)
        dispute_window = self.validate_dispute_window(None)

        # Create service hash from description
        if params.description:
            service_metadata = ServiceMetadata(
                service="basic",
                input={"description": params.description},
            )
            service_hash = ServiceHash.hash(service_metadata)
        else:
            service_hash = ServiceHash.ZERO

        # Create transaction
        tx_params = CreateTransactionParams(
            requester=self._requester_address,
            provider=provider,
            amount=amount_wei,
            deadline=deadline,
            dispute_window=dispute_window,
            service_description=service_hash,
        )
        tx_id = await self._runtime.create_transaction(tx_params)

        # Link escrow (locks funds)
        escrow_id = await self._runtime.link_escrow(
            tx_id=tx_id,
            amount=amount_wei,
        )

        # Get transaction to verify state
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            # This shouldn't happen, but handle it gracefully
            state = "COMMITTED"
        else:
            state = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        return BasicPayResult(
            tx_id=tx_id,
            escrow_id=escrow_id,
            state=state,
            amount=amount_wei,
            deadline=deadline,
        )

    async def get_transaction(self, tx_id: str) -> Optional[Dict]:
        """
        Get transaction details.

        Simple wrapper around runtime.get_transaction with dict output.

        Args:
            tx_id: Transaction ID

        Returns:
            Transaction as dictionary or None if not found
        """
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            return None

        return {
            "tx_id": tx.id,
            "requester": tx.requester,
            "provider": tx.provider,
            "amount": tx.amount,
            "state": tx.state.value if hasattr(tx.state, "value") else str(tx.state),
            "deadline": tx.deadline,
            "created_at": tx.created_at,
        }

    async def get_balance(self) -> str:
        """
        Get requester's USDC balance.

        Returns:
            Balance in USDC (formatted string like "100.00")
        """
        balance_wei = await self._runtime.get_balance(self._requester_address)
        return self.format_amount(balance_wei)

    async def check_status(self, tx_id: str) -> CheckStatusResult:
        """
        Check payment status by transaction ID.

        Returns current state plus action hints (what can be done next).

        PARITY: Matches TypeScript SDK's BasicAdapter.checkStatus() exactly.

        Action hints:
        - can_accept: Provider can accept (INITIATED state, before deadline)
        - can_complete: Provider can mark as delivered (COMMITTED/IN_PROGRESS)
        - can_dispute: Requester can dispute (DELIVERED state, within window)

        Args:
            tx_id: Transaction ID to check.

        Returns:
            CheckStatusResult with state and action hints.

        Raises:
            TransactionNotFoundError: If transaction not found.

        Example:
            >>> status = await adapter.check_status(tx_id)
            >>> print(f"State: {status['state']}")
            >>> if status['can_complete']:
            ...     print("Provider can deliver now")
        """
        tx = await self._runtime.get_transaction(tx_id)

        if tx is None:
            from agirails.errors import TransactionNotFoundError
            raise TransactionNotFoundError(tx_id)

        now = self._runtime.time.now()

        # Get state as string
        state_str = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        # Calculate action hints (matching TS SDK logic exactly)
        can_accept = state_str == "INITIATED" and tx.deadline > now
        can_complete = state_str in ("COMMITTED", "IN_PROGRESS")

        # can_dispute: DELIVERED state + within dispute window
        can_dispute = False
        if state_str == "DELIVERED" and tx.completed_at is not None:
            dispute_window_end = tx.completed_at + tx.dispute_window
            can_dispute = now < dispute_window_end

        return CheckStatusResult(
            state=state_str,
            can_accept=can_accept,
            can_complete=can_complete,
            can_dispute=can_dispute,
        )
