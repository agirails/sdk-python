"""
Intermediate adapter for AGIRAILS SDK.

Provides granular control over the ACTP transaction lifecycle:
- Separate create_transaction() and link_escrow()
- Manual state transitions
- Escrow management
- Full transaction lifecycle control

Use this adapter when you need more control than BeginnerAdapter provides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, List, Optional, Union

from agirails.adapters.base import (
    BaseAdapter,
    DEFAULT_DISPUTE_WINDOW_SECONDS,
)
from agirails.runtime.base import CreateTransactionParams
from agirails.runtime.types import State
from agirails.utils.helpers import ServiceHash, ServiceMetadata

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime
    from agirails.runtime.types import MockTransaction


@dataclass
class IntermediateTransactionParams:
    """
    Parameters for intermediate create_transaction().

    Args:
        provider: Provider address
        amount: Amount in USDC (string, int, or float)
        deadline: Deadline (timestamp, relative, or None for default)
        dispute_window: Dispute window in seconds (None for default)
        description: Service description (optional)
        service_hash: Pre-computed service hash (optional, overrides description)
    """

    provider: str
    amount: Union[str, int, float]
    deadline: Optional[Union[str, int]] = None
    dispute_window: Optional[int] = None
    description: Optional[str] = None
    service_hash: Optional[str] = None


@dataclass
class TransactionDetails:
    """
    Detailed transaction information.

    Returned by get_transaction() for intermediate users who need full details.
    """

    id: str
    requester: str
    provider: str
    amount: str
    state: str
    deadline: int
    dispute_window: int
    service_description: str
    created_at: int
    updated_at: int
    escrow_id: Optional[str] = None
    delivery_proof: Optional[str] = None
    attestation_uid: Optional[str] = None


class IntermediateAdapter(BaseAdapter):
    """
    Intermediate adapter for granular ACTP transaction control.

    Provides separate methods for each step of the transaction lifecycle:
    1. create_transaction() - Create transaction (no funds locked yet)
    2. link_escrow() - Lock funds in escrow
    3. transition_state() - Move through states
    4. release_escrow() - Release funds to provider
    5. get_transaction() - Check transaction details

    Example:
        >>> client = await ACTPClient.create(mode="mock", requester_address="0x...")
        >>>
        >>> # Step 1: Create transaction
        >>> tx_id = await client.intermediate.create_transaction(
        ...     IntermediateTransactionParams(
        ...         provider="0x...",
        ...         amount="100.50",
        ...         deadline="24h",
        ...         description="AI text generation"
        ...     )
        ... )
        >>>
        >>> # Step 2: Link escrow (locks funds)
        >>> escrow_id = await client.intermediate.link_escrow(tx_id)
        >>>
        >>> # Step 3: Provider delivers work...
        >>> await client.intermediate.transition_state(tx_id, "DELIVERED")
        >>>
        >>> # Step 4: Release funds
        >>> await client.intermediate.release_escrow(escrow_id)
    """

    async def create_transaction(
        self, params: Union[IntermediateTransactionParams, dict]
    ) -> str:
        """
        Create a new ACTP transaction.

        This creates the transaction record but does NOT lock funds.
        Call link_escrow() to lock funds and move to COMMITTED state.

        Args:
            params: Transaction parameters

        Returns:
            Transaction ID (bytes32)

        Raises:
            ValidationError: If inputs are invalid
            InvalidAddressError: If addresses are invalid
        """
        # Convert dict to dataclass if needed
        if isinstance(params, dict):
            params = IntermediateTransactionParams(**params)

        # Validate provider address
        provider = self.validate_address(params.provider, "provider")

        # Parse amount
        amount_wei = self.parse_amount(params.amount)

        # Parse deadline
        deadline = self.parse_deadline(params.deadline)

        # Validate dispute window
        dispute_window = self.validate_dispute_window(params.dispute_window)

        # Determine service hash
        if params.service_hash:
            service_hash = params.service_hash
        elif params.description:
            service_metadata = ServiceMetadata(
                service="intermediate",
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

        return tx_id

    async def link_escrow(self, tx_id: str, amount: Optional[Union[str, int, float]] = None) -> str:
        """
        Link escrow to transaction (locks funds).

        This locks the funds and transitions the transaction to COMMITTED state.

        Args:
            tx_id: Transaction ID
            amount: Override amount (optional, uses transaction amount if not provided)

        Returns:
            Escrow ID (bytes32)

        Raises:
            TransactionNotFoundError: If transaction doesn't exist
            InvalidStateTransitionError: If transaction is not in INITIATED/QUOTED state
            InsufficientBalanceError: If requester has insufficient funds
        """
        # Get transaction to determine amount if not provided
        if amount is None:
            tx = await self._runtime.get_transaction(tx_id)
            if tx is None:
                from agirails.errors import TransactionNotFoundError
                raise TransactionNotFoundError(tx_id=tx_id)
            amount_wei = tx.amount
        else:
            amount_wei = self.parse_amount(amount)

        # Link escrow
        escrow_id = await self._runtime.link_escrow(
            tx_id=tx_id,
            amount=amount_wei,
        )

        return escrow_id

    async def transition_state(
        self,
        tx_id: str,
        new_state: Union[str, State],
        proof: Optional[str] = None,
    ) -> None:
        """
        Transition transaction to a new state.

        Valid transitions depend on current state:
        - INITIATED → QUOTED, COMMITTED, CANCELLED
        - QUOTED → COMMITTED, CANCELLED
        - COMMITTED → IN_PROGRESS, DELIVERED, CANCELLED
        - IN_PROGRESS → DELIVERED, CANCELLED
        - DELIVERED → SETTLED, DISPUTED
        - DISPUTED → SETTLED

        Note: Some transitions (like → COMMITTED) happen automatically via link_escrow().

        Args:
            tx_id: Transaction ID
            new_state: Target state (string or State enum)
            proof: Optional proof for DELIVERED state

        Raises:
            TransactionNotFoundError: If transaction doesn't exist
            InvalidStateTransitionError: If transition is not allowed
        """
        # Convert string to State enum if needed
        if isinstance(new_state, str):
            new_state = State(new_state)

        await self._runtime.transition_state(
            tx_id=tx_id,
            new_state=new_state,
            proof=proof,
        )

    async def release_escrow(
        self,
        escrow_id: str,
        attestation_uid: Optional[str] = None,
    ) -> None:
        """
        Release escrow funds to provider.

        This releases the locked funds to the provider, transitioning
        the transaction to SETTLED state.

        Args:
            escrow_id: Escrow ID to release
            attestation_uid: Optional EAS attestation UID

        Raises:
            EscrowNotFoundError: If escrow doesn't exist
            DisputeWindowActiveError: If dispute window is still active
            InvalidStateTransitionError: If transaction is not in DELIVERED state
        """
        await self._runtime.release_escrow(
            escrow_id=escrow_id,
            attestation_uid=attestation_uid or "",
        )

    async def get_escrow_balance(self, escrow_id: str) -> str:
        """
        Get escrow balance.

        Args:
            escrow_id: Escrow ID

        Returns:
            Balance in wei (string)

        Raises:
            EscrowNotFoundError: If escrow doesn't exist
        """
        return await self._runtime.get_escrow_balance(escrow_id)

    async def get_transaction(self, tx_id: str) -> Optional[TransactionDetails]:
        """
        Get transaction details.

        Args:
            tx_id: Transaction ID

        Returns:
            TransactionDetails or None if not found
        """
        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            return None

        # Get escrow info if available
        escrow_id = None
        if hasattr(self._runtime, "_state"):
            # Mock runtime - look up escrow by tx_id
            state = await self._runtime._state_manager.load()
            for eid, escrow in state.escrows.items():
                if escrow.tx_id == tx_id:
                    escrow_id = eid
                    break

        return TransactionDetails(
            id=tx.id,
            requester=tx.requester,
            provider=tx.provider,
            amount=tx.amount,
            state=tx.state.value if hasattr(tx.state, "value") else str(tx.state),
            deadline=tx.deadline,
            dispute_window=tx.dispute_window,
            service_description=tx.service_description or "",
            created_at=tx.created_at,
            updated_at=tx.updated_at,
            escrow_id=escrow_id,
            delivery_proof=tx.proof,
            attestation_uid=None,  # Not tracked in MockTransaction
        )

    async def get_all_transactions(self) -> List[TransactionDetails]:
        """
        Get all transactions.

        Returns:
            List of TransactionDetails
        """
        transactions = await self._runtime.get_all_transactions()
        result = []
        for tx in transactions:
            details = await self.get_transaction(tx.id)
            if details:
                result.append(details)
        return result

    async def get_transactions_by_provider(
        self,
        provider_address: str,
        state: Optional[Union[str, State]] = None,
        limit: int = 100,
    ) -> List[TransactionDetails]:
        """
        Get transactions by provider address.

        Args:
            provider_address: Provider address to filter by
            state: Optional state filter
            limit: Maximum number of results

        Returns:
            List of TransactionDetails
        """
        # Validate provider address
        provider = self.validate_address(provider_address, "provider")

        # Convert state if needed
        state_filter = None
        if state is not None:
            if isinstance(state, str):
                state_filter = State(state)
            else:
                state_filter = state

        transactions = await self._runtime.get_transactions_by_provider(
            provider=provider,
            state=state_filter,
            limit=limit,
        )

        result = []
        for tx in transactions:
            details = await self.get_transaction(tx.id)
            if details:
                result.append(details)
        return result
