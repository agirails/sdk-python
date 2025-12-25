"""
Transaction types for AGIRAILS SDK.

Provides types for ACTP protocol transactions and their states.

The ACTP protocol uses an 8-state transaction lifecycle:
1. INITIATED - Transaction created, awaiting escrow
2. QUOTED - Provider submitted price quote (optional)
3. COMMITTED - Escrow linked, provider committed
4. IN_PROGRESS - Provider actively working (optional)
5. DELIVERED - Provider delivered result
6. SETTLED - Payment released (terminal)
7. DISPUTED - Consumer disputed delivery
8. CANCELLED - Transaction cancelled (terminal)

Example:
    >>> tx = Transaction(
    ...     id="0x123...",
    ...     state=TransactionState.INITIATED,
    ...     requester="0xabc...",
    ...     provider="0xdef...",
    ...     amount=1000000,
    ... )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set


class TransactionState(IntEnum):
    """
    ACTP transaction states.

    Matches the on-chain State enum in ACTPKernel.sol.
    """

    INITIATED = 0
    QUOTED = 1
    COMMITTED = 2
    IN_PROGRESS = 3
    DELIVERED = 4
    SETTLED = 5
    DISPUTED = 6
    CANCELLED = 7

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self in (TransactionState.SETTLED, TransactionState.CANCELLED)

    @property
    def is_active(self) -> bool:
        """Check if transaction is active (not terminal)."""
        return not self.is_terminal

    @property
    def can_cancel(self) -> bool:
        """Check if transaction can be cancelled from this state."""
        return self in (
            TransactionState.INITIATED,
            TransactionState.QUOTED,
            TransactionState.COMMITTED,
        )

    @property
    def can_dispute(self) -> bool:
        """Check if transaction can be disputed from this state."""
        return self == TransactionState.DELIVERED

    def next_states(self) -> List[TransactionState]:
        """Get valid next states from this state."""
        transitions = {
            TransactionState.INITIATED: [
                TransactionState.QUOTED,
                TransactionState.COMMITTED,
                TransactionState.CANCELLED,
            ],
            TransactionState.QUOTED: [
                TransactionState.COMMITTED,
                TransactionState.CANCELLED,
            ],
            TransactionState.COMMITTED: [
                TransactionState.IN_PROGRESS,
                TransactionState.DELIVERED,
                TransactionState.CANCELLED,
            ],
            TransactionState.IN_PROGRESS: [
                TransactionState.DELIVERED,
            ],
            TransactionState.DELIVERED: [
                TransactionState.SETTLED,
                TransactionState.DISPUTED,
            ],
            TransactionState.DISPUTED: [
                TransactionState.SETTLED,
            ],
            TransactionState.SETTLED: [],
            TransactionState.CANCELLED: [],
        }
        return transitions.get(self, [])


@dataclass
class Transaction:
    """
    ACTP protocol transaction.

    Represents a complete transaction record from the blockchain.

    Attributes:
        id: Transaction ID (bytes32 hex string)
        state: Current transaction state
        requester: Requester's Ethereum address
        provider: Provider's Ethereum address
        amount: Amount in USDC (6 decimals)
        fee: Platform fee in USDC (6 decimals)
        deadline: Transaction deadline (Unix timestamp)
        dispute_window: Dispute window in seconds
        input_hash: Hash of the input data
        output_hash: Hash of the output data (after delivery)
        attestation_uid: EAS attestation UID (after delivery)
        created_at: Creation timestamp
        updated_at: Last update timestamp
        completed_at: Completion timestamp (for DELIVERED state)
        metadata: Additional metadata
    """

    id: str
    state: TransactionState
    requester: str
    provider: str
    amount: int
    fee: int = 0
    deadline: int = 0
    dispute_window: int = 3600  # 1 hour default
    input_hash: str = ""
    output_hash: str = ""
    attestation_uid: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def amount_usdc(self) -> float:
        """Get amount in USDC (human-readable)."""
        return self.amount / 1_000_000

    @property
    def fee_usdc(self) -> float:
        """Get fee in USDC (human-readable)."""
        return self.fee / 1_000_000

    @property
    def total_usdc(self) -> float:
        """Get total (amount + fee) in USDC."""
        return (self.amount + self.fee) / 1_000_000

    @property
    def deadline_datetime(self) -> datetime:
        """Get deadline as datetime."""
        return datetime.fromtimestamp(self.deadline)

    @property
    def is_expired(self) -> bool:
        """Check if transaction deadline has passed."""
        return datetime.now().timestamp() > self.deadline

    @property
    def is_in_dispute_window(self) -> bool:
        """Check if transaction is within dispute window."""
        if self.completed_at is None:
            return False
        window_end = self.completed_at.timestamp() + self.dispute_window
        return datetime.now().timestamp() < window_end

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "state": self.state.value,
            "stateName": self.state.name,
            "requester": self.requester,
            "provider": self.provider,
            "amount": self.amount,
            "amountUsdc": self.amount_usdc,
            "fee": self.fee,
            "feeUsdc": self.fee_usdc,
            "deadline": self.deadline,
            "disputeWindow": self.dispute_window,
            "inputHash": self.input_hash,
            "outputHash": self.output_hash,
            "attestationUid": self.attestation_uid,
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "completedAt": self.completed_at.isoformat() if self.completed_at else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Transaction:
        """Create Transaction from dictionary."""
        return cls(
            id=data["id"],
            state=TransactionState(data["state"]),
            requester=data["requester"],
            provider=data["provider"],
            amount=data["amount"],
            fee=data.get("fee", 0),
            deadline=data.get("deadline", 0),
            dispute_window=data.get("disputeWindow", 3600),
            input_hash=data.get("inputHash", ""),
            output_hash=data.get("outputHash", ""),
            attestation_uid=data.get("attestationUid", ""),
            created_at=datetime.fromisoformat(data["createdAt"])
            if "createdAt" in data
            else datetime.now(),
            updated_at=datetime.fromisoformat(data["updatedAt"])
            if "updatedAt" in data
            else datetime.now(),
            completed_at=datetime.fromisoformat(data["completedAt"])
            if data.get("completedAt")
            else None,
            metadata=data.get("metadata", {}),
        )


@dataclass
class TransactionReceipt:
    """
    Receipt for a blockchain transaction.

    Attributes:
        transaction_hash: On-chain transaction hash
        block_number: Block number where transaction was included
        block_hash: Block hash
        gas_used: Gas used by the transaction
        effective_gas_price: Effective gas price in wei
        status: Transaction status (1 = success, 0 = failure)
        logs: Transaction logs/events
    """

    transaction_hash: str
    block_number: int
    block_hash: str
    gas_used: int
    effective_gas_price: int
    status: int
    logs: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if transaction was successful."""
        return self.status == 1

    @property
    def gas_cost_wei(self) -> int:
        """Get total gas cost in wei."""
        return self.gas_used * self.effective_gas_price

    @property
    def gas_cost_eth(self) -> float:
        """Get total gas cost in ETH."""
        return self.gas_cost_wei / 1e18

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "transactionHash": self.transaction_hash,
            "blockNumber": self.block_number,
            "blockHash": self.block_hash,
            "gasUsed": self.gas_used,
            "effectiveGasPrice": self.effective_gas_price,
            "status": self.status,
            "success": self.success,
            "gasCostWei": self.gas_cost_wei,
            "gasCostEth": self.gas_cost_eth,
            "logs": self.logs,
        }


@dataclass
class TransactionFilter:
    """
    Filter for querying transactions.

    Attributes:
        requester: Filter by requester address
        provider: Filter by provider address
        states: Filter by transaction states
        min_amount: Minimum amount in USDC (6 decimals)
        max_amount: Maximum amount in USDC (6 decimals)
        from_block: Starting block number
        to_block: Ending block number
        from_timestamp: Starting timestamp
        to_timestamp: Ending timestamp
    """

    requester: Optional[str] = None
    provider: Optional[str] = None
    states: Optional[List[TransactionState]] = None
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    from_block: Optional[int] = None
    to_block: Optional[int] = None
    from_timestamp: Optional[int] = None
    to_timestamp: Optional[int] = None

    def matches(self, tx: Transaction) -> bool:
        """
        Check if a transaction matches this filter.

        Args:
            tx: Transaction to check

        Returns:
            True if transaction matches all criteria
        """
        if self.requester and tx.requester.lower() != self.requester.lower():
            return False

        if self.provider and tx.provider.lower() != self.provider.lower():
            return False

        if self.states and tx.state not in self.states:
            return False

        if self.min_amount is not None and tx.amount < self.min_amount:
            return False

        if self.max_amount is not None and tx.amount > self.max_amount:
            return False

        if self.from_timestamp is not None:
            if tx.created_at.timestamp() < self.from_timestamp:
                return False

        if self.to_timestamp is not None:
            if tx.created_at.timestamp() > self.to_timestamp:
                return False

        return True


# State transition constants
VALID_TRANSITIONS: Dict[TransactionState, Set[TransactionState]] = {
    TransactionState.INITIATED: {
        TransactionState.QUOTED,
        TransactionState.COMMITTED,
        TransactionState.CANCELLED,
    },
    TransactionState.QUOTED: {
        TransactionState.COMMITTED,
        TransactionState.CANCELLED,
    },
    TransactionState.COMMITTED: {
        TransactionState.IN_PROGRESS,
        TransactionState.DELIVERED,
        TransactionState.CANCELLED,
    },
    TransactionState.IN_PROGRESS: {
        TransactionState.DELIVERED,
    },
    TransactionState.DELIVERED: {
        TransactionState.SETTLED,
        TransactionState.DISPUTED,
    },
    TransactionState.DISPUTED: {
        TransactionState.SETTLED,
    },
    TransactionState.SETTLED: set(),
    TransactionState.CANCELLED: set(),
}


def is_valid_transition(from_state: TransactionState, to_state: TransactionState) -> bool:
    """
    Check if a state transition is valid.

    Args:
        from_state: Current state
        to_state: Target state

    Returns:
        True if transition is allowed
    """
    return to_state in VALID_TRANSITIONS.get(from_state, set())
