"""
Runtime types for ACTP protocol.

Defines the state machine, transaction types, and mock state structures
that implement the 8-state ACTP transaction lifecycle.

State Machine:
    INITIATED -> QUOTED -> COMMITTED -> IN_PROGRESS -> DELIVERED -> SETTLED
                                     -> CANCELLED     -> DISPUTED -> SETTLED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Literal, Optional, Union


class State(str, Enum):
    """
    ACTP transaction states.

    The protocol implements an 8-state machine:
    - INITIATED (0): Transaction created, awaiting escrow
    - QUOTED (1): Provider submitted price quote (optional)
    - COMMITTED (2): Escrow linked, provider committed
    - IN_PROGRESS (3): Provider actively working (optional)
    - DELIVERED (4): Provider delivered result + proof
    - SETTLED (5): Payment released (terminal)
    - DISPUTED (6): Consumer disputed delivery
    - CANCELLED (7): Transaction cancelled (terminal)
    """

    INITIATED = "INITIATED"
    QUOTED = "QUOTED"
    COMMITTED = "COMMITTED"
    IN_PROGRESS = "IN_PROGRESS"
    DELIVERED = "DELIVERED"
    SETTLED = "SETTLED"
    DISPUTED = "DISPUTED"
    CANCELLED = "CANCELLED"

    @property
    def value_int(self) -> int:
        """Return the integer value of the state for contract compatibility."""
        return _STATE_TO_INT[self]


# State string literal type for type hints
TransactionStateValue = Literal[
    "INITIATED",
    "QUOTED",
    "COMMITTED",
    "IN_PROGRESS",
    "DELIVERED",
    "SETTLED",
    "DISPUTED",
    "CANCELLED",
]

# Map state enum to integer for contract compatibility
_STATE_TO_INT: Dict[State, int] = {
    State.INITIATED: 0,
    State.QUOTED: 1,
    State.COMMITTED: 2,
    State.IN_PROGRESS: 3,
    State.DELIVERED: 4,
    State.SETTLED: 5,
    State.DISPUTED: 6,
    State.CANCELLED: 7,
}

# Map integer to state enum
INT_TO_STATE: Dict[int, State] = {v: k for k, v in _STATE_TO_INT.items()}


# Valid state transitions (directed acyclic graph)
# Key: current state, Value: list of valid target states
# AUDIT FIX: COMMITTED cannot skip to DELIVERED - must go through IN_PROGRESS
STATE_TRANSITIONS: Dict[State, List[State]] = {
    State.INITIATED: [State.QUOTED, State.COMMITTED, State.CANCELLED],
    State.QUOTED: [State.COMMITTED, State.CANCELLED],
    State.COMMITTED: [State.IN_PROGRESS, State.CANCELLED],  # AUDIT FIX: removed DELIVERED
    State.IN_PROGRESS: [State.DELIVERED, State.CANCELLED],
    State.DELIVERED: [State.SETTLED, State.DISPUTED],
    State.DISPUTED: [State.SETTLED, State.CANCELLED],  # AUDIT FIX: admin can cancel
    State.SETTLED: [],  # Terminal
    State.CANCELLED: [],  # Terminal
}

# Terminal states (no further transitions possible)
TERMINAL_STATES: FrozenSet[State] = frozenset({State.SETTLED, State.CANCELLED})


def is_valid_transition(current: Union[State, str], target: Union[State, str]) -> bool:
    """
    Check if a state transition is valid.

    Args:
        current: Current transaction state.
        target: Target state to transition to.

    Returns:
        True if the transition is allowed, False otherwise.

    Example:
        >>> is_valid_transition(State.INITIATED, State.COMMITTED)
        True
        >>> is_valid_transition(State.SETTLED, State.INITIATED)
        False
    """
    if isinstance(current, str):
        current = State(current)
    if isinstance(target, str):
        target = State(target)

    return target in STATE_TRANSITIONS.get(current, [])


def is_terminal_state(state: Union[State, str]) -> bool:
    """
    Check if a state is terminal (no further transitions).

    Args:
        state: State to check.

    Returns:
        True if the state is terminal (SETTLED or CANCELLED).

    Example:
        >>> is_terminal_state(State.SETTLED)
        True
        >>> is_terminal_state(State.DELIVERED)
        False
    """
    if isinstance(state, str):
        state = State(state)
    return state in TERMINAL_STATES


@dataclass
class MockTransaction:
    """
    Represents a transaction in the mock runtime.

    PARITY: Field names match TS SDK MockState.Transaction interface.

    Attributes:
        id: Transaction ID (bytes32 hex string).
        requester: Requester's Ethereum address.
        provider: Provider's Ethereum address.
        amount: Transaction amount in USDC wei (string for precision).
        state: Current transaction state.
        deadline: Unix timestamp deadline.
        dispute_window: Dispute window duration in seconds.
        created_at: Unix timestamp of creation.
        updated_at: Unix timestamp of last update.
        completed_at: Unix timestamp when DELIVERED (None if not delivered).
        escrow_id: Linked escrow ID (if any).
        service_description: Optional service description or hash.
        delivery_proof: Optional delivery proof JSON string.
    """

    id: str
    requester: str
    provider: str
    amount: str
    state: State
    deadline: int
    dispute_window: int
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None
    escrow_id: Optional[str] = None
    service_description: Optional[str] = None
    delivery_proof: Optional[str] = None  # PARITY: TS uses 'deliveryProof'

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "requester": self.requester,
            "provider": self.provider,
            "amount": self.amount,
            "state": self.state.value,
            "deadline": self.deadline,
            "disputeWindow": self.dispute_window,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "completedAt": self.completed_at,
            "escrowId": self.escrow_id,
            "serviceDescription": self.service_description,
            "deliveryProof": self.delivery_proof,  # PARITY: camelCase for JSON
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MockTransaction":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            id=data["id"],
            requester=data["requester"],
            provider=data["provider"],
            amount=data["amount"],
            state=State(data["state"]),
            deadline=data["deadline"],
            dispute_window=data.get("disputeWindow", data.get("dispute_window", 172800)),
            created_at=data.get("createdAt", data.get("created_at", 0)),
            updated_at=data.get("updatedAt", data.get("updated_at", 0)),
            completed_at=data.get("completedAt", data.get("completed_at")),
            escrow_id=data.get("escrowId", data.get("escrow_id")),
            service_description=data.get("serviceDescription", data.get("service_description")),
            # PARITY: Support both old 'proof' and new 'deliveryProof' keys
            delivery_proof=data.get("deliveryProof", data.get("delivery_proof", data.get("proof"))),
        )


@dataclass
class MockEscrow:
    """
    Represents an escrow in the mock runtime.

    Attributes:
        id: Escrow ID.
        tx_id: Linked transaction ID.
        amount: Locked amount in USDC wei.
        created_at: Unix timestamp of creation.
        released: Whether funds have been released.
    """

    id: str
    tx_id: str
    amount: str
    created_at: int
    released: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "txId": self.tx_id,
            "amount": self.amount,
            "createdAt": self.created_at,
            "released": self.released,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MockEscrow":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            id=data["id"],
            tx_id=data.get("txId", data.get("tx_id")),
            amount=data["amount"],
            created_at=data.get("createdAt", data.get("created_at", 0)),
            released=data.get("released", False),
        )


@dataclass
class MockAccount:
    """
    Represents an account balance in the mock runtime.

    Attributes:
        address: Ethereum address.
        balance: USDC balance in wei.
    """

    address: str
    balance: str

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {"address": self.address, "balance": self.balance}

    @classmethod
    def from_dict(cls, data: dict) -> "MockAccount":
        """Create from dictionary (JSON deserialization)."""
        return cls(address=data["address"], balance=data["balance"])


@dataclass
class MockBlockchain:
    """
    Simulated blockchain state for mock runtime.

    Attributes:
        block_number: Current block number.
        timestamp: Current block timestamp.
        block_time: Seconds per block (default 2 for Base L2).
    """

    block_number: int = 0
    timestamp: int = 0
    block_time: int = 2

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "blockNumber": self.block_number,
            "timestamp": self.timestamp,
            "blockTime": self.block_time,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MockBlockchain":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            block_number=data.get("blockNumber", data.get("block_number", 0)),
            timestamp=data.get("timestamp", 0),
            block_time=data.get("blockTime", data.get("block_time", 2)),
        )


@dataclass
class MockEvent:
    """
    Represents an event emitted by the mock runtime.

    Attributes:
        event_type: Event name (e.g., "TransactionCreated").
        tx_id: Related transaction ID.
        data: Event-specific data.
        block_number: Block number when emitted.
        timestamp: Unix timestamp when emitted.
    """

    event_type: str
    tx_id: str
    data: dict
    block_number: int
    timestamp: int

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "eventType": self.event_type,
            "txId": self.tx_id,
            "data": self.data,
            "blockNumber": self.block_number,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MockEvent":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            event_type=data.get("eventType", data.get("event_type")),
            tx_id=data.get("txId", data.get("tx_id")),
            data=data.get("data", {}),
            block_number=data.get("blockNumber", data.get("block_number", 0)),
            timestamp=data.get("timestamp", 0),
        )


@dataclass
class MockState:
    """
    Root state object for the mock runtime.

    This is persisted to `.actp/mock-state.json` and contains
    all transactions, escrows, balances, and events.

    Attributes:
        version: State schema version.
        transactions: Map of transaction ID to transaction.
        escrows: Map of escrow ID to escrow.
        balances: Map of address to balance.
        events: List of emitted events.
        blockchain: Simulated blockchain state.
    """

    version: str = "2.0.0"
    transactions: Dict[str, MockTransaction] = field(default_factory=dict)
    escrows: Dict[str, MockEscrow] = field(default_factory=dict)
    balances: Dict[str, str] = field(default_factory=dict)
    events: List[MockEvent] = field(default_factory=list)
    blockchain: MockBlockchain = field(default_factory=MockBlockchain)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "transactions": {k: v.to_dict() for k, v in self.transactions.items()},
            "escrows": {k: v.to_dict() for k, v in self.escrows.items()},
            "balances": self.balances,
            "events": [e.to_dict() for e in self.events],
            "blockchain": self.blockchain.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MockState":
        """Create from dictionary (JSON deserialization)."""
        return cls(
            version=data.get("version", "2.0.0"),
            transactions={
                k: MockTransaction.from_dict(v) for k, v in data.get("transactions", {}).items()
            },
            escrows={k: MockEscrow.from_dict(v) for k, v in data.get("escrows", {}).items()},
            balances=data.get("balances", {}),
            events=[MockEvent.from_dict(e) for e in data.get("events", [])],
            blockchain=MockBlockchain.from_dict(data.get("blockchain", {})),
        )


def create_default_state() -> MockState:
    """Create a new default mock state with current timestamp."""
    import time

    now = int(time.time())
    return MockState(
        blockchain=MockBlockchain(
            block_number=0,
            timestamp=now,
            block_time=2,
        )
    )


# Default values for mock state configuration
MOCK_STATE_DEFAULTS = {
    "version": "2.0.0",
    "state_directory": ".actp",
    "state_filename": "mock-state.json",
    "default_dispute_window": 172800,  # 2 days
    "default_deadline_hours": 24,
    "min_amount_wei": 50_000,  # $0.05 USDC
    "block_time_seconds": 2,
}
