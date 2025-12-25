"""
Mock runtime implementation for ACTP protocol.

Provides a local, file-based implementation of the ACTP protocol
for development and testing purposes.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable, List, Optional, Union

from agirails.errors import (
    TransactionNotFoundError,
    InvalidStateTransitionError,
    EscrowNotFoundError,
    DeadlinePassedError,
    DisputeWindowActiveError,
    InsufficientBalanceError,
    InvalidAmountError,
    QueryCapExceededError,
)
from agirails.runtime.base import CreateTransactionParams, IMockRuntime
from agirails.runtime.mock_state_manager import MockStateManager
from agirails.runtime.types import (
    State,
    MockState,
    MockTransaction,
    MockEscrow,
    MockEvent,
    is_valid_transition,
    STATE_TRANSITIONS,
    MOCK_STATE_DEFAULTS,
)


class MockTimeManager:
    """
    Time management for mock runtime.

    Provides time manipulation methods for testing scenarios.
    """

    def __init__(self, state_manager: MockStateManager) -> None:
        self._state_manager = state_manager
        self._cached_timestamp: Optional[int] = None

    def now(self) -> int:
        """
        Get current timestamp.

        Returns cached timestamp if available, otherwise uses system time.
        """
        if self._cached_timestamp is not None:
            return self._cached_timestamp

        return int(time.time())

    def _set_cached_time(self, timestamp: int) -> None:
        """Set cached timestamp (internal use)."""
        self._cached_timestamp = timestamp

    async def advance_time(self, seconds: int) -> None:
        """
        Advance time by specified seconds.

        Args:
            seconds: Number of seconds to advance (must be positive).
        """
        if seconds < 0:
            raise ValueError("Cannot advance time by negative seconds")

        async def update(state: MockState) -> MockState:
            new_timestamp = state.blockchain.timestamp + seconds
            state.blockchain.timestamp = new_timestamp
            state.blockchain.block_number += seconds // state.blockchain.block_time
            self._set_cached_time(new_timestamp)
            return state

        await self._state_manager.with_lock(update)

    async def advance_blocks(self, blocks: int) -> None:
        """
        Advance time by specified blocks.

        Args:
            blocks: Number of blocks to advance (must be positive).
        """
        if blocks < 0:
            raise ValueError("Cannot advance by negative blocks")

        async def update(state: MockState) -> MockState:
            seconds = blocks * state.blockchain.block_time
            state.blockchain.timestamp += seconds
            state.blockchain.block_number += blocks
            self._set_cached_time(state.blockchain.timestamp)
            return state

        await self._state_manager.with_lock(update)

    async def set_time(self, timestamp: int) -> None:
        """
        Set exact timestamp.

        Args:
            timestamp: New Unix timestamp (must be >= current time).

        Raises:
            ValueError: If timestamp is less than current time.
        """
        current = self.now()
        if timestamp < current:
            raise ValueError(
                f"Cannot set time to past: {timestamp} < {current}"
            )

        async def update(state: MockState) -> MockState:
            state.blockchain.timestamp = timestamp
            self._set_cached_time(timestamp)
            return state

        await self._state_manager.with_lock(update)

    async def _sync_from_state(self, state: MockState) -> None:
        """Sync cached time from loaded state."""
        self._cached_timestamp = state.blockchain.timestamp


class MockRuntime(IMockRuntime):
    """
    Mock runtime implementation for ACTP protocol.

    Provides a file-based implementation for local development
    and testing. State is persisted to `.actp/mock-state.json`.

    Example:
        >>> runtime = MockRuntime()
        >>> await runtime.mint_tokens("0xRequester...", "1000000000")
        >>>
        >>> tx_id = await runtime.create_transaction(
        ...     CreateTransactionParams(
        ...         provider="0xProvider...",
        ...         requester="0xRequester...",
        ...         amount="100000000",
        ...         deadline=int(time.time()) + 86400,
        ...     )
        ... )
        >>>
        >>> escrow_id = await runtime.link_escrow(tx_id, "100000000")
        >>> await runtime.transition_state(tx_id, State.DELIVERED)
        >>> await runtime.time.advance_time(172800)  # 2 days
        >>> await runtime.release_escrow(escrow_id)
    """

    def __init__(
        self,
        state_directory: Optional[Union[str, Path]] = None,
        state_manager: Optional[MockStateManager] = None,
    ) -> None:
        """
        Initialize MockRuntime.

        Args:
            state_directory: Directory for state file (default: .actp in cwd).
            state_manager: Optional pre-configured state manager.
        """
        if state_manager is not None:
            self._state_manager = state_manager
        else:
            self._state_manager = MockStateManager(state_directory)

        self._time = MockTimeManager(self._state_manager)
        self._initialized = False

    @property
    def time(self) -> MockTimeManager:
        """Time management interface."""
        return self._time

    async def _ensure_initialized(self) -> None:
        """Ensure runtime is initialized by loading state once."""
        if not self._initialized:
            state = await self._state_manager.load()
            await self._time._sync_from_state(state)
            self._initialized = True

    def _generate_tx_id(
        self,
        requester: str,
        provider: str,
        amount: str,
        deadline: int,
        timestamp: int,
    ) -> str:
        """
        Generate deterministic transaction ID.

        Uses keccak256-like hashing for compatibility with on-chain IDs.
        """
        data = f"{requester}{provider}{amount}{deadline}{timestamp}"
        hash_bytes = hashlib.sha256(data.encode()).digest()
        return "0x" + hash_bytes.hex()

    def _emit_event(
        self,
        state: MockState,
        event_type: str,
        tx_id: str,
        data: dict,
    ) -> None:
        """Add event to state."""
        event = MockEvent(
            event_type=event_type,
            tx_id=tx_id,
            data=data,
            block_number=state.blockchain.block_number,
            timestamp=state.blockchain.timestamp,
        )
        state.events.append(event)

    async def create_transaction(self, params: CreateTransactionParams) -> str:
        """
        Create a new transaction.

        Args:
            params: Transaction creation parameters.

        Returns:
            Transaction ID (bytes32 hex string).

        Raises:
            DeadlinePassedError: If deadline is in the past.
            InvalidAmountError: If amount is zero, negative, or below minimum.
        """
        await self._ensure_initialized()

        async def create(state: MockState) -> str:
            current_time = state.blockchain.timestamp

            # Validate deadline
            if params.deadline <= current_time:
                raise DeadlinePassedError(
                    params.deadline,
                    current_time,
                )

            # Validate amount
            try:
                amount_int = int(params.amount)
            except ValueError:
                raise InvalidAmountError(params.amount, reason="Invalid number format")

            if amount_int <= 0:
                raise InvalidAmountError(params.amount, reason="Amount must be positive")

            min_amount = MOCK_STATE_DEFAULTS["min_amount_wei"]
            if amount_int < min_amount:
                raise InvalidAmountError(
                    params.amount,
                    reason=f"Amount below minimum (${min_amount / 1_000_000:.2f} USDC)",
                    min_amount=min_amount,
                )

            # Generate transaction ID
            tx_id = self._generate_tx_id(
                params.requester,
                params.provider,
                params.amount,
                params.deadline,
                current_time,
            )

            # Create transaction
            tx = MockTransaction(
                id=tx_id,
                requester=params.requester.lower(),
                provider=params.provider.lower(),
                amount=params.amount,
                state=State.INITIATED,
                deadline=params.deadline,
                dispute_window=params.dispute_window,
                created_at=current_time,
                updated_at=current_time,
                service_description=params.service_description,
            )

            state.transactions[tx_id] = tx

            # Emit event
            self._emit_event(
                state,
                "TransactionCreated",
                tx_id,
                {
                    "requester": params.requester,
                    "provider": params.provider,
                    "amount": params.amount,
                    "deadline": params.deadline,
                },
            )

            # Save state and return tx_id
            await self._state_manager.save(state)
            return tx_id

        return await self._state_manager.with_lock(create)

    async def link_escrow(self, tx_id: str, amount: str) -> str:
        """
        Link an escrow to a transaction and lock funds.

        Automatically transitions INITIATED or QUOTED -> COMMITTED.

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
        await self._ensure_initialized()

        async def link(state: MockState) -> str:
            # Get transaction
            tx = state.transactions.get(tx_id)
            if tx is None:
                raise TransactionNotFoundError(tx_id)

            # Validate state
            if tx.state not in (State.INITIATED, State.QUOTED):
                raise InvalidStateTransitionError(
                    tx.state.value,
                    State.COMMITTED.value,
                    tx_id=tx_id,
                    allowed_transitions=[s.value for s in STATE_TRANSITIONS.get(tx.state, [])],
                )

            # Check requester balance
            requester_balance = int(state.balances.get(tx.requester.lower(), "0"))
            amount_int = int(amount)

            if requester_balance < amount_int:
                raise InsufficientBalanceError(
                    tx.requester,
                    amount_int,
                    requester_balance,
                )

            # Deduct from requester
            state.balances[tx.requester.lower()] = str(requester_balance - amount_int)

            # Create escrow (using tx_id as escrow_id for simplicity)
            escrow_id = tx_id
            escrow = MockEscrow(
                id=escrow_id,
                tx_id=tx_id,
                amount=amount,
                created_at=state.blockchain.timestamp,
            )
            state.escrows[escrow_id] = escrow

            # Update transaction
            tx.escrow_id = escrow_id
            tx.state = State.COMMITTED
            tx.updated_at = state.blockchain.timestamp

            # Emit events
            self._emit_event(
                state,
                "EscrowLinked",
                tx_id,
                {"escrowId": escrow_id, "amount": amount},
            )
            self._emit_event(
                state,
                "StateTransitioned",
                tx_id,
                {"from": "INITIATED", "to": "COMMITTED"},
            )

            await self._state_manager.save(state)
            return escrow_id

        return await self._state_manager.with_lock(link)

    async def transition_state(
        self,
        tx_id: str,
        new_state: Union[State, str],
        proof: Optional[str] = None,
    ) -> None:
        """
        Transition a transaction to a new state.

        Args:
            tx_id: Transaction ID.
            new_state: Target state.
            proof: Optional proof data (used for DELIVERED state).

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If transition is not valid.
        """
        await self._ensure_initialized()

        if isinstance(new_state, str):
            new_state = State(new_state)

        async def transition(state: MockState) -> MockState:
            tx = state.transactions.get(tx_id)
            if tx is None:
                raise TransactionNotFoundError(tx_id)

            # Validate transition
            if not is_valid_transition(tx.state, new_state):
                raise InvalidStateTransitionError(
                    tx.state.value,
                    new_state.value,
                    tx_id=tx_id,
                    allowed_transitions=[s.value for s in STATE_TRANSITIONS.get(tx.state, [])],
                )

            old_state = tx.state.value

            # Update transaction
            tx.state = new_state
            tx.updated_at = state.blockchain.timestamp
            if proof:
                tx.proof = proof

            # Emit event
            self._emit_event(
                state,
                "StateTransitioned",
                tx_id,
                {"from": old_state, "to": new_state.value, "proof": proof},
            )

            return state

        await self._state_manager.with_lock(transition)

    async def get_transaction(self, tx_id: str) -> Optional[MockTransaction]:
        """Get a transaction by ID."""
        await self._ensure_initialized()
        state = await self._state_manager.load()
        return state.transactions.get(tx_id)

    async def get_all_transactions(self) -> List[MockTransaction]:
        """Get all transactions."""
        await self._ensure_initialized()
        state = await self._state_manager.load()
        return list(state.transactions.values())

    async def get_transactions_by_provider(
        self,
        provider: str,
        state: Optional[Union[State, str]] = None,
        limit: int = 100,
    ) -> List[MockTransaction]:
        """
        Get transactions for a specific provider with filtering.

        Security measure (H-1) - uses filtered queries with limit.

        Args:
            provider: Provider address to filter by.
            state: Optional state to filter by.
            limit: Maximum number of results (default 100, max 1000).

        Returns:
            List of matching transactions.

        Raises:
            QueryCapExceededError: If limit exceeds maximum.
        """
        await self._ensure_initialized()

        max_limit = 1000
        if limit > max_limit:
            raise QueryCapExceededError(limit, max_limit, query_type="transactions")

        state_filter = state

        mock_state = await self._state_manager.load()
        provider_lower = provider.lower()

        if isinstance(state_filter, str):
            state_filter = State(state_filter)

        results: List[MockTransaction] = []
        for tx in mock_state.transactions.values():
            if tx.provider.lower() == provider_lower:
                if state_filter is None or tx.state == state_filter:
                    results.append(tx)
                    if len(results) >= limit:
                        break

        return results

    async def release_escrow(
        self,
        escrow_id: str,
        attestation_uid: Optional[str] = None,
    ) -> None:
        """
        Release escrow funds to the provider.

        Args:
            escrow_id: Escrow ID.
            attestation_uid: Optional attestation UID (for blockchain mode).

        Raises:
            EscrowNotFoundError: If escrow doesn't exist.
            TransactionNotFoundError: If linked transaction doesn't exist.
            InvalidStateTransitionError: If transaction not in DELIVERED state.
            DisputeWindowActiveError: If dispute window still active.
        """
        await self._ensure_initialized()

        async def release(state: MockState) -> MockState:
            # Get escrow
            escrow = state.escrows.get(escrow_id)
            if escrow is None:
                raise EscrowNotFoundError(escrow_id)

            # Get linked transaction
            tx = state.transactions.get(escrow.tx_id)
            if tx is None:
                raise TransactionNotFoundError(escrow.tx_id)

            # Validate state
            if tx.state != State.DELIVERED:
                raise InvalidStateTransitionError(
                    tx.state.value,
                    State.SETTLED.value,
                    tx_id=escrow.tx_id,
                )

            # Check dispute window
            current_time = state.blockchain.timestamp
            window_end = tx.updated_at + tx.dispute_window
            if current_time < window_end:
                remaining = window_end - current_time
                raise DisputeWindowActiveError(
                    remaining,
                    escrow_id=escrow_id,
                    tx_id=escrow.tx_id,
                )

            # Transfer funds to provider
            provider_balance = int(state.balances.get(tx.provider.lower(), "0"))
            provider_balance += int(escrow.amount)
            state.balances[tx.provider.lower()] = str(provider_balance)

            # Mark escrow as released
            escrow.released = True

            # Transition to SETTLED
            tx.state = State.SETTLED
            tx.updated_at = current_time

            # Emit events
            self._emit_event(
                state,
                "EscrowReleased",
                escrow.tx_id,
                {"escrowId": escrow_id, "amount": escrow.amount, "to": tx.provider},
            )
            self._emit_event(
                state,
                "StateTransitioned",
                escrow.tx_id,
                {"from": "DELIVERED", "to": "SETTLED"},
            )

            return state

        await self._state_manager.with_lock(release)

    async def get_escrow_balance(self, escrow_id: str) -> str:
        """Get the balance of an escrow."""
        await self._ensure_initialized()
        state = await self._state_manager.load()

        escrow = state.escrows.get(escrow_id)
        if escrow is None:
            raise EscrowNotFoundError(escrow_id)

        if escrow.released:
            return "0"

        return escrow.amount

    async def reset(self) -> None:
        """Reset state to default."""
        await self._state_manager.reset()
        self._initialized = False

    async def mint_tokens(self, address: str, amount: str) -> None:
        """
        Mint tokens to an address.

        Args:
            address: Address to mint tokens to.
            amount: Amount to mint in USDC wei.
        """
        await self._ensure_initialized()

        async def mint(state: MockState) -> MockState:
            address_lower = address.lower()
            current_balance = int(state.balances.get(address_lower, "0"))
            new_balance = current_balance + int(amount)
            state.balances[address_lower] = str(new_balance)

            self._emit_event(
                state,
                "TokensMinted",
                "",
                {"to": address, "amount": amount},
            )

            return state

        await self._state_manager.with_lock(mint)

    async def get_balance(self, address: str) -> str:
        """Get balance of an address."""
        await self._ensure_initialized()
        state = await self._state_manager.load()
        return state.balances.get(address.lower(), "0")
