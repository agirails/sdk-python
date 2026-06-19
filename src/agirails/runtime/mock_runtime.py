"""
Mock runtime implementation for ACTP protocol.

Provides a local, file-based implementation of the ACTP protocol
for development and testing purposes.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable, List, Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from agirails.builders.quote import QuoteMessage

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
        nonce: int,
    ) -> str:
        """
        Generate deterministic transaction ID.

        Includes a per-state nonce so consecutive create calls with
        identical params don't collide — real ACTP IDs are always
        unique per call (derived from blockhash + sender nonce), and
        the mock has to honour the same invariant for property-based
        / stateful tests to be well-defined.
        """
        data = f"{requester}{provider}{amount}{deadline}{timestamp}{nonce}"
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

            # Generate transaction ID with a per-state monotonic nonce
            # (count of existing txs) so two creates with identical
            # params + same blockchain timestamp don't produce the same
            # ID — real on-chain IDs are unique per call.
            tx_id = self._generate_tx_id(
                params.requester,
                params.provider,
                params.amount,
                params.deadline,
                current_time,
                len(state.transactions),
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
            current_time = state.blockchain.timestamp

            # Update transaction
            tx.state = new_state
            tx.updated_at = current_time

            # Set completed_at when transitioning to DELIVERED (parity with TS SDK).
            # PROOF GUARD (PARITY: MockRuntime.ts:724-732): only store the delivery
            # proof on the DELIVERED transition, and ONLY if not already set. The
            # Agent writes the real delivery proof BEFORE transitioning and passes
            # the dispute-window proof as the `proof` arg — overwriting (or storing
            # proof on a non-DELIVERED transition like DISPUTED) would clobber the
            # real proof.
            if new_state == State.DELIVERED:
                tx.completed_at = current_time
                if proof and not tx.delivery_proof:
                    tx.delivery_proof = proof  # PARITY: TS uses 'deliveryProof'

            # Handle escrow refund on CANCELLED state.
            # PARITY: MockRuntime.ts:734-773 — refund the requester, zero out
            # the escrow, and emit EscrowRefunded. The Python escrow model uses
            # `amount` + `released` (vs TS `balance`/`locked`); an un-released
            # escrow whose amount > 0 is the effective live balance.
            if new_state == State.CANCELLED and tx.escrow_id is not None:
                escrow = state.escrows.get(tx.escrow_id)
                if escrow is not None and not escrow.released and int(escrow.amount) > 0:
                    refund_amount = int(escrow.amount)

                    # Return funds to requester (create the balance slot if absent)
                    requester_key = tx.requester.lower()
                    requester_balance = int(state.balances.get(requester_key, "0"))
                    state.balances[requester_key] = str(requester_balance + refund_amount)

                    # Clear escrow balance (released=True ⇒ get_escrow_balance → "0",
                    # mirroring TS clearing escrow.balance to '0' and locked=False).
                    escrow.released = True

                    # Record EscrowRefunded event (TS MockEvent shape)
                    self._emit_event(
                        state,
                        "EscrowRefunded",
                        tx_id,
                        {
                            "escrowId": tx.escrow_id,
                            "requester": tx.requester,
                            "amount": str(refund_amount),
                        },
                    )

            # Emit event
            self._emit_event(
                state,
                "StateTransitioned",
                tx_id,
                {"from": old_state, "to": new_state.value, "proof": proof},
            )

            return state

        await self._state_manager.with_lock(transition)

    async def accept_quote(self, tx_id: str, new_amount: str) -> None:
        """
        Accept a provider's quote, updating the transaction amount.

        Mirrors on-chain acceptQuote() behavior:
        - Requires QUOTED state
        - Updates amount to new_amount
        - Does NOT change state (stays QUOTED)
        - Emits QuoteAccepted event

        Args:
            tx_id: Transaction ID.
            new_amount: New amount in USDC wei.

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If not in QUOTED state.
            InvalidAmountError: If amount is invalid.
            DeadlinePassedError: If deadline has passed.
        """
        await self._ensure_initialized()

        async def accept(state: MockState) -> MockState:
            tx = state.transactions.get(tx_id)
            if tx is None:
                raise TransactionNotFoundError(tx_id)

            # Must be in QUOTED state
            if tx.state != State.QUOTED:
                raise InvalidStateTransitionError(
                    tx.state.value,
                    State.QUOTED.value,
                    tx_id=tx_id,
                )

            # Validate amount
            try:
                amount_int = int(new_amount)
            except ValueError:
                raise InvalidAmountError(new_amount, reason="Invalid number format")

            if amount_int <= 0:
                raise InvalidAmountError(new_amount, reason="Amount must be positive")

            # Check deadline
            current_time = state.blockchain.timestamp
            if current_time > tx.deadline:
                raise DeadlinePassedError(tx.deadline, current_time)

            old_amount = tx.amount

            # Update amount (state stays QUOTED)
            tx.amount = new_amount
            tx.updated_at = current_time

            # Emit QuoteAccepted event
            self._emit_event(
                state,
                "QuoteAccepted",
                tx_id,
                {
                    "oldAmount": old_amount,
                    "newAmount": new_amount,
                },
            )

            await self._state_manager.save(state)
            return state

        await self._state_manager.with_lock(accept)

    async def submit_quote(self, tx_id: str, quote: "QuoteMessage") -> None:
        """Submit an AIP-2 price quote: INITIATED → QUOTED with the canonical
        quote hash stored on the transaction.

        PARITY: MockRuntime.ts:862-890. AIP-2.1 designates this as the only
        sanctioned entry point for reaching QUOTED. The canonical hash is
        ``keccak256`` of the verifier-authoritative QuoteMessage shape
        (signature stripped) — reuses the ported :class:`QuoteBuilder`
        ``compute_hash`` so mock-mode buyers run the exact cross-reference
        check they'd run against on-chain anchored quote metadata.

        Raw ``transition_state(tx_id, 'QUOTED', custom_proof)`` still works
        for backward compatibility but produces a hash the buyer-side
        verifier cannot reconstruct from the QuoteMessage (legacy path).

        Args:
            tx_id: Transaction ID (must be in INITIATED state).
            quote: The signer-independent ``QuoteMessage`` to anchor.

        Raises:
            TransactionNotFoundError: If transaction doesn't exist.
            InvalidStateTransitionError: If not in INITIATED state.
        """
        await self._ensure_initialized()

        # Compute the canonical hash off the verifier-authoritative shape.
        # compute_hash is signer-independent (strips the signature before
        # hashing) so a no-arg builder yields the same hash any verifier
        # computes. PARITY: MockRuntime.ts:867-868.
        from agirails.builders.quote import QuoteBuilder

        quote_hash = QuoteBuilder().compute_hash(quote)

        async def stamp(state: MockState) -> MockState:
            tx = state.transactions.get(tx_id)
            if tx is None:
                raise TransactionNotFoundError(tx_id)
            if tx.state != State.INITIATED:
                raise InvalidStateTransitionError(
                    tx.state.value,
                    State.QUOTED.value,
                    tx_id=tx_id,
                )
            tx.quote_hash = quote_hash
            return state

        await self._state_manager.with_lock(stamp)

        # transition_state handles the actual state bump + event emission.
        # Passing the hash as `proof` for parity with BlockchainRuntime where
        # the kernel reads the same bytes. PARITY: MockRuntime.ts:889.
        await self.transition_state(tx_id, State.QUOTED, quote_hash)

    async def get_transaction(self, tx_id: str) -> Optional[MockTransaction]:
        """Get a transaction by ID.

        AUTO-RELEASE: If the transaction is DELIVERED and its dispute window has
        passed, it is automatically settled before being returned ("lazy
        auto-release"). PARITY: MockRuntime.ts:525-532.
        """
        await self._ensure_initialized()
        # First, check if auto-settle is needed (lazy auto-release).
        await self._auto_settle_if_ready(tx_id)
        # Then return the (possibly updated) transaction.
        state = await self._state_manager.load()
        return state.transactions.get(tx_id)

    async def _auto_settle_if_ready(self, tx_id: str) -> None:
        """Auto-settle a DELIVERED transaction whose dispute window has expired.

        When anyone reads a DELIVERED transaction with an expired dispute window
        and a linked escrow, it is settled atomically. Mirrors the on-chain
        permissionless settlement window. PARITY: MockRuntime.ts:542-565.

        Pre-checks without the lock to avoid unnecessary lock acquisition; the
        actual settlement re-validates state inside ``release_escrow``'s lock,
        so a concurrent state change (already settled / disputed) is safely
        ignored.
        """
        precheck = await self._state_manager.load()
        pre_tx = precheck.transactions.get(tx_id)
        if pre_tx is None or pre_tx.state != State.DELIVERED:
            return
        # completed_at is set on the DELIVERED transition; fall back to
        # updated_at for parity with release_escrow's window math.
        completed_at = (
            pre_tx.completed_at if pre_tx.completed_at is not None else pre_tx.updated_at
        )
        if precheck.blockchain.timestamp < completed_at + pre_tx.dispute_window:
            return
        if not pre_tx.escrow_id:
            return

        # Settle atomically; release_escrow re-checks state under the lock.
        try:
            await self.release_escrow(pre_tx.escrow_id)
        except Exception:
            # Already settled, disputed, window edge race, or other concurrent
            # change — ignore. PARITY: MockRuntime.ts:562-564.
            pass

    async def get_all_transactions(
        self,
        from_block: int | None = None,
        limit: int = 100,
    ) -> List[MockTransaction]:
        """Get all transactions (from_block ignored in mock — in-memory)."""
        await self._ensure_initialized()
        state = await self._state_manager.load()
        txs = list(state.transactions.values())
        return txs[-limit:] if len(txs) > limit else txs

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

    async def sweep_expired_delivered_for_provider(self, provider_address: str) -> None:
        """
        Sweep all expired DELIVERED transactions for a provider.
        Called by SettleOnInteract when operating on MockRuntime.

        Args:
            provider_address: Provider address to sweep for.
        """
        txs = await self.get_transactions_by_provider(provider_address, State.DELIVERED)
        for tx in txs:
            # Find the escrow linked to this transaction
            mock_state = await self._state_manager.load()
            for esc_id, esc in mock_state.escrows.items():
                if esc.tx_id == tx.id and not esc.released:
                    try:
                        await self.release_escrow(esc_id)
                    except Exception:
                        pass  # Already settled or window still active
                    break

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

            # Check dispute window (use completed_at for DELIVERED state)
            current_time = state.blockchain.timestamp
            completed_at = tx.completed_at if tx.completed_at is not None else tx.updated_at
            window_end = completed_at + tx.dispute_window
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

    async def transfer(self, from_addr: str, to_addr: str, amount: str) -> None:
        """Transfer USDC tokens between addresses.

        PARITY: MockRuntime.ts:1215-1262. Debits ``from_addr``, credits
        ``to_addr`` (creating the slot if absent) and emits a ``Transfer``
        event. Balances are keyed by lowercased address in the Python state
        model (vs the TS ``accounts[addr].usdcBalance`` map) — semantically
        identical.

        Args:
            from_addr: Sender address.
            to_addr: Recipient address.
            amount: Amount to transfer in USDC wei (string).

        Raises:
            InsufficientBalanceError: If the sender has insufficient funds.
        """
        await self._ensure_initialized()

        async def do_transfer(state: MockState) -> MockState:
            from_key = from_addr.lower()
            to_key = to_addr.lower()
            from_balance = int(state.balances.get(from_key, "0"))
            transfer_amount = int(amount)

            if from_balance < transfer_amount:
                raise InsufficientBalanceError(
                    from_addr,
                    transfer_amount,
                    from_balance,
                )

            state.balances[from_key] = str(from_balance - transfer_amount)
            to_balance = int(state.balances.get(to_key, "0"))
            state.balances[to_key] = str(to_balance + transfer_amount)

            self._emit_event(
                state,
                "Transfer",
                "",
                {"from": from_addr, "to": to_addr, "amount": amount},
            )

            return state

        await self._state_manager.with_lock(do_transfer)

    async def get_state(self) -> MockState:
        """Get the complete mock state snapshot.

        PARITY: MockRuntime.ts:1284-1286 (getState). Returns the current
        ``MockState`` loaded from the state file. Async because the Python
        state model is file-backed.
        """
        await self._ensure_initialized()
        return await self._state_manager.load()

    @property
    def events(self) -> "_MockEventAccessor":
        """Event access interface.

        PARITY: MockRuntime.ts:320-329 / 351-361. Exposes ``get_all()``,
        ``get_by_type(type)``, ``get_by_transaction(tx_id)`` and ``clear()``.
        Methods are async because the Python event log is persisted in the
        state file (vs the TS in-memory ``eventLog``).
        """
        return _MockEventAccessor(self)


class _MockEventAccessor:
    """Async accessor for the MockRuntime persisted event log.

    PARITY: MockRuntime.ts events interface (getAll / getByType /
    getByTransaction / clear).
    """

    def __init__(self, runtime: "MockRuntime") -> None:
        self._runtime = runtime

    async def get_all(self) -> List["MockEvent"]:
        """Return all recorded events."""
        await self._runtime._ensure_initialized()
        state = await self._runtime._state_manager.load()
        return list(state.events)

    async def get_by_type(self, event_type: str) -> List["MockEvent"]:
        """Return events filtered by event type."""
        await self._runtime._ensure_initialized()
        state = await self._runtime._state_manager.load()
        return [e for e in state.events if e.event_type == event_type]

    async def get_by_transaction(self, tx_id: str) -> List["MockEvent"]:
        """Return events recorded for a specific transaction."""
        await self._runtime._ensure_initialized()
        state = await self._runtime._state_manager.load()
        return [e for e in state.events if e.tx_id == tx_id]

    async def clear(self) -> None:
        """Clear all recorded events."""
        await self._runtime._ensure_initialized()

        async def _clear(state: MockState) -> MockState:
            state.events = []
            return state

        await self._runtime._state_manager.with_lock(_clear)
