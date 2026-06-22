"""
Event monitoring for ACTP protocol contracts.

Provides async methods for subscribing to and processing blockchain events
from ACTPKernel and EscrowVault contracts.

Example:
    >>> from web3 import AsyncWeb3
    >>> from agirails.protocol import EventMonitor
    >>> from agirails.config import get_network
    >>>
    >>> config = get_network("base-sepolia")
    >>> w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config.rpc_url))
    >>> monitor = EventMonitor.from_config(w3, config)
    >>>
    >>> # Subscribe to transaction events
    >>> async for event in monitor.watch_transactions(requester="0x..."):
    ...     print(f"Transaction {event.transaction_id}: {event.event_type}")
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Union

from web3 import AsyncWeb3
from web3.contract import AsyncContract
from web3.types import LogReceipt

try:  # web3 v6/v7 expose these; guard the import so older shims don't break.
    from web3.exceptions import (  # type: ignore
        ABIEventNotFound,
        MismatchedABI,
        NoABIEventsFound,
    )

    # "Event genuinely not in the ABI" errors — the ONLY class of failure the
    # per-event guards below are allowed to swallow. Real RPC / range-exhaustion
    # errors must propagate. PARITY intent: do not silently drop real errors.
    _ABI_EVENT_MISSING_ERRORS: tuple = (
        NoABIEventsFound,
        ABIEventNotFound,
        MismatchedABI,
    )
except Exception:  # pragma: no cover - defensive for ABI-error import drift
    _ABI_EVENT_MISSING_ERRORS = (AttributeError,)

from agirails.config.networks import NetworkConfig
from agirails.types.transaction import TransactionState


# ============================================================================
# Event Types
# ============================================================================


class EventType(str, Enum):
    """Types of events emitted by ACTP contracts."""

    # ACTPKernel events
    TRANSACTION_CREATED = "TransactionCreated"
    STATE_TRANSITIONED = "StateTransitioned"
    ESCROW_LINKED = "EscrowLinked"
    ESCROW_RELEASED = "EscrowReleased"
    ATTESTATION_ANCHORED = "AttestationAnchored"
    MILESTONE_RELEASED = "MilestoneReleased"

    # EscrowVault events
    ESCROW_CREATED = "EscrowCreated"
    ESCROW_PAYOUT = "EscrowPayout"
    ESCROW_COMPLETED = "EscrowCompleted"

    # Dispute events (PRD P2-5 / AIP-14b §3.4)
    DISPUTE_SPLIT_RECORDED = "DisputeSplitRecorded"  # CompositeMediator
    UMA_DISPUTE_ESCALATED = "UMADisputeEscalated"  # BondEscalation


@dataclass
class ACTPEvent:
    """
    Base class for ACTP protocol events.

    Attributes:
        event_type: The type of event
        contract_address: The emitting contract address
        block_number: Block where event was emitted
        transaction_hash: Transaction that emitted the event
        log_index: Log index within the transaction
        timestamp: Event timestamp (if available)
        raw_data: Raw event data
    """

    event_type: EventType
    contract_address: str
    block_number: int
    transaction_hash: str
    log_index: int
    timestamp: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "eventType": self.event_type.value,
            "contractAddress": self.contract_address,
            "blockNumber": self.block_number,
            "transactionHash": self.transaction_hash,
            "logIndex": self.log_index,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "rawData": self.raw_data,
        }


@dataclass
class TransactionCreatedEvent(ACTPEvent):
    """Event emitted when a new transaction is created."""

    transaction_id: str = ""
    requester: str = ""
    provider: str = ""
    amount: int = 0
    deadline: int = 0
    dispute_window: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "transactionId": self.transaction_id,
                "requester": self.requester,
                "provider": self.provider,
                "amount": self.amount,
                "deadline": self.deadline,
                "disputeWindow": self.dispute_window,
            }
        )
        return base


@dataclass
class StateTransitionedEvent(ACTPEvent):
    """Event emitted when a transaction state changes."""

    transaction_id: str = ""
    previous_state: Optional[TransactionState] = None
    new_state: Optional[TransactionState] = None
    actor: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "transactionId": self.transaction_id,
                "previousState": self.previous_state.name if self.previous_state else None,
                "newState": self.new_state.name if self.new_state else None,
                "actor": self.actor,
            }
        )
        return base


@dataclass
class EscrowLinkedEvent(ACTPEvent):
    """Event emitted when an escrow is linked to a transaction."""

    transaction_id: str = ""
    escrow_contract: str = ""
    escrow_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "transactionId": self.transaction_id,
                "escrowContract": self.escrow_contract,
                "escrowId": self.escrow_id,
            }
        )
        return base


@dataclass
class EscrowCreatedEvent(ACTPEvent):
    """Event emitted when a new escrow is created."""

    escrow_id: str = ""
    requester: str = ""
    provider: str = ""
    amount: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "escrowId": self.escrow_id,
                "requester": self.requester,
                "provider": self.provider,
                "amount": self.amount,
            }
        )
        return base


@dataclass
class EscrowPayoutEvent(ACTPEvent):
    """Event emitted when escrow funds are released."""

    escrow_id: str = ""
    recipient: str = ""
    amount: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "escrowId": self.escrow_id,
                "recipient": self.recipient,
                "amount": self.amount,
            }
        )
        return base


@dataclass
class DisputeSplitRecordedEvent(ACTPEvent):
    """CompositeMediator ruling-2 trace (AIP-14b §3.4). PARITY: TS DisputeEvent."""

    tx_id: str = ""
    requester: str = ""
    provider: str = ""
    split_bps: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "txId": self.tx_id,
                "requester": self.requester,
                "provider": self.provider,
                "splitBps": self.split_bps,
            }
        )
        return base


@dataclass
class UMADisputeEscalatedEvent(ACTPEvent):
    """BondEscalation Tier-2 assertion pushed to UMA DVM (AIP-14b §8.5)."""

    dispute_id: str = ""
    assertion_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "disputeId": self.dispute_id,
                "assertionId": self.assertion_id,
            }
        )
        return base


# Event type mapping
EVENT_CLASSES = {
    EventType.TRANSACTION_CREATED: TransactionCreatedEvent,
    EventType.STATE_TRANSITIONED: StateTransitionedEvent,
    EventType.ESCROW_LINKED: EscrowLinkedEvent,
    EventType.ESCROW_CREATED: EscrowCreatedEvent,
    EventType.ESCROW_PAYOUT: EscrowPayoutEvent,
    EventType.DISPUTE_SPLIT_RECORDED: DisputeSplitRecordedEvent,
    EventType.UMA_DISPUTE_ESCALATED: UMADisputeEscalatedEvent,
}


# ============================================================================
# Event Filter
# ============================================================================


@dataclass
class EventFilter:
    """
    Filter for event queries.

    Attributes:
        event_types: Filter by event types
        transaction_id: Filter by transaction ID
        escrow_id: Filter by escrow ID
        requester: Filter by requester address
        provider: Filter by provider address
        from_block: Starting block number
        to_block: Ending block number
    """

    event_types: Optional[List[EventType]] = None
    transaction_id: Optional[str] = None
    escrow_id: Optional[str] = None
    requester: Optional[str] = None
    provider: Optional[str] = None
    from_block: Optional[int] = None
    to_block: Optional[int] = None


# ============================================================================
# Event Monitor
# ============================================================================


class EventMonitor:
    """
    Monitor for ACTP protocol events.

    Provides methods for querying historical events and watching
    for new events in real-time.

    Attributes:
        kernel_contract: The ACTPKernel contract instance
        escrow_contract: The EscrowVault contract instance
        w3: The AsyncWeb3 instance
    """

    def __init__(
        self,
        kernel_contract: AsyncContract,
        escrow_contract: AsyncContract,
        w3: AsyncWeb3,
        mediator_contract: Optional[AsyncContract] = None,
        bond_escalation_contract: Optional[AsyncContract] = None,
    ) -> None:
        """
        Initialize EventMonitor.

        Args:
            kernel_contract: The ACTPKernel contract instance
            escrow_contract: The EscrowVault contract instance
            w3: The AsyncWeb3 instance
            mediator_contract: Optional CompositeMediator (for DisputeSplitRecorded)
            bond_escalation_contract: Optional BondEscalation (for UMADisputeEscalated)
        """
        self.kernel_contract = kernel_contract
        self.escrow_contract = escrow_contract
        self.w3 = w3
        self.mediator_contract = mediator_contract
        self.bond_escalation_contract = bond_escalation_contract

    @classmethod
    def from_config(
        cls,
        w3: AsyncWeb3,
        config: NetworkConfig,
    ) -> "EventMonitor":
        """
        Create EventMonitor from network configuration.

        Args:
            w3: The AsyncWeb3 instance
            config: Network configuration with contract addresses

        Returns:
            Initialized EventMonitor instance

        Example:
            >>> config = get_network("base-sepolia")
            >>> monitor = EventMonitor.from_config(w3, config)
        """
        kernel_abi = cls._load_abi("actp_kernel.json")
        escrow_abi = cls._load_abi("escrow_vault.json")

        kernel_contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.actp_kernel),
            abi=kernel_abi,
        )

        escrow_contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.escrow_vault),
            abi=escrow_abi,
        )

        return cls(kernel_contract, escrow_contract, w3)

    @staticmethod
    def _load_abi(filename: str) -> List[Dict[str, Any]]:
        """Load an ABI from the abis directory."""
        abi_path = Path(__file__).parent.parent / "abis" / filename
        with open(abi_path) as f:
            return json.load(f)

    # =========================================================================
    # Historical Events
    # =========================================================================

    async def get_events(
        self,
        event_filter: Optional[EventFilter] = None,
        from_block: Union[int, str] = "earliest",
        to_block: Union[int, str] = "latest",
    ) -> List[ACTPEvent]:
        """
        Get historical events matching the filter.

        Args:
            event_filter: Optional filter for events
            from_block: Starting block (default: "earliest")
            to_block: Ending block (default: "latest")

        Returns:
            List of matching events

        Example:
            >>> events = await monitor.get_events(
            ...     EventFilter(requester="0x..."),
            ...     from_block=1000000,
            ... )
        """
        events: List[ACTPEvent] = []

        # Apply filter block range if specified
        if event_filter:
            if event_filter.from_block is not None:
                from_block = event_filter.from_block
            if event_filter.to_block is not None:
                to_block = event_filter.to_block

        # Get kernel events
        kernel_events = await self._get_kernel_events(
            event_filter, from_block, to_block
        )
        events.extend(kernel_events)

        # Get escrow events
        escrow_events = await self._get_escrow_events(
            event_filter, from_block, to_block
        )
        events.extend(escrow_events)

        # Sort by block number, then log index
        events.sort(key=lambda e: (e.block_number, e.log_index))

        return events

    async def get_transaction_events(
        self,
        transaction_id: str,
        from_block: Union[int, str] = "earliest",
    ) -> List[ACTPEvent]:
        """
        Get all events for a specific transaction.

        Args:
            transaction_id: The transaction ID
            from_block: Starting block (default: "earliest")

        Returns:
            List of events for the transaction
        """
        return await self.get_events(
            EventFilter(transaction_id=transaction_id),
            from_block=from_block,
        )

    async def get_escrow_events(
        self,
        escrow_id: str,
        from_block: Union[int, str] = "earliest",
    ) -> List[ACTPEvent]:
        """
        Get all events for a specific escrow.

        Args:
            escrow_id: The escrow ID
            from_block: Starting block (default: "earliest")

        Returns:
            List of events for the escrow
        """
        return await self.get_events(
            EventFilter(escrow_id=escrow_id),
            from_block=from_block,
        )

    # =========================================================================
    # Dispute surfacing (PRD P2-5 / AIP-14b §3.4)
    # =========================================================================

    async def get_dispute_events(
        self,
        from_block: Union[int, str] = "earliest",
        to_block: Union[int, str] = "latest",
    ) -> List[ACTPEvent]:
        """
        One-shot historical sweep of all three dispute signals across a block
        window — the read half the split-rate indexer (P2-8) builds on.

        Surfaces, block/log-ordered:
            - kernel ``DISPUTED → CANCELLED`` transitions (admin-CANCELLED
              included — OQ-11 counts these at the same weight as splits),
            - ``DisputeSplitRecorded`` (if a mediator contract is wired),
            - ``UMADisputeEscalated`` (if a BondEscalation contract is wired).

        PARITY: TS ``EventMonitor.getDisputeEvents``.
        """
        events: List[ACTPEvent] = []

        # Kernel DISPUTED→CANCELLED — filter StateTransitioned by from/to states.
        try:
            state_logs = await self._query_event_logs(
                self.kernel_contract.events.StateTransitioned,
                from_block,
                to_block,
            )
            for log in state_logs:
                event = self._parse_state_transitioned(log)
                if (
                    event.previous_state == TransactionState.DISPUTED
                    and event.new_state == TransactionState.CANCELLED
                ):
                    events.append(event)
        except _ABI_EVENT_MISSING_ERRORS:
            pass

        # CompositeMediator DisputeSplitRecorded (if wired).
        if self.mediator_contract is not None:
            try:
                split_logs = await self._query_event_logs(
                    self.mediator_contract.events.DisputeSplitRecorded,
                    from_block,
                    to_block,
                )
                for log in split_logs:
                    events.append(self._parse_dispute_split_recorded(log))
            except _ABI_EVENT_MISSING_ERRORS:
                pass

        # BondEscalation UMADisputeEscalated (if wired).
        if self.bond_escalation_contract is not None:
            try:
                uma_logs = await self._query_event_logs(
                    self.bond_escalation_contract.events.UMADisputeEscalated,
                    from_block,
                    to_block,
                )
                for log in uma_logs:
                    events.append(self._parse_uma_dispute_escalated(log))
            except _ABI_EVENT_MISSING_ERRORS:
                pass

        events.sort(key=lambda e: (e.block_number, e.log_index))
        return events

    async def on_dispute_split_recorded(
        self,
        callback: Callable[[DisputeSplitRecordedEvent], None],
        poll_interval: float = 2.0,
    ) -> asyncio.Task:
        """
        Subscribe to ``DisputeSplitRecorded`` (CompositeMediator ruling-2 trace).

        Requires a ``mediator_contract`` to have been passed to the constructor.
        PARITY: TS ``EventMonitor.onDisputeSplitRecorded``.

        Raises:
            ValueError: if no mediator contract was provided.
        """
        if self.mediator_contract is None:
            raise ValueError(
                "on_dispute_split_recorded: EventMonitor was constructed without "
                "a CompositeMediator contract"
            )
        contract = self.mediator_contract

        async def _watch() -> None:
            last_block = await self.w3.eth.block_number
            while True:
                try:
                    current_block = await self.w3.eth.block_number
                    if current_block > last_block:
                        logs = await self._query_event_logs(
                            contract.events.DisputeSplitRecorded,
                            last_block + 1,
                            current_block,
                        )
                        for log in logs:
                            callback(self._parse_dispute_split_recorded(log))
                        last_block = current_block
                    await asyncio.sleep(poll_interval)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(poll_interval)

        return asyncio.create_task(_watch())

    async def on_disputed_to_cancelled(
        self,
        callback: Callable[[StateTransitionedEvent], None],
        poll_interval: float = 2.0,
    ) -> asyncio.Task:
        """
        Subscribe to kernel ``DISPUTED → CANCELLED`` transitions — the
        kernel-level split path (admin-CANCELLED disputes route here without
        touching CompositeMediator). OQ-11 counts these in the headline
        split-rate at the SAME weight as ``DisputeSplitRecorded``.
        PARITY: TS ``EventMonitor.onDisputedToCancelled``.
        """

        async def _watch() -> None:
            last_block = await self.w3.eth.block_number
            while True:
                try:
                    current_block = await self.w3.eth.block_number
                    if current_block > last_block:
                        logs = await self._query_event_logs(
                            self.kernel_contract.events.StateTransitioned,
                            last_block + 1,
                            current_block,
                        )
                        for log in logs:
                            event = self._parse_state_transitioned(log)
                            if (
                                event.previous_state == TransactionState.DISPUTED
                                and event.new_state == TransactionState.CANCELLED
                            ):
                                callback(event)
                        last_block = current_block
                    await asyncio.sleep(poll_interval)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(poll_interval)

        return asyncio.create_task(_watch())

    async def on_uma_dispute_escalated(
        self,
        callback: Callable[[UMADisputeEscalatedEvent], None],
        poll_interval: float = 2.0,
    ) -> asyncio.Task:
        """
        Subscribe to BondEscalation ``UMADisputeEscalated`` — a Tier-2 assertion
        was disputed and pushed to UMA's DVM (AIP-14b §8.5).

        Requires a ``bond_escalation_contract`` to have been passed to the
        constructor. PARITY: TS ``EventMonitor.onUMADisputeEscalated``.

        Raises:
            ValueError: if no BondEscalation contract was provided.
        """
        if self.bond_escalation_contract is None:
            raise ValueError(
                "on_uma_dispute_escalated: EventMonitor was constructed without "
                "a BondEscalation contract"
            )
        contract = self.bond_escalation_contract

        async def _watch() -> None:
            last_block = await self.w3.eth.block_number
            while True:
                try:
                    current_block = await self.w3.eth.block_number
                    if current_block > last_block:
                        logs = await self._query_event_logs(
                            contract.events.UMADisputeEscalated,
                            last_block + 1,
                            current_block,
                        )
                        for log in logs:
                            callback(self._parse_uma_dispute_escalated(log))
                        last_block = current_block
                    await asyncio.sleep(poll_interval)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(poll_interval)

        return asyncio.create_task(_watch())

    # =========================================================================
    # Real-time Watching
    # =========================================================================

    async def watch_transactions(
        self,
        requester: Optional[str] = None,
        provider: Optional[str] = None,
        poll_interval: float = 2.0,
    ) -> AsyncIterator[ACTPEvent]:
        """
        Watch for new transaction events in real-time.

        Args:
            requester: Optional filter by requester address
            provider: Optional filter by provider address
            poll_interval: Polling interval in seconds

        Yields:
            New transaction events as they occur

        Example:
            >>> async for event in monitor.watch_transactions(requester="0x..."):
            ...     print(f"Event: {event.event_type}")
        """
        event_filter = EventFilter(requester=requester, provider=provider)
        last_block = await self.w3.eth.block_number

        while True:
            try:
                current_block = await self.w3.eth.block_number

                if current_block > last_block:
                    events = await self.get_events(
                        event_filter,
                        from_block=last_block + 1,
                        to_block=current_block,
                    )

                    for event in events:
                        yield event

                    last_block = current_block

                await asyncio.sleep(poll_interval)

            except asyncio.CancelledError:
                break
            except Exception:
                # Log error but continue watching
                await asyncio.sleep(poll_interval)

    async def watch_escrows(
        self,
        requester: Optional[str] = None,
        provider: Optional[str] = None,
        poll_interval: float = 2.0,
    ) -> AsyncIterator[ACTPEvent]:
        """
        Watch for new escrow events in real-time.

        Args:
            requester: Optional filter by requester address
            provider: Optional filter by provider address
            poll_interval: Polling interval in seconds

        Yields:
            New escrow events as they occur
        """
        event_filter = EventFilter(
            requester=requester,
            provider=provider,
            event_types=[
                EventType.ESCROW_CREATED,
                EventType.ESCROW_PAYOUT,
                EventType.ESCROW_COMPLETED,
            ],
        )
        last_block = await self.w3.eth.block_number

        while True:
            try:
                current_block = await self.w3.eth.block_number

                if current_block > last_block:
                    events = await self.get_events(
                        event_filter,
                        from_block=last_block + 1,
                        to_block=current_block,
                    )

                    for event in events:
                        yield event

                    last_block = current_block

                await asyncio.sleep(poll_interval)

            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(poll_interval)

    # =========================================================================
    # Callbacks
    # =========================================================================

    async def subscribe(
        self,
        callback: Callable[[ACTPEvent], None],
        event_filter: Optional[EventFilter] = None,
        poll_interval: float = 2.0,
    ) -> asyncio.Task:
        """
        Subscribe to events with a callback function.

        Args:
            callback: Function to call for each event
            event_filter: Optional filter for events
            poll_interval: Polling interval in seconds

        Returns:
            The background task (can be cancelled to stop)

        Example:
            >>> def handle_event(event):
            ...     print(f"Received: {event.event_type}")
            >>> task = await monitor.subscribe(handle_event)
            >>> # Later: task.cancel() to stop
        """

        async def _watch():
            last_block = await self.w3.eth.block_number

            while True:
                try:
                    current_block = await self.w3.eth.block_number

                    if current_block > last_block:
                        events = await self.get_events(
                            event_filter,
                            from_block=last_block + 1,
                            to_block=current_block,
                        )

                        for event in events:
                            callback(event)

                        last_block = current_block

                    await asyncio.sleep(poll_interval)

                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(poll_interval)

        return asyncio.create_task(_watch())

    # =========================================================================
    # Internal Methods
    # =========================================================================

    # Heuristic substrings that mean the eth_getLogs block range was too large.
    # PARITY: EventMonitor.ts:198-207 (isBlockRangeError).
    _BLOCK_RANGE_ERROR_MARKERS = (
        "block range",
        "range is too",
        "range too",
        "up to a",
        "more than",
        "response size",
        "query timeout",
        "limit exceeded",
        "-32600",
        "-32005",
    )

    @classmethod
    def _is_block_range_error(cls, err: BaseException) -> bool:
        """Heuristic: does this error mean the eth_getLogs block range was too large?

        PARITY: EventMonitor.ts:198-207.
        """
        message = str(err).lower()
        return any(marker in message for marker in cls._BLOCK_RANGE_ERROR_MARKERS)

    async def _query_logs_chunked(
        self,
        event_obj: Any,
        from_block: int,
        to_block: int,
    ) -> List[LogReceipt]:
        """Adaptive eth_getLogs over ``[from_block, to_block]``.

        Tries the full window first; on a block-range error, splits the window
        in half and retries each half — adapting to ANY RPC's eth_getLogs cap
        (10, 1000, 10000, …) with no hardcoded chunk size. In practice a 10000
        block window halves toward ~1000 on a standard-tier RPC. A single-block
        window that still fails is a genuine error and is re-raised (NOT
        swallowed). PARITY: EventMonitor.ts:182-196 (queryFilterChunked).
        """
        try:
            log_filter = event_obj.create_filter(
                fromBlock=from_block,
                toBlock=to_block,
            )
            return await log_filter.get_all_entries()
        except Exception as err:
            # Single-block window or a non-range error → genuine. Re-raise so the
            # caller's ABI-existence guard handles "event not in ABI" but real
            # RPC failures are never silently dropped.
            if from_block >= to_block or not self._is_block_range_error(err):
                raise
            mid = (from_block + to_block) // 2
            lower = await self._query_logs_chunked(event_obj, from_block, mid)
            upper = await self._query_logs_chunked(event_obj, mid + 1, to_block)
            return [*lower, *upper]

    async def _query_event_logs(
        self,
        event_obj: Any,
        from_block: Union[int, str],
        to_block: Union[int, str],
    ) -> List[LogReceipt]:
        """Query logs for one event, chunking adaptively when bounds are numeric.

        Non-numeric bounds (e.g. ``"earliest"`` / ``"latest"``) fall through to a
        single ``get_all_entries`` call — there's nothing to halve without
        concrete block numbers. PARITY: EventMonitor.ts:131-136.
        """
        if isinstance(from_block, int) and isinstance(to_block, int):
            return await self._query_logs_chunked(event_obj, from_block, to_block)

        log_filter = event_obj.create_filter(fromBlock=from_block, toBlock=to_block)
        return await log_filter.get_all_entries()

    async def _get_kernel_events(
        self,
        event_filter: Optional[EventFilter],
        from_block: Union[int, str],
        to_block: Union[int, str],
    ) -> List[ACTPEvent]:
        """Get events from ACTPKernel contract."""
        events: List[ACTPEvent] = []

        # TransactionCreated events
        try:
            tx_created_logs = await self._query_event_logs(
                self.kernel_contract.events.TransactionCreated,
                from_block,
                to_block,
            )

            for log in tx_created_logs:
                event = self._parse_transaction_created(log)
                if self._matches_filter(event, event_filter):
                    events.append(event)
        except _ABI_EVENT_MISSING_ERRORS:
            pass  # Event genuinely not in ABI — real RPC errors propagate.

        # StateTransitioned events
        try:
            state_logs = await self._query_event_logs(
                self.kernel_contract.events.StateTransitioned,
                from_block,
                to_block,
            )

            for log in state_logs:
                event = self._parse_state_transitioned(log)
                if self._matches_filter(event, event_filter):
                    events.append(event)
        except _ABI_EVENT_MISSING_ERRORS:
            pass

        return events

    async def _get_escrow_events(
        self,
        event_filter: Optional[EventFilter],
        from_block: Union[int, str],
        to_block: Union[int, str],
    ) -> List[ACTPEvent]:
        """Get events from EscrowVault contract."""
        events: List[ACTPEvent] = []

        # EscrowCreated events
        try:
            escrow_created_logs = await self._query_event_logs(
                self.escrow_contract.events.EscrowCreated,
                from_block,
                to_block,
            )

            for log in escrow_created_logs:
                event = self._parse_escrow_created(log)
                if self._matches_filter(event, event_filter):
                    events.append(event)
        except _ABI_EVENT_MISSING_ERRORS:
            pass

        # EscrowPayout events
        try:
            payout_logs = await self._query_event_logs(
                self.escrow_contract.events.EscrowPayout,
                from_block,
                to_block,
            )

            for log in payout_logs:
                event = self._parse_escrow_payout(log)
                if self._matches_filter(event, event_filter):
                    events.append(event)
        except _ABI_EVENT_MISSING_ERRORS:
            pass

        return events

    def _parse_transaction_created(self, log: LogReceipt) -> TransactionCreatedEvent:
        """Parse TransactionCreated event log."""
        args = log.get("args", {})
        return TransactionCreatedEvent(
            event_type=EventType.TRANSACTION_CREATED,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            transaction_id=self._bytes_to_hex(args.get("transactionId", b"")),
            requester=args.get("requester", ""),
            provider=args.get("provider", ""),
            amount=args.get("amount", 0),
            deadline=args.get("deadline", 0),
            dispute_window=args.get("disputeWindow", 0),
            raw_data=dict(args),
        )

    def _parse_state_transitioned(self, log: LogReceipt) -> StateTransitionedEvent:
        """Parse StateTransitioned event log.

        The on-chain ABI names the fields ``oldState`` / ``newState`` /
        ``triggeredBy`` (see ACTPKernel.json). Earlier code read the
        non-existent ``previousState`` / ``actor`` keys, so state fields were
        never populated against real logs — fixed here, with a fallback to the
        legacy synthetic names so any existing caller keeps working. This decode
        is load-bearing for P2-5 DISPUTED→CANCELLED surfacing (OQ-11).
        """
        args = log.get("args", {})
        prev_state = args.get("oldState", args.get("previousState"))
        new_state = args.get("newState")
        actor = args.get("triggeredBy", args.get("actor", ""))

        return StateTransitionedEvent(
            event_type=EventType.STATE_TRANSITIONED,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            transaction_id=self._bytes_to_hex(args.get("transactionId", b"")),
            previous_state=TransactionState(prev_state) if prev_state is not None else None,
            new_state=TransactionState(new_state) if new_state is not None else None,
            actor=actor,
            raw_data=dict(args),
        )

    def _parse_escrow_created(self, log: LogReceipt) -> EscrowCreatedEvent:
        """Parse EscrowCreated event log."""
        args = log.get("args", {})
        return EscrowCreatedEvent(
            event_type=EventType.ESCROW_CREATED,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            escrow_id=self._bytes_to_hex(args.get("escrowId", b"")),
            requester=args.get("requester", ""),
            provider=args.get("provider", ""),
            amount=args.get("amount", 0),
            raw_data=dict(args),
        )

    def _parse_escrow_payout(self, log: LogReceipt) -> EscrowPayoutEvent:
        """Parse EscrowPayout event log."""
        args = log.get("args", {})
        return EscrowPayoutEvent(
            event_type=EventType.ESCROW_PAYOUT,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            escrow_id=self._bytes_to_hex(args.get("escrowId", b"")),
            recipient=args.get("recipient", ""),
            amount=args.get("amount", 0),
            raw_data=dict(args),
        )

    def _parse_dispute_split_recorded(
        self, log: LogReceipt
    ) -> DisputeSplitRecordedEvent:
        """Parse DisputeSplitRecorded event log. PARITY: decode_dispute_split_recorded."""
        args = log.get("args", {})
        return DisputeSplitRecordedEvent(
            event_type=EventType.DISPUTE_SPLIT_RECORDED,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            tx_id=self._bytes_to_hex(args.get("txId", b"")),
            requester=args.get("requester", ""),
            provider=args.get("provider", ""),
            split_bps=int(args.get("splitBps", 0)),
            raw_data=dict(args),
        )

    def _parse_uma_dispute_escalated(
        self, log: LogReceipt
    ) -> UMADisputeEscalatedEvent:
        """Parse UMADisputeEscalated event log (BondEscalation, AIP-14b §8.5)."""
        args = log.get("args", {})
        return UMADisputeEscalatedEvent(
            event_type=EventType.UMA_DISPUTE_ESCALATED,
            contract_address=log["address"],
            block_number=log["blockNumber"],
            transaction_hash="0x" + log["transactionHash"].hex()
            if isinstance(log["transactionHash"], bytes)
            else log["transactionHash"],
            log_index=log["logIndex"],
            dispute_id=self._bytes_to_hex(args.get("disputeId", b"")),
            assertion_id=self._bytes_to_hex(args.get("assertionId", b"")),
            raw_data=dict(args),
        )

    def _bytes_to_hex(self, value: Union[bytes, str]) -> str:
        """Convert bytes to hex string."""
        if isinstance(value, bytes):
            return "0x" + value.hex()
        return value if value.startswith("0x") else "0x" + value

    def _matches_filter(
        self, event: ACTPEvent, event_filter: Optional[EventFilter]
    ) -> bool:
        """Check if event matches the filter."""
        if event_filter is None:
            return True

        # Filter by event types
        if event_filter.event_types:
            if event.event_type not in event_filter.event_types:
                return False

        # Filter by transaction ID
        if event_filter.transaction_id:
            if hasattr(event, "transaction_id"):
                if event.transaction_id.lower() != event_filter.transaction_id.lower():
                    return False

        # Filter by escrow ID
        if event_filter.escrow_id:
            if hasattr(event, "escrow_id"):
                if event.escrow_id.lower() != event_filter.escrow_id.lower():
                    return False

        # Filter by requester
        if event_filter.requester:
            if hasattr(event, "requester"):
                if event.requester.lower() != event_filter.requester.lower():
                    return False

        # Filter by provider
        if event_filter.provider:
            if hasattr(event, "provider"):
                if event.provider.lower() != event_filter.provider.lower():
                    return False

        return True
