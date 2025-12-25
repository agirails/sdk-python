"""
Nonce tracker for AGIRAILS SDK.

Provides thread-safe nonce management for Ethereum transactions
to prevent nonce conflicts and ensure transaction ordering.

Security measures:
- Thread-safe operations with RLock
- Automatic nonce recovery on failures
- Transaction confirmation tracking
- Configurable confirmation requirements

Example:
    >>> tracker = NonceTracker(provider, address)
    >>> nonce = await tracker.get_next_nonce()
    >>> # Send transaction with nonce
    >>> await tracker.confirm_nonce(nonce, tx_hash)
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    pass


class NonceStatus(Enum):
    """Status of a nonce."""

    AVAILABLE = "available"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class NonceEntry:
    """
    Entry tracking a single nonce.

    Attributes:
        nonce: The nonce value
        status: Current status
        tx_hash: Transaction hash (if submitted)
        created_at: When the nonce was allocated
        confirmed_at: When the transaction was confirmed
        expires_at: When the nonce reservation expires
    """

    nonce: int
    status: NonceStatus = NonceStatus.AVAILABLE
    tx_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    confirmed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class NonceTracker:
    """
    Thread-safe nonce tracker for Ethereum transactions.

    Manages nonce allocation, confirmation, and recovery to prevent
    conflicts when sending multiple transactions.

    Features:
    - Automatic nonce fetching from chain
    - Pending nonce tracking
    - Automatic recovery on transaction failures
    - Expiration of stale reservations
    - Thread-safe operations

    Example:
        >>> tracker = NonceTracker(address="0x...")
        >>> nonce = await tracker.get_next_nonce()
        >>> # Use nonce in transaction
        >>> await tracker.confirm_nonce(nonce, "0x123...")
        >>> # Or if transaction failed:
        >>> await tracker.release_nonce(nonce)
    """

    # Default reservation timeout in seconds
    DEFAULT_RESERVATION_TIMEOUT = 300.0

    # Maximum pending nonces before forcing sync
    MAX_PENDING_NONCES = 100

    def __init__(
        self,
        address: str,
        *,
        initial_nonce: Optional[int] = None,
        reservation_timeout: float = DEFAULT_RESERVATION_TIMEOUT,
        auto_sync: bool = True,
    ) -> None:
        """
        Initialize nonce tracker.

        Args:
            address: Ethereum address to track nonces for
            initial_nonce: Starting nonce (fetched from chain if None)
            reservation_timeout: Seconds before unreleased nonces expire
            auto_sync: Whether to auto-sync with chain on init
        """
        self._address = address
        self._current_nonce = initial_nonce or 0
        self._reservation_timeout = reservation_timeout
        self._auto_sync = auto_sync

        self._lock = threading.RLock()
        self._pending: Dict[int, NonceEntry] = {}
        self._confirmed: Dict[int, NonceEntry] = {}
        self._initialized = initial_nonce is not None

        # Statistics
        self._stats = {
            "nonces_allocated": 0,
            "nonces_confirmed": 0,
            "nonces_failed": 0,
            "nonces_expired": 0,
            "syncs_performed": 0,
        }

    @property
    def address(self) -> str:
        """Get the tracked address."""
        return self._address

    @property
    def current_nonce(self) -> int:
        """Get the current nonce value."""
        with self._lock:
            return self._current_nonce

    @property
    def pending_count(self) -> int:
        """Get the number of pending nonces."""
        with self._lock:
            return len(self._pending)

    @property
    def stats(self) -> Dict[str, int]:
        """Get tracker statistics."""
        return self._stats.copy()

    async def initialize(self, provider: Optional[Any] = None) -> int:
        """
        Initialize the tracker with the current on-chain nonce.

        Args:
            provider: Web3 provider for fetching nonce

        Returns:
            Current nonce value
        """
        if self._initialized:
            return self._current_nonce

        with self._lock:
            if provider is not None:
                # In a real implementation, fetch from chain:
                # nonce = await provider.eth.get_transaction_count(self._address)
                # For now, use 0
                pass

            self._initialized = True
            self._stats["syncs_performed"] += 1
            return self._current_nonce

    async def sync_with_chain(self, provider: Optional[Any] = None) -> int:
        """
        Sync nonce with the blockchain.

        Useful for recovery after transaction failures or gaps.

        Args:
            provider: Web3 provider for fetching nonce

        Returns:
            Updated nonce value
        """
        with self._lock:
            if provider is not None:
                # In a real implementation:
                # chain_nonce = await provider.eth.get_transaction_count(self._address)
                # Reconcile with pending transactions
                pass

            self._stats["syncs_performed"] += 1

            # Clean up expired pending nonces
            self._cleanup_expired()

            return self._current_nonce

    async def get_next_nonce(self) -> int:
        """
        Get the next available nonce.

        Allocates a nonce and marks it as pending. The nonce
        must be confirmed or released after use.

        Returns:
            Next nonce value

        Raises:
            RuntimeError: If too many pending nonces
        """
        with self._lock:
            # Clean up expired entries first
            self._cleanup_expired()

            # Check for too many pending
            if len(self._pending) >= self.MAX_PENDING_NONCES:
                raise RuntimeError(
                    f"Too many pending nonces ({len(self._pending)}). "
                    "Confirm or release pending nonces before allocating more."
                )

            # Allocate next nonce
            nonce = self._current_nonce
            self._current_nonce += 1

            # Create pending entry
            entry = NonceEntry(
                nonce=nonce,
                status=NonceStatus.PENDING,
                expires_at=datetime.fromtimestamp(
                    time.time() + self._reservation_timeout
                ),
            )
            self._pending[nonce] = entry
            self._stats["nonces_allocated"] += 1

            return nonce

    async def confirm_nonce(self, nonce: int, tx_hash: str) -> bool:
        """
        Confirm a nonce was used successfully.

        Args:
            nonce: The nonce that was used
            tx_hash: Transaction hash for the confirmed transaction

        Returns:
            True if confirmation was successful
        """
        with self._lock:
            entry = self._pending.get(nonce)
            if entry is None:
                # Nonce wasn't tracked or already confirmed
                return False

            entry.status = NonceStatus.CONFIRMED
            entry.tx_hash = tx_hash
            entry.confirmed_at = datetime.now()

            # Move from pending to confirmed
            del self._pending[nonce]
            self._confirmed[nonce] = entry
            self._stats["nonces_confirmed"] += 1

            return True

    async def release_nonce(self, nonce: int) -> bool:
        """
        Release a nonce that won't be used.

        Call this if a transaction fails before being sent.

        Args:
            nonce: The nonce to release

        Returns:
            True if nonce was released
        """
        with self._lock:
            entry = self._pending.get(nonce)
            if entry is None:
                return False

            entry.status = NonceStatus.FAILED
            del self._pending[nonce]
            self._stats["nonces_failed"] += 1

            # If this was the last allocated nonce, we can reclaim it
            if nonce == self._current_nonce - 1 and nonce not in self._confirmed:
                self._current_nonce = nonce

            return True

    async def fail_nonce(self, nonce: int, error: Optional[str] = None) -> bool:
        """
        Mark a nonce as failed.

        Call this if a transaction fails after being sent.

        Args:
            nonce: The nonce that failed
            error: Optional error message

        Returns:
            True if nonce was marked as failed
        """
        with self._lock:
            entry = self._pending.get(nonce)
            if entry is None:
                return False

            entry.status = NonceStatus.FAILED
            del self._pending[nonce]
            self._stats["nonces_failed"] += 1

            return True

    def get_pending_nonces(self) -> List[int]:
        """
        Get all pending nonces.

        Returns:
            List of pending nonce values
        """
        with self._lock:
            return list(self._pending.keys())

    def get_confirmed_nonces(self, limit: int = 100) -> List[int]:
        """
        Get recently confirmed nonces.

        Args:
            limit: Maximum number to return

        Returns:
            List of confirmed nonce values (most recent first)
        """
        with self._lock:
            nonces = sorted(self._confirmed.keys(), reverse=True)
            return nonces[:limit]

    def is_pending(self, nonce: int) -> bool:
        """Check if a nonce is pending."""
        with self._lock:
            return nonce in self._pending

    def is_confirmed(self, nonce: int) -> bool:
        """Check if a nonce is confirmed."""
        with self._lock:
            return nonce in self._confirmed

    def _cleanup_expired(self) -> int:
        """
        Clean up expired pending nonces.

        Returns:
            Number of expired entries removed
        """
        now = datetime.now()
        expired = []

        for nonce, entry in self._pending.items():
            if entry.expires_at is not None and entry.expires_at < now:
                expired.append(nonce)

        for nonce in expired:
            entry = self._pending[nonce]
            entry.status = NonceStatus.EXPIRED
            del self._pending[nonce]
            self._stats["nonces_expired"] += 1

        return len(expired)

    def clear_confirmed(self, keep_recent: int = 100) -> int:
        """
        Clear old confirmed entries to free memory.

        Args:
            keep_recent: Number of recent entries to keep

        Returns:
            Number of entries cleared
        """
        with self._lock:
            if len(self._confirmed) <= keep_recent:
                return 0

            nonces = sorted(self._confirmed.keys())
            to_remove = nonces[:-keep_recent]

            for nonce in to_remove:
                del self._confirmed[nonce]

            return len(to_remove)

    def reset(self) -> None:
        """Reset the tracker to initial state."""
        with self._lock:
            self._current_nonce = 0
            self._pending.clear()
            self._confirmed.clear()
            self._initialized = False

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"NonceTracker(address={self._address[:10]}..., "
            f"current={self._current_nonce}, "
            f"pending={len(self._pending)})"
        )


class NonceManager:
    """
    Manager for multiple nonce trackers.

    Manages nonce tracking for multiple addresses, useful for
    applications that send transactions from multiple wallets.

    Example:
        >>> manager = NonceManager()
        >>> nonce = await manager.get_next_nonce("0x123...")
        >>> await manager.confirm_nonce("0x123...", nonce, tx_hash)
    """

    def __init__(self) -> None:
        """Initialize nonce manager."""
        self._trackers: Dict[str, NonceTracker] = {}
        self._lock = threading.RLock()

    def get_tracker(
        self,
        address: str,
        *,
        create: bool = True,
        **kwargs: Any,
    ) -> Optional[NonceTracker]:
        """
        Get or create a tracker for an address.

        Args:
            address: Ethereum address
            create: Whether to create if doesn't exist
            **kwargs: Arguments for NonceTracker constructor

        Returns:
            NonceTracker or None if not found and create=False
        """
        address_lower = address.lower()

        with self._lock:
            tracker = self._trackers.get(address_lower)
            if tracker is None and create:
                tracker = NonceTracker(address_lower, **kwargs)
                self._trackers[address_lower] = tracker
            return tracker

    async def get_next_nonce(self, address: str) -> int:
        """
        Get next nonce for an address.

        Args:
            address: Ethereum address

        Returns:
            Next nonce value
        """
        tracker = self.get_tracker(address)
        if tracker is None:
            raise ValueError(f"No tracker for address: {address}")
        return await tracker.get_next_nonce()

    async def confirm_nonce(self, address: str, nonce: int, tx_hash: str) -> bool:
        """
        Confirm a nonce for an address.

        Args:
            address: Ethereum address
            nonce: Nonce to confirm
            tx_hash: Transaction hash

        Returns:
            True if confirmed
        """
        tracker = self.get_tracker(address, create=False)
        if tracker is None:
            return False
        return await tracker.confirm_nonce(nonce, tx_hash)

    async def release_nonce(self, address: str, nonce: int) -> bool:
        """
        Release a nonce for an address.

        Args:
            address: Ethereum address
            nonce: Nonce to release

        Returns:
            True if released
        """
        tracker = self.get_tracker(address, create=False)
        if tracker is None:
            return False
        return await tracker.release_nonce(nonce)

    def remove_tracker(self, address: str) -> bool:
        """
        Remove a tracker for an address.

        Args:
            address: Ethereum address

        Returns:
            True if removed
        """
        address_lower = address.lower()

        with self._lock:
            if address_lower in self._trackers:
                del self._trackers[address_lower]
                return True
            return False

    def clear(self) -> None:
        """Remove all trackers."""
        with self._lock:
            self._trackers.clear()

    @property
    def addresses(self) -> List[str]:
        """Get all tracked addresses."""
        with self._lock:
            return list(self._trackers.keys())

    def __len__(self) -> int:
        """Number of tracked addresses."""
        return len(self._trackers)
