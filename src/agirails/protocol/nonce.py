"""
Nonce management for blockchain transactions.

Provides thread-safe nonce tracking for sending multiple transactions
without waiting for each to confirm. Handles nonce gaps and resets.

The NonceManager tracks pending transactions and allocates nonces
sequentially to avoid conflicts.

Example:
    >>> from web3 import AsyncWeb3
    >>> from agirails.protocol import NonceManager
    >>>
    >>> w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider("https://..."))
    >>> account = w3.eth.account.from_key(private_key)
    >>> nonce_manager = NonceManager(w3, account.address)
    >>>
    >>> # Get next nonce for transaction
    >>> nonce = await nonce_manager.get_nonce()
    >>>
    >>> # Mark nonce as used after sending
    >>> nonce_manager.confirm_nonce(nonce)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from web3 import AsyncWeb3


@dataclass
class NonceState:
    """
    Internal state for nonce tracking.

    Attributes:
        current_nonce: The next available nonce
        pending_nonces: Set of nonces that have been allocated but not confirmed
        confirmed_nonces: Set of nonces that have been confirmed on-chain
        last_synced: Last block number when nonce was synced
    """

    current_nonce: int = 0
    pending_nonces: Set[int] = field(default_factory=set)
    confirmed_nonces: Set[int] = field(default_factory=set)
    last_synced: int = 0


class NonceManager:
    """
    Thread-safe nonce manager for blockchain transactions.

    Tracks allocated and confirmed nonces to enable sending multiple
    transactions without waiting for confirmations.

    Attributes:
        w3: The AsyncWeb3 instance
        address: The account address to track nonces for
    """

    def __init__(
        self,
        w3: AsyncWeb3,
        address: str,
        auto_sync: bool = True,
    ) -> None:
        """
        Initialize NonceManager.

        Args:
            w3: The AsyncWeb3 instance
            address: The account address to track nonces for
            auto_sync: Whether to sync with chain on first get_nonce call
        """
        self.w3 = w3
        self.address = w3.to_checksum_address(address)
        self._state = NonceState()
        self._lock = asyncio.Lock()
        self._auto_sync = auto_sync
        self._initialized = False

    async def get_nonce(self, sync: bool = False) -> int:
        """
        Get the next available nonce.

        Args:
            sync: Force sync with on-chain state before returning nonce

        Returns:
            The next nonce to use for a transaction

        Example:
            >>> nonce = await nonce_manager.get_nonce()
            >>> # Use nonce in transaction
            >>> tx = {"nonce": nonce, ...}
        """
        async with self._lock:
            # Initialize on first call or if sync requested
            if not self._initialized or sync:
                await self._sync_with_chain()
                self._initialized = True

            # Get and increment nonce
            nonce = self._state.current_nonce
            self._state.pending_nonces.add(nonce)
            self._state.current_nonce += 1

            return nonce

    async def peek_nonce(self) -> int:
        """
        Peek at the next nonce without allocating it.

        Returns:
            The next nonce that would be allocated
        """
        async with self._lock:
            if not self._initialized:
                await self._sync_with_chain()
                self._initialized = True

            return self._state.current_nonce

    def confirm_nonce(self, nonce: int) -> None:
        """
        Mark a nonce as confirmed (transaction included in block).

        Args:
            nonce: The nonce that was confirmed

        Example:
            >>> nonce = await nonce_manager.get_nonce()
            >>> # ... send transaction ...
            >>> nonce_manager.confirm_nonce(nonce)
        """
        self._state.pending_nonces.discard(nonce)
        self._state.confirmed_nonces.add(nonce)

    def release_nonce(self, nonce: int) -> None:
        """
        Release an allocated nonce (transaction failed/cancelled).

        This allows the nonce to be reused for another transaction.

        Args:
            nonce: The nonce to release

        Example:
            >>> nonce = await nonce_manager.get_nonce()
            >>> try:
            ...     # ... send transaction ...
            ... except Exception:
            ...     nonce_manager.release_nonce(nonce)
        """
        self._state.pending_nonces.discard(nonce)

        # If this was the most recently allocated nonce, we can reuse it
        if nonce == self._state.current_nonce - 1:
            self._state.current_nonce = nonce

    async def sync(self) -> int:
        """
        Synchronize nonce state with on-chain data.

        Returns:
            The current on-chain nonce

        Example:
            >>> on_chain_nonce = await nonce_manager.sync()
        """
        async with self._lock:
            await self._sync_with_chain()
            return self._state.current_nonce

    async def reset(self) -> int:
        """
        Reset nonce state and sync with chain.

        Clears all pending and confirmed nonces and resyncs.

        Returns:
            The current on-chain nonce
        """
        async with self._lock:
            self._state = NonceState()
            await self._sync_with_chain()
            self._initialized = True
            return self._state.current_nonce

    def get_pending_count(self) -> int:
        """Get the number of pending (unconfirmed) transactions."""
        return len(self._state.pending_nonces)

    def get_pending_nonces(self) -> Set[int]:
        """Get the set of pending nonce values."""
        return self._state.pending_nonces.copy()

    async def wait_for_confirmations(
        self,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> bool:
        """
        Wait for all pending transactions to be confirmed.

        Args:
            timeout: Maximum time to wait in seconds
            poll_interval: Interval between checks in seconds

        Returns:
            True if all confirmed, False if timeout

        Example:
            >>> success = await nonce_manager.wait_for_confirmations()
        """
        import time

        start_time = time.time()

        while len(self._state.pending_nonces) > 0:
            if time.time() - start_time > timeout:
                return False

            # Check on-chain nonce
            on_chain_nonce = await self.w3.eth.get_transaction_count(self.address)

            # All nonces below on-chain nonce are confirmed
            confirmed = {n for n in self._state.pending_nonces if n < on_chain_nonce}
            for nonce in confirmed:
                self.confirm_nonce(nonce)

            if len(self._state.pending_nonces) == 0:
                return True

            await asyncio.sleep(poll_interval)

        return True

    async def _sync_with_chain(self) -> None:
        """Sync nonce state with on-chain data."""
        on_chain_nonce = await self.w3.eth.get_transaction_count(self.address)
        current_block = await self.w3.eth.block_number

        # Update state
        self._state.current_nonce = max(on_chain_nonce, self._state.current_nonce)
        self._state.last_synced = current_block

        # Clear pending nonces that have been confirmed
        confirmed = {n for n in self._state.pending_nonces if n < on_chain_nonce}
        self._state.pending_nonces -= confirmed
        self._state.confirmed_nonces |= confirmed


class NonceManagerPool:
    """
    Pool of NonceManagers for multiple accounts.

    Manages nonce tracking for multiple accounts, creating NonceManagers
    on demand and caching them for reuse.

    Example:
        >>> pool = NonceManagerPool(w3)
        >>> nonce = await pool.get_nonce(account_address)
    """

    def __init__(self, w3: AsyncWeb3) -> None:
        """
        Initialize NonceManagerPool.

        Args:
            w3: The AsyncWeb3 instance
        """
        self.w3 = w3
        self._managers: Dict[str, NonceManager] = {}
        self._lock = asyncio.Lock()

    async def get_nonce(self, address: str, sync: bool = False) -> int:
        """
        Get the next nonce for an address.

        Args:
            address: The account address
            sync: Force sync with on-chain state

        Returns:
            The next nonce for the address
        """
        manager = await self._get_or_create_manager(address)
        return await manager.get_nonce(sync=sync)

    def confirm_nonce(self, address: str, nonce: int) -> None:
        """
        Confirm a nonce for an address.

        Args:
            address: The account address
            nonce: The nonce to confirm
        """
        address = self.w3.to_checksum_address(address)
        if address in self._managers:
            self._managers[address].confirm_nonce(nonce)

    def release_nonce(self, address: str, nonce: int) -> None:
        """
        Release a nonce for an address.

        Args:
            address: The account address
            nonce: The nonce to release
        """
        address = self.w3.to_checksum_address(address)
        if address in self._managers:
            self._managers[address].release_nonce(nonce)

    async def sync(self, address: str) -> int:
        """
        Sync nonce state for an address.

        Args:
            address: The account address

        Returns:
            The current on-chain nonce
        """
        manager = await self._get_or_create_manager(address)
        return await manager.sync()

    async def reset(self, address: Optional[str] = None) -> None:
        """
        Reset nonce state for an address or all addresses.

        Args:
            address: The account address (None to reset all)
        """
        if address:
            address = self.w3.to_checksum_address(address)
            if address in self._managers:
                await self._managers[address].reset()
        else:
            for manager in self._managers.values():
                await manager.reset()

    async def _get_or_create_manager(self, address: str) -> NonceManager:
        """Get or create a NonceManager for an address."""
        address = self.w3.to_checksum_address(address)

        async with self._lock:
            if address not in self._managers:
                self._managers[address] = NonceManager(self.w3, address)

            return self._managers[address]
