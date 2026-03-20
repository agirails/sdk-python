"""
DualNonceManager -- Manages both EntryPoint and ACTP nonces.

ERC-4337 UserOps need two independent nonces:
  1. EntryPoint nonce -- anti-replay for the UserOp itself
  2. ACTP nonce -- used to compute deterministic txId

This manager uses an asyncio.Lock mutex queue to ensure:
  - Only one UserOp is in-flight at a time
  - ACTP nonce increments only on confirmed receipt
  - On failure, next call re-reads from chain

This is a 1:1 port of sdk-js/src/wallet/aa/DualNonceManager.ts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, Optional, TypeVar

from web3 import Web3

from agirails.wallet.aa.constants import ENTRYPOINT_V06

logger = logging.getLogger("agirails.wallet.aa.nonce")

T = TypeVar("T")


# ============================================================================
# ABI fragments
# ============================================================================

ENTRYPOINT_NONCE_ABI = [
    {
        "inputs": [
            {"name": "sender", "type": "address"},
            {"name": "key", "type": "uint192"},
        ],
        "name": "getNonce",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]

ACTP_KERNEL_NONCE_ABI = [
    {
        "inputs": [{"name": "requester", "type": "address"}],
        "name": "requesterNonces",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]


# ============================================================================
# Data types
# ============================================================================


@dataclass
class NonceSet:
    """Current EntryPoint and ACTP nonces."""

    entry_point_nonce: int
    actp_nonce: int


@dataclass
class EnqueueResult(Generic[T]):
    """Result from a nonce-managed operation."""

    result: T
    success: bool


# ============================================================================
# DualNonceManager
# ============================================================================


class DualNonceManager:
    """Manages EntryPoint nonce + ACTP nonce with asyncio.Lock mutex.

    Ensures sequential execution: only one UserOp in-flight at a time.
    ACTP nonce increments only on success. Resets cache on failure.

    Args:
        w3: Web3 instance connected to the target chain.
        sender_address: Smart Wallet address (the ERC-4337 sender).
        actp_kernel_address: ACTPKernel contract address.
    """

    def __init__(
        self,
        w3: Web3,
        sender_address: str,
        actp_kernel_address: str,
    ) -> None:
        self._w3 = w3
        self._sender_address = Web3.to_checksum_address(sender_address)
        self._actp_kernel_address = Web3.to_checksum_address(actp_kernel_address)
        self._mutex: Optional[asyncio.Lock] = None
        self._mutex_loop: Optional[asyncio.AbstractEventLoop] = None
        self._cached_actp_nonce: Optional[int] = None

    def _get_mutex(self) -> asyncio.Lock:
        """Lazily create asyncio.Lock with event loop detection (P-8 pattern)."""
        current_loop: Optional[asyncio.AbstractEventLoop] = None
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if self._mutex is None or (current_loop is not None and current_loop is not self._mutex_loop):
            self._mutex = asyncio.Lock()
            self._mutex_loop = current_loop
        return self._mutex

    async def enqueue(
        self,
        fn: Callable[[NonceSet], Awaitable[EnqueueResult[T]]],
        increments_actp_nonce: bool = True,
    ) -> T:
        """Execute a callback while holding the nonce mutex.

        The callback receives current nonces and must return an EnqueueResult
        indicating whether the operation succeeded (to decide ACTP nonce increment).

        Args:
            fn: Async callback receiving NonceSet, returning EnqueueResult.
            increments_actp_nonce: Whether success increments the ACTP nonce.

        Returns:
            The result from the callback.
        """
        async with self._get_mutex():
            try:
                # Read nonces
                entry_point_nonce = await self._read_entry_point_nonce()
                actp_nonce = (
                    self._cached_actp_nonce
                    if self._cached_actp_nonce is not None
                    else await self._read_actp_nonce()
                )

                logger.info(
                    "Nonces acquired: entryPoint=%d actp=%d",
                    entry_point_nonce,
                    actp_nonce,
                )

                nonces = NonceSet(
                    entry_point_nonce=entry_point_nonce,
                    actp_nonce=actp_nonce,
                )

                result = await fn(nonces)

                if result.success and increments_actp_nonce:
                    self._cached_actp_nonce = actp_nonce + 1
                elif not result.success:
                    # Reset cache on failure -- next call re-reads from chain
                    self._cached_actp_nonce = None

                return result.result
            except Exception:
                # Reset on error
                self._cached_actp_nonce = None
                raise

    async def _read_entry_point_nonce(self) -> int:
        """Read current EntryPoint nonce for the sender.

        Key 0 is the default key for CoinbaseSmartWallet.
        """
        entry_point = self._w3.eth.contract(
            address=Web3.to_checksum_address(ENTRYPOINT_V06),
            abi=ENTRYPOINT_NONCE_ABI,
        )
        return entry_point.functions.getNonce(self._sender_address, 0).call()

    async def _read_actp_nonce(self) -> int:
        """Read current ACTP nonce for the requester.

        requesterNonces is public on ACTPKernel (added in v2).
        Older deployments may not expose this -- fall back to 0.
        """
        try:
            kernel = self._w3.eth.contract(
                address=self._actp_kernel_address,
                abi=ACTP_KERNEL_NONCE_ABI,
            )
            nonce = kernel.functions.requesterNonces(self._sender_address).call()
            self._cached_actp_nonce = nonce
            return nonce
        except Exception:
            logger.warning(
                "requesterNonces not available on ACTPKernel -- using 0 (older deployment?)"
            )
            self._cached_actp_nonce = 0
            return 0

    def invalidate_cache(self) -> None:
        """Invalidate cached ACTP nonce (forces re-read on next operation)."""
        self._cached_actp_nonce = None
