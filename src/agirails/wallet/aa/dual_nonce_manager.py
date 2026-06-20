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
from typing import Any, Awaitable, Callable, Generic, List, Optional, TypeVar

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

# TransactionCreated(bytes32,address,address,uint256,bytes32,uint256,uint256,uint256)
# topic0 — used to derive the ACTP nonce from logs when requesterNonces is absent.
# Mirrors TS DualNonceManager.ts:32-34.
TX_CREATED_EVENT_TOPIC = Web3.keccak(
    text="TransactionCreated(bytes32,address,address,uint256,bytes32,uint256,uint256,uint256)"
).hex()
if not TX_CREATED_EVENT_TOPIC.startswith("0x"):
    TX_CREATED_EVENT_TOPIC = "0x" + TX_CREATED_EVENT_TOPIC

# Adaptive getLogs chunking bounds (TS DualNonceManager.ts:35-36).
INITIAL_LOG_CHUNK_SIZE = 10_000
MIN_LOG_CHUNK_SIZE = 1_000


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
        known_deployment_block: Known deployment block of ACTPKernel
            (skips binary search when deriving the ACTP nonce from events).
    """

    def __init__(
        self,
        w3: Web3,
        sender_address: str,
        actp_kernel_address: str,
        known_deployment_block: Optional[int] = None,
    ) -> None:
        self._w3 = w3
        self._sender_address = Web3.to_checksum_address(sender_address)
        self._actp_kernel_address = Web3.to_checksum_address(actp_kernel_address)
        self._mutex: Optional[asyncio.Lock] = None
        self._mutex_loop: Optional[asyncio.AbstractEventLoop] = None
        self._cached_actp_nonce: Optional[int] = None
        # Cached deployment block for ACTPKernel address (TS DualNonceManager.ts:78-81).
        self._cached_kernel_deployment_block: Optional[int] = known_deployment_block
        # Whether the cached deployment-block hint has been validated against the chain.
        self._deployment_block_validated: bool = False

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

    async def read_entry_point_nonce(self) -> int:
        """Read current EntryPoint nonce for the sender.

        Key 0 is the default key for CoinbaseSmartWallet.

        Public so that retry loops (e.g. ``pay_actp_batched`` nonce collision)
        can re-read after a consumed UserOp. Mirrors TS
        ``readEntryPointNonce`` (DualNonceManager.ts:150-157).
        """
        entry_point = self._w3.eth.contract(
            address=Web3.to_checksum_address(ENTRYPOINT_V06),
            abi=ENTRYPOINT_NONCE_ABI,
        )
        return await asyncio.to_thread(
            entry_point.functions.getNonce(self._sender_address, 0).call
        )

    # Backwards-compatible private alias (existing callers used the underscore name).
    async def _read_entry_point_nonce(self) -> int:
        return await self.read_entry_point_nonce()

    async def _read_actp_nonce(self) -> int:
        """Read current ACTP nonce for the requester.

        requesterNonces is public on ACTPKernel (added in v2). Older
        deployments may not expose this -- derive the nonce from on-chain
        ``TransactionCreated`` logs (deployment-block binary search +
        adaptive chunked getLogs), falling back to 0 only as a last resort.

        Mirrors TS ``readActpNonce`` (DualNonceManager.ts:164-210).
        """
        try:
            kernel = self._w3.eth.contract(
                address=self._actp_kernel_address,
                abi=ACTP_KERNEL_NONCE_ABI,
            )
            nonce = await asyncio.to_thread(
                kernel.functions.requesterNonces(self._sender_address).call
            )
            self._cached_actp_nonce = nonce
            return nonce
        except Exception:
            # Older ACTPKernel deployments don't expose requesterNonces.
            # Derive nonce from TransactionCreated events for this requester.
            # Uses deployment-block binary search + chunked logs (avoids block-0 scans).
            logger.warning(
                "requesterNonces not available on ACTPKernel -- deriving nonce "
                "from events (older deployment?)"
            )
            try:
                latest_block = await asyncio.to_thread(
                    lambda: self._w3.eth.block_number
                )
                deployment_block = await self._find_contract_deployment_block(
                    latest_block
                )
                events = await self._count_requester_transaction_created_events(
                    deployment_block, latest_block
                )
                derived_nonce = len(events)

                logger.info(
                    "Derived ACTP nonce from TransactionCreated events: "
                    "requester=%s events=%d fromBlock=%d toBlock=%d derivedNonce=%d",
                    self._sender_address,
                    len(events),
                    deployment_block,
                    latest_block,
                    derived_nonce,
                )

                self._cached_actp_nonce = derived_nonce
                return derived_nonce
            except Exception as derive_error:
                # Last-resort fallback for very old/limited RPCs.
                logger.warning(
                    "Could not derive ACTP nonce from events -- using 0 as last "
                    "resort: %s",
                    str(derive_error),
                )
                self._cached_actp_nonce = 0
                return 0

    def set_cached_actp_nonce(self, nonce: int) -> None:
        """Override cached ACTP nonce.

        Used when caller deterministically advances the nonce (e.g. retrying
        batched creation after "Escrow ID already used" failures). Mirrors TS
        ``setCachedActpNonce`` (DualNonceManager.ts:225-227).
        """
        self._cached_actp_nonce = nonce

    async def _find_contract_deployment_block(self, latest_block: int) -> int:
        """Find ACTPKernel deployment block via binary search on getCode().

        If a known deployment block was provided at construction, it is
        validated once (code at hint AND no code at hint-1). On mismatch the
        hint is discarded and the full binary search runs.

        Mirrors TS ``findContractDeploymentBlock`` (DualNonceManager.ts:236-293).
        """

        async def get_code(block: int) -> bytes:
            return await asyncio.to_thread(
                self._w3.eth.get_code, self._actp_kernel_address, block
            )

        def has_code(code: bytes) -> bool:
            return code not in (b"", b"\x00")

        if self._cached_kernel_deployment_block is not None:
            if not self._deployment_block_validated:
                self._deployment_block_validated = True
                hint = self._cached_kernel_deployment_block
                code_at_hint = await get_code(hint)
                if not has_code(code_at_hint):
                    logger.warning(
                        "knownDeploymentBlock is invalid (no code at that block) -- "
                        "falling back to binary search: %d",
                        hint,
                    )
                    self._cached_kernel_deployment_block = None
                    # Fall through to binary search below.
                elif hint > 0:
                    code_before_hint = await get_code(hint - 1)
                    if has_code(code_before_hint):
                        logger.warning(
                            "knownDeploymentBlock is too high (code exists before "
                            "it) -- falling back to binary search: %d",
                            hint,
                        )
                        self._cached_kernel_deployment_block = None
                        # Fall through to binary search below.
                    else:
                        return hint
                else:
                    return hint  # hint == 0, can't check before
            else:
                return self._cached_kernel_deployment_block

        code_at_latest = await get_code(latest_block)
        if not has_code(code_at_latest):
            raise RuntimeError(
                f"ACTPKernel has no code at latest block {latest_block}"
            )

        low = 0
        high = latest_block
        while low < high:
            mid = (low + high) // 2
            code_at_mid = await get_code(mid)
            if not has_code(code_at_mid):
                low = mid + 1
            else:
                high = mid

        self._cached_kernel_deployment_block = low
        self._deployment_block_validated = True  # binary search result is inherently valid
        return low

    async def _count_requester_transaction_created_events(
        self, from_block: int, to_block: int
    ) -> List[Any]:
        """Count TransactionCreated logs for the requester in adaptive chunks.

        Chunking avoids RPC range limits on providers that reject very large
        log windows; the chunk size halves on range errors (10k down to 1k).

        Mirrors TS ``countRequesterTransactionCreatedEvents``
        (DualNonceManager.ts:300-341).
        """
        # Zero-padded 32-byte address topic, lowercase (matches ethers.zeroPadValue).
        requester_topic = (
            "0x" + self._sender_address.lower().replace("0x", "").rjust(64, "0")
        )
        logs: List[Any] = []

        cursor = from_block
        chunk_size = INITIAL_LOG_CHUNK_SIZE

        while cursor <= to_block:
            chunk_end = min(cursor + chunk_size - 1, to_block)
            try:
                chunk_logs = await asyncio.to_thread(
                    self._w3.eth.get_logs,
                    {
                        "address": self._actp_kernel_address,
                        "topics": [TX_CREATED_EVENT_TOPIC, None, requester_topic],
                        "fromBlock": cursor,
                        "toBlock": chunk_end,
                    },
                )
                logs.extend(chunk_logs)
                cursor = chunk_end + 1
            except Exception:
                if chunk_size <= MIN_LOG_CHUNK_SIZE:
                    raise
                chunk_size = max(MIN_LOG_CHUNK_SIZE, chunk_size // 2)
                logger.warning(
                    "TransactionCreated log scan range too large; reducing chunk "
                    "size while deriving ACTP nonce: nextChunkSize=%d fromBlock=%d "
                    "attemptedToBlock=%d",
                    chunk_size,
                    cursor,
                    chunk_end,
                )

        return logs

    def invalidate_cache(self) -> None:
        """Invalidate cached ACTP nonce (forces re-read on next operation)."""
        self._cached_actp_nonce = None
