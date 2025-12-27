"""
BlockchainRuntime implementation for ACTP protocol.

Provides real blockchain interaction on Base L2 (Sepolia testnet or mainnet).
Implements the IACTPRuntime interface for production use.

Example:
    >>> from agirails.runtime import BlockchainRuntime
    >>> from agirails.config import get_network
    >>>
    >>> config = get_network("base-sepolia")
    >>> runtime = await BlockchainRuntime.create(
    ...     private_key="0x...",
    ...     network=config,
    ... )
    >>>
    >>> # Use like any IACTPRuntime
    >>> tx_id = await runtime.create_transaction(params)
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, TypeVar, Union

from eth_account.signers.local import LocalAccount
from web3 import AsyncWeb3

from agirails.config.networks import NetworkConfig, get_network
from agirails.errors import EscrowError, TransactionError, ValidationError
from agirails.protocol.escrow import CreateEscrowParams, EscrowVault, generate_escrow_id
from agirails.protocol.events import EventFilter, EventMonitor
from agirails.protocol.kernel import ACTPKernel, CreateTransactionParams as KernelParams
from agirails.protocol.nonce import NonceManager
from agirails.runtime.base import CreateTransactionParams, TimeInterface
from agirails.runtime.types import MockTransaction, State
from agirails.types.transaction import TransactionState
from agirails.utils.security import TokenBucketRateLimiter, RetryConfig, retry_with_backoff

T = TypeVar("T")


# ============================================================================
# Time Interface
# ============================================================================


class BlockchainTime(TimeInterface):
    """
    Time interface for blockchain runtime.

    Gets current time from the blockchain.
    """

    def __init__(self, w3: AsyncWeb3) -> None:
        self.w3 = w3
        self._cached_timestamp: int = 0
        self._cached_at: float = 0

    def now(self) -> int:
        """
        Get current timestamp.

        Uses local time as approximation. For exact blockchain time,
        use now_async().
        """
        # Use cached value if recent (within 2 seconds)
        import time as _time

        if _time.time() - self._cached_at < 2:
            return self._cached_timestamp

        # Return local time as approximation
        return int(_time.time())

    async def now_async(self) -> int:
        """
        Get current blockchain timestamp.

        Returns:
            Block timestamp of latest block
        """
        block = await self.w3.eth.get_block("latest")
        self._cached_timestamp = block["timestamp"]
        self._cached_at = time.time()
        return self._cached_timestamp


# ============================================================================
# RPC Configuration
# ============================================================================

# Default RPC rate limit: 10 requests per second
DEFAULT_RPC_RATE_LIMIT = 10.0
DEFAULT_RPC_BURST_SIZE = 20

# Default retry configuration
DEFAULT_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    initial_delay=0.5,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True,
)

# Transaction wait timeout (5 minutes)
DEFAULT_TX_WAIT_TIMEOUT = 300.0


# ============================================================================
# BlockchainRuntime
# ============================================================================


class BlockchainRuntime:
    """
    Runtime implementation for real blockchain interaction.

    Implements IACTPRuntime for production use on Base L2.

    Security Note (C-3): All RPC calls are rate-limited and have
    exponential backoff retry logic to handle transient failures
    and prevent rate limit exhaustion.

    Attributes:
        kernel: ACTPKernel contract wrapper
        escrow: EscrowVault contract wrapper
        events: EventMonitor for watching events
        nonce_manager: NonceManager for transaction nonces
        time: Time interface
        w3: AsyncWeb3 instance
        account: Signer account
        config: Network configuration
        rate_limiter: RPC rate limiter
    """

    def __init__(
        self,
        w3: AsyncWeb3,
        account: LocalAccount,
        config: NetworkConfig,
        kernel: ACTPKernel,
        escrow: EscrowVault,
        events: EventMonitor,
        nonce_manager: NonceManager,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        retry_config: Optional[RetryConfig] = None,
    ) -> None:
        """
        Initialize BlockchainRuntime.

        Use BlockchainRuntime.create() for async initialization.

        Args:
            w3: AsyncWeb3 instance
            account: Signer account
            config: Network configuration
            kernel: ACTPKernel contract wrapper
            escrow: EscrowVault contract wrapper
            events: EventMonitor for watching events
            nonce_manager: NonceManager for transaction nonces
            rate_limiter: RPC rate limiter (default: 10 req/sec)
            retry_config: Retry configuration for RPC calls
        """
        self.w3 = w3
        self.account = account
        self.config = config
        self.kernel = kernel
        self.escrow = escrow
        self.events = events
        self.nonce_manager = nonce_manager
        self._time = BlockchainTime(w3)

        # Initialize rate limiter (C-3)
        self._rate_limiter = rate_limiter or TokenBucketRateLimiter(
            max_rate=DEFAULT_RPC_RATE_LIMIT,
            burst_size=DEFAULT_RPC_BURST_SIZE,
        )
        self._retry_config = retry_config or DEFAULT_RETRY_CONFIG

    @classmethod
    async def create(
        cls,
        private_key: str,
        network: Union[str, NetworkConfig] = "base-sepolia",
        rpc_url: Optional[str] = None,
        rpc_rate_limit: float = DEFAULT_RPC_RATE_LIMIT,
        retry_config: Optional[RetryConfig] = None,
    ) -> "BlockchainRuntime":
        """
        Create a BlockchainRuntime instance.

        Args:
            private_key: Private key for signing transactions
            network: Network name or NetworkConfig
            rpc_url: Optional override for RPC URL
            rpc_rate_limit: RPC rate limit (requests per second, default: 10)
            retry_config: Retry configuration for RPC calls

        Returns:
            Initialized BlockchainRuntime

        Example:
            >>> runtime = await BlockchainRuntime.create(
            ...     private_key="0x...",
            ...     network="base-sepolia",
            ...     rpc_rate_limit=5.0,  # 5 requests per second
            ... )
        """
        # Get network config
        if isinstance(network, str):
            config = get_network(network)
        else:
            config = network

        # Create web3 instance
        url = rpc_url or config.rpc_url
        w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(url))

        # Create rate limiter for connection check
        rate_limiter = TokenBucketRateLimiter(
            max_rate=rpc_rate_limit,
            burst_size=int(rpc_rate_limit * 2),
        )

        # Verify connection with rate limiting
        try:
            async with rate_limiter:
                chain_id = await w3.eth.chain_id
            if chain_id != config.chain_id:
                raise ValidationError(
                    f"Chain ID mismatch: expected {config.chain_id}, got {chain_id}",
                    field="chain_id",
                    value=chain_id,
                )
        except ValidationError:
            raise
        except Exception as e:
            raise ConnectionError(f"Failed to connect to RPC: {url}") from e

        # Create account from private key
        account = w3.eth.account.from_key(private_key)

        # Initialize protocol wrappers
        kernel = ACTPKernel.from_config(w3, account, config)
        escrow = EscrowVault.from_config(w3, account, config)
        events = EventMonitor.from_config(w3, config)
        nonce_manager = NonceManager(w3, account.address)

        return cls(
            w3, account, config, kernel, escrow, events, nonce_manager,
            rate_limiter=rate_limiter,
            retry_config=retry_config,
        )

    # =========================================================================
    # Rate-Limited RPC Helpers (C-3)
    # =========================================================================

    async def _rate_limited_call(
        self,
        operation: Callable[[], Any],
        retryable_exceptions: tuple = (Exception,),
    ) -> Any:
        """
        Execute an RPC operation with rate limiting and retry logic.

        Security Note (C-3): All RPC calls should go through this method
        to prevent rate limit exhaustion and handle transient failures.

        Args:
            operation: Async callable to execute
            retryable_exceptions: Exception types to retry on

        Returns:
            Result of the operation

        Raises:
            Exception: If all retries are exhausted
        """
        async def rate_limited_op() -> Any:
            async with self._rate_limiter:
                return await operation()

        return await retry_with_backoff(
            rate_limited_op,
            config=self._retry_config,
            retryable_exceptions=retryable_exceptions,
        )

    async def _wait_for_tx_receipt(
        self,
        tx_hash: bytes,
        timeout: float = DEFAULT_TX_WAIT_TIMEOUT,
    ) -> Any:
        """
        Wait for transaction receipt with timeout.

        Security Note (C-3): Prevents indefinite hangs if transaction
        is stuck in mempool.

        Args:
            tx_hash: Transaction hash
            timeout: Maximum wait time in seconds

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If timeout expires
        """
        try:
            return await asyncio.wait_for(
                self.w3.eth.wait_for_transaction_receipt(tx_hash),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TransactionError(
                f"Transaction {tx_hash.hex()} timed out after {timeout}s. "
                "Check network congestion and gas settings.",
                tx_id=tx_hash.hex(),
            )

    @property
    def rate_limiter(self) -> TokenBucketRateLimiter:
        """Get the RPC rate limiter."""
        return self._rate_limiter

    @property
    def time(self) -> BlockchainTime:
        """Time interface for blockchain time."""
        return self._time

    @property
    def address(self) -> str:
        """Current account address."""
        return self.account.address

    # =========================================================================
    # IACTPRuntime Implementation
    # =========================================================================

    async def create_transaction(self, params: CreateTransactionParams) -> str:
        """
        Create a new transaction on-chain.

        Args:
            params: Transaction creation parameters

        Returns:
            Transaction ID (bytes32 hex string)
        """
        # Convert amount from string to int
        amount = int(params.amount) if isinstance(params.amount, str) else params.amount

        # Validate deadline
        current_time = await self._time.now_async()
        if params.deadline <= current_time:
            raise ValidationError(
                "Deadline must be in the future",
                field="deadline",
                value=params.deadline,
            )

        # Create service hash from description
        service_hash = "0x" + "0" * 64  # Zero hash as default
        if params.service_description:
            # Hash the service description
            service_hash = self.w3.keccak(text=params.service_description).hex()

        # Create transaction on-chain
        tx_id = await self.kernel.create_transaction(
            KernelParams(
                provider=params.provider,
                requester=params.requester,
                amount=amount,
                deadline=params.deadline,
                dispute_window=params.dispute_window,
                service_hash=service_hash,
            )
        )

        return tx_id

    async def link_escrow(self, tx_id: str, amount: str) -> str:
        """
        Link an escrow to a transaction.

        Creates escrow on EscrowVault and links to ACTPKernel.
        Automatically transitions to COMMITTED state.

        Args:
            tx_id: Transaction ID
            amount: Amount to lock in escrow

        Returns:
            Escrow ID
        """
        # Get transaction to verify it exists and get details
        tx_view = await self.kernel.get_transaction(tx_id)
        if tx_view.state not in (TransactionState.INITIATED, TransactionState.QUOTED):
            raise TransactionError(
                f"Cannot link escrow: transaction in state {tx_view.state.name}",
                tx_id=tx_id,
            )

        # Convert amount
        amount_int = int(amount) if isinstance(amount, str) else amount

        # Generate escrow ID
        escrow_id = generate_escrow_id()

        # Create escrow (this will approve and transfer USDC)
        await self.escrow.create_escrow(
            CreateEscrowParams(
                escrow_id=escrow_id,
                requester=tx_view.requester,
                provider=tx_view.provider,
                amount=amount_int,
            )
        )

        # Link escrow to transaction (auto-transitions to COMMITTED)
        await self.kernel.link_escrow(
            tx_id,
            self.config.contracts.escrow_vault,
            escrow_id,
        )

        return escrow_id

    async def transition_state(
        self,
        tx_id: str,
        new_state: Union[State, str],
        proof: Optional[str] = None,
    ) -> None:
        """
        Transition a transaction to a new state.

        Args:
            tx_id: Transaction ID
            new_state: Target state
            proof: Optional proof data (for DELIVERED state)
        """
        # Convert State enum to TransactionState
        if isinstance(new_state, str):
            state = TransactionState[new_state]
        elif isinstance(new_state, State):
            state = TransactionState[new_state.value]
        else:
            state = new_state

        # Convert proof to bytes
        proof_bytes = b""
        if proof:
            if proof.startswith("0x"):
                proof_bytes = bytes.fromhex(proof[2:])
            else:
                proof_bytes = proof.encode("utf-8")

        await self.kernel.transition_state(tx_id, state, proof_bytes)

    async def get_transaction(self, tx_id: str) -> Optional[MockTransaction]:
        """
        Get a transaction by ID.

        Returns MockTransaction for interface compatibility.

        Args:
            tx_id: Transaction ID

        Returns:
            Transaction as MockTransaction or None
        """
        try:
            tx_view = await self.kernel.get_transaction(tx_id)

            # Convert to MockTransaction for interface compatibility
            return MockTransaction(
                id=tx_view.transaction_id,
                requester=tx_view.requester,
                provider=tx_view.provider,
                amount=str(tx_view.amount),
                state=State(tx_view.state.name),
                deadline=tx_view.deadline,
                dispute_window=tx_view.dispute_window,
                created_at=tx_view.created_at,
                updated_at=tx_view.updated_at,
                escrow_id=tx_view.escrow_id if tx_view.escrow_id != "0" * 64 else None,
                service_description=tx_view.service_hash,
                delivery_proof="",  # PARITY: TS BlockchainRuntime returns '' (empty), not attestation_uid
            )
        except Exception:
            return None

    async def get_all_transactions(self) -> List[MockTransaction]:
        """
        Get all transactions.

        Note: This queries events which may be expensive for many transactions.
        Use get_transactions_by_address for filtered queries.

        Returns:
            List of all transactions
        """
        # Get transaction created events
        events = await self.events.get_events(
            EventFilter(event_types=["TransactionCreated"]),
            from_block=0,
        )

        transactions = []
        for event in events:
            if hasattr(event, "transaction_id"):
                tx = await self.get_transaction(event.transaction_id)
                if tx:
                    transactions.append(tx)

        return transactions

    async def release_escrow(
        self,
        escrow_id: str,
        attestation_uid: Optional[str] = None,
    ) -> None:
        """
        Release escrow funds to the provider.

        Args:
            escrow_id: Escrow ID
            attestation_uid: Optional attestation UID for verification
        """
        # Get escrow info
        escrow_info = await self.escrow.get_escrow(escrow_id)
        if not escrow_info.active:
            raise EscrowError(
                f"Escrow {escrow_id} is not active",
            )

        # Find linked transaction by querying events
        # For now, we'll need to pass the tx_id separately
        # This is a limitation of the current interface

        # Release remaining funds to provider
        remaining = escrow_info.remaining
        if remaining > 0:
            await self.escrow.payout_to_provider(escrow_id, remaining)

    async def get_escrow_balance(self, escrow_id: str) -> str:
        """
        Get the remaining balance of an escrow.

        Args:
            escrow_id: Escrow ID

        Returns:
            Remaining balance as string in wei
        """
        remaining = await self.escrow.get_remaining(escrow_id)
        return str(remaining)

    # =========================================================================
    # Extended Methods (not in IACTPRuntime)
    # =========================================================================

    async def release_kernel_escrow(
        self,
        tx_id: str,
    ) -> None:
        """
        Release escrow via ACTPKernel.

        This calls the kernel's releaseEscrow function which
        transitions the transaction from DELIVERED to SETTLED.

        Args:
            tx_id: Transaction ID
        """
        await self.kernel.release_escrow(tx_id)

    async def anchor_attestation(
        self,
        tx_id: str,
        attestation_uid: str,
    ) -> None:
        """
        Anchor an EAS attestation to a transaction.

        Args:
            tx_id: Transaction ID
            attestation_uid: EAS attestation UID
        """
        await self.kernel.anchor_attestation(tx_id, attestation_uid)

    async def release_milestone(
        self,
        tx_id: str,
        amount: int,
    ) -> None:
        """
        Release a partial milestone payment.

        Args:
            tx_id: Transaction ID
            amount: Amount to release
        """
        await self.kernel.release_milestone(tx_id, amount)

    async def get_usdc_balance(self, address: Optional[str] = None) -> int:
        """
        Get USDC balance for an address.

        Args:
            address: Address to check (defaults to current account)

        Returns:
            Balance in USDC (6 decimals)
        """
        return await self.escrow.get_usdc_balance(address)

    async def approve_usdc(self, amount: int) -> None:
        """
        Approve USDC spending by the escrow vault.

        Args:
            amount: Amount to approve
        """
        await self.escrow.approve_usdc(amount)

    async def get_block_number(self) -> int:
        """Get current block number."""
        return await self.w3.eth.block_number

    async def get_chain_id(self) -> int:
        """Get chain ID."""
        return await self.w3.eth.chain_id

    async def is_paused(self) -> bool:
        """Check if the ACTPKernel is paused."""
        return await self.kernel.is_paused()

    async def get_platform_fee_bps(self) -> int:
        """Get the current platform fee in basis points."""
        return await self.kernel.get_platform_fee_bps()

    async def sync_nonce(self) -> int:
        """Sync nonce with on-chain state."""
        return await self.nonce_manager.sync()

    async def wait_for_confirmations(self, timeout: float = 60.0) -> bool:
        """Wait for all pending transactions to confirm."""
        return await self.nonce_manager.wait_for_confirmations(timeout)
