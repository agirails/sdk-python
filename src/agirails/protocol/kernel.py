"""
ACTPKernel contract wrapper.

Provides async methods for interacting with the ACTP protocol kernel contract
on Base L2. Handles transaction creation, state transitions, escrow linking,
and attestation anchoring.

Example:
    >>> from web3 import AsyncWeb3
    >>> from agirails.protocol import ACTPKernel
    >>> from agirails.config import get_network
    >>>
    >>> config = get_network("base-sepolia")
    >>> w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config.rpc_url))
    >>> account = w3.eth.account.from_key(private_key)
    >>> kernel = ACTPKernel.from_config(w3, account, config)
    >>>
    >>> tx_id = await kernel.create_transaction(
    ...     provider="0x...",
    ...     amount=1000000,  # 1 USDC
    ...     deadline=int(time.time()) + 86400,
    ... )
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from eth_account.signers.local import LocalAccount
from web3 import AsyncWeb3
from web3.contract import AsyncContract
from web3.types import TxReceipt, Wei

from agirails.config.networks import NetworkConfig
from agirails.errors import TransactionError, ValidationError
from agirails.types.transaction import Transaction, TransactionReceipt, TransactionState


# ============================================================================
# Constants
# ============================================================================

# Zero values for optional parameters
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ZERO_BYTES32 = "0x" + "0" * 64

# Security Note (M-3): Default timeout for transaction receipts (5 minutes)
DEFAULT_TX_WAIT_TIMEOUT = 300.0

# Default values
DEFAULT_DISPUTE_WINDOW = 48 * 3600  # 48 hours in seconds
DEFAULT_DEADLINE_HOURS = 24  # 24 hours

# Security Note (L-5): Gas limits are configurable via environment variables
# to handle network congestion. Format: AGIRAILS_GAS_<OPERATION>=<LIMIT>
# Example: AGIRAILS_GAS_CREATE_TRANSACTION=300000


def _get_gas_limit(operation: str, default: int) -> int:
    """
    Get gas limit from environment variable or use default.

    Security Note (L-5): Allows gas limit overrides for network congestion.

    Args:
        operation: Operation name (e.g., "create_transaction")
        default: Default gas limit if not set

    Returns:
        Gas limit (from env or default)
    """
    env_key = f"AGIRAILS_GAS_{operation.upper()}"
    env_value = os.environ.get(env_key)
    if env_value:
        try:
            limit = int(env_value)
            if limit > 0:
                return limit
        except ValueError:
            pass
    return default


# Default gas limits for different operations
_DEFAULT_GAS_LIMITS = {
    "create_transaction": 200_000,
    "transition_state": 150_000,
    "link_escrow": 150_000,
    "release_escrow": 200_000,
    "anchor_attestation": 100_000,
    "release_milestone": 150_000,
}

# Build actual gas limits with environment overrides
GAS_LIMITS = {
    op: _get_gas_limit(op, default)
    for op, default in _DEFAULT_GAS_LIMITS.items()
}


# ============================================================================
# Types
# ============================================================================


@dataclass
class CreateTransactionParams:
    """
    Parameters for creating a new transaction.

    Attributes:
        provider: Provider's Ethereum address
        requester: Requester's Ethereum address (defaults to sender)
        amount: Amount in USDC (6 decimals, e.g., 1000000 = 1 USDC)
        deadline: Transaction deadline (Unix timestamp)
        dispute_window: Dispute window in seconds (default: 48 hours)
        service_hash: Hash of service description (bytes32)
    """

    provider: str
    amount: int
    deadline: int
    requester: Optional[str] = None
    dispute_window: int = DEFAULT_DISPUTE_WINDOW
    service_hash: str = ZERO_BYTES32

    def __post_init__(self) -> None:
        """Validate parameters after initialization."""
        if not self.provider or not self.provider.startswith("0x"):
            raise ValidationError(
                "Provider must be a valid Ethereum address",
                field="provider",
                value=self.provider,
            )

        if self.amount <= 0:
            raise ValidationError(
                "Amount must be greater than 0",
                field="amount",
                value=self.amount,
            )

        if self.deadline <= int(time.time()):
            raise ValidationError(
                "Deadline must be in the future",
                field="deadline",
                value=self.deadline,
            )


@dataclass
class TransactionView:
    """
    On-chain transaction view from getTransaction().

    Maps to the TransactionView struct in the ACTPKernel contract.
    """

    transaction_id: str
    requester: str
    provider: str
    state: TransactionState
    amount: int
    created_at: int
    updated_at: int
    deadline: int
    service_hash: str
    escrow_contract: str
    escrow_id: str
    attestation_uid: str
    dispute_window: int
    metadata: str
    platform_fee_bps_locked: int

    def to_transaction(self) -> Transaction:
        """Convert to Transaction type."""
        return Transaction(
            id=self.transaction_id,
            state=self.state,
            requester=self.requester,
            provider=self.provider,
            amount=self.amount,
            deadline=self.deadline,
            dispute_window=self.dispute_window,
            input_hash=self.service_hash,
            attestation_uid=self.attestation_uid,
            created_at=datetime.fromtimestamp(self.created_at),
            updated_at=datetime.fromtimestamp(self.updated_at),
            metadata={"platformFeeBpsLocked": self.platform_fee_bps_locked},
        )

    @classmethod
    def from_tuple(cls, data: Tuple) -> "TransactionView":
        """Create from contract return tuple."""
        return cls(
            transaction_id=data[0].hex() if isinstance(data[0], bytes) else data[0],
            requester=data[1],
            provider=data[2],
            state=TransactionState(data[3]),
            amount=data[4],
            created_at=data[5],
            updated_at=data[6],
            deadline=data[7],
            service_hash=data[8].hex() if isinstance(data[8], bytes) else data[8],
            escrow_contract=data[9],
            escrow_id=data[10].hex() if isinstance(data[10], bytes) else data[10],
            attestation_uid=data[11].hex() if isinstance(data[11], bytes) else data[11],
            dispute_window=data[12],
            metadata=data[13].hex() if isinstance(data[13], bytes) else data[13],
            platform_fee_bps_locked=data[14],
        )


# ============================================================================
# ACTPKernel Contract Wrapper
# ============================================================================


class ACTPKernel:
    """
    ACTPKernel contract wrapper for ACTP protocol interactions.

    Provides async methods for all kernel contract operations including
    transaction creation, state transitions, and escrow management.

    Attributes:
        contract: The web3 contract instance
        account: The account used for signing transactions
        w3: The AsyncWeb3 instance
        chain_id: The chain ID of the network
    """

    def __init__(
        self,
        contract: AsyncContract,
        account: LocalAccount,
        w3: AsyncWeb3,
        chain_id: int,
    ) -> None:
        """
        Initialize ACTPKernel wrapper.

        Args:
            contract: The ACTPKernel contract instance
            account: The account for signing transactions
            w3: The AsyncWeb3 instance
            chain_id: The chain ID of the network
        """
        self.contract = contract
        self.account = account
        self.w3 = w3
        self.chain_id = chain_id

    @classmethod
    def from_config(
        cls,
        w3: AsyncWeb3,
        account: LocalAccount,
        config: NetworkConfig,
    ) -> "ACTPKernel":
        """
        Create ACTPKernel from network configuration.

        Args:
            w3: The AsyncWeb3 instance
            account: The account for signing transactions
            config: Network configuration with contract addresses

        Returns:
            Initialized ACTPKernel instance

        Example:
            >>> config = get_network("base-sepolia")
            >>> kernel = ACTPKernel.from_config(w3, account, config)
        """
        abi = cls._load_abi()
        contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.actp_kernel),
            abi=abi,
        )
        return cls(contract, account, w3, config.chain_id)

    @staticmethod
    def _load_abi() -> List[Dict[str, Any]]:
        """Load the ACTPKernel ABI from the abis directory."""
        abi_path = Path(__file__).parent.parent / "abis" / "actp_kernel.json"
        with open(abi_path) as f:
            return json.load(f)

    # =========================================================================
    # Transaction Creation
    # =========================================================================

    async def create_transaction(
        self,
        params: Union[CreateTransactionParams, Dict[str, Any]],
        gas_limit: Optional[int] = None,
        max_fee_per_gas: Optional[int] = None,
        max_priority_fee_per_gas: Optional[int] = None,
    ) -> str:
        """
        Create a new ACTP transaction.

        Args:
            params: Transaction parameters (CreateTransactionParams or dict)
            gas_limit: Optional gas limit override
            max_fee_per_gas: Optional max fee per gas override
            max_priority_fee_per_gas: Optional priority fee override

        Returns:
            The transaction ID (bytes32 hex string)

        Raises:
            TransactionError: If the transaction fails
            ValidationError: If parameters are invalid

        Example:
            >>> tx_id = await kernel.create_transaction(
            ...     CreateTransactionParams(
            ...         provider="0x...",
            ...         amount=1000000,
            ...         deadline=int(time.time()) + 86400,
            ...     )
            ... )
        """
        # Convert dict to dataclass if needed
        if isinstance(params, dict):
            params = CreateTransactionParams(**params)

        # Use sender address as requester if not specified
        requester = params.requester or self.account.address

        # Convert service_hash to bytes32
        service_hash = self._to_bytes32(params.service_hash)

        # Build transaction
        tx = await self.contract.functions.createTransaction(
            params.provider,
            requester,
            params.amount,
            params.deadline,
            params.dispute_window,
            service_hash,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["create_transaction"],
                max_fee_per_gas=max_fee_per_gas,
                max_priority_fee_per_gas=max_priority_fee_per_gas,
            )
        )

        # Sign and send transaction
        receipt = await self._sign_and_send(tx)

        # Extract transaction ID from logs
        tx_id = self._extract_transaction_id(receipt)
        return tx_id

    # =========================================================================
    # State Transitions
    # =========================================================================

    async def transition_state(
        self,
        transaction_id: str,
        new_state: TransactionState,
        proof: bytes = b"",
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Transition a transaction to a new state.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            new_state: The target state
            proof: Optional proof data (for DELIVERED state)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If the transition fails

        Example:
            >>> await kernel.transition_state(
            ...     tx_id,
            ...     TransactionState.DELIVERED,
            ...     proof=delivery_proof_bytes,
            ... )
        """
        tx_id_bytes = self._to_bytes32(transaction_id)

        tx = await self.contract.functions.transitionState(
            tx_id_bytes,
            new_state.value,
            proof,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["transition_state"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    # =========================================================================
    # Escrow Management
    # =========================================================================

    async def link_escrow(
        self,
        transaction_id: str,
        escrow_contract: str,
        escrow_id: str,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Link an escrow to a transaction.

        This automatically transitions the transaction to COMMITTED state.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            escrow_contract: The escrow vault contract address
            escrow_id: The escrow ID (bytes32 hex string)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Example:
            >>> await kernel.link_escrow(tx_id, escrow_address, escrow_id)
        """
        tx_id_bytes = self._to_bytes32(transaction_id)
        escrow_id_bytes = self._to_bytes32(escrow_id)

        tx = await self.contract.functions.linkEscrow(
            tx_id_bytes,
            escrow_contract,
            escrow_id_bytes,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["link_escrow"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def release_escrow(
        self,
        transaction_id: str,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Release escrow funds after delivery.

        Transitions the transaction from DELIVERED to SETTLED state.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Example:
            >>> await kernel.release_escrow(tx_id)
        """
        tx_id_bytes = self._to_bytes32(transaction_id)

        tx = await self.contract.functions.releaseEscrow(
            tx_id_bytes,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["release_escrow"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def release_milestone(
        self,
        transaction_id: str,
        amount: int,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Release a partial milestone payment.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            amount: The amount to release in USDC (6 decimals)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Example:
            >>> await kernel.release_milestone(tx_id, 500000)  # 0.5 USDC
        """
        tx_id_bytes = self._to_bytes32(transaction_id)

        tx = await self.contract.functions.releaseMilestone(
            tx_id_bytes,
            amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["release_milestone"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    # =========================================================================
    # Attestation
    # =========================================================================

    async def anchor_attestation(
        self,
        transaction_id: str,
        attestation_uid: str,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Anchor an EAS attestation to a transaction.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            attestation_uid: The EAS attestation UID (bytes32 hex string)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Example:
            >>> await kernel.anchor_attestation(tx_id, attestation_uid)
        """
        tx_id_bytes = self._to_bytes32(transaction_id)
        attestation_bytes = self._to_bytes32(attestation_uid)

        tx = await self.contract.functions.anchorAttestation(
            tx_id_bytes,
            attestation_bytes,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["anchor_attestation"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    # =========================================================================
    # Read Operations
    # =========================================================================

    async def get_transaction(self, transaction_id: str) -> TransactionView:
        """
        Get transaction details from the contract.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)

        Returns:
            TransactionView with all on-chain transaction data

        Example:
            >>> tx_view = await kernel.get_transaction(tx_id)
            >>> print(f"State: {tx_view.state.name}")
        """
        tx_id_bytes = self._to_bytes32(transaction_id)
        result = await self.contract.functions.getTransaction(tx_id_bytes).call()
        return TransactionView.from_tuple(result)

    async def get_platform_fee_bps(self) -> int:
        """Get the current platform fee in basis points."""
        return await self.contract.functions.platformFeeBps().call()

    async def get_min_transaction_amount(self) -> int:
        """Get the minimum transaction amount in USDC."""
        return await self.contract.functions.MIN_TRANSACTION_AMOUNT().call()

    async def get_max_transaction_amount(self) -> int:
        """Get the maximum transaction amount in USDC."""
        return await self.contract.functions.MAX_TRANSACTION_AMOUNT().call()

    async def get_default_dispute_window(self) -> int:
        """Get the default dispute window in seconds."""
        return await self.contract.functions.DEFAULT_DISPUTE_WINDOW().call()

    async def is_paused(self) -> bool:
        """Check if the contract is paused."""
        return await self.contract.functions.paused().call()

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _build_tx_params(
        self,
        gas_limit: int,
        max_fee_per_gas: Optional[int] = None,
        max_priority_fee_per_gas: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Build transaction parameters."""
        nonce = await self.w3.eth.get_transaction_count(self.account.address)

        # Get gas prices if not provided
        if max_fee_per_gas is None or max_priority_fee_per_gas is None:
            block = await self.w3.eth.get_block("latest")
            base_fee = block.get("baseFeePerGas", 1_000_000_000)  # 1 gwei fallback

            if max_priority_fee_per_gas is None:
                max_priority_fee_per_gas = 1_000_000_000  # 1 gwei

            if max_fee_per_gas is None:
                # 2x base fee + priority fee
                max_fee_per_gas = (base_fee * 2) + max_priority_fee_per_gas

        return {
            "from": self.account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "chainId": self.chain_id,
        }

    async def _sign_and_send(
        self,
        tx: Dict[str, Any],
        timeout: float = DEFAULT_TX_WAIT_TIMEOUT,
    ) -> TxReceipt:
        """
        Sign and send a transaction, waiting for receipt.

        Security Note (M-3): Uses timeout to prevent indefinite hangs.

        Args:
            tx: Transaction dictionary
            timeout: Max seconds to wait for receipt (default: 300s)

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If transaction fails or times out
        """
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        tx_hash = await self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        try:
            receipt = await asyncio.wait_for(
                self.w3.eth.wait_for_transaction_receipt(tx_hash),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TransactionError(
                f"Transaction {tx_hash.hex()} timed out after {timeout}s. "
                "Check network congestion and gas settings.",
                tx_id=tx_hash.hex(),
            )

        if receipt["status"] != 1:
            raise TransactionError(
                f"Transaction failed: {tx_hash.hex()}",
                tx_id=tx_hash.hex(),
            )

        return receipt

    def _to_bytes32(self, value: str) -> bytes:
        """Convert hex string to bytes32."""
        if value.startswith("0x"):
            value = value[2:]

        # Pad to 32 bytes if needed
        value = value.zfill(64)
        return bytes.fromhex(value)

    def _extract_transaction_id(self, receipt: TxReceipt) -> str:
        """Extract transaction ID from TransactionCreated event."""
        # Look for TransactionCreated event
        for log in receipt.get("logs", []):
            if log["address"].lower() == self.contract.address.lower():
                # TransactionCreated event has transactionId as first indexed topic
                if len(log.get("topics", [])) >= 2:
                    tx_id = log["topics"][1]
                    if isinstance(tx_id, bytes):
                        return "0x" + tx_id.hex()
                    return tx_id

        raise TransactionError(
            "Could not extract transaction ID from receipt",
            tx_id=receipt.get("transactionHash", "unknown"),
        )

    def _to_receipt(self, receipt: TxReceipt) -> TransactionReceipt:
        """Convert web3 receipt to TransactionReceipt."""
        return TransactionReceipt(
            transaction_hash=receipt["transactionHash"].hex()
            if isinstance(receipt["transactionHash"], bytes)
            else receipt["transactionHash"],
            block_number=receipt["blockNumber"],
            block_hash=receipt["blockHash"].hex()
            if isinstance(receipt["blockHash"], bytes)
            else receipt["blockHash"],
            gas_used=receipt["gasUsed"],
            effective_gas_price=receipt.get("effectiveGasPrice", 0),
            status=receipt["status"],
            logs=[dict(log) for log in receipt.get("logs", [])],
        )
