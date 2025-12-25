"""
EscrowVault contract wrapper.

Provides async methods for interacting with the ACTP escrow vault contract
on Base L2. Handles escrow creation, fund management, and payouts.

The EscrowVault holds USDC funds during transactions and releases them
based on ACTPKernel state transitions.

Example:
    >>> from web3 import AsyncWeb3
    >>> from agirails.protocol import EscrowVault
    >>> from agirails.config import get_network
    >>>
    >>> config = get_network("base-sepolia")
    >>> w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config.rpc_url))
    >>> account = w3.eth.account.from_key(private_key)
    >>> escrow = EscrowVault.from_config(w3, account, config)
    >>>
    >>> # Create and fund escrow
    >>> escrow_id = await escrow.create_escrow(
    ...     requester="0x...",
    ...     provider="0x...",
    ...     amount=1000000,  # 1 USDC
    ... )
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from eth_account.signers.local import LocalAccount
from web3 import AsyncWeb3
from web3.contract import AsyncContract
from web3.types import TxReceipt

from agirails.config.networks import NetworkConfig
from agirails.errors import TransactionError, ValidationError
from agirails.types.transaction import TransactionReceipt


# ============================================================================
# Constants
# ============================================================================

# Gas limits for escrow operations
GAS_LIMITS = {
    "create_escrow": 200_000,
    "payout": 150_000,
    "payout_to_provider": 150_000,
    "refund_to_requester": 150_000,
    "approve_usdc": 100_000,
}


# ============================================================================
# Types
# ============================================================================


@dataclass
class EscrowInfo:
    """
    Information about an escrow from the contract.

    Attributes:
        escrow_id: The escrow ID (bytes32 hex string)
        requester: The requester's address
        provider: The provider's address
        amount: The original escrow amount
        released_amount: Amount already released
        active: Whether the escrow is still active
    """

    escrow_id: str
    requester: str
    provider: str
    amount: int
    released_amount: int
    active: bool

    @property
    def remaining(self) -> int:
        """Calculate remaining balance in escrow."""
        return self.amount - self.released_amount

    @property
    def amount_usdc(self) -> float:
        """Get amount in USDC (human-readable)."""
        return self.amount / 1_000_000

    @property
    def released_usdc(self) -> float:
        """Get released amount in USDC (human-readable)."""
        return self.released_amount / 1_000_000

    @property
    def remaining_usdc(self) -> float:
        """Get remaining balance in USDC (human-readable)."""
        return self.remaining / 1_000_000

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "escrowId": self.escrow_id,
            "requester": self.requester,
            "provider": self.provider,
            "amount": self.amount,
            "amountUsdc": self.amount_usdc,
            "releasedAmount": self.released_amount,
            "releasedUsdc": self.released_usdc,
            "remaining": self.remaining,
            "remainingUsdc": self.remaining_usdc,
            "active": self.active,
        }


@dataclass
class CreateEscrowParams:
    """
    Parameters for creating a new escrow.

    Attributes:
        requester: Requester's Ethereum address
        provider: Provider's Ethereum address
        amount: Amount in USDC (6 decimals)
        escrow_id: Optional escrow ID (generated if not provided)
    """

    requester: str
    provider: str
    amount: int
    escrow_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate parameters and generate escrow ID if needed."""
        if not self.requester or not self.requester.startswith("0x"):
            raise ValidationError(
                "Requester must be a valid Ethereum address",
                field="requester",
                value=self.requester,
            )

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

        # Generate escrow ID if not provided
        if self.escrow_id is None:
            self.escrow_id = "0x" + secrets.token_hex(32)


# ============================================================================
# EscrowVault Contract Wrapper
# ============================================================================


class EscrowVault:
    """
    EscrowVault contract wrapper for fund management.

    Provides async methods for creating escrows, managing payouts,
    and querying escrow state.

    Attributes:
        contract: The web3 contract instance
        usdc_contract: The USDC token contract instance
        account: The account used for signing transactions
        w3: The AsyncWeb3 instance
        chain_id: The chain ID of the network
    """

    def __init__(
        self,
        contract: AsyncContract,
        usdc_contract: AsyncContract,
        account: LocalAccount,
        w3: AsyncWeb3,
        chain_id: int,
    ) -> None:
        """
        Initialize EscrowVault wrapper.

        Args:
            contract: The EscrowVault contract instance
            usdc_contract: The USDC token contract instance
            account: The account for signing transactions
            w3: The AsyncWeb3 instance
            chain_id: The chain ID of the network
        """
        self.contract = contract
        self.usdc_contract = usdc_contract
        self.account = account
        self.w3 = w3
        self.chain_id = chain_id

    @classmethod
    def from_config(
        cls,
        w3: AsyncWeb3,
        account: LocalAccount,
        config: NetworkConfig,
    ) -> "EscrowVault":
        """
        Create EscrowVault from network configuration.

        Args:
            w3: The AsyncWeb3 instance
            account: The account for signing transactions
            config: Network configuration with contract addresses

        Returns:
            Initialized EscrowVault instance

        Example:
            >>> config = get_network("base-sepolia")
            >>> escrow = EscrowVault.from_config(w3, account, config)
        """
        escrow_abi = cls._load_abi("escrow_vault.json")
        usdc_abi = cls._load_abi("usdc.json")

        escrow_contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.escrow_vault),
            abi=escrow_abi,
        )

        usdc_contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.usdc),
            abi=usdc_abi,
        )

        return cls(escrow_contract, usdc_contract, account, w3, config.chain_id)

    @staticmethod
    def _load_abi(filename: str) -> List[Dict[str, Any]]:
        """Load an ABI from the abis directory."""
        abi_path = Path(__file__).parent.parent / "abis" / filename
        with open(abi_path) as f:
            return json.load(f)

    # =========================================================================
    # Escrow Creation
    # =========================================================================

    async def create_escrow(
        self,
        params: CreateEscrowParams,
        auto_approve: bool = True,
        gas_limit: Optional[int] = None,
    ) -> str:
        """
        Create a new escrow and fund it with USDC.

        Args:
            params: Escrow creation parameters
            auto_approve: Whether to approve USDC transfer automatically
            gas_limit: Optional gas limit override

        Returns:
            The escrow ID (bytes32 hex string)

        Raises:
            TransactionError: If the transaction fails

        Example:
            >>> escrow_id = await escrow.create_escrow(
            ...     CreateEscrowParams(
            ...         requester="0x...",
            ...         provider="0x...",
            ...         amount=1000000,  # 1 USDC
            ...     )
            ... )
        """
        # Approve USDC transfer if needed
        if auto_approve:
            await self.approve_usdc(params.amount)

        # Convert escrow_id to bytes32
        escrow_id_bytes = self._to_bytes32(params.escrow_id)

        # Build transaction
        tx = await self.contract.functions.createEscrow(
            escrow_id_bytes,
            params.requester,
            params.provider,
            params.amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["create_escrow"],
            )
        )

        # Sign and send transaction
        await self._sign_and_send(tx)

        return params.escrow_id

    async def approve_usdc(
        self,
        amount: int,
        spender: Optional[str] = None,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Approve USDC spending by the escrow vault.

        Args:
            amount: Amount to approve in USDC (6 decimals)
            spender: Optional spender address (defaults to escrow vault)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Example:
            >>> await escrow.approve_usdc(1000000)  # Approve 1 USDC
        """
        spender = spender or self.contract.address

        tx = await self.usdc_contract.functions.approve(
            spender,
            amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["approve_usdc"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    # =========================================================================
    # Payouts
    # =========================================================================

    async def payout(
        self,
        escrow_id: str,
        recipient: str,
        amount: int,
        gas_limit: Optional[int] = None,
    ) -> Tuple[int, TransactionReceipt]:
        """
        Release funds to a specified recipient.

        Note: This is typically called by the ACTPKernel, not directly.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)
            recipient: The recipient address
            amount: Amount to release in USDC (6 decimals)
            gas_limit: Optional gas limit override

        Returns:
            Tuple of (amount released, transaction receipt)
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)

        tx = await self.contract.functions.payout(
            escrow_id_bytes,
            recipient,
            amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["payout"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return amount, self._to_receipt(receipt)

    async def payout_to_provider(
        self,
        escrow_id: str,
        amount: int,
        gas_limit: Optional[int] = None,
    ) -> Tuple[int, TransactionReceipt]:
        """
        Release funds to the provider.

        Note: This is typically called by the ACTPKernel, not directly.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)
            amount: Amount to release in USDC (6 decimals)
            gas_limit: Optional gas limit override

        Returns:
            Tuple of (amount released, transaction receipt)
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)

        tx = await self.contract.functions.payoutToProvider(
            escrow_id_bytes,
            amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["payout_to_provider"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return amount, self._to_receipt(receipt)

    async def refund_to_requester(
        self,
        escrow_id: str,
        amount: int,
        gas_limit: Optional[int] = None,
    ) -> Tuple[int, TransactionReceipt]:
        """
        Refund funds to the requester.

        Note: This is typically called by the ACTPKernel, not directly.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)
            amount: Amount to refund in USDC (6 decimals)
            gas_limit: Optional gas limit override

        Returns:
            Tuple of (amount refunded, transaction receipt)
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)

        tx = await self.contract.functions.refundToRequester(
            escrow_id_bytes,
            amount,
        ).build_transaction(
            await self._build_tx_params(
                gas_limit=gas_limit or GAS_LIMITS["refund_to_requester"],
            )
        )

        receipt = await self._sign_and_send(tx)
        return amount, self._to_receipt(receipt)

    # =========================================================================
    # Read Operations
    # =========================================================================

    async def get_escrow(self, escrow_id: str) -> EscrowInfo:
        """
        Get escrow information from the contract.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)

        Returns:
            EscrowInfo with escrow details

        Example:
            >>> info = await escrow.get_escrow(escrow_id)
            >>> print(f"Remaining: ${info.remaining_usdc}")
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)
        result = await self.contract.functions.escrows(escrow_id_bytes).call()

        return EscrowInfo(
            escrow_id=escrow_id,
            requester=result[0],
            provider=result[1],
            amount=result[2],
            released_amount=result[3],
            active=result[4],
        )

    async def get_remaining(self, escrow_id: str) -> int:
        """
        Get remaining balance in an escrow.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)

        Returns:
            Remaining amount in USDC (6 decimals)
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)
        return await self.contract.functions.remaining(escrow_id_bytes).call()

    async def verify_escrow(
        self,
        escrow_id: str,
        requester: str,
        provider: str,
        amount: int,
    ) -> Tuple[bool, int]:
        """
        Verify an escrow matches expected parameters.

        Args:
            escrow_id: The escrow ID (bytes32 hex string)
            requester: Expected requester address
            provider: Expected provider address
            amount: Expected amount

        Returns:
            Tuple of (is_active, escrow_amount)
        """
        escrow_id_bytes = self._to_bytes32(escrow_id)
        result = await self.contract.functions.verifyEscrow(
            escrow_id_bytes,
            requester,
            provider,
            amount,
        ).call()
        return result[0], result[1]

    async def get_usdc_balance(self, address: Optional[str] = None) -> int:
        """
        Get USDC balance for an address.

        Args:
            address: Address to check (defaults to current account)

        Returns:
            Balance in USDC (6 decimals)
        """
        address = address or self.account.address
        return await self.usdc_contract.functions.balanceOf(address).call()

    async def get_usdc_allowance(
        self,
        owner: Optional[str] = None,
        spender: Optional[str] = None,
    ) -> int:
        """
        Get USDC allowance for spender.

        Args:
            owner: Token owner address (defaults to current account)
            spender: Spender address (defaults to escrow vault)

        Returns:
            Allowance in USDC (6 decimals)
        """
        owner = owner or self.account.address
        spender = spender or self.contract.address
        return await self.usdc_contract.functions.allowance(owner, spender).call()

    async def get_token_address(self) -> str:
        """Get the USDC token address used by the vault."""
        return await self.contract.functions.token().call()

    async def get_kernel_address(self) -> str:
        """Get the ACTPKernel address linked to the vault."""
        return await self.contract.functions.kernel().call()

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

    async def _sign_and_send(self, tx: Dict[str, Any]) -> TxReceipt:
        """Sign and send a transaction, waiting for receipt."""
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        tx_hash = await self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash)

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


def generate_escrow_id() -> str:
    """Generate a random escrow ID (bytes32 hex string)."""
    return "0x" + secrets.token_hex(32)
