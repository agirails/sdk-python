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
from agirails.errors import (
    InvalidStateTransitionError,
    TransactionError,
    TransactionNotFoundError,
    ValidationError,
)
from agirails.protocol.base import ContractBase
from agirails.protocol.nonce import NonceManager
from agirails.types.transaction import Transaction, TransactionReceipt, TransactionState


# ============================================================================
# Constants
# ============================================================================

# Zero values for optional parameters
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ZERO_BYTES32 = "0x" + "0" * 64

# Legacy 16-field getTransaction shape — matches what's deployed on Base
# Mainnet (kernel 0x132B…2d29, deployed 2026-02-09) and what was canonical
# through SDK 2.7.0. The current 21-field ABI doesn't decode against the
# older deployment, so this is used as a fallback when the primary call
# returns a decode failure (BAD_DATA). PARITY: ACTPKernel.ts:5-19.
_LEGACY_GET_TRANSACTION_ABI: List[Dict[str, Any]] = [
    {
        "inputs": [{"name": "transactionId", "type": "bytes32"}],
        "name": "getTransaction",
        "outputs": [
            {
                "components": [
                    {"name": "transactionId", "type": "bytes32"},
                    {"name": "requester", "type": "address"},
                    {"name": "provider", "type": "address"},
                    {"name": "state", "type": "uint8"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "createdAt", "type": "uint256"},
                    {"name": "updatedAt", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                    {"name": "serviceHash", "type": "bytes32"},
                    {"name": "escrowContract", "type": "address"},
                    {"name": "escrowId", "type": "bytes32"},
                    {"name": "attestationUID", "type": "bytes32"},
                    {"name": "disputeWindow", "type": "uint256"},
                    {"name": "metadata", "type": "bytes32"},
                    {"name": "platformFeeBpsLocked", "type": "uint16"},
                    {"name": "agentId", "type": "uint256"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    }
]

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
    "create_transaction": 300_000,  # Actual: ~240k, with buffer
    "transition_state": 200_000,  # Increased for safety
    "link_escrow": 350_000,  # Actual: ~280k (creates escrow + state transition)
    "release_escrow": 300_000,  # Increased for safety
    "anchor_attestation": 200_000,  # Increased for safety
    "release_milestone": 250_000,  # Increased for safety
    # PARITY: Dispute operations (matches TS SDK gas floors)
    "raise_dispute": 200_000,  # Large proof data handling
    "resolve_dispute": 350_000,  # Complex multi-party settlement
    "accept_quote": 200_000,  # Quote acceptance + amount update
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
        agent_id: ERC-8004 agent ID for provider (0 if not applicable)
    """

    provider: str
    amount: int
    deadline: int
    requester: Optional[str] = None
    dispute_window: int = DEFAULT_DISPUTE_WINDOW
    service_hash: str = ZERO_BYTES32
    agent_id: int = 0
    requester_agent_id: int = 0  # AIP-14: Requester's ERC-8004 agent ID

    @staticmethod
    def _is_valid_address(addr: str) -> bool:
        """Check if string is a valid Ethereum address (0x + 40 hex chars)."""
        if not addr or len(addr) != 42 or not addr.startswith("0x"):
            return False
        try:
            int(addr, 16)
            return True
        except ValueError:
            return False

    def __post_init__(self) -> None:
        """Validate parameters after initialization."""
        if not self._is_valid_address(self.provider or ""):
            raise ValidationError(
                "Provider must be a valid Ethereum address (0x + 40 hex chars)",
                field="provider",
                value=self.provider,
            )

        if self.requester and not self._is_valid_address(self.requester):
            raise ValidationError(
                "Requester must be a valid Ethereum address (0x + 40 hex chars)",
                field="requester",
                value=self.requester,
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
    requester_penalty_bps_locked: int = 0  # AIP-14 / d9c6e8e: locked penalty rate at tx creation
    dispute_bond_bps_locked: int = 0  # INV-30: locked dispute bond rate at tx creation
    agent_id: int = 0
    requester_agent_id: int = 0  # AIP-14
    dispute_initiator: str = ""  # AIP-14
    dispute_bond: int = 0  # AIP-14

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
            metadata={
                "platformFeeBpsLocked": self.platform_fee_bps_locked,
                "requesterPenaltyBpsLocked": self.requester_penalty_bps_locked,
                "disputeBondBpsLocked": self.dispute_bond_bps_locked,
            },
        )

    @classmethod
    def from_tuple(cls, data: Tuple) -> "TransactionView":
        """Create from contract return tuple.

        Expects the V3+ 21-field shape that ships with the bundled ABI:
        [0]  transaction_id          [11] attestation_uid
        [1]  requester               [12] dispute_window
        [2]  provider                [13] metadata
        [3]  state                   [14] platform_fee_bps_locked
        [4]  amount                  [15] requester_penalty_bps_locked  (INV-30 / AIP-14 d9c6e8e)
        [5]  created_at              [16] dispute_bond_bps_locked       (INV-30)
        [6]  updated_at              [17] agent_id
        [7]  deadline                [18] requester_agent_id            (AIP-14)
        [8]  service_hash            [19] dispute_initiator             (AIP-14)
        [9]  escrow_contract         [20] dispute_bond                  (AIP-14)
        [10] escrow_id

        web3.py decodes against the bundled ABI, so tuples reaching this
        method are already 21-field. Reading a pre-V3 (19-field) contract
        with this SDK version will error at decode time before reaching
        from_tuple — loud failure is the intended behavior so callers know
        they're against the wrong contract generation.
        """
        return cls(
            transaction_id="0x" + data[0].hex() if isinstance(data[0], bytes) else data[0],
            requester=data[1],
            provider=data[2],
            state=TransactionState(data[3]),
            amount=data[4],
            created_at=data[5],
            updated_at=data[6],
            deadline=data[7],
            service_hash="0x" + data[8].hex() if isinstance(data[8], bytes) else data[8],
            escrow_contract=data[9],
            escrow_id="0x" + data[10].hex() if isinstance(data[10], bytes) else data[10],
            attestation_uid="0x" + data[11].hex() if isinstance(data[11], bytes) else data[11],
            dispute_window=data[12],
            metadata="0x" + data[13].hex() if isinstance(data[13], bytes) else data[13],
            platform_fee_bps_locked=data[14],
            requester_penalty_bps_locked=data[15],
            dispute_bond_bps_locked=data[16],
            agent_id=data[17],
            requester_agent_id=data[18],
            dispute_initiator=data[19],
            dispute_bond=data[20],
        )

    @classmethod
    def from_legacy_tuple(cls, data: Tuple) -> "TransactionView":
        """Create from the legacy 16-field contract return tuple.

        Used as the BAD_DATA fallback for pre-V3 deployments (Base Mainnet
        kernel ``0x132B…2d29``). The newer fields
        (``requester_penalty_bps_locked``, ``dispute_bond_bps_locked``,
        ``requester_agent_id``, ``dispute_initiator``, ``dispute_bond``) are
        absent on those deployments and default to 0 / "". Field order matches
        ``_LEGACY_GET_TRANSACTION_ABI`` above. PARITY: ACTPKernel.ts:600-636.
        """
        return cls(
            transaction_id="0x" + data[0].hex() if isinstance(data[0], bytes) else data[0],
            requester=data[1],
            provider=data[2],
            state=TransactionState(data[3]),
            amount=data[4],
            created_at=data[5],
            updated_at=data[6],
            deadline=data[7],
            service_hash="0x" + data[8].hex() if isinstance(data[8], bytes) else data[8],
            escrow_contract=data[9],
            escrow_id="0x" + data[10].hex() if isinstance(data[10], bytes) else data[10],
            attestation_uid="0x" + data[11].hex() if isinstance(data[11], bytes) else data[11],
            dispute_window=data[12],
            metadata="0x" + data[13].hex() if isinstance(data[13], bytes) else data[13],
            platform_fee_bps_locked=data[14],
            agent_id=data[15],
            # Fields absent in the legacy shape — explicit defaults.
            requester_penalty_bps_locked=0,
            dispute_bond_bps_locked=0,
            requester_agent_id=0,
            dispute_initiator="",
            dispute_bond=0,
        )


@dataclass
class EconomicParams:
    """
    Economic parameters (fee structure).

    PARITY: types/transaction.ts:66-72 (EconomicParams interface) and
    ACTPKernel.ts:667-685 (getEconomicParams). ``base_fee_denominator`` is
    always 10000 (BPS); ``provider_penalty_bps`` is not in the current
    contract ABI and is reported as 0 for forward-compat.
    """

    base_fee_numerator: int
    base_fee_denominator: int
    fee_recipient: str
    requester_penalty_bps: int
    provider_penalty_bps: int


# ============================================================================
# ACTPKernel Contract Wrapper
# ============================================================================


class ACTPKernel(ContractBase):
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
        *,
        nonce_manager: Optional[NonceManager] = None,
    ) -> None:
        """
        Initialize ACTPKernel wrapper.

        Args:
            contract: The ACTPKernel contract instance
            account: The account for signing transactions
            w3: The AsyncWeb3 instance
            chain_id: The chain ID of the network
            nonce_manager: Optional shared NonceManager for nonce tracking
        """
        super().__init__(contract, account, w3, chain_id, nonce_manager=nonce_manager)

    @classmethod
    def from_config(
        cls,
        w3: AsyncWeb3,
        account: LocalAccount,
        config: NetworkConfig,
        *,
        nonce_manager: Optional[NonceManager] = None,
    ) -> "ACTPKernel":
        """
        Create ACTPKernel from network configuration.

        Args:
            w3: The AsyncWeb3 instance
            account: The account for signing transactions
            config: Network configuration with contract addresses
            nonce_manager: Optional shared NonceManager for nonce tracking

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
        return cls(contract, account, w3, config.chain_id, nonce_manager=nonce_manager)

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

        # Convert addresses to checksum format (web3.py requirement)
        provider_checksum = self.w3.to_checksum_address(params.provider)
        requester_checksum = self.w3.to_checksum_address(requester)

        # Convert service_hash to bytes32
        service_hash = self._to_bytes32(params.service_hash)

        # Build transaction
        contract_fn = self.contract.functions.createTransaction(
            provider_checksum,
            requester_checksum,
            params.amount,
            params.deadline,
            params.dispute_window,
            service_hash,
            params.agent_id,
            params.requester_agent_id,
        )
        # P-2 fix: dynamic gas estimation with hardcoded floor fallback
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["create_transaction"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
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

        contract_fn = self.contract.functions.transitionState(
            tx_id_bytes,
            new_state.value,
            proof,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["transition_state"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def accept_quote(
        self,
        transaction_id: str,
        new_amount: int,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Accept a provider's quote and update transaction amount.

        This is a dedicated on-chain function (NOT a transitionState wrapper).
        It updates the transaction amount to the quoted amount and locks the
        current platformFeeBps, but does NOT change the transaction state
        (stays in QUOTED). After accept_quote, call link_escrow to move to COMMITTED.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            new_amount: New amount in USDC (6 decimals, e.g., 2000000 = 2 USDC)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If the call fails (wrong state, wrong caller, etc.)

        Example:
            >>> await kernel.accept_quote(tx_id, 2000000)  # Accept quote for 2 USDC
        """
        tx_id_bytes = self._to_bytes32(transaction_id)

        contract_fn = self.contract.functions.acceptQuote(
            tx_id_bytes,
            new_amount,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["accept_quote"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def submit_quote(
        self,
        transaction_id: str,
        quote_hash: str,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Submit a price quote for a transaction (AIP-2).

        Transitions the transaction from INITIATED -> QUOTED with the
        canonical quote hash stored on-chain (encoded as the bytes proof).

        PARITY: ACTPKernel.ts:330-358 (submitQuote). The hash is ABI-encoded
        as ``['bytes32']`` and handed to ``transition_state(QUOTED, proof)``,
        which mirrors the TS wrapper exactly.

        Args:
            transaction_id: Transaction ID (bytes32 hex string).
            quote_hash: Keccak256 hash of the canonical JSON quote message
                (bytes32 hex string, must be non-zero).
            gas_limit: Optional gas limit override.

        Returns:
            Transaction receipt.

        Raises:
            ValidationError: If quote_hash is not a valid non-zero bytes32.
            InvalidStateTransitionError: If the transaction is not INITIATED.

        Example:
            >>> await kernel.submit_quote(tx_id, "0xabc...")  # 0x + 64 hex
        """
        # Input validation — mirror ACTPKernel.ts:332-342.
        if (
            not isinstance(quote_hash, str)
            or not quote_hash.startswith("0x")
            or len(quote_hash) != 66
        ):
            raise ValidationError(
                "Must be valid bytes32 hex string",
                field="quote_hash",
                value=quote_hash,
            )
        try:
            int(quote_hash, 16)
        except ValueError:
            raise ValidationError(
                "Must be valid bytes32 hex string",
                field="quote_hash",
                value=quote_hash,
            )
        if quote_hash.lower() == ZERO_BYTES32:
            raise ValidationError(
                "Cannot be zero hash",
                field="quote_hash",
                value=quote_hash,
            )

        # Validate current state is INITIATED — mirror ACTPKernel.ts:343-349.
        current_tx = await self.get_transaction(transaction_id)
        if current_tx.state != TransactionState.INITIATED:
            raise InvalidStateTransitionError(
                current_tx.state.name,
                TransactionState.QUOTED.name,
                tx_id=transaction_id,
                allowed_transitions=["INITIATED"],
            )

        # Encode quote hash as bytes proof — abiCoder.encode(['bytes32'], [hash]).
        # PARITY: ACTPKernel.ts:352-354.
        from eth_abi import encode

        quote_hash_bytes = self._to_bytes32(quote_hash)
        proof = encode(["bytes32"], [quote_hash_bytes])

        # Transition to QUOTED state with the encoded quote hash as proof.
        return await self.transition_state(
            transaction_id,
            TransactionState.QUOTED,
            proof,
            gas_limit=gas_limit,
        )

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

        contract_fn = self.contract.functions.linkEscrow(
            tx_id_bytes,
            escrow_contract,
            escrow_id_bytes,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["link_escrow"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
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

        contract_fn = self.contract.functions.releaseEscrow(
            tx_id_bytes,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["release_escrow"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
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

        contract_fn = self.contract.functions.releaseMilestone(
            tx_id_bytes,
            amount,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["release_milestone"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
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

        contract_fn = self.contract.functions.anchorAttestation(
            tx_id_bytes,
            attestation_bytes,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["anchor_attestation"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    # =========================================================================
    # Dispute Management (PARITY: matches TS SDK ACTPKernel)
    # =========================================================================

    async def raise_dispute(
        self,
        transaction_id: str,
        reason: str,
        evidence: str,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Raise a dispute on a delivered transaction.

        Reference: Yellow Paper §3.4 (Dispute Management)

        PARITY: Matches TS SDK raiseDispute() behavior.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            reason: Dispute reason (human-readable)
            evidence: Evidence hash (typically IPFS CID)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Raises:
            TransactionError: If the dispute fails (e.g., wrong state)

        Example:
            >>> await kernel.raise_dispute(
            ...     tx_id,
            ...     reason="Service not delivered as described",
            ...     evidence="QmHash...",  # IPFS CID
            ... )
        """
        from eth_abi import encode

        tx_id_bytes = self._to_bytes32(transaction_id)

        # Encode dispute proof with reason and evidence (IPFS hash)
        proof_data = encode(["string", "string"], [reason, evidence])

        contract_fn = self.contract.functions.transitionState(
            tx_id_bytes,
            TransactionState.DISPUTED.value,
            proof_data,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["raise_dispute"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def resolve_dispute(
        self,
        transaction_id: str,
        requester_amount: int,
        provider_amount: int,
        mediator_amount: int = 0,
        mediator: str = ZERO_ADDRESS,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Resolve a dispute with payment split.

        Reference: Yellow Paper §3.4

        PARITY: Matches TS SDK resolveDispute() behavior.
        Disputes are settled via transitionState(SETTLED, proof) per §3.2.
        The kernel contract decodes the proof and handles escrow disbursement.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)
            requester_amount: Amount to refund to requester (wei)
            provider_amount: Amount to pay to provider (wei)
            mediator_amount: Amount to pay to mediator (wei, default 0)
            mediator: Mediator address (only if mediator_amount > 0)
            gas_limit: Optional gas limit override

        Returns:
            Transaction receipt

        Raises:
            ValidationError: If amounts are invalid
            TransactionError: If the resolution fails

        Example:
            >>> # Full refund to requester
            >>> await kernel.resolve_dispute(tx_id, 1000000, 0)
            >>>
            >>> # Split 70% provider, 30% requester
            >>> await kernel.resolve_dispute(tx_id, 300000, 700000)
            >>>
            >>> # With mediator fee
            >>> await kernel.resolve_dispute(
            ...     tx_id,
            ...     requester_amount=300000,
            ...     provider_amount=650000,
            ...     mediator_amount=50000,
            ...     mediator="0x..."
            ... )
        """
        from eth_abi import encode

        # Validate amounts
        if requester_amount < 0 or provider_amount < 0 or mediator_amount < 0:
            raise ValidationError("Dispute resolution amounts cannot be negative")

        # Validate mediator address if mediator amount > 0
        if mediator_amount > 0 and mediator == ZERO_ADDRESS:
            raise ValidationError(
                "Mediator address required when mediator_amount > 0"
            )

        tx_id_bytes = self._to_bytes32(transaction_id)

        # AUDIT FIX: Encode in correct order per contract expectation
        # Contract expects: abi.decode(proof, (uint256, uint256, address, uint256))
        # = [requesterAmount, providerAmount, mediator, mediatorAmount]
        proof_data = encode(
            ["uint256", "uint256", "address", "uint256"],
            [requester_amount, provider_amount, mediator, mediator_amount],
        )

        contract_fn = self.contract.functions.transitionState(
            tx_id_bytes,
            TransactionState.SETTLED.value,
            proof_data,
        )
        effective_gas = gas_limit or await self._estimate_gas(
            contract_fn, GAS_LIMITS["resolve_dispute"]
        )
        tx = await contract_fn.build_transaction(
            await self._build_tx_params(
                gas_limit=effective_gas,
            )
        )

        receipt = await self._sign_and_send(tx)
        return self._to_receipt(receipt)

    async def settle_dispute(
        self,
        transaction_id: str,
        requester_amount: int,
        provider_amount: int,
        mediator_amount: int = 0,
        mediator: str = ZERO_ADDRESS,
        gas_limit: Optional[int] = None,
    ) -> TransactionReceipt:
        """
        Settle a disputed transaction (alias for resolve_dispute).

        PARITY: Matches TS SDK settleDispute() alias.
        """
        return await self.resolve_dispute(
            transaction_id=transaction_id,
            requester_amount=requester_amount,
            provider_amount=provider_amount,
            mediator_amount=mediator_amount,
            mediator=mediator,
            gas_limit=gas_limit,
        )

    # =========================================================================
    # Read Operations
    # =========================================================================

    async def get_transaction(self, transaction_id: str) -> TransactionView:
        """
        Get transaction details from the contract.

        Decode failures (BAD_DATA / "could not decode result data") fall back
        to a legacy 16-field ABI shape — the older tuple deployed on Base
        Mainnet (kernel ``0x132B…2d29``) that the bundled 21-field ABI can't
        decode. Without this fallback, every read against an older deployment
        surfaces as a generic decode error which downstream
        ``BlockchainRuntime.get_transaction`` swallows as TX_NOT_FOUND for a
        real on-chain tx. PARITY: ACTPKernel.ts:564-636 (Damir review
        2026-04-18, Issue A). "Tx missing" reverts map to
        ``TransactionNotFoundError``.

        Args:
            transaction_id: The transaction ID (bytes32 hex string)

        Returns:
            TransactionView with all on-chain transaction data

        Example:
            >>> tx_view = await kernel.get_transaction(tx_id)
            >>> print(f"State: {tx_view.state.name}")
        """
        tx_id_bytes = self._to_bytes32(transaction_id)
        try:
            result = await self.contract.functions.getTransaction(tx_id_bytes).call()
        except Exception as error:
            reason = str(error)
            reason_lc = reason.lower()

            # Deployed kernel reverts on missing transactions (e.g. "Tx missing").
            if "tx missing" in reason_lc:
                raise TransactionNotFoundError(transaction_id) from error

            # Decode failure → fall back to the legacy 16-field ABI.
            # PARITY: ACTPKernel.ts:584-619 (BAD_DATA / "could not decode result
            # data"). web3.py surfaces a mismatched-return-data decode as
            # InsufficientDataBytes / BadFunctionCallOutput / MismatchedABI, or a
            # message containing "could not decode" / "insufficient data" / the
            # eth_abi "ABIDecoding" marker. None of these overlap with genuine
            # RPC transport errors, which propagate.
            error_type = type(error).__name__
            reason_no_space = reason_lc.replace(" ", "")
            is_decode_failure = (
                error_type
                in ("BadFunctionCallOutput", "InsufficientDataBytes", "MismatchedABI")
                or "could not decode" in reason_lc
                or "insufficient data" in reason_lc
                or "abidecoding" in reason_no_space
            )
            if not is_decode_failure:
                raise

            try:
                legacy = self.w3.eth.contract(
                    address=self.contract.address,
                    abi=_LEGACY_GET_TRANSACTION_ABI,
                )
                result = await legacy.functions.getTransaction(tx_id_bytes).call()
            except Exception as legacy_error:
                legacy_reason = str(legacy_error).lower()
                if "tx missing" in legacy_reason:
                    raise TransactionNotFoundError(transaction_id) from legacy_error
                raise TransactionError(
                    f"Failed to fetch transaction {transaction_id} "
                    f"(legacy fallback also failed): {legacy_error}",
                    tx_id=transaction_id,
                ) from legacy_error

            return TransactionView.from_legacy_tuple(result)

        return TransactionView.from_tuple(result)

    async def get_platform_fee_bps(self) -> int:
        """Get the current platform fee in basis points."""
        return await self.contract.functions.platformFeeBps().call()

    async def get_economic_params(self) -> EconomicParams:
        """
        Get economic parameters (fee structure).

        The contract has NO combined ``getEconomicParams()`` function — this
        calls the individual view getters ``platformFeeBps()``,
        ``requesterPenaltyBps()`` and ``feeRecipient()`` (concurrently) and
        assembles the result. ``base_fee_denominator`` is always 10000 (BPS);
        ``provider_penalty_bps`` is not in the current contract ABI and is
        reported as 0. PARITY: ACTPKernel.ts:667-685.

        Returns:
            EconomicParams with the assembled fee structure.
        """
        platform_fee_bps, requester_penalty_bps, fee_recipient = await asyncio.gather(
            self.contract.functions.platformFeeBps().call(),
            self.contract.functions.requesterPenaltyBps().call(),
            self.contract.functions.feeRecipient().call(),
        )

        return EconomicParams(
            base_fee_numerator=int(platform_fee_bps),
            base_fee_denominator=10000,  # BPS is always out of 10000
            fee_recipient=fee_recipient,
            requester_penalty_bps=int(requester_penalty_bps),
            provider_penalty_bps=0,  # Not in current contract ABI
        )

    async def estimate_create_transaction(
        self,
        params: Union[CreateTransactionParams, Dict[str, Any]],
    ) -> int:
        """
        Estimate gas for transaction creation.

        Builds the same ``createTransaction`` call as :meth:`create_transaction`
        and returns the estimated gas (without sending). PARITY:
        ACTPKernel.ts:689-714.

        Args:
            params: Transaction parameters (CreateTransactionParams or dict).

        Returns:
            Estimated gas units (int).
        """
        if isinstance(params, dict):
            params = CreateTransactionParams(**params)

        requester = params.requester or self.account.address
        provider_checksum = self.w3.to_checksum_address(params.provider)
        requester_checksum = self.w3.to_checksum_address(requester)
        service_hash = self._to_bytes32(params.service_hash)

        contract_fn = self.contract.functions.createTransaction(
            provider_checksum,
            requester_checksum,
            params.amount,
            params.deadline,
            params.dispute_window,
            service_hash,
            params.agent_id,
            params.requester_agent_id,
        )
        return await contract_fn.estimate_gas({"from": self.account.address})

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

