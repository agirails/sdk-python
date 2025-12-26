"""
Agent Registry wrapper for AGIRAILS SDK.

Provides integration with the AgentRegistry contract (AIP-7):
- Agent registration and discovery
- Service descriptor management
- Reputation queries

Example:
    >>> from agirails.protocol import AgentRegistry
    >>> registry = await AgentRegistry.create(private_key, network="base-sepolia")
    >>> await registry.register_agent("https://my-agent.io/api", services)
    >>> agents = await registry.query_agents_by_service("echo", min_reputation=80)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# Security Note (M-3): Default timeout for transaction receipts (5 minutes)
DEFAULT_TX_WAIT_TIMEOUT = 300.0

try:
    from eth_account import Account
    from eth_account.signers.local import LocalAccount
    from web3 import AsyncWeb3
    from web3.contract import AsyncContract

    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False
    Account = None  # type: ignore[misc, assignment]
    AsyncWeb3 = None  # type: ignore[misc, assignment]
    AsyncContract = None  # type: ignore[misc, assignment]
    LocalAccount = None  # type: ignore[misc, assignment]

from agirails.config.networks import NetworkConfig, get_network
from agirails.types.transaction import TransactionReceipt


@dataclass
class ServiceDescriptor:
    """
    Service descriptor for agent capabilities.

    Attributes:
        service_type: Service type name (e.g., "echo", "translation")
        service_type_hash: Keccak256 hash of service type
        schema_uri: URI to service schema definition
        min_price: Minimum price in USDC (6 decimals)
        max_price: Maximum price in USDC (6 decimals)
        avg_completion_time: Average completion time in seconds
        metadata_cid: IPFS CID for additional metadata
    """

    service_type: str
    service_type_hash: str = ""
    schema_uri: str = ""
    min_price: int = 0
    max_price: int = 0
    avg_completion_time: int = 60
    metadata_cid: str = ""

    def __post_init__(self) -> None:
        """Compute service type hash if not provided."""
        if not self.service_type_hash:
            self.service_type_hash = compute_service_type_hash(self.service_type)

    def to_tuple(self) -> tuple:
        """Convert to contract tuple format."""
        return (
            bytes.fromhex(self.service_type_hash.replace("0x", "")),
            self.service_type,
            self.schema_uri,
            self.min_price,
            self.max_price,
            self.avg_completion_time,
            self.metadata_cid,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "serviceType": self.service_type,
            "serviceTypeHash": self.service_type_hash,
            "schemaURI": self.schema_uri,
            "minPrice": self.min_price,
            "maxPrice": self.max_price,
            "avgCompletionTime": self.avg_completion_time,
            "metadataCID": self.metadata_cid,
        }

    @classmethod
    def from_tuple(cls, data: tuple) -> "ServiceDescriptor":
        """Create from contract tuple."""
        return cls(
            service_type_hash="0x" + data[0].hex() if isinstance(data[0], bytes) else data[0],
            service_type=data[1],
            schema_uri=data[2],
            min_price=data[3],
            max_price=data[4],
            avg_completion_time=data[5],
            metadata_cid=data[6],
        )


@dataclass
class AgentProfile:
    """
    Agent profile from the registry.

    Attributes:
        address: Agent's Ethereum address
        did: Decentralized identifier
        endpoint: Agent API endpoint URL
        service_types: List of service type hashes
        staked_amount: Staked amount (for future staking)
        reputation_score: Reputation score (0-100 scaled)
        total_transactions: Total completed transactions
        disputed_transactions: Number of disputed transactions
        total_volume_usdc: Total volume in USDC (6 decimals)
        registered_at: Registration timestamp
        updated_at: Last update timestamp
        is_active: Whether agent is currently active
    """

    address: str
    did: str = ""
    endpoint: str = ""
    service_types: List[str] = field(default_factory=list)
    staked_amount: int = 0
    reputation_score: int = 0
    total_transactions: int = 0
    disputed_transactions: int = 0
    total_volume_usdc: int = 0
    registered_at: int = 0
    updated_at: int = 0
    is_active: bool = True

    @property
    def reputation_percentage(self) -> float:
        """Get reputation as percentage (0-100)."""
        # Score is stored as 0-10000, convert to percentage
        return self.reputation_score / 100

    @property
    def dispute_rate(self) -> float:
        """Get dispute rate as percentage."""
        if self.total_transactions == 0:
            return 0.0
        return (self.disputed_transactions / self.total_transactions) * 100

    @property
    def total_volume_usdc_human(self) -> float:
        """Get total volume in human-readable USDC."""
        return self.total_volume_usdc / 1_000_000

    @property
    def registered_at_datetime(self) -> datetime:
        """Get registration time as datetime."""
        return datetime.fromtimestamp(self.registered_at)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": self.address,
            "did": self.did,
            "endpoint": self.endpoint,
            "serviceTypes": self.service_types,
            "stakedAmount": self.staked_amount,
            "reputationScore": self.reputation_score,
            "reputationPercentage": self.reputation_percentage,
            "totalTransactions": self.total_transactions,
            "disputedTransactions": self.disputed_transactions,
            "disputeRate": self.dispute_rate,
            "totalVolumeUSDC": self.total_volume_usdc,
            "registeredAt": self.registered_at,
            "updatedAt": self.updated_at,
            "isActive": self.is_active,
        }

    @classmethod
    def from_tuple(cls, data: tuple) -> "AgentProfile":
        """Create from contract tuple."""
        service_types = [
            "0x" + st.hex() if isinstance(st, bytes) else st
            for st in data[3]
        ]
        return cls(
            address=data[0],
            did=data[1],
            endpoint=data[2],
            service_types=service_types,
            staked_amount=data[4],
            reputation_score=data[5],
            total_transactions=data[6],
            disputed_transactions=data[7],
            total_volume_usdc=data[8],
            registered_at=data[9],
            updated_at=data[10],
            is_active=data[11],
        )


def compute_service_type_hash(service_type: str) -> str:
    """
    Compute keccak256 hash of service type.

    Args:
        service_type: Service type name

    Returns:
        Hex-encoded keccak256 hash
    """
    try:
        from eth_utils import keccak

        return "0x" + keccak(text=service_type).hex()
    except ImportError:
        # Fallback to sha256 if eth_utils not available
        hash_bytes = hashlib.sha256(service_type.encode("utf-8")).digest()
        return "0x" + hash_bytes.hex()


# Load AgentRegistry ABI
def _load_agent_registry_abi() -> List[Dict[str, Any]]:
    """Load AgentRegistry ABI from file."""
    import os

    abi_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "config",
        "abis",
        "AgentRegistry.json",
    )

    if os.path.exists(abi_path):
        with open(abi_path, "r") as f:
            return json.load(f)

    # Minimal fallback ABI
    return [
        {
            "type": "function",
            "name": "getAgent",
            "inputs": [{"name": "agentAddress", "type": "address"}],
            "outputs": [
                {
                    "name": "profile",
                    "type": "tuple",
                    "components": [
                        {"name": "agentAddress", "type": "address"},
                        {"name": "did", "type": "string"},
                        {"name": "endpoint", "type": "string"},
                        {"name": "serviceTypes", "type": "bytes32[]"},
                        {"name": "stakedAmount", "type": "uint256"},
                        {"name": "reputationScore", "type": "uint256"},
                        {"name": "totalTransactions", "type": "uint256"},
                        {"name": "disputedTransactions", "type": "uint256"},
                        {"name": "totalVolumeUSDC", "type": "uint256"},
                        {"name": "registeredAt", "type": "uint256"},
                        {"name": "updatedAt", "type": "uint256"},
                        {"name": "isActive", "type": "bool"},
                    ],
                }
            ],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "getAgentByDID",
            "inputs": [{"name": "did", "type": "string"}],
            "outputs": [
                {
                    "name": "profile",
                    "type": "tuple",
                    "components": [
                        {"name": "agentAddress", "type": "address"},
                        {"name": "did", "type": "string"},
                        {"name": "endpoint", "type": "string"},
                        {"name": "serviceTypes", "type": "bytes32[]"},
                        {"name": "stakedAmount", "type": "uint256"},
                        {"name": "reputationScore", "type": "uint256"},
                        {"name": "totalTransactions", "type": "uint256"},
                        {"name": "disputedTransactions", "type": "uint256"},
                        {"name": "totalVolumeUSDC", "type": "uint256"},
                        {"name": "registeredAt", "type": "uint256"},
                        {"name": "updatedAt", "type": "uint256"},
                        {"name": "isActive", "type": "bool"},
                    ],
                }
            ],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "registerAgent",
            "inputs": [
                {"name": "endpoint", "type": "string"},
                {
                    "name": "serviceDescriptors_",
                    "type": "tuple[]",
                    "components": [
                        {"name": "serviceTypeHash", "type": "bytes32"},
                        {"name": "serviceType", "type": "string"},
                        {"name": "schemaURI", "type": "string"},
                        {"name": "minPrice", "type": "uint256"},
                        {"name": "maxPrice", "type": "uint256"},
                        {"name": "avgCompletionTime", "type": "uint256"},
                        {"name": "metadataCID", "type": "string"},
                    ],
                },
            ],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
        {
            "type": "function",
            "name": "queryAgentsByService",
            "inputs": [
                {"name": "serviceTypeHash", "type": "bytes32"},
                {"name": "minReputation", "type": "uint256"},
                {"name": "offset", "type": "uint256"},
                {"name": "limit", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "address[]"}],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "getServiceDescriptors",
            "inputs": [{"name": "agentAddress", "type": "address"}],
            "outputs": [
                {
                    "name": "descriptors",
                    "type": "tuple[]",
                    "components": [
                        {"name": "serviceTypeHash", "type": "bytes32"},
                        {"name": "serviceType", "type": "string"},
                        {"name": "schemaURI", "type": "string"},
                        {"name": "minPrice", "type": "uint256"},
                        {"name": "maxPrice", "type": "uint256"},
                        {"name": "avgCompletionTime", "type": "uint256"},
                        {"name": "metadataCID", "type": "string"},
                    ],
                }
            ],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "updateEndpoint",
            "inputs": [{"name": "newEndpoint", "type": "string"}],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
        {
            "type": "function",
            "name": "addServiceType",
            "inputs": [{"name": "serviceType", "type": "string"}],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
        {
            "type": "function",
            "name": "removeServiceType",
            "inputs": [{"name": "serviceTypeHash", "type": "bytes32"}],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
        {
            "type": "function",
            "name": "setActiveStatus",
            "inputs": [{"name": "isActive", "type": "bool"}],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
        {
            "type": "function",
            "name": "supportsService",
            "inputs": [
                {"name": "agentAddress", "type": "address"},
                {"name": "serviceTypeHash", "type": "bytes32"},
            ],
            "outputs": [{"name": "supported", "type": "bool"}],
            "stateMutability": "view",
        },
    ]


class AgentRegistry:
    """
    AgentRegistry contract wrapper for agent discovery and management.

    Provides methods to register agents, query by service, and manage
    agent profiles and service descriptors.

    Args:
        contract: AgentRegistry contract instance
        account: Signing account
        w3: Web3 instance
        chain_id: Chain ID

    Example:
        >>> registry = await AgentRegistry.create(private_key, "base-sepolia")
        >>> services = [ServiceDescriptor(service_type="echo", min_price=50000)]
        >>> await registry.register_agent("https://api.example.com", services)
    """

    def __init__(
        self,
        contract: AsyncContract,
        account: LocalAccount,
        w3: AsyncWeb3,
        chain_id: int,
    ) -> None:
        self._contract = contract
        self._account = account
        self._w3 = w3
        self._chain_id = chain_id

    @classmethod
    async def create(
        cls,
        private_key: str,
        network: Union[str, NetworkConfig] = "base-sepolia",
        rpc_url: Optional[str] = None,
    ) -> "AgentRegistry":
        """
        Create AgentRegistry with connection to blockchain.

        Args:
            private_key: Ethereum private key
            network: Network name or config
            rpc_url: Optional custom RPC URL

        Returns:
            Configured AgentRegistry instance
        """
        if not HAS_WEB3:
            raise ImportError(
                "web3 and eth_account are required for AgentRegistry. "
                "Install with: pip install web3 eth-account"
            )

        # Get network config
        if isinstance(network, str):
            config = get_network(network)
        else:
            config = network

        # Check if agent registry is deployed
        if not config.contracts.agent_registry:
            raise ValueError(
                f"AgentRegistry not deployed on {config.name}. "
                "This feature requires the agent registry contract."
            )

        # Use custom RPC or network default
        rpc = rpc_url or config.rpc_url

        # Create web3 instance
        w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc))
        account = Account.from_key(private_key)  # type: ignore[union-attr]

        # Load ABI and create contract
        abi = _load_agent_registry_abi()
        contract = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.agent_registry),
            abi=abi,
        )

        return cls(
            contract=contract,
            account=account,
            w3=w3,
            chain_id=config.chain_id,
        )

    @property
    def address(self) -> str:
        """Get account address."""
        return self._account.address

    @property
    def contract_address(self) -> str:
        """Get registry contract address."""
        return self._contract.address

    async def _build_transaction(
        self,
        function: Any,
    ) -> Dict[str, Any]:
        """Build transaction parameters."""
        nonce = await self._w3.eth.get_transaction_count(self._account.address)
        gas_price = await self._w3.eth.gas_price

        tx_params = {
            "from": self._account.address,
            "nonce": nonce,
            "gasPrice": gas_price,
            "chainId": self._chain_id,
        }

        # Estimate gas
        gas = await function.estimate_gas(tx_params)
        tx_params["gas"] = int(gas * 1.2)  # 20% buffer

        return function.build_transaction(tx_params)

    async def _send_transaction(
        self,
        tx: Dict[str, Any],
        timeout: float = DEFAULT_TX_WAIT_TIMEOUT,
    ) -> TransactionReceipt:
        """
        Sign and send transaction.

        Security Note (M-3): Uses timeout to prevent indefinite hangs.

        Args:
            tx: Transaction dictionary
            timeout: Max seconds to wait for receipt (default: 300s)

        Returns:
            Transaction receipt

        Raises:
            RuntimeError: If transaction times out
        """
        signed = self._account.sign_transaction(tx)
        tx_hash = await self._w3.eth.send_raw_transaction(signed.raw_transaction)

        try:
            receipt = await asyncio.wait_for(
                self._w3.eth.wait_for_transaction_receipt(tx_hash),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Transaction {tx_hash.hex()} timed out after {timeout}s. "
                "Check network congestion and gas settings."
            )

        return TransactionReceipt(
            transaction_hash=receipt["transactionHash"].hex(),
            block_number=receipt["blockNumber"],
            block_hash=receipt["blockHash"].hex(),
            gas_used=receipt["gasUsed"],
            effective_gas_price=receipt.get("effectiveGasPrice", 0),
            status=receipt["status"],
            logs=[dict(log) for log in receipt.get("logs", [])],
        )

    async def get_agent(self, address: str) -> AgentProfile:
        """
        Get agent profile by address.

        Args:
            address: Agent's Ethereum address

        Returns:
            AgentProfile
        """
        result = await self._contract.functions.getAgent(
            self._w3.to_checksum_address(address)
        ).call()
        return AgentProfile.from_tuple(result)

    async def get_agent_by_did(self, did: str) -> AgentProfile:
        """
        Get agent profile by DID.

        Args:
            did: Decentralized identifier

        Returns:
            AgentProfile
        """
        result = await self._contract.functions.getAgentByDID(did).call()
        return AgentProfile.from_tuple(result)

    async def is_registered(self, address: str) -> bool:
        """
        Check if an agent is registered.

        Args:
            address: Agent's Ethereum address

        Returns:
            True if registered
        """
        try:
            profile = await self.get_agent(address)
            return profile.registered_at > 0
        except Exception:
            return False

    async def register_agent(
        self,
        endpoint: str,
        service_descriptors: List[ServiceDescriptor],
    ) -> TransactionReceipt:
        """
        Register a new agent.

        Args:
            endpoint: Agent API endpoint URL
            service_descriptors: List of service descriptors

        Returns:
            Transaction receipt
        """
        descriptors_tuple = [sd.to_tuple() for sd in service_descriptors]

        function = self._contract.functions.registerAgent(
            endpoint,
            descriptors_tuple,
        )
        tx = await self._build_transaction(function)
        return await self._send_transaction(tx)

    async def update_endpoint(self, new_endpoint: str) -> TransactionReceipt:
        """
        Update agent's endpoint URL.

        Args:
            new_endpoint: New API endpoint URL

        Returns:
            Transaction receipt
        """
        function = self._contract.functions.updateEndpoint(new_endpoint)
        tx = await self._build_transaction(function)
        return await self._send_transaction(tx)

    async def add_service_type(self, service_type: str) -> TransactionReceipt:
        """
        Add a service type to agent's capabilities.

        Args:
            service_type: Service type name

        Returns:
            Transaction receipt
        """
        function = self._contract.functions.addServiceType(service_type)
        tx = await self._build_transaction(function)
        return await self._send_transaction(tx)

    async def remove_service_type(self, service_type: str) -> TransactionReceipt:
        """
        Remove a service type from agent's capabilities.

        Args:
            service_type: Service type name or hash

        Returns:
            Transaction receipt
        """
        # Convert to hash if not already
        if not service_type.startswith("0x"):
            service_type_hash = compute_service_type_hash(service_type)
        else:
            service_type_hash = service_type

        hash_bytes = bytes.fromhex(service_type_hash.replace("0x", ""))
        function = self._contract.functions.removeServiceType(hash_bytes)
        tx = await self._build_transaction(function)
        return await self._send_transaction(tx)

    async def set_active_status(self, is_active: bool) -> TransactionReceipt:
        """
        Set agent's active status.

        Args:
            is_active: Whether agent should be active

        Returns:
            Transaction receipt
        """
        function = self._contract.functions.setActiveStatus(is_active)
        tx = await self._build_transaction(function)
        return await self._send_transaction(tx)

    async def get_service_descriptors(
        self,
        address: str,
    ) -> List[ServiceDescriptor]:
        """
        Get service descriptors for an agent.

        Args:
            address: Agent's Ethereum address

        Returns:
            List of service descriptors
        """
        result = await self._contract.functions.getServiceDescriptors(
            self._w3.to_checksum_address(address)
        ).call()

        return [ServiceDescriptor.from_tuple(sd) for sd in result]

    async def supports_service(
        self,
        address: str,
        service_type: str,
    ) -> bool:
        """
        Check if agent supports a service type.

        Args:
            address: Agent's Ethereum address
            service_type: Service type name or hash

        Returns:
            True if agent supports the service
        """
        # Convert to hash if not already
        if not service_type.startswith("0x"):
            service_type_hash = compute_service_type_hash(service_type)
        else:
            service_type_hash = service_type

        hash_bytes = bytes.fromhex(service_type_hash.replace("0x", ""))

        return await self._contract.functions.supportsService(
            self._w3.to_checksum_address(address),
            hash_bytes,
        ).call()

    async def query_agents_by_service(
        self,
        service_type: str,
        min_reputation: int = 0,
        offset: int = 0,
        limit: int = 100,
    ) -> List[str]:
        """
        Query agents by service type.

        Args:
            service_type: Service type name or hash
            min_reputation: Minimum reputation score (0-10000)
            offset: Pagination offset
            limit: Maximum results to return

        Returns:
            List of agent addresses
        """
        # Convert to hash if not already
        if not service_type.startswith("0x"):
            service_type_hash = compute_service_type_hash(service_type)
        else:
            service_type_hash = service_type

        hash_bytes = bytes.fromhex(service_type_hash.replace("0x", ""))

        return await self._contract.functions.queryAgentsByService(
            hash_bytes,
            min_reputation,
            offset,
            limit,
        ).call()

    async def find_providers_for_service(
        self,
        service_type: str,
        min_reputation_percentage: float = 0,
        active_only: bool = True,
        limit: int = 10,
    ) -> List[AgentProfile]:
        """
        Find providers for a service type with filtering.

        Args:
            service_type: Service type name
            min_reputation_percentage: Minimum reputation (0-100)
            active_only: Only return active agents
            limit: Maximum results

        Returns:
            List of matching agent profiles
        """
        # Convert percentage to contract format (0-10000)
        min_rep_score = int(min_reputation_percentage * 100)

        addresses = await self.query_agents_by_service(
            service_type=service_type,
            min_reputation=min_rep_score,
            limit=limit,
        )

        profiles = []
        for addr in addresses:
            try:
                profile = await self.get_agent(addr)
                if active_only and not profile.is_active:
                    continue
                profiles.append(profile)
            except Exception:
                continue

        return profiles


__all__ = [
    "AgentRegistry",
    "AgentProfile",
    "ServiceDescriptor",
    "compute_service_type_hash",
    "HAS_WEB3",
]
