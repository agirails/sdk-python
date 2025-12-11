from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional

__all__ = ["State", "TransactionView", "ServiceDescriptor", "AgentProfile"]


class State(IntEnum):
    INITIATED = 0
    QUOTED = 1
    COMMITTED = 2
    IN_PROGRESS = 3
    DELIVERED = 4
    SETTLED = 5
    DISPUTED = 6
    CANCELLED = 7


@dataclass
class TransactionView:
    transaction_id: bytes
    requester: str
    provider: str
    state: State
    amount: int
    created_at: int
    updated_at: int
    deadline: int
    service_hash: bytes
    escrow_contract: str
    escrow_id: bytes
    attestation_uid: bytes
    dispute_window: int
    metadata: bytes
    platform_fee_bps_locked: int


@dataclass
class ServiceDescriptor:
    """Service descriptor for agent capabilities (AIP-7).

    Describes a service type an agent can provide, including pricing
    and expected completion time.

    Attributes:
        service_type_hash: Keccak256 hash of service type string
        service_type: Human-readable service type (e.g., "text-generation")
        schema_uri: IPFS/Arweave URI for service schema definition
        min_price: Minimum price in USDC (6 decimals)
        max_price: Maximum price in USDC (6 decimals)
        avg_completion_time: Average completion time in seconds
        metadata_cid: IPFS CID for additional metadata
    """
    service_type_hash: str
    service_type: str
    schema_uri: str
    min_price: int
    max_price: int
    avg_completion_time: int
    metadata_cid: str


@dataclass
class AgentProfile:
    """Agent profile from registry (AIP-7).

    Contains all on-chain data about a registered agent, including
    service capabilities, reputation metrics, and activity status.

    Attributes:
        agent_address: Ethereum address of the agent
        did: Decentralized Identifier (did:ethr:<chainId>:<address>)
        endpoint: Webhook/API endpoint URL
        service_types: List of service type hashes agent supports
        staked_amount: Amount staked for reputation (USDC, 6 decimals)
        reputation_score: Reputation score (0-10000 scale, 10000 = 100%)
        total_transactions: Total number of transactions completed
        disputed_transactions: Number of disputed transactions
        total_volume_usdc: Total transaction volume (USDC, 6 decimals)
        registered_at: Unix timestamp of registration
        updated_at: Unix timestamp of last update
        is_active: Whether agent is accepting new requests
    """
    agent_address: str
    did: str
    endpoint: str
    service_types: List[str]
    staked_amount: int
    reputation_score: int
    total_transactions: int
    disputed_transactions: int
    total_volume_usdc: int
    registered_at: int
    updated_at: int
    is_active: bool
