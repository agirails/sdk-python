"""
ERC-8004 type definitions for AGIRAILS SDK.

Provides types for the ERC-8004 Agent Identity and Reputation registries
deployed on Base L2. These canonical CREATE2 contracts are the same on all chains.

Registry addresses:
- Identity (mainnet): 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432
- Identity (testnet): 0x8004A818BFB912233c491871b3d84c89A494BD9e
- Reputation (mainnet): 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63
- Reputation (testnet): 0x8004B663056A597Dffe9eCcC1965A193B7388713
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Literal, Optional


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

ERC8004Network = Literal["base-mainnet", "base-sepolia"]

ERC8004_IDENTITY_REGISTRY: Dict[ERC8004Network, str] = {
    "base-mainnet": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    "base-sepolia": "0x8004A818BFB912233c491871b3d84c89A494BD9e",
}

ERC8004_REPUTATION_REGISTRY: Dict[ERC8004Network, str] = {
    "base-mainnet": "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    "base-sepolia": "0x8004B663056A597Dffe9eCcC1965A193B7388713",
}

ERC8004_DEFAULT_RPC: Dict[ERC8004Network, str] = {
    "base-mainnet": "https://mainnet.base.org",
    "base-sepolia": "https://sepolia.base.org",
}

# ---------------------------------------------------------------------------
# ACTP feedback tags used by ReputationReporter
# ---------------------------------------------------------------------------

ACTP_FEEDBACK_TAGS: Dict[str, str] = {
    "SETTLED": "actp_settled",
    "DISPUTE_WON": "actp_dispute_won",
    "DISPUTE_LOST": "actp_dispute_lost",
    # Neutral split-outcome trace (AIP-14b §3.4, §3.5, INV-22). A dispute that
    # resolved to a SPLIT (CompositeMediator ruling-2 or kernel DISPUTED->CANCELLED).
    # Carries NO on-chain penalty — written with value=0 — but is NOT
    # reputation-invisible: indexers surface per-agent split rates.
    # PARITY: TS ACTP_FEEDBACK_TAGS.DISPUTE_SPLIT — the tag STRING
    # 'actp_dispute_split' is identical across both SDKs.
    "DISPUTE_SPLIT": "actp_dispute_split",
}

# ---------------------------------------------------------------------------
# Minimal ABIs (view functions only for bridge, write for reputation)
# ---------------------------------------------------------------------------

ERC8004_IDENTITY_ABI = [
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "getAgentURI",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "owner", "type": "address"},
            {"name": "index", "type": "uint256"},
        ],
        "name": "tokenOfOwnerByIndex",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

# Canonical ERC-8004 Reputation Registry ABI. PARITY: TS types/erc8004.ts:252-259.
# The on-chain signatures are:
#   giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals,
#                string tag1, string tag2, string endpoint, string feedbackURI,
#                bytes32 feedbackHash)
#   revokeLatest(uint256 agentId, uint64 feedbackIndex)
#   getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2)
#       -> (uint256 count, int256 summaryValue, uint8 summaryValueDecimals)
#   readFeedback(uint256 agentId, uint64 feedbackIndex)
#       -> (int128 value, uint8 valueDecimals, string tag1, string tag2,
#           bool isRevoked, uint64 feedbackIndex)
# (Matches ERC8004_REPUTATION_ABI_CANONICAL in erc8004/reputation_reporter.py.)
ERC8004_REPUTATION_ABI = [
    # Write — giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "value", "type": "int128"},
            {"name": "valueDecimals", "type": "uint8"},
            {"name": "tag1", "type": "string"},
            {"name": "tag2", "type": "string"},
            {"name": "endpoint", "type": "string"},
            {"name": "feedbackURI", "type": "string"},
            {"name": "feedbackHash", "type": "bytes32"},
        ],
        "name": "giveFeedback",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # Write — revokeLatest(uint256,uint64)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "feedbackIndex", "type": "uint64"},
        ],
        "name": "revokeLatest",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # Read — getSummary(uint256,address[],string,string)
    #     -> (uint256 count, int256 summaryValue, uint8 summaryValueDecimals)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "clientAddresses", "type": "address[]"},
            {"name": "tag1", "type": "string"},
            {"name": "tag2", "type": "string"},
        ],
        "name": "getSummary",
        "outputs": [
            {"name": "count", "type": "uint256"},
            {"name": "summaryValue", "type": "int256"},
            {"name": "summaryValueDecimals", "type": "uint8"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    # Read — readFeedback(uint256,uint64)
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "feedbackIndex", "type": "uint64"},
        ],
        "name": "readFeedback",
        "outputs": [
            {
                "components": [
                    {"name": "value", "type": "int128"},
                    {"name": "valueDecimals", "type": "uint8"},
                    {"name": "tag1", "type": "string"},
                    {"name": "tag2", "type": "string"},
                    {"name": "isRevoked", "type": "bool"},
                    {"name": "feedbackIndex", "type": "uint64"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class ERC8004ErrorCode(Enum):
    """Error codes for ERC-8004 operations."""

    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    INVALID_AGENT_ID = "INVALID_AGENT_ID"
    NETWORK_ERROR = "NETWORK_ERROR"
    METADATA_FETCH_FAILED = "METADATA_FETCH_FAILED"


class ERC8004Error(Exception):
    """
    Exception for ERC-8004 operations.

    Attributes:
        code: Structured error code from ERC8004ErrorCode.
        message: Human-readable error description.
        details: Optional additional context.
    """

    def __init__(
        self,
        code: ERC8004ErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(f"[{code.value}] {message}")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ERC8004AgentMetadata:
    """
    Parsed metadata from an ERC-8004 agent URI.

    Fields follow the ERC-8004 metadata JSON schema.
    """

    name: Optional[str] = None
    description: Optional[str] = None
    wallet: Optional[str] = None
    payment_address: Optional[str] = None
    services: Optional[list] = field(default_factory=list)
    image: Optional[str] = None
    external_url: Optional[str] = None
    raw: Optional[Dict[str, Any]] = field(default=None, repr=False)


@dataclass
class ERC8004Agent:
    """
    Resolved ERC-8004 agent with on-chain and off-chain data.

    Attributes:
        agent_id: The numeric token ID as a string.
        owner: Checksummed Ethereum address of the token owner.
        wallet: Checksummed payment destination (resolved priority:
                paymentAddress > wallet > owner).
        agent_uri: Raw URI from the identity registry.
        metadata: Parsed metadata, or None if fetch failed.
        network: The network this agent was resolved on.
    """

    agent_id: str
    owner: str
    wallet: str
    agent_uri: str
    metadata: Optional[ERC8004AgentMetadata]
    network: ERC8004Network


# ---------------------------------------------------------------------------
# Config data classes
# ---------------------------------------------------------------------------


@dataclass
class ERC8004BridgeConfig:
    """
    Configuration for the ERC-8004 bridge.

    Attributes:
        network: Target network.
        rpc_url: Optional custom RPC URL (defaults to public Base RPC).
        cache_ttl_seconds: Cache TTL in seconds (default 60).
        metadata_timeout: HTTP timeout for metadata fetch in seconds.
        ipfs_gateway: IPFS gateway base URL for ipfs:// URI conversion.
    """

    network: ERC8004Network = "base-mainnet"
    rpc_url: Optional[str] = None
    cache_ttl_seconds: int = 60
    metadata_timeout: float = 10.0
    ipfs_gateway: str = "https://ipfs.io/ipfs/"


@dataclass
class ReputationReporterConfig:
    """
    Configuration for the reputation reporter.

    Attributes:
        network: Target network.
        rpc_url: Optional custom RPC URL.
        private_key: Hex-encoded private key for signing transactions.
        gas_limit: Gas limit for reputation transactions.
    """

    network: ERC8004Network = "base-mainnet"
    rpc_url: Optional[str] = None
    private_key: Optional[str] = None
    gas_limit: int = 200_000


@dataclass
class ReportResult:
    """
    Result of a reputation report transaction.

    Attributes:
        tx_hash: Transaction hash on-chain.
        agent_id: The agent that received feedback.
        feedback_hash: The keccak256 hash used as feedbackHash.
        tag: The ACTP feedback tag applied.
    """

    tx_hash: str
    agent_id: str
    feedback_hash: str
    tag: str


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_valid_erc8004_agent_id(agent_id: str) -> bool:
    """Check if agent_id is a valid non-negative integer string."""
    try:
        return int(agent_id) >= 0
    except (ValueError, TypeError):
        return False


def is_valid_address(address: str) -> bool:
    """Check if address matches 0x + 40 hex chars."""
    return bool(_ADDRESS_RE.match(address))
