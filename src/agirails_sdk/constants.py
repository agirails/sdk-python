"""Constants for AGIRAILS SDK.

This module defines all constant values used across the SDK,
including ABI encoding constants, gas parameters, network settings,
and validation bounds.
"""

# ABI Encoding Constants
ABI_SELECTOR_LENGTH = 4
ABI_WORD_LENGTH = 32
REVERT_SELECTOR = "0x08c379a0"

# Ethereum Constants
BYTES32_HEX_LENGTH = 64
BYTES32_LENGTH = 32

# Gas Constants (Base L2)
DEFAULT_GAS_LIMIT = 450_000
GAS_ESTIMATION_BUFFER = 1.15
MAX_FEE_MULTIPLIER = 2
MIN_MAX_FEE_GWEI = "0.01"
PRIORITY_FEE_GWEI = "0.001"
MAX_GAS_LIMIT = 1_000_000  # 1M gas max (reasonable for any ACTP operation)

# Amount Validation Constants
MAX_SAFE_AMOUNT = 2**255 - 1  # Half of uint256 max, prevents overflow in arithmetic

# Network Constants
PROVIDER_TIMEOUT_SECONDS = 30

# Agent Registry (AIP-7) Constants
MAX_SERVICE_TYPE_LENGTH = 64  # Max chars for service type string
MAX_SERVICE_DESCRIPTORS = 100  # Max services per agent
MAX_PRICE_USDC = 1_000_000_000_000  # $1M USDC (6 decimals)
MAX_COMPLETION_TIME_SECONDS = 30 * 24 * 60 * 60  # 30 days
MAX_QUERY_LIMIT = 1000  # Max agents per query
QUERY_CAP = 1000  # Registry size cap for on-chain queries
REPUTATION_MAX = 10000  # Max reputation score (100.00%)
MAX_METADATA_CID_LENGTH = 100  # Max length for IPFS/Arweave CIDs
MAX_SCHEMA_URI_LENGTH = 200  # Max length for schema URIs

# Service type regex pattern: lowercase alphanumeric with hyphens
SERVICE_TYPE_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"

# DID regex pattern: did:ethr:<chainId>:<address>
DID_PATTERN = r"^did:ethr:(\d+):(0x[a-fA-F0-9]{40})$"

__all__ = [
    "ABI_SELECTOR_LENGTH",
    "ABI_WORD_LENGTH",
    "REVERT_SELECTOR",
    "BYTES32_HEX_LENGTH",
    "BYTES32_LENGTH",
    "DEFAULT_GAS_LIMIT",
    "GAS_ESTIMATION_BUFFER",
    "MAX_FEE_MULTIPLIER",
    "MIN_MAX_FEE_GWEI",
    "PRIORITY_FEE_GWEI",
    "MAX_GAS_LIMIT",
    "MAX_SAFE_AMOUNT",
    "PROVIDER_TIMEOUT_SECONDS",
    # AIP-7 Agent Registry
    "MAX_SERVICE_TYPE_LENGTH",
    "MAX_SERVICE_DESCRIPTORS",
    "MAX_PRICE_USDC",
    "MAX_COMPLETION_TIME_SECONDS",
    "MAX_QUERY_LIMIT",
    "QUERY_CAP",
    "REPUTATION_MAX",
    "MAX_METADATA_CID_LENGTH",
    "MAX_SCHEMA_URI_LENGTH",
    "SERVICE_TYPE_PATTERN",
    "DID_PATTERN",
]
