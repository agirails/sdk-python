"""
Storage Types (AIP-7 §4)

Type definitions for the AGIRAILS hybrid storage architecture:
- Tier 1: IPFS (Filebase) for hot storage
- Tier 2: Arweave (Irys) for permanent archive
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional, TypedDict

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Currency and Network Types
# ============================================================================

IrysCurrency = Literal[
    "base-eth",      # RECOMMENDED: Base ETH (native to AGIRAILS)
    "ethereum",      # Ethereum mainnet ETH
    "matic",         # Polygon MATIC
    "arbitrum",      # Arbitrum ETH
    "usdc-eth",      # USDC on Ethereum
    "usdc-polygon",  # USDC on Polygon
]
"""Supported Irys payment tokens.

See: https://docs.irys.xyz/build/d/features/supported-tokens
"""

IrysNetwork = Literal["mainnet", "devnet"]
"""Irys network type."""


# ============================================================================
# Circuit Breaker Configuration
# ============================================================================

class CircuitBreakerConfig(BaseModel):
    """
    Circuit breaker configuration for gateway health tracking.

    When enabled, tracks gateway failures and temporarily blocks
    requests to unhealthy gateways (retry amplification protection).
    """

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(
        default=True,
        description="Enable circuit breaker",
    )
    failure_threshold: int = Field(
        default=5,
        ge=1,
        description="Number of failures before opening circuit",
    )
    reset_timeout_ms: int = Field(
        default=60000,
        ge=1000,
        description="Cooldown period in ms before attempting reset",
    )
    failure_window_ms: int = Field(
        default=300000,
        ge=1000,
        description="Time window in ms for counting failures",
    )
    success_threshold: int = Field(
        default=2,
        ge=1,
        description="Number of successes in half-open to close circuit",
    )


# ============================================================================
# Filebase Configuration
# ============================================================================

class FilebaseConfig(BaseModel):
    """
    Configuration for Filebase S3-compatible IPFS client.

    Example:
        ```python
        config = FilebaseConfig(
            access_key=os.environ["FILEBASE_ACCESS_KEY"],
            secret_key=os.environ["FILEBASE_SECRET_KEY"],
        )
        ```
    """

    model_config = ConfigDict(frozen=True)

    access_key: str = Field(
        ...,
        description="Filebase access key ID. Get from: https://console.filebase.com/keys",
    )
    secret_key: str = Field(
        ...,
        description="Filebase secret access key. SECURITY: Store in environment variable",
    )
    bucket: str = Field(
        default="agirails-storage",
        description="Filebase bucket name",
    )
    endpoint: str = Field(
        default="https://s3.filebase.com",
        description="Filebase S3 endpoint",
    )
    gateway_url: str = Field(
        default="https://ipfs.filebase.io/ipfs/",
        description="IPFS gateway URL for retrieval",
    )
    timeout: int = Field(
        default=30000,
        ge=1000,
        description="Request timeout in milliseconds",
    )
    max_file_size: int = Field(
        default=104857600,  # 100MB
        ge=1,
        description="Maximum file size in bytes for uploads",
    )
    max_download_size: int = Field(
        default=52428800,  # 50MB
        ge=1,
        description="Maximum download size in bytes (P1-1: DoS protection)",
    )
    circuit_breaker: Optional[CircuitBreakerConfig] = Field(
        default=None,
        description="Circuit breaker configuration for gateway health tracking",
    )


# ============================================================================
# Arweave Configuration
# ============================================================================

class ArweaveConfig(BaseModel):
    """
    Configuration for Arweave client via Irys.

    Example:
        ```python
        config = ArweaveConfig(
            private_key=os.environ["ARCHIVE_KEY"],
            rpc_url=os.environ["BASE_RPC"],
        )
        ```
    """

    model_config = ConfigDict(frozen=True)

    private_key: str = Field(
        ...,
        description="Private key for signing transactions. SECURITY: Store in env var",
    )
    rpc_url: str = Field(
        ...,
        description="RPC URL for the payment chain",
    )
    currency: IrysCurrency = Field(
        default="base-eth",
        description="Payment currency/token",
    )
    network: IrysNetwork = Field(
        default="mainnet",
        description="Irys network (mainnet or devnet)",
    )
    timeout: int = Field(
        default=60000,
        ge=1000,
        description="Request timeout in milliseconds",
    )
    circuit_breaker: Optional[CircuitBreakerConfig] = Field(
        default=None,
        description="Circuit breaker configuration for gateway health tracking",
    )


# ============================================================================
# Archive Bundle Types (AIP-7 §4.4)
# ============================================================================

ARCHIVE_BUNDLE_TYPE = "actp.archive.v1.minimal"
"""Archive bundle type identifier."""

ArchiveChainId = Literal[8453, 84532]
"""Supported chain IDs: Base Mainnet (8453) | Base Sepolia (84532)."""

ArchiveFinalState = Literal["SETTLED", "CANCELLED"]
"""Final transaction states that can be archived."""


class ArchiveParticipants(BaseModel):
    """Transaction participants (addresses only, not full profiles)."""

    model_config = ConfigDict(frozen=True)

    requester: str = Field(
        ...,
        pattern=r"^0x[0-9a-fA-F]{40}$",
        description="Requester Ethereum address",
    )
    provider: str = Field(
        ...,
        pattern=r"^0x[0-9a-fA-F]{40}$",
        description="Provider Ethereum address",
    )


class ArchiveReferences(BaseModel):
    """IPFS CID references to full content."""

    model_config = ConfigDict(frozen=True)

    request_cid: str = Field(
        ...,
        alias="requestCID",
        description="IPFS CID of AIP-1 request metadata",
    )
    delivery_cid: str = Field(
        ...,
        alias="deliveryCID",
        description="IPFS CID of AIP-4 delivery proof",
    )
    result_cid: Optional[str] = Field(
        default=None,
        alias="resultCID",
        description="IPFS CID of actual result/output (optional)",
    )


class ArchiveHashes(BaseModel):
    """Cryptographic hashes for verification."""

    model_config = ConfigDict(frozen=True)

    request_hash: str = Field(
        ...,
        alias="requestHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="keccak256 of canonical request metadata JSON",
    )
    delivery_hash: str = Field(
        ...,
        alias="deliveryHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="keccak256 of canonical delivery proof JSON",
    )
    service_hash: str = Field(
        ...,
        alias="serviceHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="serviceHash from ACTPKernel transaction",
    )


class ArchiveSignatures(BaseModel):
    """Cryptographic signatures for self-verification."""

    model_config = ConfigDict(frozen=True)

    provider_delivery_signature: str = Field(
        ...,
        alias="providerDeliverySignature",
        description="EIP-712 signature by provider over deliveryHash",
    )
    requester_settlement_signature: Optional[str] = Field(
        default=None,
        alias="requesterSettlementSignature",
        description="Optional: requester signature authorizing settlement",
    )


class ArchiveAttestation(BaseModel):
    """EAS attestation reference."""

    model_config = ConfigDict(frozen=True)

    eas_uid: str = Field(
        ...,
        alias="easUID",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="Ethereum Attestation Service UID",
    )
    schema_uid: Optional[str] = Field(
        default=None,
        alias="schemaUID",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="EAS schema UID used for attestation (optional)",
    )


class EscrowRelease(BaseModel):
    """Escrow release details."""

    model_config = ConfigDict(frozen=True)

    to: str = Field(
        ...,
        pattern=r"^0x[0-9a-fA-F]{40}$",
        description="Recipient address (provider or requester)",
    )
    amount: str = Field(
        ...,
        description="Released amount (USDC base units, string for BigInt safety)",
    )


class ArchiveSettlement(BaseModel):
    """Settlement information."""

    model_config = ConfigDict(frozen=True)

    settled_at: int = Field(
        ...,
        alias="settledAt",
        ge=0,
        description="Settlement timestamp (Unix seconds)",
    )
    final_state: ArchiveFinalState = Field(
        ...,
        alias="finalState",
        description="Final transaction state",
    )
    escrow_released: EscrowRelease = Field(
        ...,
        alias="escrowReleased",
        description="Escrow release details",
    )
    platform_fee: str = Field(
        ...,
        alias="platformFee",
        description="Platform fee collected (USDC base units)",
    )
    was_disputed: bool = Field(
        ...,
        alias="wasDisputed",
        description="Whether transaction went through dispute",
    )


class ArchiveBundle(BaseModel):
    """
    Archive Bundle (AIP-7 §4.4 - Minimal Hash-First).

    Contains minimal metadata with cryptographic hashes and references.
    Full content (request metadata, delivery proof) remains on IPFS.
    """

    model_config = ConfigDict(
        frozen=True,
        populate_by_name=True,
    )

    protocol_version: str = Field(
        ...,
        alias="protocolVersion",
        description='AGIRAILS protocol version (e.g., "1.0.0")',
    )
    archive_schema_version: str = Field(
        ...,
        alias="archiveSchemaVersion",
        description='Archive bundle schema version (e.g., "1.0.0")',
    )
    type: str = Field(
        default=ARCHIVE_BUNDLE_TYPE,
        description="Archive bundle type identifier",
    )
    tx_id: str = Field(
        ...,
        alias="txId",
        pattern=r"^0x[0-9a-fA-F]{64}$",
        description="ACTP transaction ID (bytes32)",
    )
    chain_id: ArchiveChainId = Field(
        ...,
        alias="chainId",
        description="Blockchain network chain ID",
    )
    archived_at: int = Field(
        ...,
        alias="archivedAt",
        ge=0,
        description="Archive timestamp (Unix seconds)",
    )
    participants: ArchiveParticipants = Field(
        ...,
        description="Transaction participants (addresses only)",
    )
    references: ArchiveReferences = Field(
        ...,
        description="IPFS CID references to full content",
    )
    hashes: ArchiveHashes = Field(
        ...,
        description="Cryptographic hashes for verification",
    )
    signatures: ArchiveSignatures = Field(
        ...,
        description="Cryptographic signatures",
    )
    attestation: Optional[ArchiveAttestation] = Field(
        default=None,
        description="EAS attestation reference (optional for cancelled transactions)",
    )
    settlement: ArchiveSettlement = Field(
        ...,
        description="Settlement information",
    )


# ============================================================================
# Upload/Download Results
# ============================================================================

class IPFSUploadResult(BaseModel):
    """Result of uploading to IPFS."""

    model_config = ConfigDict(frozen=True)

    cid: str = Field(
        ...,
        description="IPFS CID (CIDv1, base32)",
    )
    size: int = Field(
        ...,
        ge=0,
        description="Size of uploaded content in bytes",
    )
    uploaded_at: datetime = Field(
        ...,
        description="Upload timestamp",
    )


class ArweaveUploadResult(BaseModel):
    """Result of uploading to Arweave."""

    model_config = ConfigDict(frozen=True)

    tx_id: str = Field(
        ...,
        description="Arweave transaction ID",
    )
    size: int = Field(
        ...,
        ge=0,
        description="Size of uploaded content in bytes",
    )
    uploaded_at: datetime = Field(
        ...,
        description="Upload timestamp",
    )
    cost: str = Field(
        ...,
        description="Cost in the payment currency (wei for ETH)",
    )


class DownloadResult(BaseModel):
    """Result of downloading content."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    data: bytes = Field(
        ...,
        description="Downloaded content as bytes",
    )
    size: int = Field(
        ...,
        ge=0,
        description="Size of downloaded content in bytes",
    )
    downloaded_at: datetime = Field(
        ...,
        description="Download timestamp",
    )


# ============================================================================
# Irys Tags
# ============================================================================

class ArchiveTags(TypedDict):
    """Arweave/Irys tags for archive bundles."""

    Content_Type: str
    Protocol: str
    Version: str
    Schema: str
    Type: str
    ChainId: str
    TxId: str
