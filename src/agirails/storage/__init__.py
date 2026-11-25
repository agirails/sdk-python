"""
Storage Module - Hybrid Storage Architecture (AIP-7 §4)

Two-tier storage model:
- Tier 1: IPFS (Filebase) for hot storage
- Tier 2: Arweave (Irys) for permanent archive

Example:
    ```python
    import os
    from agirails.storage import (
        FilebaseClient,
        FilebaseConfig,
        ArweaveClient,
        ArweaveConfig,
        ArchiveBundleBuilder,
    )

    # IPFS hot storage
    ipfs = FilebaseClient(FilebaseConfig(
        access_key=os.environ["FILEBASE_ACCESS_KEY"],
        secret_key=os.environ["FILEBASE_SECRET_KEY"],
    ))

    # Arweave permanent storage
    arweave = await ArweaveClient.create(ArweaveConfig(
        private_key=os.environ["ARCHIVE_KEY"],
        rpc_url=os.environ["BASE_RPC"],
    ))

    # Build archive bundle
    bundle = (
        ArchiveBundleBuilder()
        .set_transaction_id(tx_id)
        .set_chain_id(8453)
        # ... other fields
        .build()
    )

    # Upload to Arweave (CRITICAL: Arweave-first write order!)
    result = await arweave.upload_bundle(bundle)
    print(f"Archived at: {result.tx_id}")
    ```
"""

from __future__ import annotations

# ============================================================================
# Clients
# ============================================================================

from agirails.storage.arweave_client import ArweaveClient
from agirails.storage.filebase_client import FilebaseClient

# ============================================================================
# Builders
# ============================================================================

from agirails.storage.archive_bundle_builder import (
    ARCHIVE_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    ArchiveBundleBuilder,
    compute_content_hash,
    compute_json_hash,
    validate_archive_bundle,
)

# ============================================================================
# Types
# ============================================================================

from agirails.storage.types import (
    # Archive Bundle
    ARCHIVE_BUNDLE_TYPE,
    ArchiveAttestation,
    ArchiveBundle,
    ArchiveChainId,
    ArchiveFinalState,
    ArchiveHashes,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveSettlement,
    ArchiveSignatures,
    ArchiveTags,
    # Arweave
    ArweaveConfig,
    # Results
    ArweaveUploadResult,
    # Circuit Breaker
    CircuitBreakerConfig,
    DownloadResult,
    EscrowRelease,
    # Filebase
    FilebaseConfig,
    IPFSUploadResult,
    IrysCurrency,
    IrysNetwork,
)

__all__ = [
    # Clients
    "FilebaseClient",
    "ArweaveClient",
    # Builders
    "ArchiveBundleBuilder",
    "compute_content_hash",
    "compute_json_hash",
    "validate_archive_bundle",
    "PROTOCOL_VERSION",
    "ARCHIVE_SCHEMA_VERSION",
    # Types - Filebase
    "FilebaseConfig",
    # Types - Arweave
    "ArweaveConfig",
    "IrysCurrency",
    "IrysNetwork",
    # Types - Archive Bundle
    "ArchiveBundle",
    "ArchiveChainId",
    "ArchiveFinalState",
    "ArchiveParticipants",
    "ArchiveReferences",
    "ArchiveHashes",
    "ArchiveSignatures",
    "ArchiveAttestation",
    "ArchiveSettlement",
    "EscrowRelease",
    "ArchiveTags",
    "ARCHIVE_BUNDLE_TYPE",
    # Types - Results
    "IPFSUploadResult",
    "ArweaveUploadResult",
    "DownloadResult",
    # Types - Circuit Breaker
    "CircuitBreakerConfig",
]
