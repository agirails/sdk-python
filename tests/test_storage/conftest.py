"""
Shared fixtures for storage module tests.
"""

import time
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.storage.types import (
    ArchiveBundle,
    ArchiveChainId,
    ArchiveFinalState,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveHashes,
    ArchiveSignatures,
    ArchiveSettlement,
    ArchiveAttestation,
    EscrowRelease,
    FilebaseConfig,
    ArweaveConfig,
    CircuitBreakerConfig,
    ARCHIVE_BUNDLE_TYPE,
)


# =============================================================================
# Test Constants
# =============================================================================

# Valid Ethereum addresses (checksummed format)
VALID_REQUESTER = "0x1234567890123456789012345678901234567890"
VALID_PROVIDER = "0xabcdefABCDEFabcdefABCDEFabcdefABCDEFabcd"
VALID_FEE_RECIPIENT = "0x9876543210987654321098765432109876543210"

# Valid transaction ID (bytes32)
VALID_TX_ID = "0x" + "a" * 64

# Valid hashes (keccak256)
VALID_REQUEST_HASH = "0x" + "b" * 64
VALID_DELIVERY_HASH = "0x" + "c" * 64
VALID_SERVICE_HASH = "0x" + "d" * 64

# Valid CIDs
VALID_CID_V0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"  # 46 chars
VALID_CID_V1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"  # 59 chars

# Valid signatures
VALID_SIGNATURE = "0x" + "e" * 130  # 65 bytes hex

# Valid EAS UID
VALID_EAS_UID = "0x" + "f" * 64


# =============================================================================
# Fixtures - Configurations
# =============================================================================


@pytest.fixture
def filebase_config() -> FilebaseConfig:
    """Create a test FilebaseConfig."""
    return FilebaseConfig(
        access_key="test_access_key",
        secret_key="test_secret_key",
        bucket="test-bucket",
        endpoint="https://s3.filebase.com",
        gateway_url="https://ipfs.filebase.io/ipfs/",
        timeout=30000,
        max_file_size=104857600,  # 100MB
        max_download_size=52428800,  # 50MB
        circuit_breaker=CircuitBreakerConfig(
            enabled=True,
            failure_threshold=5,
            reset_timeout_ms=60000,
        ),
    )


@pytest.fixture
def arweave_config() -> ArweaveConfig:
    """Create a test ArweaveConfig."""
    return ArweaveConfig(
        private_key="0x" + "1" * 64,  # Test private key
        rpc_url="https://mainnet.base.org",
        currency="base-eth",
        network="devnet",  # Use devnet for tests
        timeout=60000,
        circuit_breaker=CircuitBreakerConfig(
            enabled=True,
            failure_threshold=3,
            reset_timeout_ms=30000,
        ),
    )


@pytest.fixture
def circuit_breaker_config() -> CircuitBreakerConfig:
    """Create a test CircuitBreakerConfig."""
    return CircuitBreakerConfig(
        enabled=True,
        failure_threshold=3,
        reset_timeout_ms=1000,  # Fast reset for tests
        failure_window_ms=5000,
        success_threshold=2,
    )


# =============================================================================
# Fixtures - Archive Bundle Components
# =============================================================================


@pytest.fixture
def archive_participants() -> ArchiveParticipants:
    """Create test ArchiveParticipants."""
    return ArchiveParticipants(
        requester=VALID_REQUESTER.lower(),
        provider=VALID_PROVIDER.lower(),
    )


@pytest.fixture
def archive_references() -> ArchiveReferences:
    """Create test ArchiveReferences."""
    return ArchiveReferences(
        requestCID=VALID_CID_V0,
        deliveryCID=VALID_CID_V1,
        resultCID=None,
    )


@pytest.fixture
def archive_hashes() -> ArchiveHashes:
    """Create test ArchiveHashes."""
    return ArchiveHashes(
        requestHash=VALID_REQUEST_HASH.lower(),
        deliveryHash=VALID_DELIVERY_HASH.lower(),
        serviceHash=VALID_SERVICE_HASH.lower(),
    )


@pytest.fixture
def archive_signatures() -> ArchiveSignatures:
    """Create test ArchiveSignatures."""
    return ArchiveSignatures(
        providerDeliverySignature=VALID_SIGNATURE,
        requesterSettlementSignature=None,
    )


@pytest.fixture
def archive_attestation() -> ArchiveAttestation:
    """Create test ArchiveAttestation."""
    return ArchiveAttestation(
        easUID=VALID_EAS_UID.lower(),
        schemaUID=None,
    )


@pytest.fixture
def archive_settlement() -> ArchiveSettlement:
    """Create test ArchiveSettlement."""
    return ArchiveSettlement(
        settledAt=int(time.time()),
        finalState="SETTLED",
        escrowReleased=EscrowRelease(
            to=VALID_PROVIDER.lower(),
            amount="1000000000",  # 1000 USDC (6 decimals)
        ),
        platformFee="10000000",  # 10 USDC
        wasDisputed=False,
    )


@pytest.fixture
def valid_archive_bundle(
    archive_participants: ArchiveParticipants,
    archive_references: ArchiveReferences,
    archive_hashes: ArchiveHashes,
    archive_signatures: ArchiveSignatures,
    archive_settlement: ArchiveSettlement,
) -> ArchiveBundle:
    """Create a valid ArchiveBundle for testing."""
    return ArchiveBundle(
        protocolVersion="1.0.0",
        archiveSchemaVersion="1.0.0",
        type=ARCHIVE_BUNDLE_TYPE,
        txId=VALID_TX_ID.lower(),
        chainId=8453,  # Base Mainnet
        archivedAt=int(time.time()),
        participants=archive_participants,
        references=archive_references,
        hashes=archive_hashes,
        signatures=archive_signatures,
        attestation=None,
        settlement=archive_settlement,
    )


# =============================================================================
# Fixtures - Mock HTTP Responses
# =============================================================================


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx client for testing HTTP operations."""
    with patch("httpx.AsyncClient") as mock:
        client_instance = AsyncMock()
        mock.return_value.__aenter__.return_value = client_instance
        mock.return_value.__aexit__.return_value = AsyncMock()
        yield client_instance


@pytest.fixture
def mock_s3_client():
    """Create a mock S3 client for Filebase testing."""
    with patch("aioboto3.Session") as mock_session:
        mock_client = AsyncMock()
        mock_session.return_value.client.return_value.__aenter__.return_value = mock_client
        mock_session.return_value.client.return_value.__aexit__.return_value = AsyncMock()
        yield mock_client


# =============================================================================
# Fixtures - Test Data
# =============================================================================


@pytest.fixture
def sample_json_data() -> Dict[str, Any]:
    """Sample JSON data for upload tests."""
    return {
        "service": "text-generation",
        "model": "gpt-4",
        "input": {"prompt": "Hello, world!"},
        "output": {"text": "Hello! How can I help you today?"},
        "timestamp": 1704067200,
    }


@pytest.fixture
def sample_binary_data() -> bytes:
    """Sample binary data for upload tests."""
    return b"Hello, AGIRAILS! This is test content for storage operations."


@pytest.fixture
def large_binary_data() -> bytes:
    """Large binary data for size limit tests."""
    return b"X" * (100 * 1024 * 1024 + 1)  # 100MB + 1 byte
