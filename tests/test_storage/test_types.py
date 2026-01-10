"""
Tests for storage type definitions and Pydantic validation.

Tests cover:
- FilebaseConfig validation
- ArweaveConfig validation
- ArchiveBundle and component models
- JSON serialization with camelCase aliases
- Invalid data rejection
"""

import json
import time
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from agirails.storage.types import (
    # Config types
    FilebaseConfig,
    ArweaveConfig,
    CircuitBreakerConfig,
    # Archive bundle types
    ArchiveBundle,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveHashes,
    ArchiveSignatures,
    ArchiveAttestation,
    ArchiveSettlement,
    EscrowRelease,
    # Result types
    IPFSUploadResult,
    ArweaveUploadResult,
    DownloadResult,
    # Constants
    ARCHIVE_BUNDLE_TYPE,
)

from .conftest import (
    VALID_TX_ID,
    VALID_REQUESTER,
    VALID_PROVIDER,
    VALID_CID_V0,
    VALID_CID_V1,
    VALID_REQUEST_HASH,
    VALID_DELIVERY_HASH,
    VALID_SERVICE_HASH,
    VALID_SIGNATURE,
    VALID_EAS_UID,
)


# =============================================================================
# FilebaseConfig Tests
# =============================================================================


class TestFilebaseConfig:
    """Tests for FilebaseConfig validation."""

    def test_valid_config(self, filebase_config: FilebaseConfig) -> None:
        """Test valid FilebaseConfig creation."""
        assert filebase_config.access_key == "test_access_key"
        assert filebase_config.secret_key == "test_secret_key"
        assert filebase_config.bucket == "test-bucket"
        assert filebase_config.endpoint == "https://s3.filebase.com"
        assert filebase_config.timeout == 30000
        assert filebase_config.max_file_size == 104857600

    def test_default_values(self) -> None:
        """Test FilebaseConfig default values."""
        config = FilebaseConfig(
            access_key="key",
            secret_key="secret",
        )
        assert config.bucket == "agirails-storage"
        assert config.endpoint == "https://s3.filebase.com"
        assert config.gateway_url == "https://ipfs.filebase.io/ipfs/"
        assert config.timeout == 30000
        assert config.max_file_size == 104857600  # 100MB
        assert config.max_download_size == 52428800  # 50MB
        assert config.circuit_breaker is None

    def test_missing_required_fields(self) -> None:
        """Test FilebaseConfig rejects missing required fields."""
        with pytest.raises(ValidationError) as exc_info:
            FilebaseConfig()  # type: ignore
        errors = exc_info.value.errors()
        assert len(errors) >= 2  # access_key and secret_key required

    def test_with_circuit_breaker(self) -> None:
        """Test FilebaseConfig with circuit breaker config."""
        config = FilebaseConfig(
            access_key="key",
            secret_key="secret",
            circuit_breaker=CircuitBreakerConfig(
                enabled=True,
                failure_threshold=10,
            ),
        )
        assert config.circuit_breaker is not None
        assert config.circuit_breaker.failure_threshold == 10


# =============================================================================
# ArweaveConfig Tests
# =============================================================================


class TestArweaveConfig:
    """Tests for ArweaveConfig validation."""

    def test_valid_config(self, arweave_config: ArweaveConfig) -> None:
        """Test valid ArweaveConfig creation."""
        assert arweave_config.private_key.startswith("0x")
        assert arweave_config.rpc_url == "https://mainnet.base.org"
        assert arweave_config.currency == "base-eth"
        assert arweave_config.network == "devnet"
        assert arweave_config.timeout == 60000

    def test_default_values(self) -> None:
        """Test ArweaveConfig default values."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
        )
        assert config.currency == "base-eth"
        assert config.network == "mainnet"
        assert config.timeout == 60000
        assert config.circuit_breaker is None

    def test_valid_currencies(self) -> None:
        """Test all valid currency types."""
        valid_currencies = [
            "base-eth",
            "ethereum",
            "matic",
            "arbitrum",
            "usdc-eth",
            "usdc-polygon",
        ]
        for currency in valid_currencies:
            config = ArweaveConfig(
                private_key="0x" + "1" * 64,
                rpc_url="https://mainnet.base.org",
                currency=currency,  # type: ignore
            )
            assert config.currency == currency

    def test_valid_networks(self) -> None:
        """Test valid network types."""
        for network in ["mainnet", "devnet"]:
            config = ArweaveConfig(
                private_key="0x" + "1" * 64,
                rpc_url="https://mainnet.base.org",
                network=network,  # type: ignore
            )
            assert config.network == network


# =============================================================================
# CircuitBreakerConfig Tests
# =============================================================================


class TestCircuitBreakerConfig:
    """Tests for CircuitBreakerConfig validation."""

    def test_default_values(self) -> None:
        """Test CircuitBreakerConfig default values."""
        config = CircuitBreakerConfig()
        assert config.enabled is True
        assert config.failure_threshold == 5
        assert config.reset_timeout_ms == 60000
        assert config.failure_window_ms == 300000
        assert config.success_threshold == 2

    def test_custom_values(self, circuit_breaker_config: CircuitBreakerConfig) -> None:
        """Test CircuitBreakerConfig with custom values."""
        assert circuit_breaker_config.enabled is True
        assert circuit_breaker_config.failure_threshold == 3
        assert circuit_breaker_config.reset_timeout_ms == 1000

    def test_disabled_circuit_breaker(self) -> None:
        """Test disabled circuit breaker config."""
        config = CircuitBreakerConfig(enabled=False)
        assert config.enabled is False


# =============================================================================
# ArchiveParticipants Tests
# =============================================================================


class TestArchiveParticipants:
    """Tests for ArchiveParticipants validation."""

    def test_valid_participants(self, archive_participants: ArchiveParticipants) -> None:
        """Test valid ArchiveParticipants creation."""
        assert archive_participants.requester == VALID_REQUESTER.lower()
        assert archive_participants.provider == VALID_PROVIDER.lower()

    def test_json_serialization(self, archive_participants: ArchiveParticipants) -> None:
        """Test JSON serialization maintains field names."""
        json_dict = archive_participants.model_dump()
        assert "requester" in json_dict
        assert "provider" in json_dict


# =============================================================================
# ArchiveReferences Tests
# =============================================================================


class TestArchiveReferences:
    """Tests for ArchiveReferences validation."""

    def test_valid_references(self, archive_references: ArchiveReferences) -> None:
        """Test valid ArchiveReferences creation."""
        assert archive_references.request_cid == VALID_CID_V0
        assert archive_references.delivery_cid == VALID_CID_V1
        assert archive_references.result_cid is None

    def test_json_serialization_uses_aliases(
        self, archive_references: ArchiveReferences
    ) -> None:
        """Test JSON serialization uses camelCase aliases."""
        json_dict = archive_references.model_dump(by_alias=True)
        assert "requestCID" in json_dict
        assert "deliveryCID" in json_dict
        assert "resultCID" in json_dict

    def test_with_result_cid(self) -> None:
        """Test ArchiveReferences with optional result CID."""
        refs = ArchiveReferences(
            requestCID=VALID_CID_V0,
            deliveryCID=VALID_CID_V1,
            resultCID=VALID_CID_V0,
        )
        assert refs.result_cid == VALID_CID_V0


# =============================================================================
# ArchiveHashes Tests
# =============================================================================


class TestArchiveHashes:
    """Tests for ArchiveHashes validation."""

    def test_valid_hashes(self, archive_hashes: ArchiveHashes) -> None:
        """Test valid ArchiveHashes creation."""
        assert archive_hashes.request_hash == VALID_REQUEST_HASH.lower()
        assert archive_hashes.delivery_hash == VALID_DELIVERY_HASH.lower()
        assert archive_hashes.service_hash == VALID_SERVICE_HASH.lower()

    def test_json_serialization_uses_aliases(
        self, archive_hashes: ArchiveHashes
    ) -> None:
        """Test JSON serialization uses camelCase aliases."""
        json_dict = archive_hashes.model_dump(by_alias=True)
        assert "requestHash" in json_dict
        assert "deliveryHash" in json_dict
        assert "serviceHash" in json_dict


# =============================================================================
# ArchiveSignatures Tests
# =============================================================================


class TestArchiveSignatures:
    """Tests for ArchiveSignatures validation."""

    def test_valid_signatures(self, archive_signatures: ArchiveSignatures) -> None:
        """Test valid ArchiveSignatures creation."""
        assert archive_signatures.provider_delivery_signature == VALID_SIGNATURE
        assert archive_signatures.requester_settlement_signature is None

    def test_json_serialization_uses_aliases(
        self, archive_signatures: ArchiveSignatures
    ) -> None:
        """Test JSON serialization uses camelCase aliases."""
        json_dict = archive_signatures.model_dump(by_alias=True)
        assert "providerDeliverySignature" in json_dict
        assert "requesterSettlementSignature" in json_dict


# =============================================================================
# ArchiveSettlement Tests
# =============================================================================


class TestArchiveSettlement:
    """Tests for ArchiveSettlement validation."""

    def test_valid_settlement(self, archive_settlement: ArchiveSettlement) -> None:
        """Test valid ArchiveSettlement creation."""
        assert archive_settlement.final_state == "SETTLED"
        assert archive_settlement.was_disputed is False
        assert archive_settlement.escrow_released is not None

    def test_cancelled_state(self) -> None:
        """Test settlement with CANCELLED state."""
        settlement = ArchiveSettlement(
            settledAt=int(time.time()),
            finalState="CANCELLED",
            escrowReleased=EscrowRelease(
                to=VALID_REQUESTER.lower(),
                amount="1000000000",
            ),
            platformFee="0",
            wasDisputed=False,
        )
        assert settlement.final_state == "CANCELLED"

    def test_disputed_settlement(self) -> None:
        """Test settlement that went through dispute."""
        settlement = ArchiveSettlement(
            settledAt=int(time.time()),
            finalState="SETTLED",
            escrowReleased=EscrowRelease(
                to=VALID_PROVIDER.lower(),
                amount="500000000",  # Partial after dispute
            ),
            platformFee="10000000",
            wasDisputed=True,
        )
        assert settlement.was_disputed is True

    def test_json_serialization_uses_aliases(
        self, archive_settlement: ArchiveSettlement
    ) -> None:
        """Test JSON serialization uses camelCase aliases."""
        json_dict = archive_settlement.model_dump(by_alias=True)
        assert "settledAt" in json_dict
        assert "finalState" in json_dict
        assert "escrowReleased" in json_dict
        assert "platformFee" in json_dict
        assert "wasDisputed" in json_dict


# =============================================================================
# EscrowRelease Tests
# =============================================================================


class TestEscrowRelease:
    """Tests for EscrowRelease validation."""

    def test_valid_escrow_release(self) -> None:
        """Test valid EscrowRelease creation."""
        release = EscrowRelease(
            to=VALID_PROVIDER.lower(),
            amount="1000000000",
        )
        assert release.to == VALID_PROVIDER.lower()
        assert release.amount == "1000000000"

    def test_amount_as_string(self) -> None:
        """Test amount is stored as string for BigInt safety."""
        release = EscrowRelease(
            to=VALID_PROVIDER.lower(),
            amount="999999999999999999999",  # Large number
        )
        assert release.amount == "999999999999999999999"


# =============================================================================
# ArchiveBundle Tests
# =============================================================================


class TestArchiveBundle:
    """Tests for ArchiveBundle validation."""

    def test_valid_bundle(self, valid_archive_bundle: ArchiveBundle) -> None:
        """Test valid ArchiveBundle creation."""
        assert valid_archive_bundle.protocol_version == "1.0.0"
        assert valid_archive_bundle.archive_schema_version == "1.0.0"
        assert valid_archive_bundle.type == ARCHIVE_BUNDLE_TYPE
        assert valid_archive_bundle.chain_id == 8453
        assert valid_archive_bundle.participants is not None
        assert valid_archive_bundle.references is not None
        assert valid_archive_bundle.hashes is not None
        assert valid_archive_bundle.signatures is not None
        assert valid_archive_bundle.settlement is not None

    def test_sepolia_chain_id(
        self,
        archive_participants: ArchiveParticipants,
        archive_references: ArchiveReferences,
        archive_hashes: ArchiveHashes,
        archive_signatures: ArchiveSignatures,
        archive_settlement: ArchiveSettlement,
    ) -> None:
        """Test bundle with Base Sepolia chain ID."""
        bundle = ArchiveBundle(
            protocolVersion="1.0.0",
            archiveSchemaVersion="1.0.0",
            type=ARCHIVE_BUNDLE_TYPE,
            txId=VALID_TX_ID.lower(),
            chainId=84532,  # Base Sepolia
            archivedAt=int(time.time()),
            participants=archive_participants,
            references=archive_references,
            hashes=archive_hashes,
            signatures=archive_signatures,
            attestation=None,
            settlement=archive_settlement,
        )
        assert bundle.chain_id == 84532

    def test_with_attestation(
        self,
        valid_archive_bundle: ArchiveBundle,
        archive_attestation: ArchiveAttestation,
    ) -> None:
        """Test bundle with optional attestation."""
        bundle_dict = valid_archive_bundle.model_dump(by_alias=True)
        bundle_dict["attestation"] = archive_attestation.model_dump(by_alias=True)
        bundle = ArchiveBundle(**bundle_dict)
        assert bundle.attestation is not None
        assert bundle.attestation.eas_uid == VALID_EAS_UID.lower()

    def test_json_round_trip(self, valid_archive_bundle: ArchiveBundle) -> None:
        """Test JSON serialization and deserialization."""
        # Serialize to JSON with aliases
        json_str = valid_archive_bundle.model_dump_json(by_alias=True)
        json_dict = json.loads(json_str)

        # Verify camelCase keys
        assert "protocolVersion" in json_dict
        assert "archiveSchemaVersion" in json_dict
        assert "txId" in json_dict
        assert "chainId" in json_dict
        assert "archivedAt" in json_dict

        # Deserialize back
        restored = ArchiveBundle(**json_dict)
        assert restored.protocol_version == valid_archive_bundle.protocol_version
        assert restored.tx_id == valid_archive_bundle.tx_id

    def test_bundle_type_constant(self) -> None:
        """Test ARCHIVE_BUNDLE_TYPE constant."""
        assert ARCHIVE_BUNDLE_TYPE == "actp.archive.v1.minimal"


# =============================================================================
# Result Types Tests
# =============================================================================


class TestResultTypes:
    """Tests for upload/download result types."""

    def test_ipfs_upload_result(self) -> None:
        """Test IPFSUploadResult creation."""
        from datetime import datetime, timezone

        result = IPFSUploadResult(
            cid=VALID_CID_V0,
            size=1024,
            uploaded_at=datetime.now(timezone.utc),
        )
        assert result.cid == VALID_CID_V0
        assert result.size == 1024

    def test_arweave_upload_result(self) -> None:
        """Test ArweaveUploadResult creation."""
        from datetime import datetime, timezone

        result = ArweaveUploadResult(
            tx_id="arweave_tx_id_here",
            size=2048,
            uploaded_at=datetime.now(timezone.utc),
            cost="1000000000",  # 1 Gwei
        )
        assert result.tx_id == "arweave_tx_id_here"
        assert result.size == 2048
        assert result.cost == "1000000000"

    def test_download_result(self) -> None:
        """Test DownloadResult creation."""
        from datetime import datetime, timezone

        result = DownloadResult(
            data=b"Hello, AGIRAILS!",
            size=16,
            downloaded_at=datetime.now(timezone.utc),
        )
        assert result.data == b"Hello, AGIRAILS!"
        assert result.size == 16


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_strings_rejected_for_required_fields(self) -> None:
        """Test that empty strings are rejected by Pydantic validation."""
        from pydantic import ValidationError

        # Empty strings should be rejected by Pydantic pattern validation
        with pytest.raises(ValidationError):
            ArchiveParticipants(
                requester="",
                provider="",
            )

    def test_zero_timestamp(
        self,
        archive_participants: ArchiveParticipants,
        archive_references: ArchiveReferences,
        archive_hashes: ArchiveHashes,
        archive_signatures: ArchiveSignatures,
        archive_settlement: ArchiveSettlement,
    ) -> None:
        """Test bundle with zero timestamp."""
        bundle = ArchiveBundle(
            protocolVersion="1.0.0",
            archiveSchemaVersion="1.0.0",
            type=ARCHIVE_BUNDLE_TYPE,
            txId=VALID_TX_ID.lower(),
            chainId=8453,
            archivedAt=0,  # Unix epoch
            participants=archive_participants,
            references=archive_references,
            hashes=archive_hashes,
            signatures=archive_signatures,
            attestation=None,
            settlement=archive_settlement,
        )
        assert bundle.archived_at == 0

    def test_large_amount_string(self) -> None:
        """Test escrow release with very large amount."""
        release = EscrowRelease(
            to=VALID_PROVIDER.lower(),
            amount="1" + "0" * 50,  # Extremely large number
        )
        assert len(release.amount) == 51
