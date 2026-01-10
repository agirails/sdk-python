"""
Tests for ArchiveBundleBuilder fluent API and validation.

Tests cover:
- Fluent builder pattern
- Required field validation
- Hash computation utilities
- Bundle validation
- Error handling for invalid data
"""

import json
import time
from typing import Any, Dict

import pytest

from agirails.storage.archive_bundle_builder import (
    ArchiveBundleBuilder,
    compute_content_hash,
    compute_json_hash,
    validate_archive_bundle,
    PROTOCOL_VERSION,
    ARCHIVE_SCHEMA_VERSION,
)
from agirails.storage.types import (
    ArchiveBundle,
    ArchiveParticipants,
    ArchiveReferences,
    ArchiveHashes,
    ArchiveSignatures,
    ArchiveSettlement,
    EscrowRelease,
    ARCHIVE_BUNDLE_TYPE,
)
from agirails.errors.storage import ArchiveBundleValidationError

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
)


# =============================================================================
# Hash Computation Tests
# =============================================================================


class TestHashComputation:
    """Tests for hash computation utilities."""

    def test_compute_content_hash(self) -> None:
        """Test keccak256 hash computation for bytes."""
        content = b"Hello, AGIRAILS!"
        result = compute_content_hash(content)

        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_compute_content_hash_deterministic(self) -> None:
        """Test hash computation is deterministic."""
        content = b"Same content"
        hash1 = compute_content_hash(content)
        hash2 = compute_content_hash(content)

        assert hash1 == hash2

    def test_compute_content_hash_different_inputs(self) -> None:
        """Test different inputs produce different hashes."""
        hash1 = compute_content_hash(b"Content A")
        hash2 = compute_content_hash(b"Content B")

        assert hash1 != hash2

    def test_compute_json_hash(self) -> None:
        """Test keccak256 hash computation for JSON."""
        data = {"key": "value", "number": 42}
        result = compute_json_hash(data)

        assert result.startswith("0x")
        assert len(result) == 66

    def test_compute_json_hash_canonical(self) -> None:
        """Test JSON hash uses canonical serialization."""
        # Different order, same content
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}

        hash1 = compute_json_hash(data1)
        hash2 = compute_json_hash(data2)

        # Should be same because keys are sorted
        assert hash1 == hash2

    def test_compute_json_hash_no_whitespace(self) -> None:
        """Test JSON hash uses compact format."""
        data = {"key": "value"}
        result = compute_json_hash(data)

        # Manually compute expected
        canonical = json.dumps(data, separators=(",", ":"), sort_keys=True)
        expected = compute_content_hash(canonical.encode("utf-8"))

        assert result == expected


# =============================================================================
# Builder Fluent API Tests
# =============================================================================


class TestBuilderFluentAPI:
    """Tests for ArchiveBundleBuilder fluent pattern."""

    def test_builder_chaining(self) -> None:
        """Test method chaining returns builder instance."""
        builder = ArchiveBundleBuilder()

        result = (
            builder
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
        )

        assert result is builder

    def test_set_transaction_id(self) -> None:
        """Test setting transaction ID."""
        builder = ArchiveBundleBuilder()
        builder.set_transaction_id(VALID_TX_ID)

        assert builder._tx_id == VALID_TX_ID.lower()

    def test_set_transaction_id_invalid_format(self) -> None:
        """Test invalid transaction ID format rejected."""
        builder = ArchiveBundleBuilder()

        with pytest.raises(ValueError) as exc_info:
            builder.set_transaction_id("invalid_tx_id")

        assert "bytes32" in str(exc_info.value).lower()

    def test_set_transaction_id_too_short(self) -> None:
        """Test too-short transaction ID rejected."""
        builder = ArchiveBundleBuilder()

        with pytest.raises(ValueError):
            builder.set_transaction_id("0x" + "a" * 32)  # Only 32 chars, need 64

    def test_set_chain_id_mainnet(self) -> None:
        """Test setting Base Mainnet chain ID."""
        builder = ArchiveBundleBuilder()
        builder.set_chain_id(8453)

        assert builder._chain_id == 8453

    def test_set_chain_id_sepolia(self) -> None:
        """Test setting Base Sepolia chain ID."""
        builder = ArchiveBundleBuilder()
        builder.set_chain_id(84532)

        assert builder._chain_id == 84532

    def test_set_chain_id_invalid(self) -> None:
        """Test invalid chain ID rejected."""
        builder = ArchiveBundleBuilder()

        with pytest.raises(ValueError) as exc_info:
            builder.set_chain_id(1)  # Ethereum mainnet, not supported

        assert "8453" in str(exc_info.value) or "84532" in str(exc_info.value)

    def test_set_archived_at(self) -> None:
        """Test setting archive timestamp."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())
        builder.set_archived_at(timestamp)

        assert builder._archived_at == timestamp

    def test_set_participants(self) -> None:
        """Test setting participants."""
        builder = ArchiveBundleBuilder()
        builder.set_participants(VALID_REQUESTER, VALID_PROVIDER)

        assert builder._participants is not None
        assert builder._participants.requester == VALID_REQUESTER.lower()
        assert builder._participants.provider == VALID_PROVIDER.lower()

    def test_set_references(self) -> None:
        """Test setting IPFS references."""
        builder = ArchiveBundleBuilder()
        builder.set_references(VALID_CID_V0, VALID_CID_V1)

        assert builder._references is not None
        assert builder._references.request_cid == VALID_CID_V0
        assert builder._references.delivery_cid == VALID_CID_V1

    def test_set_references_with_result(self) -> None:
        """Test setting references with optional result CID."""
        builder = ArchiveBundleBuilder()
        builder.set_references(VALID_CID_V0, VALID_CID_V1, result_cid=VALID_CID_V0)

        assert builder._references.result_cid == VALID_CID_V0

    def test_set_hashes(self) -> None:
        """Test setting cryptographic hashes."""
        builder = ArchiveBundleBuilder()
        builder.set_hashes(
            VALID_REQUEST_HASH,
            VALID_DELIVERY_HASH,
            VALID_SERVICE_HASH,
        )

        assert builder._hashes is not None
        assert builder._hashes.request_hash == VALID_REQUEST_HASH.lower()
        assert builder._hashes.delivery_hash == VALID_DELIVERY_HASH.lower()
        assert builder._hashes.service_hash == VALID_SERVICE_HASH.lower()

    def test_set_signatures(self) -> None:
        """Test setting signatures."""
        builder = ArchiveBundleBuilder()
        builder.set_signatures(VALID_SIGNATURE)

        assert builder._signatures is not None
        assert builder._signatures.provider_delivery_signature == VALID_SIGNATURE

    def test_set_signatures_with_requester(self) -> None:
        """Test setting signatures with requester signature."""
        builder = ArchiveBundleBuilder()
        requester_sig = "0x" + "f" * 130
        builder.set_signatures(VALID_SIGNATURE, requester_sig)

        assert builder._signatures.requester_settlement_signature == requester_sig

    def test_set_attestation(self) -> None:
        """Test setting EAS attestation."""
        builder = ArchiveBundleBuilder()
        eas_uid = "0x" + "1" * 64
        builder.set_attestation(eas_uid)

        assert builder._attestation is not None
        assert builder._attestation.eas_uid == eas_uid.lower()

    def test_set_attestation_with_schema(self) -> None:
        """Test setting attestation with schema UID."""
        builder = ArchiveBundleBuilder()
        eas_uid = "0x" + "1" * 64
        schema_uid = "0x" + "2" * 64
        builder.set_attestation(eas_uid, schema_uid)

        assert builder._attestation.schema_uid == schema_uid.lower()

    def test_set_settlement(self) -> None:
        """Test setting settlement information."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())
        builder.set_settlement(
            settled_at=timestamp,
            final_state="SETTLED",
            escrow_to=VALID_PROVIDER,
            escrow_amount="1000000000",
            platform_fee="10000000",
            was_disputed=False,
        )

        assert builder._settlement is not None
        assert builder._settlement.settled_at == timestamp
        assert builder._settlement.final_state == "SETTLED"
        assert builder._settlement.escrow_released.to == VALID_PROVIDER.lower()


# =============================================================================
# Build Tests
# =============================================================================


class TestBuilderBuild:
    """Tests for building complete archive bundles."""

    def test_build_complete_bundle(self) -> None:
        """Test building complete valid bundle."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())

        bundle = (
            builder
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
            .set_archived_at(timestamp)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=VALID_PROVIDER,
                escrow_amount="1000000000",
                platform_fee="10000000",
                was_disputed=False,
            )
            .build()
        )

        assert isinstance(bundle, ArchiveBundle)
        assert bundle.protocol_version == PROTOCOL_VERSION
        assert bundle.archive_schema_version == ARCHIVE_SCHEMA_VERSION
        assert bundle.type == ARCHIVE_BUNDLE_TYPE
        assert bundle.tx_id == VALID_TX_ID.lower()
        assert bundle.chain_id == 8453

    def test_build_with_attestation(self) -> None:
        """Test building bundle with optional attestation."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())
        eas_uid = "0x" + "1" * 64

        bundle = (
            builder
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_attestation(eas_uid)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=VALID_PROVIDER,
                escrow_amount="1000000000",
                platform_fee="10000000",
            )
            .build()
        )

        assert bundle.attestation is not None
        assert bundle.attestation.eas_uid == eas_uid.lower()

    def test_build_missing_transaction_id(self) -> None:
        """Test build fails without transaction ID."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())

        builder.set_chain_id(8453)
        builder.set_participants(VALID_REQUESTER, VALID_PROVIDER)
        builder.set_references(VALID_CID_V0, VALID_CID_V1)
        builder.set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
        builder.set_signatures(VALID_SIGNATURE)
        builder.set_settlement(
            settled_at=timestamp,
            final_state="SETTLED",
            escrow_to=VALID_PROVIDER,
            escrow_amount="1000000000",
            platform_fee="10000000",
        )

        with pytest.raises(ArchiveBundleValidationError) as exc_info:
            builder.build()

        assert "tx_id" in str(exc_info.value).lower()

    def test_build_missing_chain_id(self) -> None:
        """Test build fails without chain ID."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())

        builder.set_transaction_id(VALID_TX_ID)
        # Missing: set_chain_id()
        builder.set_participants(VALID_REQUESTER, VALID_PROVIDER)
        builder.set_references(VALID_CID_V0, VALID_CID_V1)
        builder.set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
        builder.set_signatures(VALID_SIGNATURE)
        builder.set_settlement(
            settled_at=timestamp,
            final_state="SETTLED",
            escrow_to=VALID_PROVIDER,
            escrow_amount="1000000000",
            platform_fee="10000000",
        )

        with pytest.raises(ArchiveBundleValidationError) as exc_info:
            builder.build()

        assert "chain_id" in str(exc_info.value).lower()

    def test_build_missing_multiple_fields(self) -> None:
        """Test build reports all missing fields."""
        builder = ArchiveBundleBuilder()

        with pytest.raises(ArchiveBundleValidationError) as exc_info:
            builder.build()

        error_msg = str(exc_info.value).lower()
        assert "tx_id" in error_msg
        assert "chain_id" in error_msg
        assert "participants" in error_msg


# =============================================================================
# Validation Tests
# =============================================================================


class TestBundleValidation:
    """Tests for validate_archive_bundle function.

    Note: Many validations are now handled by Pydantic at model creation time.
    These tests verify that invalid data is caught (either by Pydantic or validate_archive_bundle).
    """

    def test_validate_valid_bundle(
        self, valid_archive_bundle: ArchiveBundle
    ) -> None:
        """Test validation passes for valid bundle."""
        result = validate_archive_bundle(valid_archive_bundle)
        assert result is True

    def test_pydantic_rejects_invalid_tx_id(self) -> None:
        """Test Pydantic validation rejects invalid tx_id at model creation."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            # Try to create bundle with invalid tx_id - Pydantic catches it
            ArchiveBundle(
                protocolVersion="1.0.0",
                archiveSchemaVersion="1.0.0",
                type=ARCHIVE_BUNDLE_TYPE,
                txId="invalid",  # Invalid!
                chainId=8453,
                archivedAt=int(time.time()),
                participants=ArchiveParticipants(
                    requester=VALID_REQUESTER.lower(),
                    provider=VALID_PROVIDER.lower(),
                ),
                references=ArchiveReferences(
                    requestCID=VALID_CID_V0,
                    deliveryCID=VALID_CID_V1,
                ),
                hashes=ArchiveHashes(
                    requestHash=VALID_REQUEST_HASH.lower(),
                    deliveryHash=VALID_DELIVERY_HASH.lower(),
                    serviceHash=VALID_SERVICE_HASH.lower(),
                ),
                signatures=ArchiveSignatures(
                    providerDeliverySignature=VALID_SIGNATURE,
                ),
                settlement=ArchiveSettlement(
                    settledAt=int(time.time()),
                    finalState="SETTLED",
                    escrowReleased=EscrowRelease(
                        to=VALID_PROVIDER.lower(),
                        amount="1000000000",
                    ),
                    platformFee="10000000",
                    wasDisputed=False,
                ),
            )

        assert "txId" in str(exc_info.value) or "tx_id" in str(exc_info.value).lower()

    def test_pydantic_rejects_invalid_chain_id(self) -> None:
        """Test Pydantic validation rejects invalid chain_id."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            ArchiveBundle(
                protocolVersion="1.0.0",
                archiveSchemaVersion="1.0.0",
                type=ARCHIVE_BUNDLE_TYPE,
                txId=VALID_TX_ID,
                chainId=1,  # Invalid - not 8453 or 84532
                archivedAt=int(time.time()),
                participants=ArchiveParticipants(
                    requester=VALID_REQUESTER.lower(),
                    provider=VALID_PROVIDER.lower(),
                ),
                references=ArchiveReferences(
                    requestCID=VALID_CID_V0,
                    deliveryCID=VALID_CID_V1,
                ),
                hashes=ArchiveHashes(
                    requestHash=VALID_REQUEST_HASH.lower(),
                    deliveryHash=VALID_DELIVERY_HASH.lower(),
                    serviceHash=VALID_SERVICE_HASH.lower(),
                ),
                signatures=ArchiveSignatures(
                    providerDeliverySignature=VALID_SIGNATURE,
                ),
                settlement=ArchiveSettlement(
                    settledAt=int(time.time()),
                    finalState="SETTLED",
                    escrowReleased=EscrowRelease(
                        to=VALID_PROVIDER.lower(),
                        amount="1000000000",
                    ),
                    platformFee="10000000",
                    wasDisputed=False,
                ),
            )

        assert "chain" in str(exc_info.value).lower()

    def test_validate_invalid_type(
        self, valid_archive_bundle: ArchiveBundle
    ) -> None:
        """Test validation fails for invalid type."""
        bundle_dict = valid_archive_bundle.model_dump(by_alias=True)
        bundle_dict["type"] = "wrong.type"
        bundle = ArchiveBundle(**bundle_dict)

        with pytest.raises(ArchiveBundleValidationError) as exc_info:
            validate_archive_bundle(bundle)

        assert "type" in str(exc_info.value).lower()

    def test_pydantic_rejects_invalid_address(self) -> None:
        """Test Pydantic validation rejects invalid Ethereum addresses."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ArchiveParticipants(
                requester="invalid_address",  # Invalid!
                provider=VALID_PROVIDER.lower(),
            )

    def test_validate_invalid_cid(
        self, valid_archive_bundle: ArchiveBundle
    ) -> None:
        """Test validation fails for invalid CID format."""
        bundle_dict = valid_archive_bundle.model_dump(by_alias=True)
        # Use a short invalid CID that passes Pydantic's basic string check
        bundle_dict["references"]["requestCID"] = "short"
        bundle = ArchiveBundle(**bundle_dict)

        with pytest.raises(ArchiveBundleValidationError) as exc_info:
            validate_archive_bundle(bundle)

        assert "cid" in str(exc_info.value).lower()

    def test_pydantic_rejects_invalid_hash(self) -> None:
        """Test Pydantic validation rejects invalid hash format."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ArchiveHashes(
                requestHash="not_a_hash",  # Invalid!
                deliveryHash=VALID_DELIVERY_HASH.lower(),
                serviceHash=VALID_SERVICE_HASH.lower(),
            )

    def test_pydantic_rejects_invalid_final_state(self) -> None:
        """Test Pydantic validation rejects invalid final state."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ArchiveSettlement(
                settledAt=int(time.time()),
                finalState="INVALID_STATE",  # Invalid!
                escrowReleased=EscrowRelease(
                    to=VALID_PROVIDER.lower(),
                    amount="1000000000",
                ),
                platformFee="10000000",
                wasDisputed=False,
            )

    def test_pydantic_reports_multiple_errors(self) -> None:
        """Test Pydantic reports multiple validation errors."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            ArchiveParticipants(
                requester="invalid1",  # Invalid!
                provider="invalid2",  # Invalid!
            )

        # Should have 2 errors
        assert len(exc_info.value.errors()) == 2


# =============================================================================
# Constants Tests
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_protocol_version(self) -> None:
        """Test PROTOCOL_VERSION constant."""
        assert PROTOCOL_VERSION == "1.0.0"

    def test_archive_schema_version(self) -> None:
        """Test ARCHIVE_SCHEMA_VERSION constant."""
        assert ARCHIVE_SCHEMA_VERSION == "1.0.0"

    def test_archive_bundle_type(self) -> None:
        """Test ARCHIVE_BUNDLE_TYPE constant."""
        assert ARCHIVE_BUNDLE_TYPE == "actp.archive.v1.minimal"


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_builder_build_fails(self) -> None:
        """Test building from empty builder fails gracefully."""
        builder = ArchiveBundleBuilder()

        with pytest.raises(ArchiveBundleValidationError):
            builder.build()

    def test_builder_reuse(self) -> None:
        """Test builder can be reused for multiple bundles."""
        timestamp = int(time.time())

        # Build first bundle
        builder1 = ArchiveBundleBuilder()
        bundle1 = (
            builder1
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=VALID_PROVIDER,
                escrow_amount="1000000000",
                platform_fee="10000000",
            )
            .build()
        )

        # Build second bundle with different tx_id
        builder2 = ArchiveBundleBuilder()
        different_tx_id = "0x" + "b" * 64
        bundle2 = (
            builder2
            .set_transaction_id(different_tx_id)
            .set_chain_id(8453)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=VALID_PROVIDER,
                escrow_amount="1000000000",
                platform_fee="10000000",
            )
            .build()
        )

        assert bundle1.tx_id != bundle2.tx_id

    def test_cancelled_state_bundle(self) -> None:
        """Test building bundle with CANCELLED state."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())

        bundle = (
            builder
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_settlement(
                settled_at=timestamp,
                final_state="CANCELLED",  # Refund to requester
                escrow_to=VALID_REQUESTER,  # Funds back to requester
                escrow_amount="1000000000",
                platform_fee="0",  # No fee on cancellation
                was_disputed=False,
            )
            .build()
        )

        assert bundle.settlement.final_state == "CANCELLED"
        assert bundle.settlement.escrow_released.to == VALID_REQUESTER.lower()

    def test_disputed_settlement_bundle(self) -> None:
        """Test building bundle with disputed settlement."""
        builder = ArchiveBundleBuilder()
        timestamp = int(time.time())

        bundle = (
            builder
            .set_transaction_id(VALID_TX_ID)
            .set_chain_id(8453)
            .set_participants(VALID_REQUESTER, VALID_PROVIDER)
            .set_references(VALID_CID_V0, VALID_CID_V1)
            .set_hashes(VALID_REQUEST_HASH, VALID_DELIVERY_HASH, VALID_SERVICE_HASH)
            .set_signatures(VALID_SIGNATURE)
            .set_settlement(
                settled_at=timestamp,
                final_state="SETTLED",
                escrow_to=VALID_PROVIDER,
                escrow_amount="500000000",  # Partial after dispute
                platform_fee="10000000",
                was_disputed=True,  # Was disputed
            )
            .build()
        )

        assert bundle.settlement.was_disputed is True
