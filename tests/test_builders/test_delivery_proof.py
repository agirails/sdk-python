"""Tests for DeliveryProofBuilder."""

import pytest

from agirails.builders.delivery_proof import (
    DeliveryProof,
    DeliveryProofBuilder,
    BatchDeliveryProofBuilder,
    create_delivery_proof,
    compute_output_hash,
)


class TestComputeOutputHash:
    """Tests for compute_output_hash function."""

    def test_hash_string(self) -> None:
        """Test hashing string output."""
        hash1 = compute_output_hash("hello world")
        hash2 = compute_output_hash("hello world")

        assert hash1 == hash2  # Deterministic
        assert hash1.startswith("0x")
        assert len(hash1) == 66

    def test_hash_dict(self) -> None:
        """Test hashing dict output."""
        hash1 = compute_output_hash({"result": "success"})
        hash2 = compute_output_hash({"result": "success"})

        assert hash1 == hash2

    def test_hash_bytes(self) -> None:
        """Test hashing bytes output."""
        hash1 = compute_output_hash(b"binary data")
        assert hash1.startswith("0x")

    def test_different_outputs_different_hashes(self) -> None:
        """Test that different outputs produce different hashes."""
        hash1 = compute_output_hash("output1")
        hash2 = compute_output_hash("output2")

        assert hash1 != hash2


class TestDeliveryProof:
    """Tests for DeliveryProof dataclass."""

    def test_create_delivery_proof(self) -> None:
        """Test creating a delivery proof."""
        output_hash = compute_output_hash({"result": "done"})

        proof = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash=output_hash,
            provider="0x" + "a" * 40,
        )

        assert proof.transaction_id == "0x" + "1" * 64
        assert proof.output_hash == output_hash
        assert proof.provider == "0x" + "a" * 40
        assert proof.timestamp > 0

    def test_is_on_chain(self) -> None:
        """Test on-chain check."""
        # Not on-chain
        proof1 = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "a" * 64,
            provider="0x" + "b" * 40,
            attestation_uid="",
        )
        assert proof1.is_on_chain is False

        # On-chain
        proof2 = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "a" * 64,
            provider="0x" + "b" * 40,
            attestation_uid="0x" + "c" * 64,
        )
        assert proof2.is_on_chain is True

        # Zero attestation is not on-chain
        proof3 = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "a" * 64,
            provider="0x" + "b" * 40,
            attestation_uid="0x" + "0" * 64,
        )
        assert proof3.is_on_chain is False

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        proof = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "a" * 64,
            provider="0x" + "b" * 40,
        )

        d = proof.to_dict()
        assert d["transactionId"] == "0x" + "1" * 64
        assert d["outputHash"] == "0x" + "a" * 64
        assert d["provider"] == "0x" + "b" * 40
        assert "isOnChain" in d

    def test_to_message(self) -> None:
        """Test converting to message type."""
        proof = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "a" * 64,
            provider="0x" + "b" * 40,
            attestation_uid="0x" + "c" * 64,
        )

        message = proof.to_message()
        assert message.transaction_id == "0x" + "1" * 64
        assert message.output_hash == "0x" + "a" * 64

    def test_verify_output(self) -> None:
        """Test output verification."""
        output_data = {"result": "hello"}
        output_hash = compute_output_hash(output_data)

        proof = DeliveryProof(
            transaction_id="0x" + "1" * 64,
            output_hash=output_hash,
            provider="0x" + "a" * 40,
        )

        assert proof.verify_output(output_data) is True
        assert proof.verify_output({"result": "different"}) is False


class TestDeliveryProofBuilder:
    """Tests for DeliveryProofBuilder class."""

    def test_build_proof(self) -> None:
        """Test building a delivery proof."""
        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output({"result": "done"})
            .build()
        )

        assert proof.transaction_id == "0x" + "1" * 64
        assert proof.provider == "0x" + "a" * 40
        assert proof.output_hash.startswith("0x")

    def test_with_output_hash(self) -> None:
        """Test setting output hash directly."""
        output_hash = "0x" + "b" * 64

        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output_hash(output_hash)
            .build()
        )

        assert proof.output_hash == output_hash

    def test_with_attestation(self) -> None:
        """Test adding attestation UID."""
        attestation_uid = "0x" + "c" * 64

        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output({"result": "done"})
            .with_attestation(attestation_uid)
            .build()
        )

        assert proof.attestation_uid == attestation_uid
        assert proof.is_on_chain is True

    def test_at_timestamp(self) -> None:
        """Test setting timestamp."""
        timestamp = 1000000

        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output("result")
            .at_timestamp(timestamp)
            .build()
        )

        assert proof.timestamp == timestamp

    def test_with_metadata(self) -> None:
        """Test adding metadata."""
        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output("result")
            .with_metadata("key1", "value1")
            .with_metadata("key2", 42)
            .build()
        )

        assert proof.metadata["key1"] == "value1"
        assert proof.metadata["key2"] == 42

    def test_with_execution_time(self) -> None:
        """Test recording execution time."""
        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output("result")
            .with_execution_time(500)
            .build()
        )

        assert proof.metadata["executionTimeMs"] == 500

    def test_with_result_size(self) -> None:
        """Test recording result size."""
        proof = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output("result")
            .with_result_size(1024)
            .build()
        )

        assert proof.metadata["resultSizeBytes"] == 1024

    def test_missing_transaction_id_raises(self) -> None:
        """Test that missing transaction_id raises error."""
        with pytest.raises(ValueError) as exc_info:
            (
                DeliveryProofBuilder()
                .from_provider("0x" + "a" * 40)
                .with_output("result")
                .build()
            )

        assert "transaction_id" in str(exc_info.value)

    def test_missing_output_hash_raises(self) -> None:
        """Test that missing output_hash raises error."""
        with pytest.raises(ValueError) as exc_info:
            (
                DeliveryProofBuilder()
                .for_transaction("0x" + "1" * 64)
                .from_provider("0x" + "a" * 40)
                .build()
            )

        assert "output_hash" in str(exc_info.value)

    def test_missing_provider_raises(self) -> None:
        """Test that missing provider raises error."""
        with pytest.raises(ValueError) as exc_info:
            (
                DeliveryProofBuilder()
                .for_transaction("0x" + "1" * 64)
                .with_output("result")
                .build()
            )

        assert "provider" in str(exc_info.value)

    def test_reset(self) -> None:
        """Test resetting builder."""
        builder = (
            DeliveryProofBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_output("result")
        )

        builder.reset()

        with pytest.raises(ValueError):
            builder.build()


class TestBatchDeliveryProofBuilder:
    """Tests for BatchDeliveryProofBuilder class."""

    def test_build_batch(self) -> None:
        """Test building multiple proofs."""
        proofs = (
            BatchDeliveryProofBuilder()
            .from_provider("0x" + "a" * 40)
            .add_delivery("0x" + "1" * 64, {"result": "a"})
            .add_delivery("0x" + "2" * 64, {"result": "b"})
            .add_delivery("0x" + "3" * 64, {"result": "c"})
            .build_all()
        )

        assert len(proofs) == 3
        assert proofs[0].transaction_id == "0x" + "1" * 64
        assert proofs[1].transaction_id == "0x" + "2" * 64
        assert proofs[2].transaction_id == "0x" + "3" * 64

        # All have same provider
        for proof in proofs:
            assert proof.provider == "0x" + "a" * 40

    def test_with_shared_attestation(self) -> None:
        """Test batch with shared attestation."""
        attestation_uid = "0x" + "c" * 64

        proofs = (
            BatchDeliveryProofBuilder()
            .from_provider("0x" + "a" * 40)
            .with_attestation(attestation_uid)
            .add_delivery("0x" + "1" * 64, "result1")
            .add_delivery("0x" + "2" * 64, "result2")
            .build_all()
        )

        for proof in proofs:
            assert proof.attestation_uid == attestation_uid

    def test_missing_provider_raises(self) -> None:
        """Test that missing provider raises error."""
        with pytest.raises(ValueError) as exc_info:
            (
                BatchDeliveryProofBuilder()
                .add_delivery("0x" + "1" * 64, "result")
                .build_all()
            )

        assert "provider" in str(exc_info.value)

    def test_reset(self) -> None:
        """Test resetting batch builder."""
        builder = (
            BatchDeliveryProofBuilder()
            .from_provider("0x" + "a" * 40)
            .add_delivery("0x" + "1" * 64, "result")
        )

        builder.reset()

        with pytest.raises(ValueError):
            builder.build_all()


class TestCreateDeliveryProof:
    """Tests for create_delivery_proof helper function."""

    def test_create_minimal(self) -> None:
        """Test creating proof with minimal parameters."""
        proof = create_delivery_proof(
            transaction_id="0x" + "1" * 64,
            output={"result": "done"},
            provider="0x" + "a" * 40,
        )

        assert proof.transaction_id == "0x" + "1" * 64
        assert proof.provider == "0x" + "a" * 40
        assert proof.output_hash.startswith("0x")

    def test_create_with_attestation(self) -> None:
        """Test creating proof with attestation."""
        attestation_uid = "0x" + "c" * 64

        proof = create_delivery_proof(
            transaction_id="0x" + "1" * 64,
            output="result",
            provider="0x" + "a" * 40,
            attestation_uid=attestation_uid,
        )

        assert proof.attestation_uid == attestation_uid
        assert proof.is_on_chain is True
