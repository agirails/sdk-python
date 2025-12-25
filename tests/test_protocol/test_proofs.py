"""Tests for proof generation."""

import pytest

from agirails.protocol.proofs import (
    ProofGenerator,
    ContentProof,
    MerkleProof,
    verify_merkle_proof,
    hash_service_input,
    hash_service_output,
)


class TestProofGenerator:
    """Tests for ProofGenerator class."""

    def test_create_generator(self) -> None:
        """Test creating a proof generator."""
        generator = ProofGenerator()
        assert generator is not None

    def test_create_generator_with_algorithm(self) -> None:
        """Test creating generator with specific algorithm."""
        generator = ProofGenerator(hash_algorithm="sha256")
        assert generator is not None

    def test_invalid_algorithm_raises(self) -> None:
        """Test that invalid algorithm raises error."""
        with pytest.raises(ValueError) as exc_info:
            ProofGenerator(hash_algorithm="invalid_algorithm")
        assert "Unsupported" in str(exc_info.value)

    def test_hash_content_string(self) -> None:
        """Test hashing string content."""
        generator = ProofGenerator()
        proof = generator.hash_content("hello world", content_type="text")

        assert proof.content_hash.startswith("0x")
        assert len(proof.content_hash) == 66  # 0x + 64 hex chars
        assert proof.content_type == "text"
        assert proof.size > 0

    def test_hash_content_dict(self) -> None:
        """Test hashing dictionary content."""
        generator = ProofGenerator()
        proof = generator.hash_content({"key": "value"}, content_type="json")

        assert proof.content_hash.startswith("0x")
        assert proof.content_type == "json"

    def test_hash_input(self) -> None:
        """Test hashing input data."""
        generator = ProofGenerator()
        hash1 = generator.hash_input("test input")
        hash2 = generator.hash_input("test input")

        assert hash1 == hash2  # Deterministic
        assert hash1.startswith("0x")
        assert len(hash1) == 66

    def test_hash_input_dict(self) -> None:
        """Test hashing dict input."""
        generator = ProofGenerator()
        hash1 = generator.hash_input({"query": "hello"})
        hash2 = generator.hash_input({"query": "hello"})

        assert hash1 == hash2

    def test_hash_output(self) -> None:
        """Test hashing output data."""
        generator = ProofGenerator()
        hash1 = generator.hash_output({"result": "success"})

        assert hash1.startswith("0x")
        assert len(hash1) == 66

    def test_create_delivery_proof(self) -> None:
        """Test creating delivery proof."""
        generator = ProofGenerator()
        output_hash = generator.hash_output({"result": "done"})

        proof = generator.create_delivery_proof(
            transaction_id="0x" + "1" * 64,
            output_hash=output_hash,
            provider="0x" + "a" * 40,
        )

        assert proof.transaction_id == "0x" + "1" * 64
        assert proof.output_hash == output_hash
        assert proof.provider == "0x" + "a" * 40
        assert proof.timestamp > 0

    def test_verify_delivery(self) -> None:
        """Test verifying delivery proof."""
        generator = ProofGenerator()
        output_data = {"result": "hello"}
        output_hash = generator.hash_output(output_data)

        proof = generator.create_delivery_proof(
            transaction_id="0x" + "1" * 64,
            output_hash=output_hash,
            provider="0x" + "a" * 40,
        )

        assert generator.verify_delivery(output_data, proof) is True
        assert generator.verify_delivery({"result": "different"}, proof) is False


class TestContentProof:
    """Tests for ContentProof dataclass."""

    def test_create_content_proof(self) -> None:
        """Test creating content proof."""
        proof = ContentProof(
            content_hash="0x" + "a" * 64,
            content_type="text",
            size=100,
        )

        assert proof.content_hash == "0x" + "a" * 64
        assert proof.content_type == "text"
        assert proof.size == 100
        assert proof.timestamp > 0

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        proof = ContentProof(
            content_hash="0x" + "b" * 64,
            content_type="json",
            size=50,
        )

        d = proof.to_dict()
        assert d["contentHash"] == "0x" + "b" * 64
        assert d["contentType"] == "json"
        assert d["size"] == 50


class TestMerkleTree:
    """Tests for Merkle tree functionality."""

    def test_create_merkle_tree_single_leaf(self) -> None:
        """Test creating tree with single leaf."""
        generator = ProofGenerator()
        leaves = ["0x" + "a" * 64]

        root, levels = generator.create_merkle_tree(leaves)

        assert root.startswith("0x")
        assert len(levels) >= 1

    def test_create_merkle_tree_multiple_leaves(self) -> None:
        """Test creating tree with multiple leaves."""
        generator = ProofGenerator()
        leaves = [
            "0x" + "a" * 64,
            "0x" + "b" * 64,
            "0x" + "c" * 64,
            "0x" + "d" * 64,
        ]

        root, levels = generator.create_merkle_tree(leaves)

        assert root.startswith("0x")
        assert len(levels) == 3  # leaves, intermediate, root

    def test_create_merkle_proof(self) -> None:
        """Test creating Merkle proof."""
        generator = ProofGenerator()
        leaves = [
            "0x" + "a" * 64,
            "0x" + "b" * 64,
            "0x" + "c" * 64,
            "0x" + "d" * 64,
        ]

        proof = generator.create_merkle_proof(leaves, leaf_index=1)

        assert proof.root.startswith("0x")
        assert proof.leaf == leaves[1]
        assert proof.leaf_index == 1
        assert len(proof.proof) > 0

    def test_merkle_proof_verification(self) -> None:
        """Test Merkle proof verification."""
        generator = ProofGenerator()
        leaves = [
            "0x" + "a" * 64,
            "0x" + "b" * 64,
        ]

        proof = generator.create_merkle_proof(leaves, leaf_index=0)

        # Verify using the proof object
        assert proof.verify() is True

    def test_merkle_proof_to_dict(self) -> None:
        """Test converting Merkle proof to dict."""
        proof = MerkleProof(
            root="0x" + "1" * 64,
            proof=["0x" + "2" * 64],
            leaf="0x" + "a" * 64,
            leaf_index=0,
        )

        d = proof.to_dict()
        assert d["root"] == "0x" + "1" * 64
        assert d["leaf"] == "0x" + "a" * 64
        assert d["leafIndex"] == 0

    def test_merkle_proof_invalid_index(self) -> None:
        """Test creating proof with invalid index."""
        generator = ProofGenerator()
        leaves = ["0x" + "a" * 64]

        with pytest.raises(IndexError):
            generator.create_merkle_proof(leaves, leaf_index=5)


class TestHashFunctions:
    """Tests for hash utility functions."""

    def test_hash_service_input(self) -> None:
        """Test hashing service input."""
        hash1 = hash_service_input("echo", {"message": "hello"})
        hash2 = hash_service_input("echo", {"message": "hello"})

        assert hash1 == hash2
        assert hash1.startswith("0x")

    def test_hash_service_input_with_requester(self) -> None:
        """Test hashing with requester."""
        hash1 = hash_service_input("echo", "hello", requester="0x" + "a" * 40)
        hash2 = hash_service_input("echo", "hello", requester="0x" + "A" * 40)

        # Should be case-insensitive for addresses
        assert hash1 == hash2

    def test_hash_service_output(self) -> None:
        """Test hashing service output."""
        tx_id = "0x" + "1" * 64
        hash1 = hash_service_output(tx_id, {"result": "done"})
        hash2 = hash_service_output(tx_id, {"result": "done"})

        assert hash1 == hash2
        assert hash1.startswith("0x")

    def test_different_inputs_different_hashes(self) -> None:
        """Test that different inputs produce different hashes."""
        hash1 = hash_service_input("echo", "hello")
        hash2 = hash_service_input("echo", "world")

        assert hash1 != hash2
