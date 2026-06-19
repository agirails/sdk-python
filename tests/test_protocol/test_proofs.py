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


# ============================================================================
# Parity tests for the TS-mirroring surface (encode/decode/verify/url/AIP-4)
# ============================================================================

import httpx  # noqa: E402
import respx  # noqa: E402

from agirails.protocol.proofs import URLValidationConfig  # noqa: E402


class TestGenerateDeliveryProof:
    """generate_delivery_proof — ProofGenerator.ts:98-128."""

    def test_basic_shape(self) -> None:
        g = ProofGenerator()
        tx = "0x" + "1" * 64
        proof = g.generate_delivery_proof(tx_id=tx, deliverable="hello world")

        assert proof["type"] == "delivery.proof"
        assert proof["txId"] == tx
        assert proof["contentHash"].startswith("0x")
        assert len(proof["contentHash"]) == 66
        assert proof["metadata"]["size"] == len("hello world".encode("utf-8"))
        assert proof["metadata"]["mimeType"] == "application/octet-stream"
        assert isinstance(proof["timestamp"], int)

    def test_bytes_deliverable_and_url(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(
            tx_id="0x" + "2" * 64,
            deliverable=b"\x00\x01\x02\x03",
            delivery_url="ipfs://bafy",
        )
        assert proof["deliveryUrl"] == "ipfs://bafy"
        assert proof["metadata"]["size"] == 4

    def test_computed_fields_cannot_be_spoofed(self) -> None:
        """Caller-supplied size/mimeType are dropped; computed values enforced."""
        g = ProofGenerator()
        proof = g.generate_delivery_proof(
            tx_id="0x" + "3" * 64,
            deliverable="abc",
            metadata={"size": 99999, "mimeType": "text/plain", "author": "alice"},
        )
        # size is enforced (computed), NOT the spoofed 99999
        assert proof["metadata"]["size"] == 3
        # explicit mimeType is honored (TS: metadata.mimeType || fallback)
        assert proof["metadata"]["mimeType"] == "text/plain"
        # user metadata preserved
        assert proof["metadata"]["author"] == "alice"

    def test_content_hash_is_keccak_of_utf8(self) -> None:
        from eth_hash.auto import keccak

        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "4" * 64, deliverable="hello")
        assert proof["contentHash"] == "0x" + keccak(b"hello").hex()


class TestEncodeDecodeProof:
    """encode_proof / decode_proof — ProofGenerator.ts:140-167."""

    def test_round_trip(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "1" * 64, deliverable="payload")

        encoded = g.encode_proof(proof)
        assert isinstance(encoded, bytes)
        assert len(encoded) == 96  # 3 x 32-byte ABI words

        decoded = g.decode_proof(encoded)
        assert decoded["txId"] == proof["txId"]
        assert decoded["contentHash"] == proof["contentHash"]
        assert decoded["timestamp"] == proof["timestamp"]

    def test_decode_accepts_hex_string(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "5" * 64, deliverable="x")
        encoded = g.encode_proof(proof)
        decoded = g.decode_proof("0x" + encoded.hex())
        assert decoded["txId"] == proof["txId"]

    def test_encode_matches_ethers_abi_layout(self) -> None:
        """ABI encoding must be byte-identical to ethers defaultAbiCoder."""
        g = ProofGenerator()
        proof = {
            "txId": "0x" + "11" * 32,
            "contentHash": "0x" + "22" * 32,
            "timestamp": 1700000000,
        }
        encoded = g.encode_proof(proof)
        expected = (
            "11" * 32
            + "22" * 32
            + format(1700000000, "064x")
        )
        assert encoded.hex() == expected

    def test_encode_legacy_dataclass(self) -> None:
        """encode_proof accepts a legacy DeliveryProof dataclass."""
        from agirails.types.message import DeliveryProof as LegacyProof

        g = ProofGenerator()
        legacy = LegacyProof(
            transaction_id="0x" + "1" * 64,
            output_hash="0x" + "2" * 64,
            timestamp=12345,
        )
        encoded = g.encode_proof(legacy)
        decoded = g.decode_proof(encoded)
        assert decoded["txId"] == "0x" + "1" * 64
        assert decoded["contentHash"] == "0x" + "2" * 64
        assert decoded["timestamp"] == 12345


class TestVerifyDeliverable:
    """verify_deliverable — ProofGenerator.ts:172-175."""

    def test_matching_hash(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "1" * 64, deliverable="hello")
        assert g.verify_deliverable("hello", proof["contentHash"]) is True

    def test_mismatched_hash(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "1" * 64, deliverable="hello")
        assert g.verify_deliverable("tampered", proof["contentHash"]) is False

    def test_case_insensitive(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "1" * 64, deliverable="hello")
        assert g.verify_deliverable("hello", proof["contentHash"].upper().replace("0X", "0x")) is True

    def test_bytes_deliverable(self) -> None:
        g = ProofGenerator()
        proof = g.generate_delivery_proof(tx_id="0x" + "1" * 64, deliverable=b"\xde\xad")
        assert g.verify_deliverable(b"\xde\xad", proof["contentHash"]) is True


class TestHashFromUrlSSRF:
    """hash_from_url SSRF guards — ProofGenerator.ts:190-332."""

    async def test_blocks_http_by_default(self) -> None:
        g = ProofGenerator()
        with pytest.raises(ValueError, match="protocol"):
            await g.hash_from_url("http://example.com/file")

    async def test_blocks_localhost(self) -> None:
        g = ProofGenerator()
        with pytest.raises(ValueError, match="blocked"):
            await g.hash_from_url("https://localhost/file")

    async def test_blocks_metadata_ip(self) -> None:
        g = ProofGenerator()
        with pytest.raises(ValueError, match="blocked"):
            await g.hash_from_url("https://169.254.169.254/latest/meta-data")

    @pytest.mark.parametrize(
        "host",
        ["10.0.0.5", "172.16.5.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0"],
    )
    async def test_blocks_private_ipv4(self, host: str) -> None:
        g = ProofGenerator()
        with pytest.raises(ValueError):
            await g.hash_from_url(f"https://{host}/file")

    async def test_invalid_url(self) -> None:
        g = ProofGenerator()
        with pytest.raises(ValueError, match="Invalid URL"):
            await g.hash_from_url("not a url")

    async def test_allow_localhost_config(self) -> None:
        g = ProofGenerator(
            url_config=URLValidationConfig(allow_localhost=True, allowed_protocols=("http", "https"))
        )
        cfg = g.get_url_config()
        assert "localhost" not in cfg.blocked_hosts
        assert "127.0.0.1" not in cfg.blocked_hosts
        # metadata IP is NOT a localhost-class host → still blocked
        assert "169.254.169.254" in cfg.blocked_hosts

    @respx.mock
    async def test_happy_path_hashes_content(self) -> None:
        from eth_hash.auto import keccak

        body = b"deliverable-bytes"
        respx.get("https://cdn.example.com/file").mock(
            return_value=httpx.Response(200, content=body)
        )
        g = ProofGenerator()
        result = await g.hash_from_url("https://cdn.example.com/file")
        assert result == "0x" + keccak(body).hex()

    @respx.mock
    async def test_rejects_redirect(self) -> None:
        respx.get("https://cdn.example.com/redir").mock(
            return_value=httpx.Response(302, headers={"location": "https://evil/x"})
        )
        g = ProofGenerator()
        with pytest.raises(ValueError, match="[Rr]edirect"):
            await g.hash_from_url("https://cdn.example.com/redir")

    @respx.mock
    async def test_rejects_http_error(self) -> None:
        respx.get("https://cdn.example.com/missing").mock(
            return_value=httpx.Response(404)
        )
        g = ProofGenerator()
        with pytest.raises(ValueError, match="HTTP error"):
            await g.hash_from_url("https://cdn.example.com/missing")

    @respx.mock
    async def test_rejects_oversized_content_length(self) -> None:
        g = ProofGenerator(url_config=URLValidationConfig(max_size=10))
        respx.get("https://cdn.example.com/big").mock(
            return_value=httpx.Response(
                200, headers={"content-length": "1000"}, content=b"x" * 1000
            )
        )
        with pytest.raises(ValueError, match="too large"):
            await g.hash_from_url("https://cdn.example.com/big")

    @respx.mock
    async def test_rejects_oversized_stream(self) -> None:
        # No content-length header → caught during streaming.
        g = ProofGenerator(url_config=URLValidationConfig(max_size=4))
        respx.get("https://cdn.example.com/stream").mock(
            return_value=httpx.Response(200, content=b"abcdefgh")
        )
        with pytest.raises(ValueError, match="too large"):
            await g.hash_from_url("https://cdn.example.com/stream")
