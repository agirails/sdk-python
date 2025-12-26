"""
Proof Generator for AGIRAILS SDK.

Provides cryptographic proof generation for ACTP protocol:
- Content hashing (SHA-256)
- Input/output proof generation
- Delivery proof creation
- Merkle tree proofs (for batch operations)

Example:
    >>> from agirails.protocol import ProofGenerator
    >>> generator = ProofGenerator()
    >>> input_hash = generator.hash_input({"query": "Hello"})
    >>> output_hash = generator.hash_output({"response": "Hi there"})
    >>> proof = generator.create_delivery_proof(tx_id, output_hash, attestation_uid)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from agirails.types.message import DeliveryProof, create_input_hash, create_output_hash
from agirails.utils.canonical_json import canonical_json_dumps as canonical_json_serialize


@dataclass
class ContentProof:
    """
    Proof for content authenticity.

    Attributes:
        content_hash: SHA-256 hash of the content
        content_type: Type of content (input, output, metadata)
        timestamp: When the proof was generated
        size: Size of the original content in bytes
    """

    content_hash: str
    content_type: str
    timestamp: int = field(default_factory=lambda: int(time.time()))
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "contentHash": self.content_hash,
            "contentType": self.content_type,
            "timestamp": self.timestamp,
            "size": self.size,
        }


@dataclass
class MerkleProof:
    """
    Merkle tree proof for batch verification.

    Attributes:
        root: Merkle root hash
        proof: List of sibling hashes for verification
        leaf: The leaf hash being proven
        leaf_index: Position of the leaf in the tree
    """

    root: str
    proof: List[str]
    leaf: str
    leaf_index: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "root": self.root,
            "proof": self.proof,
            "leaf": self.leaf,
            "leafIndex": self.leaf_index,
        }

    def verify(self) -> bool:
        """
        Verify the Merkle proof.

        Returns:
            True if the proof is valid
        """
        return verify_merkle_proof(
            leaf=self.leaf,
            proof=self.proof,
            root=self.root,
            leaf_index=self.leaf_index,
        )


class ProofGenerator:
    """
    Generates cryptographic proofs for ACTP protocol.

    Provides methods to create content hashes and proofs
    for inputs, outputs, and deliveries.

    Example:
        >>> generator = ProofGenerator()
        >>> input_hash = generator.hash_input({"query": "Hello"})
        >>> output_hash = generator.hash_output({"response": "Hi"})
    """

    def __init__(self, hash_algorithm: str = "sha256") -> None:
        """
        Initialize ProofGenerator.

        Args:
            hash_algorithm: Hash algorithm to use (default: sha256)
        """
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        self._algorithm = hash_algorithm

    def _hash(self, data: bytes) -> str:
        """Compute hash of bytes and return hex string."""
        hasher = hashlib.new(self._algorithm)
        hasher.update(data)
        return "0x" + hasher.hexdigest()

    def _serialize(self, data: Any) -> bytes:
        """Serialize data to canonical JSON bytes."""
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode("utf-8")
        # Use canonical JSON for objects
        return canonical_json_serialize(data).encode("utf-8")

    def hash_content(self, content: Any, content_type: str = "generic") -> ContentProof:
        """
        Hash arbitrary content.

        Args:
            content: Content to hash (string, bytes, or JSON-serializable)
            content_type: Type label for the content

        Returns:
            ContentProof with hash and metadata
        """
        data = self._serialize(content)
        content_hash = self._hash(data)

        return ContentProof(
            content_hash=content_hash,
            content_type=content_type,
            size=len(data),
        )

    def hash_input(self, input_data: Any) -> str:
        """
        Hash input data for a service request.

        Args:
            input_data: Input data (string, dict, or any JSON-serializable)

        Returns:
            Hex-encoded hash (bytes32)
        """
        return create_input_hash(input_data)

    def hash_output(self, output_data: Any) -> str:
        """
        Hash output data from a service response.

        Args:
            output_data: Output data (string, dict, or any JSON-serializable)

        Returns:
            Hex-encoded hash (bytes32)
        """
        return create_output_hash(output_data)

    def hash_file(self, file_path: str) -> ContentProof:
        """
        Hash a file's contents.

        Args:
            file_path: Path to the file

        Returns:
            ContentProof with file hash

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        with open(file_path, "rb") as f:
            data = f.read()

        content_hash = self._hash(data)

        return ContentProof(
            content_hash=content_hash,
            content_type="file",
            size=len(data),
        )

    def hash_chunks(self, chunks: List[bytes], chunk_size: int = 1024 * 1024) -> str:
        """
        Hash data in chunks (for large files/streams).

        Args:
            chunks: List of data chunks
            chunk_size: Expected chunk size (for validation)

        Returns:
            Hex-encoded hash
        """
        hasher = hashlib.new(self._algorithm)
        for chunk in chunks:
            hasher.update(chunk)
        return "0x" + hasher.hexdigest()

    def create_delivery_proof(
        self,
        transaction_id: str,
        output_hash: str,
        attestation_uid: str = "",
        provider: str = "",
        timestamp: Optional[int] = None,
    ) -> DeliveryProof:
        """
        Create a delivery proof for a completed transaction.

        Args:
            transaction_id: ACTP transaction ID
            output_hash: Hash of the delivered output
            attestation_uid: EAS attestation UID (optional)
            provider: Provider address (optional)
            timestamp: Proof timestamp (defaults to now)

        Returns:
            DeliveryProof ready for signing
        """
        return DeliveryProof(
            transaction_id=transaction_id,
            output_hash=output_hash,
            attestation_uid=attestation_uid,
            provider=provider,
            timestamp=timestamp or int(time.time()),
        )

    def create_merkle_tree(self, leaves: List[str]) -> Tuple[str, List[List[str]]]:
        """
        Create a Merkle tree from leaf hashes.

        Args:
            leaves: List of leaf hashes (hex strings)

        Returns:
            Tuple of (root_hash, tree_levels)
            where tree_levels[0] = leaves, tree_levels[-1] = [root]
        """
        if not leaves:
            return "0x" + "0" * 64, [[]]

        # Normalize leaves
        normalized = [
            leaf if leaf.startswith("0x") else "0x" + leaf for leaf in leaves
        ]

        # Pad to power of 2
        while len(normalized) & (len(normalized) - 1) != 0:
            normalized.append(normalized[-1])  # Duplicate last leaf

        levels: List[List[str]] = [normalized]

        # Build tree bottom-up
        current_level = normalized
        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = bytes.fromhex(current_level[i].replace("0x", ""))
                right = bytes.fromhex(current_level[i + 1].replace("0x", ""))
                # Sort to make tree consistent regardless of order
                if left > right:
                    left, right = right, left
                combined = self._hash(left + right)
                next_level.append(combined)
            levels.append(next_level)
            current_level = next_level

        return current_level[0], levels

    def create_merkle_proof(
        self,
        leaves: List[str],
        leaf_index: int,
    ) -> MerkleProof:
        """
        Create a Merkle proof for a specific leaf.

        Args:
            leaves: All leaf hashes
            leaf_index: Index of the leaf to prove

        Returns:
            MerkleProof for the specified leaf

        Raises:
            IndexError: If leaf_index is out of range
        """
        if leaf_index < 0 or leaf_index >= len(leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(leaves)})")

        root, levels = self.create_merkle_tree(leaves)

        # Collect proof siblings
        proof: List[str] = []
        idx = leaf_index

        for level in levels[:-1]:  # Skip root level
            # Determine sibling index
            sibling_idx = idx ^ 1  # XOR with 1 to get sibling
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            idx //= 2

        return MerkleProof(
            root=root,
            proof=proof,
            leaf=leaves[leaf_index],
            leaf_index=leaf_index,
        )

    def verify_delivery(
        self,
        expected_output: Any,
        proof: DeliveryProof,
    ) -> bool:
        """
        Verify a delivery matches the expected output.

        Args:
            expected_output: Expected output data
            proof: Delivery proof to verify

        Returns:
            True if output hash matches
        """
        computed_hash = self.hash_output(expected_output)
        return computed_hash.lower() == proof.output_hash.lower()


def verify_merkle_proof(
    leaf: str,
    proof: List[str],
    root: str,
    leaf_index: int,
) -> bool:
    """
    Verify a Merkle proof.

    Security Note (M-5): Uses consistent hash ordering with create_merkle_tree().
    Both functions sort hashes with smaller value first to ensure deterministic
    Merkle root computation regardless of leaf position.

    Args:
        leaf: Leaf hash being proven
        proof: Sibling hashes from leaf to root
        root: Expected Merkle root
        leaf_index: Position of leaf in original tree (used for sibling pairing)

    Returns:
        True if proof is valid
    """
    if not proof:
        return leaf.lower() == root.lower()

    current = bytes.fromhex(leaf.replace("0x", ""))
    idx = leaf_index

    for sibling in proof:
        sibling_bytes = bytes.fromhex(sibling.replace("0x", ""))

        # Security Note (M-5): Always sort hashes - smaller first
        # This matches the create_merkle_tree() logic for consistent roots
        if current > sibling_bytes:
            left, right = sibling_bytes, current
        else:
            left, right = current, sibling_bytes

        hasher = hashlib.sha256()
        hasher.update(left + right)
        current = hasher.digest()
        idx //= 2

    computed_root = "0x" + current.hex()
    return computed_root.lower() == root.lower()


def hash_service_input(
    service: str,
    input_data: Any,
    requester: str = "",
) -> str:
    """
    Create a deterministic hash for a service input.

    This combines service name, input data, and requester
    for unique request identification.

    Args:
        service: Service name
        input_data: Input data
        requester: Requester address (optional)

    Returns:
        Hex-encoded hash (bytes32)
    """
    combined = {
        "service": service,
        "input": input_data,
    }
    if requester:
        combined["requester"] = requester.lower()

    encoded = canonical_json_serialize(combined)
    hash_bytes = hashlib.sha256(encoded.encode("utf-8")).digest()
    return "0x" + hash_bytes.hex()


def hash_service_output(
    transaction_id: str,
    output_data: Any,
    provider: str = "",
) -> str:
    """
    Create a deterministic hash for a service output.

    This combines transaction ID, output data, and provider
    for unique delivery identification.

    Args:
        transaction_id: ACTP transaction ID
        output_data: Output data
        provider: Provider address (optional)

    Returns:
        Hex-encoded hash (bytes32)
    """
    combined = {
        "transactionId": transaction_id,
        "output": output_data,
    }
    if provider:
        combined["provider"] = provider.lower()

    encoded = canonical_json_serialize(combined)
    hash_bytes = hashlib.sha256(encoded.encode("utf-8")).digest()
    return "0x" + hash_bytes.hex()


__all__ = [
    "ProofGenerator",
    "ContentProof",
    "MerkleProof",
    "verify_merkle_proof",
    "hash_service_input",
    "hash_service_output",
]
