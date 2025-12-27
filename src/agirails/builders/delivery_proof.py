"""
Delivery Proof Builder for AGIRAILS SDK.

Provides a fluent builder pattern for constructing delivery proofs (AIP-4).
Delivery proofs are cryptographic evidence that a provider completed work.

Example:
    >>> from agirails.builders import DeliveryProofBuilder
    >>> proof = (
    ...     DeliveryProofBuilder()
    ...     .for_transaction("0x...")
    ...     .with_output({"result": "Hello World"})
    ...     .from_provider("0x...")
    ...     .with_attestation("0x...")
    ...     .build()
    ... )
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from agirails.types.message import DeliveryProofMessage
from agirails.utils.canonical_json import canonical_json_dumps as canonical_json_serialize

# Try to import keccak for proper hashing
try:
    from eth_hash.auto import keccak as keccak256
    HAS_KECCAK = True
except ImportError:
    HAS_KECCAK = False
    keccak256 = None  # type: ignore


@dataclass
class DeliveryProof:
    """
    Proof of service delivery.

    This is the internal SDK representation used by DeliveryProofBuilder.
    Use to_message() to convert to the AIP-4 v1.1 DeliveryProofMessage
    format for EIP-712 signing and wire transport.

    Attributes:
        transaction_id: ACTP transaction ID (bytes32)
        output_hash: keccak256 hash of the output (bytes32)
        provider: Provider address or DID
        attestation_uid: EAS attestation UID (if on-chain)
        timestamp: Delivery timestamp (Unix seconds)
        output_data: Raw output data (optional, for local verification)
        metadata: Additional metadata (not signed)
        signature: Optional EIP-712 signature
        consumer: Consumer address or DID (for AIP-4 v1.1)
        result_cid: IPFS CID of result (for AIP-4 v1.1)
        nonce: Monotonically increasing nonce (for AIP-4 v1.1)
        chain_id: Chain ID (for AIP-4 v1.1)
    """

    transaction_id: str
    output_hash: str
    provider: str
    attestation_uid: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time()))
    output_data: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    # AIP-4 v1.1 additional fields (with defaults for backwards compatibility)
    consumer: str = ""
    result_cid: str = ""
    nonce: int = 0  # Monotonically increasing integer (NOT bytes32)
    chain_id: int = 84532  # Base Sepolia default

    @property
    def is_on_chain(self) -> bool:
        """Check if proof has on-chain attestation."""
        return bool(self.attestation_uid) and self.attestation_uid != "0x" + "0" * 64

    @property
    def timestamp_datetime(self) -> datetime:
        """Get timestamp as datetime."""
        return datetime.fromtimestamp(self.timestamp)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (internal format, not for wire transport)."""
        result: Dict[str, Any] = {
            "transactionId": self.transaction_id,
            "outputHash": self.output_hash,
            "provider": self.provider,
            "attestationUID": self.attestation_uid,
            "timestamp": self.timestamp,
            "isOnChain": self.is_on_chain,
            "metadata": self.metadata,
        }
        if self.signature:
            result["signature"] = self.signature
        return result

    def to_message(self) -> DeliveryProofMessage:
        """
        Convert to AIP-4 v1.1 DeliveryProofMessage for EIP-712 signing.

        PARITY CRITICAL: Returns a DeliveryProofMessage that matches the
        TypeScript SDK's AIP4DeliveryProofTypes exactly with 9 signed fields.

        Reference: sdk-js/src/types/eip712.ts AIP4DeliveryProofTypes
        """
        # Convert addresses to DIDs if needed
        def to_did(address: str, chain_id: int) -> str:
            if not address:
                return f"did:ethr:{chain_id}:{'0x' + '0' * 40}"
            if address.startswith("did:"):
                return address
            return f"did:ethr:{chain_id}:{address}"

        return DeliveryProofMessage(
            tx_id=self.transaction_id,
            provider=to_did(self.provider, self.chain_id),
            consumer=to_did(self.consumer, self.chain_id),
            result_cid=self.result_cid or "",
            result_hash=self.output_hash,
            eas_attestation_uid=self.attestation_uid or "0x" + "0" * 64,
            delivered_at=self.timestamp,
            chain_id=self.chain_id,
            nonce=self.nonce,
        )

    def verify_output(self, expected_output: Any) -> bool:
        """
        Verify that the output hash matches expected output.

        Args:
            expected_output: Expected output data

        Returns:
            True if hash matches
        """
        computed_hash = compute_output_hash(expected_output)
        return computed_hash.lower() == self.output_hash.lower()


# Maximum output size for hashing (10 MB)
MAX_OUTPUT_SIZE = 10 * 1024 * 1024


def compute_output_hash(output: Any) -> str:
    """
    Compute keccak256 hash of output data.

    PARITY: Uses keccak256 to match TypeScript SDK's computeResultHash.

    Args:
        output: Output data to hash

    Returns:
        Hex-encoded keccak256 hash (bytes32)

    Raises:
        ValueError: If output exceeds MAX_OUTPUT_SIZE (10 MB)
        ImportError: If eth_hash is not installed
    """
    if not HAS_KECCAK:
        raise ImportError(
            "eth_hash is required for keccak256 hashing. "
            "Install with: pip install eth-hash[pycryptodome]"
        )

    if isinstance(output, bytes):
        data = output
    elif isinstance(output, str):
        data = output.encode("utf-8")
    else:
        # Use canonical JSON for objects
        data = canonical_json_serialize(output).encode("utf-8")

    # Size validation to prevent DoS
    if len(data) > MAX_OUTPUT_SIZE:
        raise ValueError(
            f"Output size ({len(data)} bytes) exceeds maximum allowed size "
            f"({MAX_OUTPUT_SIZE} bytes). Consider chunking large outputs."
        )

    hash_bytes = keccak256(data)
    return "0x" + hash_bytes.hex()


class DeliveryProofBuilder:
    """
    Fluent builder for constructing delivery proofs.

    Example:
        >>> proof = (
        ...     DeliveryProofBuilder()
        ...     .for_transaction("0x123...")
        ...     .with_output({"result": "completed"})
        ...     .from_provider("0xabc...")
        ...     .build()
        ... )
    """

    def __init__(self) -> None:
        """Initialize empty builder."""
        self._transaction_id: Optional[str] = None
        self._output_hash: Optional[str] = None
        self._output_data: Optional[Any] = None
        self._provider: Optional[str] = None
        self._attestation_uid: str = ""
        self._timestamp: Optional[int] = None
        self._metadata: Dict[str, Any] = {}
        # AIP-4 v1.1 fields for build_message() parity
        self._consumer: str = ""
        self._result_cid: str = ""
        self._nonce: int = 0
        self._chain_id: int = 84532  # Base Sepolia default

    def for_transaction(self, transaction_id: str) -> "DeliveryProofBuilder":
        """
        Set the transaction ID this proof is for.

        Args:
            transaction_id: ACTP transaction ID

        Returns:
            Self for chaining
        """
        self._transaction_id = transaction_id
        return self

    def from_provider(self, provider: str) -> "DeliveryProofBuilder":
        """
        Set the provider address.

        Args:
            provider: Provider's Ethereum address

        Returns:
            Self for chaining
        """
        self._provider = provider
        return self

    def with_output(
        self,
        output: Any,
        compute_hash: bool = True,
    ) -> "DeliveryProofBuilder":
        """
        Set the output data.

        Args:
            output: Output data (any JSON-serializable)
            compute_hash: Whether to compute hash automatically

        Returns:
            Self for chaining
        """
        self._output_data = output
        if compute_hash:
            self._output_hash = compute_output_hash(output)
        return self

    def with_output_hash(self, output_hash: str) -> "DeliveryProofBuilder":
        """
        Set the output hash directly.

        Args:
            output_hash: Pre-computed output hash (bytes32 hex)

        Returns:
            Self for chaining
        """
        self._output_hash = output_hash
        return self

    def with_attestation(self, attestation_uid: str) -> "DeliveryProofBuilder":
        """
        Set the EAS attestation UID.

        Args:
            attestation_uid: EAS attestation UID

        Returns:
            Self for chaining
        """
        self._attestation_uid = attestation_uid
        return self

    def at_timestamp(self, timestamp: int) -> "DeliveryProofBuilder":
        """
        Set the delivery timestamp.

        Args:
            timestamp: Unix timestamp

        Returns:
            Self for chaining
        """
        self._timestamp = timestamp
        return self

    def with_metadata(self, key: str, value: Any) -> "DeliveryProofBuilder":
        """
        Add metadata key-value pair.

        Args:
            key: Metadata key
            value: Metadata value

        Returns:
            Self for chaining
        """
        self._metadata[key] = value
        return self

    def with_execution_time(self, milliseconds: int) -> "DeliveryProofBuilder":
        """
        Record execution time as metadata.

        Args:
            milliseconds: Execution time in milliseconds

        Returns:
            Self for chaining
        """
        self._metadata["executionTimeMs"] = milliseconds
        return self

    def with_result_size(self, bytes_count: int) -> "DeliveryProofBuilder":
        """
        Record result size as metadata.

        Args:
            bytes_count: Size of result in bytes

        Returns:
            Self for chaining
        """
        self._metadata["resultSizeBytes"] = bytes_count
        return self

    def for_consumer(self, consumer: str) -> "DeliveryProofBuilder":
        """
        Set the consumer (requester) address.

        PARITY: Required for build_message() to match TS SDK.

        Args:
            consumer: Consumer's Ethereum address or DID

        Returns:
            Self for chaining
        """
        self._consumer = consumer
        return self

    def with_result_cid(self, cid: str) -> "DeliveryProofBuilder":
        """
        Set the IPFS CID of the result.

        PARITY: Required for build_message() to match TS SDK.

        Args:
            cid: IPFS content identifier

        Returns:
            Self for chaining
        """
        self._result_cid = cid
        return self

    def with_nonce(self, nonce: int) -> "DeliveryProofBuilder":
        """
        Set the monotonically increasing nonce.

        PARITY: Required for build_message() to match TS SDK.

        Args:
            nonce: Unique nonce value

        Returns:
            Self for chaining
        """
        self._nonce = nonce
        return self

    def on_chain(self, chain_id: int) -> "DeliveryProofBuilder":
        """
        Set the chain ID.

        PARITY: Required for build_message() to match TS SDK.

        Args:
            chain_id: EVM chain ID (default: 84532 Base Sepolia)

        Returns:
            Self for chaining
        """
        self._chain_id = chain_id
        return self

    def build(self) -> DeliveryProof:
        """
        Build the DeliveryProof object.

        Returns:
            Constructed DeliveryProof

        Raises:
            ValueError: If required fields are missing
        """
        if not self._transaction_id:
            raise ValueError("transaction_id is required")
        if not self._output_hash:
            raise ValueError("output_hash is required (use with_output or with_output_hash)")
        if not self._provider:
            raise ValueError("provider is required")

        return DeliveryProof(
            transaction_id=self._transaction_id,
            output_hash=self._output_hash,
            provider=self._provider,
            attestation_uid=self._attestation_uid,
            timestamp=self._timestamp or int(time.time()),
            output_data=self._output_data,
            metadata=self._metadata,
            # AIP-4 v1.1 fields
            consumer=self._consumer,
            result_cid=self._result_cid,
            nonce=self._nonce,
            chain_id=self._chain_id,
        )

    def build_message(self) -> DeliveryProofMessage:
        """
        Build the DeliveryProofMessage directly.

        PARITY: TS SDK's DeliveryProofBuilder.build() returns DeliveryProofMessage.
        This method provides 1:1 parity with TS SDK builder output.

        Returns:
            Constructed DeliveryProofMessage (AIP-4 v1.1 format)

        Raises:
            ValueError: If required fields are missing

        Example:
            >>> message = (
            ...     DeliveryProofBuilder()
            ...     .for_transaction("0x123...")
            ...     .from_provider("0xProvider...")
            ...     .for_consumer("0xConsumer...")
            ...     .with_output({"result": "success"})
            ...     .with_result_cid("Qm...")
            ...     .with_nonce(1)
            ...     .on_chain(84532)
            ...     .build_message()
            ... )
        """
        # Build the DeliveryProof first, then convert to message
        proof = self.build()
        return proof.to_message()

    def reset(self) -> "DeliveryProofBuilder":
        """
        Reset builder to initial state.

        Returns:
            Self for chaining
        """
        self.__init__()
        return self


class BatchDeliveryProofBuilder:
    """
    Builder for multiple delivery proofs (batch operations).

    Example:
        >>> builder = BatchDeliveryProofBuilder().from_provider("0xabc...")
        >>> proofs = (
        ...     builder
        ...     .add_delivery("0x111...", {"result": "a"})
        ...     .add_delivery("0x222...", {"result": "b"})
        ...     .build_all()
        ... )
    """

    def __init__(self) -> None:
        """Initialize empty builder."""
        self._provider: Optional[str] = None
        self._attestation_uid: str = ""
        self._deliveries: List[Dict[str, Any]] = []

    def from_provider(self, provider: str) -> "BatchDeliveryProofBuilder":
        """
        Set the provider address for all proofs.

        Args:
            provider: Provider's Ethereum address

        Returns:
            Self for chaining
        """
        self._provider = provider
        return self

    def with_attestation(self, attestation_uid: str) -> "BatchDeliveryProofBuilder":
        """
        Set the EAS attestation UID for all proofs.

        Args:
            attestation_uid: EAS attestation UID

        Returns:
            Self for chaining
        """
        self._attestation_uid = attestation_uid
        return self

    def add_delivery(
        self,
        transaction_id: str,
        output: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "BatchDeliveryProofBuilder":
        """
        Add a delivery to the batch.

        Args:
            transaction_id: ACTP transaction ID
            output: Output data
            metadata: Optional metadata

        Returns:
            Self for chaining
        """
        self._deliveries.append({
            "transaction_id": transaction_id,
            "output": output,
            "metadata": metadata or {},
        })
        return self

    def build_all(self) -> List[DeliveryProof]:
        """
        Build all delivery proofs.

        Returns:
            List of DeliveryProof objects

        Raises:
            ValueError: If provider not set
        """
        if not self._provider:
            raise ValueError("provider is required")

        proofs = []
        for delivery in self._deliveries:
            proof = (
                DeliveryProofBuilder()
                .for_transaction(delivery["transaction_id"])
                .from_provider(self._provider)
                .with_output(delivery["output"])
                .with_attestation(self._attestation_uid)
                .build()
            )
            # Add any extra metadata
            proof.metadata.update(delivery["metadata"])
            proofs.append(proof)

        return proofs

    def reset(self) -> "BatchDeliveryProofBuilder":
        """
        Reset builder to initial state.

        Returns:
            Self for chaining
        """
        self.__init__()
        return self


def create_delivery_proof(
    transaction_id: str,
    output: Any,
    provider: str,
    attestation_uid: str = "",
) -> DeliveryProof:
    """
    Create a delivery proof with minimal parameters.

    Args:
        transaction_id: ACTP transaction ID
        output: Output data
        provider: Provider address
        attestation_uid: Optional EAS attestation UID

    Returns:
        DeliveryProof object
    """
    builder = (
        DeliveryProofBuilder()
        .for_transaction(transaction_id)
        .from_provider(provider)
        .with_output(output)
    )

    if attestation_uid:
        builder.with_attestation(attestation_uid)

    return builder.build()


__all__ = [
    "DeliveryProof",
    "DeliveryProofBuilder",
    "BatchDeliveryProofBuilder",
    "create_delivery_proof",
    "compute_output_hash",
    "MAX_OUTPUT_SIZE",
]
