"""
EIP-712 Message types for AGIRAILS SDK.

Provides types for typed structured data signing according to EIP-712.
Used for off-chain message signing and verification in the ACTP protocol.

This module implements AIP-4 v1.1 DeliveryProofMessage schema for parity
with the TypeScript SDK.

Example:
    >>> domain = EIP712Domain(
    ...     name="ACTP",
    ...     version="1",
    ...     chain_id=84532,
    ...     verifying_contract="0x..."
    ... )
    >>> message = ServiceRequest(
    ...     service="echo",
    ...     input_hash="0x...",
    ...     budget=1000000,
    ...     deadline=1234567890
    ... )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict


@dataclass
class EIP712Domain:
    """
    EIP-712 domain separator.

    Defines the context for typed structured data signing.

    Attributes:
        name: Protocol name
        version: Protocol version
        chain_id: Ethereum chain ID
        verifying_contract: Contract address for verification
        salt: Optional salt for uniqueness
    """

    name: str = "ACTP"
    version: str = "1"
    chain_id: int = 84532  # Base Sepolia
    verifying_contract: str = ""
    salt: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        domain: Dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "chainId": self.chain_id,
        }
        if self.verifying_contract:
            domain["verifyingContract"] = self.verifying_contract
        if self.salt:
            domain["salt"] = self.salt.hex()
        return domain

    @property
    def type_definition(self) -> List[Dict[str, str]]:
        """Get EIP-712 type definition for domain."""
        types = [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ]
        if self.verifying_contract:
            types.append({"name": "verifyingContract", "type": "address"})
        if self.salt:
            types.append({"name": "salt", "type": "bytes32"})
        return types


@dataclass
class ServiceRequest:
    """
    Service request message for signing.

    Used to create a signed request for a service.

    Attributes:
        service: Service name
        input_hash: Hash of the input data
        budget: Budget in USDC (6 decimals, e.g., 1000000 = $1.00)
        deadline: Unix timestamp deadline
        requester: Requester address
        provider: Optional specific provider
        nonce: Request nonce for replay protection
    """

    service: str
    input_hash: str
    budget: int
    deadline: int
    requester: str = ""
    provider: str = ""
    nonce: int = 0

    TYPE_NAME = "ServiceRequest"
    TYPE_DEFINITION = [
        {"name": "service", "type": "string"},
        {"name": "inputHash", "type": "bytes32"},
        {"name": "budget", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
        {"name": "requester", "type": "address"},
        {"name": "provider", "type": "address"},
        {"name": "nonce", "type": "uint256"},
    ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        return {
            "service": self.service,
            "inputHash": self.input_hash,
            "budget": self.budget,
            "deadline": self.deadline,
            "requester": self.requester,
            "provider": self.provider,
            "nonce": self.nonce,
        }


@dataclass
class ServiceResponse:
    """
    Service response message for signing.

    Used to create a signed response from a provider.

    Attributes:
        request_id: Transaction/request ID
        output_hash: Hash of the output data
        status: Response status code
        provider: Provider address
        timestamp: Response timestamp
    """

    request_id: str
    output_hash: str
    status: int
    provider: str = ""
    timestamp: int = 0

    TYPE_NAME = "ServiceResponse"
    TYPE_DEFINITION = [
        {"name": "requestId", "type": "bytes32"},
        {"name": "outputHash", "type": "bytes32"},
        {"name": "status", "type": "uint8"},
        {"name": "provider", "type": "address"},
        {"name": "timestamp", "type": "uint256"},
    ]

    def __post_init__(self) -> None:
        """Set defaults."""
        if self.timestamp == 0:
            self.timestamp = int(datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        return {
            "requestId": self.request_id,
            "outputHash": self.output_hash,
            "status": self.status,
            "provider": self.provider,
            "timestamp": self.timestamp,
        }


class DeliveryProofMetadata(TypedDict, total=False):
    """
    Optional metadata for delivery proof (NOT included in EIP-712 signing).

    This is stored separately from the signed message.
    Matches TS SDK: sdk-js/src/types/message.ts DeliveryProofMessage.metadata
    """
    execution_time: int  # executionTime in TS (seconds)
    output_format: str   # outputFormat in TS (MIME type)
    output_size: int     # outputSize in TS (bytes)
    notes: str           # Max 500 chars


@dataclass
class DeliveryProofMessage:
    """
    AIP-4 v1.1 Delivery proof message for EIP-712 signing.

    PARITY CRITICAL: This class matches the TypeScript SDK's AIP4DeliveryProofTypes
    EXACTLY with 9 signed fields. The primary type is "DeliveryProof".

    Reference: sdk-js/src/types/eip712.ts AIP4DeliveryProofTypes

    Fields are ordered to match the TS SDK type definition:
    1. txId - bytes32 (transaction ID)
    2. provider - string (provider's DID, e.g., "did:ethr:84532:0x...")
    3. consumer - string (consumer's DID)
    4. resultCID - string (IPFS CID, e.g., "bafybeig...")
    5. resultHash - bytes32 (keccak256 hash of result)
    6. easAttestationUID - bytes32 (EAS attestation UID)
    7. deliveredAt - uint256 (delivery timestamp)
    8. chainId - uint256 (chain ID)
    9. nonce - uint256 (monotonically increasing integer)

    Non-signed wrapper fields (from DeliveryProofMessage interface):
    - type: 'agirails.delivery.v1'
    - version: string (e.g., "1.0.0")
    - metadata: optional execution metadata
    - signature: EIP-712 signature

    Example:
        >>> proof = DeliveryProofMessage(
        ...     tx_id="0x1234...",
        ...     provider="did:ethr:84532:0xProvider...",
        ...     consumer="did:ethr:84532:0xConsumer...",
        ...     result_cid="bafybeig...",
        ...     result_hash="0xbbb...",
        ...     eas_attestation_uid="0xccc...",
        ...     delivered_at=1700000000,
        ...     chain_id=84532,
        ...     nonce=1,
        ... )
    """

    # Required EIP-712 signed fields (match TS SDK AIP4DeliveryProofTypes order)
    tx_id: str  # bytes32
    provider: str  # string (DID)
    consumer: str  # string (DID)
    result_cid: str  # string (IPFS CID)
    result_hash: str  # bytes32 (keccak256)
    eas_attestation_uid: str  # bytes32
    delivered_at: int  # uint256 (Unix timestamp)
    chain_id: int  # uint256
    nonce: int  # uint256 (NOT bytes32 - this is a monotonically increasing integer)

    # Non-signed wrapper fields (from DeliveryProofMessage interface)
    type: str = "agirails.delivery.v1"  # Message type constant
    version: str = "1.0.0"  # Semantic version

    # NOT included in EIP-712 signing (stored separately)
    signature: str = ""  # Set after signing
    metadata: Optional[DeliveryProofMetadata] = None  # Optional execution metadata

    # EIP-712 type constants - MUST match TS SDK AIP4DeliveryProofTypes exactly
    TYPE_NAME = "DeliveryProof"
    TYPE_DEFINITION = [
        {"name": "txId", "type": "bytes32"},
        {"name": "provider", "type": "string"},
        {"name": "consumer", "type": "string"},
        {"name": "resultCID", "type": "string"},
        {"name": "resultHash", "type": "bytes32"},
        {"name": "easAttestationUID", "type": "bytes32"},
        {"name": "deliveredAt", "type": "uint256"},
        {"name": "chainId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
    ]

    def __post_init__(self) -> None:
        """Set defaults."""
        if self.delivered_at == 0:
            self.delivered_at = int(datetime.now().timestamp())

    def to_signing_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for EIP-712 signing.

        PARITY CRITICAL: Returns ONLY the 9 fields that get signed.
        Matches TS SDK AIP4DeliveryProofData interface.
        Does NOT include type, version, signature, or metadata.
        """
        return {
            "txId": self.tx_id,
            "provider": self.provider,
            "consumer": self.consumer,
            "resultCID": self.result_cid,
            "resultHash": self.result_hash,
            "easAttestationUID": self.eas_attestation_uid,
            "deliveredAt": self.delivered_at,
            "chainId": self.chain_id,
            "nonce": self.nonce,
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to full dictionary including non-signed fields.

        Matches TS SDK DeliveryProofMessage interface.
        Use to_signing_dict() for EIP-712 signing.

        PARITY: Always includes 'signature' key (empty string before signing)
        to match TS SDK which always includes the key.
        """
        result: Dict[str, Any] = {
            "type": self.type,
            "version": self.version,
            **self.to_signing_dict(),
            "signature": self.signature,  # PARITY: Always include, even if empty
        }
        if self.metadata:
            md: Dict[str, Any] = {}
            if "execution_time" in self.metadata:
                md["executionTime"] = self.metadata["execution_time"]
            if "output_format" in self.metadata:
                md["outputFormat"] = self.metadata["output_format"]
            if "output_size" in self.metadata:
                md["outputSize"] = self.metadata["output_size"]
            if "notes" in self.metadata:
                md["notes"] = self.metadata["notes"]
            result["metadata"] = md
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeliveryProofMessage":
        """Create from dictionary (handles both camelCase and snake_case)."""
        # Handle camelCase keys from TS SDK
        metadata = None
        if "metadata" in data and data["metadata"]:
            md = data["metadata"]
            metadata = DeliveryProofMetadata(
                execution_time=md.get("executionTime", md.get("execution_time")),
                output_format=md.get("outputFormat", md.get("output_format")),
                output_size=md.get("outputSize", md.get("output_size")),
                notes=md.get("notes"),
            )
            # Remove None values
            metadata = {k: v for k, v in metadata.items() if v is not None}  # type: ignore

        return cls(
            tx_id=data.get("txId", data.get("tx_id", "")),
            provider=data.get("provider", ""),
            consumer=data.get("consumer", ""),
            result_cid=data.get("resultCID", data.get("result_cid", "")),
            result_hash=data.get("resultHash", data.get("result_hash", "")),
            eas_attestation_uid=data.get("easAttestationUID", data.get("eas_attestation_uid", "")),
            delivered_at=data.get("deliveredAt", data.get("delivered_at", 0)),
            chain_id=data.get("chainId", data.get("chain_id", 84532)),
            nonce=data.get("nonce", 0),
            type=data.get("type", "agirails.delivery.v1"),
            version=data.get("version", "1.0.0"),
            signature=data.get("signature", ""),
            metadata=metadata if metadata else None,
        )


# Backwards compatibility alias
@dataclass
class DeliveryProof:
    """
    Legacy delivery proof message (DEPRECATED).

    This class is kept for backwards compatibility. For new code,
    use DeliveryProofMessage which implements AIP-4 v1.1 schema.

    Attributes:
        transaction_id: ACTP transaction ID
        output_hash: Hash of the delivered output
        attestation_uid: EAS attestation UID
        provider: Provider address
        timestamp: Delivery timestamp
    """

    transaction_id: str
    output_hash: str
    attestation_uid: str = ""
    provider: str = ""
    timestamp: int = 0

    TYPE_NAME = "DeliveryProof"
    TYPE_DEFINITION = [
        {"name": "transactionId", "type": "bytes32"},
        {"name": "outputHash", "type": "bytes32"},
        {"name": "attestationUid", "type": "bytes32"},
        {"name": "provider", "type": "address"},
        {"name": "timestamp", "type": "uint256"},
    ]

    def __post_init__(self) -> None:
        """Set defaults."""
        if self.timestamp == 0:
            self.timestamp = int(datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        return {
            "transactionId": self.transaction_id,
            "outputHash": self.output_hash,
            "attestationUid": self.attestation_uid,
            "provider": self.provider,
            "timestamp": self.timestamp,
        }

    def to_delivery_proof_message(
        self,
        consumer: str = "",
        result_cid: str = "",
        chain_id: int = 84532,
        nonce: int = 0,
    ) -> DeliveryProofMessage:
        """
        Convert legacy DeliveryProof to AIP-4 v1.1 DeliveryProofMessage.

        Args:
            consumer: Consumer DID (e.g., "did:ethr:84532:0x...")
            result_cid: IPFS CID of result (e.g., "bafybeig...")
            chain_id: Ethereum chain ID (84532 for Base Sepolia)
            nonce: Monotonically increasing nonce for replay protection

        Returns:
            DeliveryProofMessage with mapped fields matching TS SDK schema
        """
        # Convert provider address to DID format if needed
        provider_did = self.provider
        if not provider_did.startswith("did:"):
            provider_did = f"did:ethr:{chain_id}:{self.provider}"

        return DeliveryProofMessage(
            tx_id=self.transaction_id,
            provider=provider_did,
            consumer=consumer or f"did:ethr:{chain_id}:{'0x' + '0' * 40}",
            result_cid=result_cid,
            result_hash=self.output_hash,
            eas_attestation_uid=self.attestation_uid or "0x" + "0" * 64,
            delivered_at=self.timestamp,
            chain_id=chain_id,
            nonce=nonce,
        )


@dataclass
class SignedMessage:
    """
    Container for a signed EIP-712 message.

    Attributes:
        domain: EIP-712 domain
        message: The message that was signed
        signature: The signature (v, r, s concatenated)
        signer: Address of the signer
    """

    domain: EIP712Domain
    message: Dict[str, Any]
    message_type: str
    signature: str = ""
    signer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain.to_dict(),
            "message": self.message,
            "messageType": self.message_type,
            "signature": self.signature,
            "signer": self.signer,
        }

    @property
    def is_signed(self) -> bool:
        """Check if message has a signature."""
        return bool(self.signature)

    def verify(self, expected_signer: "Optional[str]" = None) -> bool:
        """
        Verify the signature.

        Args:
            expected_signer: Expected signer address (optional)

        Returns:
            True if signature is valid

        Raises:
            NotImplementedError: Full verification requires eth_account library

        Note:
            This method performs basic checks but does NOT cryptographically
            verify the signature. For production use, integrate with eth_account:

            >>> from eth_account.messages import encode_structured_data
            >>> from eth_account import Account
            >>> recovered = Account.recover_message(signable_message, signature=sig)
        """
        if not self.is_signed:
            return False

        if expected_signer and self.signer.lower() != expected_signer.lower():
            return False

        # TODO: Implement cryptographic verification with eth_account
        # For now, we only verify that:
        # 1. A signature exists
        # 2. The signer matches expected_signer (if provided)
        #
        # Full EIP-712 verification would:
        # 1. Reconstruct the typed data hash
        # 2. Recover signer from signature using ecrecover
        # 3. Compare recovered signer with self.signer
        #
        # Example with eth_account:
        # from eth_account import Account
        # recovered = Account.recover_message(typed_data_hash, signature=self.signature)
        # return recovered.lower() == self.signer.lower()

        import warnings
        warnings.warn(
            "SignedMessage.verify() does not perform cryptographic verification. "
            "Integrate with eth_account for production use.",
            UserWarning,
            stacklevel=2,
        )
        return True


@dataclass
class TypedData:
    """
    Complete EIP-712 typed data structure.

    Used for signing with web3 wallets.

    Attributes:
        types: Type definitions
        primary_type: Primary message type
        domain: Domain separator
        message: Message to sign
    """

    types: Dict[str, List[Dict[str, str]]]
    primary_type: str
    domain: Dict[str, Any]
    message: Dict[str, Any]

    @classmethod
    def from_request(
        cls,
        request: ServiceRequest,
        domain: EIP712Domain,
    ) -> TypedData:
        """Create TypedData from a ServiceRequest."""
        return cls(
            types={
                "EIP712Domain": domain.type_definition,
                request.TYPE_NAME: request.TYPE_DEFINITION,
            },
            primary_type=request.TYPE_NAME,
            domain=domain.to_dict(),
            message=request.to_dict(),
        )

    @classmethod
    def from_response(
        cls,
        response: ServiceResponse,
        domain: EIP712Domain,
    ) -> TypedData:
        """Create TypedData from a ServiceResponse."""
        return cls(
            types={
                "EIP712Domain": domain.type_definition,
                response.TYPE_NAME: response.TYPE_DEFINITION,
            },
            primary_type=response.TYPE_NAME,
            domain=domain.to_dict(),
            message=response.to_dict(),
        )

    @classmethod
    def from_proof(
        cls,
        proof: DeliveryProof,
        domain: EIP712Domain,
    ) -> TypedData:
        """Create TypedData from a legacy DeliveryProof."""
        return cls(
            types={
                "EIP712Domain": domain.type_definition,
                proof.TYPE_NAME: proof.TYPE_DEFINITION,
            },
            primary_type=proof.TYPE_NAME,
            domain=domain.to_dict(),
            message=proof.to_dict(),
        )

    @classmethod
    def from_delivery_proof_message(
        cls,
        proof: DeliveryProofMessage,
        domain: EIP712Domain,
    ) -> TypedData:
        """
        Create TypedData from AIP-4 v1.1 DeliveryProofMessage.

        PARITY CRITICAL: Uses to_signing_dict() to include ONLY the 9 signed
        fields, matching TS SDK AIP4DeliveryProofTypes. Does NOT include
        wrapper fields (type, version, signature, metadata).
        """
        return cls(
            types={
                "EIP712Domain": domain.type_definition,
                proof.TYPE_NAME: proof.TYPE_DEFINITION,
            },
            primary_type=proof.TYPE_NAME,
            domain=domain.to_dict(),
            message=proof.to_signing_dict(),  # PARITY: Only signed fields
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        return {
            "types": self.types,
            "primaryType": self.primary_type,
            "domain": self.domain,
            "message": self.message,
        }


def _get_keccak256() -> Any:
    """
    Get keccak256 hash function.

    Tries eth_hash first (required for parity), falls back with error.

    Returns:
        keccak256 function

    Raises:
        ImportError: If eth_hash is not installed (no fallback allowed for parity)
    """
    try:
        from eth_hash.auto import keccak
        return keccak
    except ImportError:
        raise ImportError(
            "eth_hash is required for keccak256 hashing. "
            "Install with: pip install eth-hash[pycryptodome]"
        )


def compute_result_hash(result_data: Any) -> str:
    """
    Compute result hash using keccak256 over canonical JSON.

    This matches the TypeScript SDK's computeResultHash function exactly:
    - Uses fast-json-stable-stringify equivalent (sorted keys, no whitespace)
    - Uses keccak256 hash

    Args:
        result_data: Result data to hash (dict, list, or primitive)

    Returns:
        Hex-encoded keccak256 hash (0x prefixed)

    Example:
        >>> compute_result_hash({"hello": "world"})
        '0x...'
    """
    from agirails.utils.canonical_json import canonical_json_dumps

    # Get canonical JSON (matches fast-json-stable-stringify)
    canonical = canonical_json_dumps(result_data)

    # Compute keccak256
    keccak = _get_keccak256()
    hash_bytes = keccak(canonical.encode("utf-8"))
    return "0x" + hash_bytes.hex()


def hash_message(message: Dict[str, Any]) -> str:
    """
    Hash a message using keccak256 over canonical JSON.

    This is the primary hash function for EIP-712 compatible hashing.
    Uses keccak256 for parity with TypeScript SDK.

    Args:
        message: Message dictionary

    Returns:
        Hex-encoded keccak256 hash (0x prefixed)
    """
    return compute_result_hash(message)


def create_input_hash(input_data: Any) -> str:
    """
    Create a keccak256 hash of input data.

    Uses canonical JSON serialization and keccak256 hashing
    for parity with TypeScript SDK.

    Args:
        input_data: Input data to hash

    Returns:
        Hex-encoded keccak256 hash (bytes32, 0x prefixed)
    """
    return compute_result_hash(input_data)


def create_output_hash(output_data: Any) -> str:
    """
    Create a keccak256 hash of output data.

    Alias for create_input_hash - both use same hashing algorithm.

    Args:
        output_data: Output data to hash

    Returns:
        Hex-encoded keccak256 hash (bytes32, 0x prefixed)
    """
    return create_input_hash(output_data)
