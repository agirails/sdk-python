"""
EIP-712 Message types for AGIRAILS SDK.

Provides types for typed structured data signing according to EIP-712.
Used for off-chain message signing and verification in the ACTP protocol.

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

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


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


@dataclass
class DeliveryProof:
    """
    Delivery proof message for signing.

    Used to prove delivery of service output.

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
        """Create TypedData from a DeliveryProof."""
        return cls(
            types={
                "EIP712Domain": domain.type_definition,
                proof.TYPE_NAME: proof.TYPE_DEFINITION,
            },
            primary_type=proof.TYPE_NAME,
            domain=domain.to_dict(),
            message=proof.to_dict(),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for signing."""
        return {
            "types": self.types,
            "primaryType": self.primary_type,
            "domain": self.domain,
            "message": self.message,
        }


def hash_message(message: Dict[str, Any]) -> str:
    """
    Hash a message for signing.

    Args:
        message: Message dictionary

    Returns:
        Hex-encoded hash
    """
    import json

    # Canonical JSON encoding
    encoded = json.dumps(message, sort_keys=True, separators=(",", ":"))
    hash_bytes = hashlib.sha256(encoded.encode()).digest()
    return "0x" + hash_bytes.hex()


def create_input_hash(input_data: Any) -> str:
    """
    Create a hash of input data.

    Args:
        input_data: Input data to hash

    Returns:
        Hex-encoded hash (bytes32)
    """
    import json

    if isinstance(input_data, str):
        data = input_data
    else:
        data = json.dumps(input_data, sort_keys=True, separators=(",", ":"))

    hash_bytes = hashlib.sha256(data.encode()).digest()
    return "0x" + hash_bytes.hex()


def create_output_hash(output_data: Any) -> str:
    """
    Create a hash of output data.

    Args:
        output_data: Output data to hash

    Returns:
        Hex-encoded hash (bytes32)
    """
    return create_input_hash(output_data)
