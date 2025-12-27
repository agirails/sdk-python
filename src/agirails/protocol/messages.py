"""
EIP-712 Message Signer for AGIRAILS SDK.

Provides EIP-712 typed structured data signing and verification
for the ACTP protocol messages.

Example:
    >>> from agirails.protocol import MessageSigner
    >>> signer = MessageSigner(private_key, chain_id=84532)
    >>> signed = await signer.sign_request(request)
    >>> is_valid = await signer.verify_signature(signed)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from eth_account.signers.local import LocalAccount

    HAS_ETH_ACCOUNT = True
except ImportError:
    HAS_ETH_ACCOUNT = False
    Account = None  # type: ignore[misc, assignment]
    LocalAccount = None  # type: ignore[misc, assignment]

from agirails.config.networks import NetworkConfig, get_network
from agirails.utils.logger import Logger

# Module logger for debugging
_logger = Logger("agirails.protocol.messages")

# secp256k1 curve order (n) - used for signature malleability protection
# Per EIP-2, valid signatures must have s <= n/2 to prevent malleability
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_DIV_2 = SECP256K1_N // 2

from agirails.types.message import (
    DeliveryProof,
    DeliveryProofMessage,
    EIP712Domain,
    ServiceRequest,
    ServiceResponse,
    SignedMessage,
    TypedData,
)


# Standard EIP-712 type definitions
EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


@dataclass
class SignatureComponents:
    """
    EIP-712 signature components.

    Attributes:
        v: Recovery id
        r: R component of signature
        s: S component of signature
    """

    v: int
    r: bytes
    s: bytes

    @classmethod
    def from_signature(cls, signature: str) -> "SignatureComponents":
        """Parse signature hex string into components."""
        sig_bytes = bytes.fromhex(signature.replace("0x", ""))
        if len(sig_bytes) != 65:
            raise ValueError(f"Invalid signature length: {len(sig_bytes)}, expected 65")

        r = sig_bytes[:32]
        s = sig_bytes[32:64]
        v = sig_bytes[64]

        # Handle EIP-155 style signatures
        if v < 27:
            v += 27

        return cls(v=v, r=r, s=s)

    def to_hex(self) -> str:
        """Convert to hex string (r + s + v format)."""
        # Ensure v is in range [27, 28] or [0, 1] for compatibility
        v_byte = self.v if self.v < 27 else self.v - 27
        return "0x" + self.r.hex() + self.s.hex() + format(v_byte + 27, "02x")

    def is_low_s(self) -> bool:
        """
        Check if signature has low-s value (EIP-2 compliant).

        Per EIP-2, valid signatures must have s <= secp256k1_n / 2
        to prevent signature malleability.

        Returns:
            True if s is in the lower half of the curve order
        """
        s_int = int.from_bytes(self.s, "big")
        return s_int <= SECP256K1_N_DIV_2

    def normalize_s(self) -> "SignatureComponents":
        """
        Normalize signature to low-s form (EIP-2 compliant).

        If s > n/2, compute s' = n - s and flip v.
        This ensures the signature is not malleable.

        Returns:
            New SignatureComponents with low-s value
        """
        s_int = int.from_bytes(self.s, "big")

        if s_int <= SECP256K1_N_DIV_2:
            # Already low-s, return as-is
            return self

        # Compute s' = n - s
        s_normalized = SECP256K1_N - s_int
        s_bytes = s_normalized.to_bytes(32, "big")

        # Flip v: 27 <-> 28
        v_normalized = 27 if self.v == 28 else 28

        return SignatureComponents(v=v_normalized, r=self.r, s=s_bytes)


def normalize_signature(signature: str) -> str:
    """
    Normalize an ECDSA signature to low-s form (EIP-2 compliant).

    Security Note (H-3): Prevents signature malleability attacks where
    both (r, s) and (r, n-s) are valid signatures for the same message.

    Args:
        signature: Hex-encoded signature (65 bytes: r[32] + s[32] + v[1])

    Returns:
        Normalized signature hex string with low-s value
    """
    components = SignatureComponents.from_signature(signature)
    normalized = components.normalize_s()
    return normalized.to_hex()


def is_signature_malleable(signature: str) -> bool:
    """
    Check if a signature is malleable (has high-s value).

    Args:
        signature: Hex-encoded signature

    Returns:
        True if signature has s > n/2 (malleable)
    """
    try:
        components = SignatureComponents.from_signature(signature)
        return not components.is_low_s()
    except (ValueError, IndexError):
        return True  # Invalid signatures are considered malleable


class MessageSigner:
    """
    EIP-712 Message Signer for ACTP protocol.

    Provides methods to sign and verify typed structured data
    according to EIP-712 specification.

    Args:
        private_key: Ethereum private key (hex string with or without 0x)
        chain_id: Ethereum chain ID
        verifying_contract: Contract address for domain separator
        domain_name: Protocol name (default: "ACTP")
        domain_version: Protocol version (default: "1")

    Example:
        >>> signer = MessageSigner(
        ...     private_key="0x...",
        ...     chain_id=84532,
        ...     verifying_contract="0x..."
        ... )
        >>> request = ServiceRequest(
        ...     service="echo",
        ...     input_hash="0x...",
        ...     budget=1000000,
        ...     deadline=1234567890
        ... )
        >>> signed = await signer.sign_request(request)
    """

    def __init__(
        self,
        private_key: str,
        chain_id: int = 84532,
        verifying_contract: str = "",
        domain_name: str = "ACTP",
        domain_version: str = "1",
    ) -> None:
        if not HAS_ETH_ACCOUNT:
            raise ImportError(
                "eth_account is required for MessageSigner. "
                "Install with: pip install eth-account"
            )

        # Normalize private key
        if private_key.startswith("0x"):
            private_key = private_key[2:]

        self._account: LocalAccount = Account.from_key(private_key)  # type: ignore[union-attr]
        self._chain_id = chain_id
        self._verifying_contract = verifying_contract
        self._domain_name = domain_name
        self._domain_version = domain_version

    @classmethod
    def from_config(
        cls,
        private_key: str,
        config: NetworkConfig,
        contract_type: str = "actp_kernel",
    ) -> "MessageSigner":
        """
        Create MessageSigner from network configuration.

        Args:
            private_key: Ethereum private key
            config: Network configuration
            contract_type: Contract to use for verifying_contract
                          ("actp_kernel" or "escrow_vault")

        Returns:
            Configured MessageSigner instance
        """
        if contract_type == "actp_kernel":
            verifying_contract = config.contracts.actp_kernel
        elif contract_type == "escrow_vault":
            verifying_contract = config.contracts.escrow_vault
        else:
            raise ValueError(f"Unknown contract type: {contract_type}")

        return cls(
            private_key=private_key,
            chain_id=config.chain_id,
            verifying_contract=verifying_contract,
        )

    @classmethod
    def from_network(
        cls,
        private_key: str,
        network: str = "base-sepolia",
        contract_type: str = "actp_kernel",
    ) -> "MessageSigner":
        """
        Create MessageSigner from network name.

        Args:
            private_key: Ethereum private key
            network: Network name (e.g., "base-sepolia")
            contract_type: Contract to use for verifying_contract

        Returns:
            Configured MessageSigner instance
        """
        config = get_network(network)
        return cls.from_config(private_key, config, contract_type)

    @property
    def address(self) -> str:
        """Get signer's Ethereum address."""
        return self._account.address

    @property
    def domain(self) -> EIP712Domain:
        """Get EIP-712 domain."""
        return EIP712Domain(
            name=self._domain_name,
            version=self._domain_version,
            chain_id=self._chain_id,
            verifying_contract=self._verifying_contract,
        )

    def _build_typed_data(
        self,
        primary_type: str,
        type_definition: List[Dict[str, str]],
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build EIP-712 typed data structure."""
        domain_type = EIP712_DOMAIN_TYPE.copy()
        if not self._verifying_contract:
            # Remove verifyingContract if not set
            domain_type = [t for t in domain_type if t["name"] != "verifyingContract"]

        domain_data: Dict[str, Any] = {
            "name": self._domain_name,
            "version": self._domain_version,
            "chainId": self._chain_id,
        }
        if self._verifying_contract:
            domain_data["verifyingContract"] = self._verifying_contract

        return {
            "types": {
                "EIP712Domain": domain_type,
                primary_type: type_definition,
            },
            "primaryType": primary_type,
            "domain": domain_data,
            "message": message,
        }

    def _sign_typed_data(self, typed_data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Sign typed data and return signature + signer address.

        Security Note (H-3): Signatures are automatically normalized to
        low-s form to prevent signature malleability attacks.

        Returns:
            Tuple of (signature_hex, signer_address)
        """
        signable = encode_typed_data(full_message=typed_data)
        signed = self._account.sign_message(signable)
        signature_hex = signed.signature.hex()

        # Normalize to low-s form (EIP-2 compliant)
        normalized = normalize_signature("0x" + signature_hex)

        return normalized[2:], self._account.address  # Remove 0x prefix

    def sign_request(self, request: ServiceRequest) -> SignedMessage:
        """
        Sign a service request.

        Args:
            request: ServiceRequest to sign

        Returns:
            SignedMessage containing the signature
        """
        # Set requester if not provided
        if not request.requester:
            request.requester = self._account.address

        typed_data = self._build_typed_data(
            primary_type=request.TYPE_NAME,
            type_definition=request.TYPE_DEFINITION,
            message=request.to_dict(),
        )

        signature, signer = self._sign_typed_data(typed_data)

        return SignedMessage(
            domain=self.domain,
            message=request.to_dict(),
            message_type=request.TYPE_NAME,
            signature="0x" + signature if not signature.startswith("0x") else signature,
            signer=signer,
        )

    def sign_response(self, response: ServiceResponse) -> SignedMessage:
        """
        Sign a service response.

        Args:
            response: ServiceResponse to sign

        Returns:
            SignedMessage containing the signature
        """
        # Set provider if not provided
        if not response.provider:
            response.provider = self._account.address

        typed_data = self._build_typed_data(
            primary_type=response.TYPE_NAME,
            type_definition=response.TYPE_DEFINITION,
            message=response.to_dict(),
        )

        signature, signer = self._sign_typed_data(typed_data)

        return SignedMessage(
            domain=self.domain,
            message=response.to_dict(),
            message_type=response.TYPE_NAME,
            signature="0x" + signature if not signature.startswith("0x") else signature,
            signer=signer,
        )

    def sign_delivery_proof(self, proof: DeliveryProof) -> SignedMessage:
        """
        Sign a legacy delivery proof.

        For new code, use sign_delivery_proof_message() instead.

        Args:
            proof: DeliveryProof to sign

        Returns:
            SignedMessage containing the signature
        """
        # Set provider if not provided
        if not proof.provider:
            proof.provider = self._account.address

        typed_data = self._build_typed_data(
            primary_type=proof.TYPE_NAME,
            type_definition=proof.TYPE_DEFINITION,
            message=proof.to_dict(),
        )

        signature, signer = self._sign_typed_data(typed_data)

        return SignedMessage(
            domain=self.domain,
            message=proof.to_dict(),
            message_type=proof.TYPE_NAME,
            signature="0x" + signature if not signature.startswith("0x") else signature,
            signer=signer,
        )

    def sign_delivery_proof_message(self, proof: DeliveryProofMessage) -> SignedMessage:
        """
        Sign an AIP-4 v1.1 delivery proof message.

        PARITY CRITICAL: Uses to_signing_dict() which returns ONLY the 9 signed fields.
        This matches the TypeScript SDK's AIP4DeliveryProofTypes exactly:
        txId, provider, consumer, resultCID, resultHash, easAttestationUID,
        deliveredAt, chainId, nonce.

        Args:
            proof: DeliveryProofMessage to sign (AIP-4 v1.1 schema)

        Returns:
            SignedMessage containing the signature
        """
        # PARITY: Use to_signing_dict() to get ONLY the 9 signed fields
        # This excludes type, version, signature, and metadata
        typed_data = self._build_typed_data(
            primary_type=proof.TYPE_NAME,
            type_definition=proof.TYPE_DEFINITION,
            message=proof.to_signing_dict(),
        )

        signature, signer = self._sign_typed_data(typed_data)

        # Update the proof's signature field
        proof.signature = "0x" + signature if not signature.startswith("0x") else signature

        return SignedMessage(
            domain=self.domain,
            message=proof.to_signing_dict(),  # Return only signed fields
            message_type=proof.TYPE_NAME,
            signature=proof.signature,
            signer=signer,
        )

    def sign_typed_data(
        self,
        primary_type: str,
        type_definition: List[Dict[str, str]],
        message: Dict[str, Any],
    ) -> SignedMessage:
        """
        Sign arbitrary typed data.

        Args:
            primary_type: Type name for the message
            type_definition: EIP-712 type definition
            message: Message to sign

        Returns:
            SignedMessage containing the signature
        """
        typed_data = self._build_typed_data(
            primary_type=primary_type,
            type_definition=type_definition,
            message=message,
        )

        signature, signer = self._sign_typed_data(typed_data)

        return SignedMessage(
            domain=self.domain,
            message=message,
            message_type=primary_type,
            signature="0x" + signature if not signature.startswith("0x") else signature,
            signer=signer,
        )

    def verify_signature(
        self,
        signed_message: SignedMessage,
        expected_signer: Optional[str] = None,
        reject_malleable: bool = True,
    ) -> bool:
        """
        Verify an EIP-712 signature.

        Security Note (H-3): By default, rejects malleable signatures
        (high-s values) to prevent signature malleability attacks.

        Args:
            signed_message: SignedMessage to verify
            expected_signer: Expected signer address (optional)
            reject_malleable: If True, reject signatures with high-s values

        Returns:
            True if signature is valid and signer matches
        """
        if not signed_message.is_signed:
            return False

        # Security: Check for malleable signatures (high-s values)
        if reject_malleable and is_signature_malleable(signed_message.signature):
            _logger.debug("Rejected malleable signature (high-s value)")
            return False

        # Get the type definition based on message type
        type_definitions = {
            ServiceRequest.TYPE_NAME: ServiceRequest.TYPE_DEFINITION,
            ServiceResponse.TYPE_NAME: ServiceResponse.TYPE_DEFINITION,
            DeliveryProof.TYPE_NAME: DeliveryProof.TYPE_DEFINITION,
            DeliveryProofMessage.TYPE_NAME: DeliveryProofMessage.TYPE_DEFINITION,
        }

        type_def = type_definitions.get(signed_message.message_type)
        if not type_def:
            return False

        # Rebuild typed data
        domain_type = EIP712_DOMAIN_TYPE.copy()
        if not signed_message.domain.verifying_contract:
            domain_type = [t for t in domain_type if t["name"] != "verifyingContract"]

        typed_data: Dict[str, Any] = {
            "types": {
                "EIP712Domain": domain_type,
                signed_message.message_type: type_def,
            },
            "primaryType": signed_message.message_type,
            "domain": signed_message.domain.to_dict(),
            "message": signed_message.message,
        }

        try:
            signable = encode_typed_data(full_message=typed_data)
            recovered = Account.recover_message(  # type: ignore[union-attr]
                signable,
                signature=bytes.fromhex(signed_message.signature.replace("0x", "")),
            )

            # Compare addresses (case-insensitive)
            if expected_signer:
                return recovered.lower() == expected_signer.lower()
            return recovered.lower() == signed_message.signer.lower()

        except Exception as e:
            _logger.debug(f"Signature verification failed: {e}")
            return False

    @staticmethod
    def recover_signer(
        typed_data: Dict[str, Any],
        signature: str,
    ) -> str:
        """
        Recover signer address from typed data and signature.

        Args:
            typed_data: EIP-712 typed data structure
            signature: Signature hex string

        Returns:
            Recovered signer address

        Raises:
            ImportError: If eth_account is not installed
            ValueError: If recovery fails
        """
        if not HAS_ETH_ACCOUNT:
            raise ImportError(
                "eth_account is required for signature recovery. "
                "Install with: pip install eth-account"
            )

        try:
            signable = encode_typed_data(full_message=typed_data)
            recovered = Account.recover_message(  # type: ignore[union-attr]
                signable,
                signature=bytes.fromhex(signature.replace("0x", "")),
            )
            return recovered
        except Exception as e:
            raise ValueError(f"Failed to recover signer: {e}") from e


def hash_typed_data(typed_data: Dict[str, Any]) -> str:
    """
    Compute the EIP-712 hash of typed data.

    This is the hash that gets signed.

    PARITY NOTE: eth_account is REQUIRED - no SHA-256 fallback.
    This ensures parity with TypeScript SDK which always uses keccak256.

    Args:
        typed_data: EIP-712 typed data structure

    Returns:
        Hex-encoded hash (bytes32)

    Raises:
        ImportError: If eth_account is not installed (no fallback)

    Note:
        This computes the same hash that eth_account uses internally.
        Requires eth_account for proper EIP-712 hashing.
    """
    if not HAS_ETH_ACCOUNT:
        # PARITY FIX: No SHA-256 fallback - eth_account is required
        # This ensures TypeScript and Python SDKs produce identical hashes
        raise ImportError(
            "eth_account is required for EIP-712 hash computation. "
            "Install with: pip install eth-account\n"
            "SHA-256 fallback is not supported for parity with TypeScript SDK."
        )

    signable = encode_typed_data(full_message=typed_data)
    return "0x" + signable.body.hex()


def create_typed_data(
    message: Union[ServiceRequest, ServiceResponse, DeliveryProof, DeliveryProofMessage],
    domain: EIP712Domain,
) -> Dict[str, Any]:
    """
    Create EIP-712 typed data from a message.

    Args:
        message: Message to convert
        domain: EIP-712 domain

    Returns:
        EIP-712 typed data dictionary
    """
    domain_type = EIP712_DOMAIN_TYPE.copy()
    if not domain.verifying_contract:
        domain_type = [t for t in domain_type if t["name"] != "verifyingContract"]

    return {
        "types": {
            "EIP712Domain": domain_type,
            message.TYPE_NAME: message.TYPE_DEFINITION,
        },
        "primaryType": message.TYPE_NAME,
        "domain": domain.to_dict(),
        "message": message.to_dict(),
    }


__all__ = [
    "MessageSigner",
    "SignatureComponents",
    "hash_typed_data",
    "create_typed_data",
    "normalize_signature",
    "is_signature_malleable",
    "SECP256K1_N",
    "SECP256K1_N_DIV_2",
    "HAS_ETH_ACCOUNT",
]
