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
import re
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
from agirails.utils.canonical_json import canonical_json_dumps
from agirails.utils.logger import Logger
from agirails.utils.received_nonce_tracker import IReceivedNonceTracker

# Module logger for debugging
_logger = Logger("agirails.protocol.messages")


# ============================================================================
# EIP-712 type definitions for the generic ACTPMessage surface
#
# PARITY: 1:1 with sdk-js/src/types/eip712.ts. The Python SignedMessage path
# (sign_request/sign_response/...) uses dataclass TYPE_DEFINITIONs; these mirror
# the TS *generic-message* registry consumed by signMessage/signQuoteRequest/
# signQuoteResponse so cross-SDK signatures over those message types match.
# ============================================================================

# ACTPMessageTypes — eip712.ts:146-156
ACTP_MESSAGE_TYPE_DEFINITION = [
    {"name": "type", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "from", "type": "string"},
    {"name": "to", "type": "string"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
    {"name": "payload", "type": "bytes"},
]

# QuoteRequestTypes — eip712.ts:24-35
QUOTE_REQUEST_TYPE_DEFINITION = [
    {"name": "from", "type": "string"},
    {"name": "to", "type": "string"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
    {"name": "serviceType", "type": "string"},
    {"name": "requirements", "type": "string"},
    {"name": "deadline", "type": "uint256"},
    {"name": "disputeWindow", "type": "uint256"},
]

# QuoteResponseTypes — eip712.ts:52-64
QUOTE_RESPONSE_TYPE_DEFINITION = [
    {"name": "from", "type": "string"},
    {"name": "to", "type": "string"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
    {"name": "requestId", "type": "bytes32"},
    {"name": "price", "type": "uint256"},
    {"name": "currency", "type": "address"},
    {"name": "deliveryTime", "type": "uint256"},
    {"name": "terms", "type": "string"},
]

# Nonce format: bytes32 hex (0x + 64 hex chars) — MessageSigner.ts:164
_NONCE_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
# Sequential-nonce warning threshold — MessageSigner.ts:177 (< 0xFFFFFFFF).
_LOW_ENTROPY_NONCE_MAX = 0xFFFFFFFF

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
        domain_name: Protocol name (default: "AGIRAILS" — matches TS MessageSigner)
        domain_version: Protocol version (default: "1.0" — matches TS MessageSigner)

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
        domain_name: str = "AGIRAILS",
        domain_version: str = "1.0",
        nonce_tracker: Optional[IReceivedNonceTracker] = None,
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
        # Optional replay protection (receiver side) — PARITY: MessageSigner.ts
        # constructor `nonceTracker` option (MessageSigner.ts:48-51, 74-85).
        self._nonce_tracker = nonce_tracker

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

    # ------------------------------------------------------------------
    # Generic ACTPMessage surface (1:1 with TS MessageSigner.signMessage /
    # signQuoteRequest / signQuoteResponse + ReceivedNonceTracker integration)
    # ------------------------------------------------------------------

    @staticmethod
    def _recursive_sort(obj: Any) -> Any:
        """Recursively sort dict keys for deterministic JSON.

        PARITY: mirrors ``MessageSigner.recursiveSort``
        (MessageSigner.ts:388-412). Lists keep order; only dict keys are sorted.
        """
        if obj is None:
            return obj
        if isinstance(obj, list):
            return [MessageSigner._recursive_sort(item) for item in obj]
        if isinstance(obj, dict):
            return {k: MessageSigner._recursive_sort(obj[k]) for k in sorted(obj.keys())}
        return obj

    @classmethod
    def _canonicalize_payload(cls, payload: Dict[str, Any]) -> str:
        """Canonicalize a payload to a deterministic JSON string.

        PARITY: ``MessageSigner.canonicalizePayload``
        (MessageSigner.ts:381-383) → ``JSON.stringify(recursiveSort(payload))``.
        ``canonical_json_dumps`` is byte-identical to ``JSON.stringify`` over
        sorted keys (minimal separators, JS number formatting, unicode kept).
        """
        return canonical_json_dumps(cls._recursive_sort(payload))

    def _encode_payload_bytes(self, payload: Dict[str, Any]) -> bytes:
        """ABI-encode the canonical payload string as ``bytes`` (the ``payload``
        field of the generic ACTPMessage typed struct).

        PARITY: ``AbiCoder.encode(['string'], [canonicalizePayload(payload)])``
        (MessageSigner.ts:190-194). Returns raw ABI bytes (TS feeds the hex into
        the ``bytes`` typed field).
        """
        from eth_abi import encode

        return encode(["string"], [self._canonicalize_payload(payload)])

    @staticmethod
    def _validate_and_warn_nonce(nonce: Optional[str]) -> None:
        """Validate bytes32 nonce format and warn on low-entropy nonces.

        PARITY: MessageSigner.ts:163-187 — hard error on bad format, warn (not
        error) on sequential / repeated-digit nonces.
        """
        if not nonce or not _NONCE_RE.match(nonce):
            raise ValueError(
                f'Invalid nonce format: "{nonce}". '
                "Nonce MUST be a bytes32 hex string (0x + 64 hex chars). "
                "Use SecureNonce.generate_secure_nonce() to generate "
                "cryptographically secure nonces. Never use sequential integers "
                "(1, 2, 3...) or timestamps as nonces."
            )

        nonce_value = int(nonce, 16)
        if nonce_value < _LOW_ENTROPY_NONCE_MAX:
            _logger.warn(
                "Nonce appears sequential - use SecureNonce.generate_secure_nonce()",
                {"nonce": nonce},
            )

        hex_digits = nonce[2:]
        first_digit = hex_digits[0]
        if all(d == first_digit for d in hex_digits):
            _logger.warn(
                "Nonce has low entropy - use SecureNonce.generate_secure_nonce()",
                {"nonce": nonce, "repeatedDigit": first_digit},
            )

    def sign_message(self, message: Dict[str, Any]) -> str:
        """
        Sign a generic ACTPMessage with EIP-712 (backward-compatible path).

        PARITY: mirrors ``MessageSigner.signMessage``
        (MessageSigner.ts:154-214). Validates the bytes32 ``nonce``, warns about
        low-entropy nonces, canonically encodes the remaining payload fields,
        and signs the generic ``ACTPMessage`` typed struct
        (type, version, from, to, timestamp, nonce, payload).

        Returns the raw signature hex (``0x``-prefixed), like the TS method —
        NOT a :class:`SignedMessage`. For strict typed messages use
        :meth:`sign_quote_request` / :meth:`sign_quote_response` /
        :meth:`sign_delivery_proof_message`.

        Args:
            message: Dict with keys ``type``, ``version``, ``from``, ``to``,
                ``timestamp``, ``nonce`` plus arbitrary payload fields.

        Returns:
            Signature hex (``0x``-prefixed, EIP-2 low-s normalized).
        """
        reserved = {"type", "version", "from", "to", "timestamp", "nonce", "signature"}
        nonce = message.get("nonce")

        # Security: validate nonce format / warn on low entropy (ts:163-187).
        self._validate_and_warn_nonce(nonce)

        payload = {k: v for k, v in message.items() if k not in reserved}
        payload_bytes = self._encode_payload_bytes(payload)

        typed_message = {
            "type": message.get("type"),
            "version": message.get("version"),
            "from": message.get("from"),
            "to": message.get("to"),
            "timestamp": message.get("timestamp"),
            "nonce": nonce,
            "payload": payload_bytes,
        }

        typed_data = self._build_typed_data(
            primary_type="ACTPMessage",
            type_definition=ACTP_MESSAGE_TYPE_DEFINITION,
            message=typed_message,
        )
        signature, _ = self._sign_typed_data(typed_data)
        return "0x" + signature if not signature.startswith("0x") else signature

    def sign_quote_request(self, data: Dict[str, Any]) -> str:
        """
        Sign a typed QuoteRequest (AIP-2) message.

        PARITY: mirrors ``MessageSigner.signQuoteRequest``
        (MessageSigner.ts:219-229). Uses the ``QuoteRequest`` EIP-712 type
        (eip712.ts:24-35) and returns the raw signature hex.

        Args:
            data: QuoteRequest fields — ``from``, ``to``, ``timestamp``,
                ``nonce``, ``serviceType``, ``requirements``, ``deadline``,
                ``disputeWindow``.

        Returns:
            Signature hex (``0x``-prefixed, EIP-2 low-s normalized).
        """
        typed_data = self._build_typed_data(
            primary_type="QuoteRequest",
            type_definition=QUOTE_REQUEST_TYPE_DEFINITION,
            message=data,
        )
        signature, _ = self._sign_typed_data(typed_data)
        return "0x" + signature if not signature.startswith("0x") else signature

    def sign_quote_response(self, data: Dict[str, Any]) -> str:
        """
        Sign a typed QuoteResponse (AIP-2) message.

        PARITY: mirrors ``MessageSigner.signQuoteResponse``
        (MessageSigner.ts:234-244). Uses the ``QuoteResponse`` EIP-712 type
        (eip712.ts:52-64) and returns the raw signature hex.

        Args:
            data: QuoteResponse fields — ``from``, ``to``, ``timestamp``,
                ``nonce``, ``requestId``, ``price``, ``currency``,
                ``deliveryTime``, ``terms``.

        Returns:
            Signature hex (``0x``-prefixed, EIP-2 low-s normalized).
        """
        typed_data = self._build_typed_data(
            primary_type="QuoteResponse",
            type_definition=QUOTE_RESPONSE_TYPE_DEFINITION,
            message=data,
        )
        signature, _ = self._sign_typed_data(typed_data)
        return "0x" + signature if not signature.startswith("0x") else signature

    @staticmethod
    def _did_to_address(did: str) -> str:
        """Convert a DID (or raw address) to an Ethereum address.

        PARITY: mirrors ``MessageSigner.didToAddress``
        (MessageSigner.ts:426-487). Handles legacy ``did:ethr:<address>`` and
        canonical EIP-3770 ``did:ethr:<chainId>:<address>``.
        """
        did_prefix = "did:ethr:"
        if did.startswith(did_prefix):
            remainder = did[len(did_prefix):]
            parts = remainder.split(":")
            if len(parts) == 2:
                chain_id_str, address = parts
                if not chain_id_str.isdigit():
                    raise ValueError(
                        f"Invalid DID format: {did}. Expected "
                        f"did:ethr:<chainId>:<address> but chainId "
                        f'"{chain_id_str}" is not a number.'
                    )
                if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
                    raise ValueError(
                        f"Invalid DID format: {did}. Expected "
                        f"did:ethr:<chainId>:<address> but "
                        f'"{address}" is not a valid Ethereum address.'
                    )
                return address
            if len(parts) == 1 and re.match(r"^0x[0-9a-fA-F]{40}$", parts[0]):
                return parts[0]
            raise ValueError(
                f"Invalid DID format: {did}. Expected did:ethr:<address> "
                f"or did:ethr:<chainId>:<address>."
            )

        if re.match(r"^0x[0-9a-fA-F]{40}$", did):
            return did

        raise ValueError(
            f"Invalid DID format: {did}. Expected Ethereum address (0x...) "
            f"or DID (did:ethr:...)."
        )

    def address_to_did(self, address: str) -> str:
        """Convert an Ethereum address to a canonical DID.

        PARITY: mirrors ``MessageSigner.addressToDID``
        (MessageSigner.ts:497-509). Uses ``did:ethr:<chainId>:<address>`` when a
        chainId is configured, else legacy ``did:ethr:<address>``.
        """
        if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
            raise ValueError(f"Invalid Ethereum address: {address}")
        if self._chain_id:
            return f"did:ethr:{self._chain_id}:{address}"
        return f"did:ethr:{address}"

    def verify_message(self, message: Dict[str, Any], signature: str) -> bool:
        """
        Verify a generic ACTPMessage signature (with optional replay protection).

        PARITY: mirrors ``MessageSigner.verifySignature``
        (MessageSigner.ts:275-326). Recovers the signer from the generic
        ``ACTPMessage`` typed struct, checks it matches ``from`` (DID→address),
        and — if a ``nonce_tracker`` was supplied — validates+records the nonce
        for replay protection, returning ``False`` on a detected replay.

        Args:
            message: The original ACTPMessage dict (same shape as
                :meth:`sign_message`).
            signature: Signature hex to verify.

        Returns:
            True if the signature is valid and (if tracking) the nonce is fresh.
        """
        reserved = {"type", "version", "from", "to", "timestamp", "nonce", "signature"}
        nonce = message.get("nonce")
        payload = {k: v for k, v in message.items() if k not in reserved}
        payload_bytes = self._encode_payload_bytes(payload)

        typed_message = {
            "type": message.get("type"),
            "version": message.get("version"),
            "from": message.get("from"),
            "to": message.get("to"),
            "timestamp": message.get("timestamp"),
            "nonce": nonce,
            "payload": payload_bytes,
        }

        typed_data = self._build_typed_data(
            primary_type="ACTPMessage",
            type_definition=ACTP_MESSAGE_TYPE_DEFINITION,
            message=typed_message,
        )

        try:
            signable = encode_typed_data(full_message=typed_data)
            recovered = Account.recover_message(  # type: ignore[union-attr]
                signable,
                signature=bytes.fromhex(signature.replace("0x", "")),
            )
        except Exception as e:  # pragma: no cover - defensive
            _logger.debug(f"Signature verification failed: {e}")
            return False

        expected_address = self._did_to_address(str(message.get("from", "")))
        if recovered.lower() != expected_address.lower():
            return False

        # Replay protection (ts:316-323): only when a tracker is configured.
        if self._nonce_tracker is not None:
            result = self._nonce_tracker.validate_and_record(
                str(message.get("from", "")), str(message.get("type", "")), str(nonce)
            )
            if not result.valid:
                return False

        return True

    def verify_message_or_raise(self, message: Dict[str, Any], signature: str) -> None:
        """
        Verify a generic ACTPMessage signature, raising on failure.

        PARITY: mirrors ``MessageSigner.verifySignatureOrThrow``
        (MessageSigner.ts:332-374). Raises
        :class:`SignatureVerificationError` on a signer mismatch and a
        ``ValueError`` describing the replay on a nonce-tracker rejection.
        """
        from agirails.errors import SignatureVerificationError

        reserved = {"type", "version", "from", "to", "timestamp", "nonce", "signature"}
        nonce = message.get("nonce")
        payload = {k: v for k, v in message.items() if k not in reserved}
        payload_bytes = self._encode_payload_bytes(payload)

        typed_message = {
            "type": message.get("type"),
            "version": message.get("version"),
            "from": message.get("from"),
            "to": message.get("to"),
            "timestamp": message.get("timestamp"),
            "nonce": nonce,
            "payload": payload_bytes,
        }

        typed_data = self._build_typed_data(
            primary_type="ACTPMessage",
            type_definition=ACTP_MESSAGE_TYPE_DEFINITION,
            message=typed_message,
        )

        signable = encode_typed_data(full_message=typed_data)
        recovered = Account.recover_message(  # type: ignore[union-attr]
            signable,
            signature=bytes.fromhex(signature.replace("0x", "")),
        )

        expected_address = self._did_to_address(str(message.get("from", "")))
        if recovered.lower() != expected_address.lower():
            raise SignatureVerificationError(
                "Generic ACTPMessage signature does not match sender",
                expected_signer=expected_address,
                actual_signer=recovered,
            )

        if self._nonce_tracker is not None:
            result = self._nonce_tracker.validate_and_record(
                str(message.get("from", "")), str(message.get("type", "")), str(nonce)
            )
            if not result.valid:
                raise ValueError(
                    f"Nonce replay attack detected: {result.reason}. "
                    f"Received nonce: {result.received_nonce}. "
                    + (
                        f"Expected minimum: {result.expected_minimum}"
                        if result.expected_minimum
                        else ""
                    )
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
