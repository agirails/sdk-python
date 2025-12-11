"""EIP-712 Message Signing for ACTP Protocol.

This module provides cryptographic signing for ACTP messages using EIP-712 typed data.
Reference: Yellow Paper §11.4.2, TypeScript SDK MessageSigner.ts

Key Features:
- EIP-712 domain separation per chain/contract
- Typed structured data hashing
- Quote request/response signing (AIP-2)
- Delivery proof signing (AIP-4)
- Signature verification
"""

import json
from typing import Any, Dict, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_typing import ChecksumAddress
from web3 import Web3

from .errors import ValidationError


# EIP-712 Type Definitions

def get_domain(
    name: str,
    version: str,
    chain_id: int,
    verifying_contract: str
) -> Dict[str, Any]:
    """Get EIP-712 domain separator.

    Args:
        name: Protocol name (e.g., "ACTP", "AGIRAILS")
        version: Protocol version (e.g., "1.0", "1")
        chain_id: Network chain ID (84532 for Base Sepolia, 8453 for Base Mainnet)
        verifying_contract: Contract address (ACTPKernel address)

    Returns:
        EIP-712 domain dict
    """
    return {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": verifying_contract
    }


# AIP-2 Quote Message Types

AIP2_QUOTE_TYPES = {
    "PriceQuote": [
        {"name": "txId", "type": "bytes32"},
        {"name": "provider", "type": "string"},
        {"name": "consumer", "type": "string"},
        {"name": "quotedAmount", "type": "string"},
        {"name": "originalAmount", "type": "string"},
        {"name": "maxPrice", "type": "string"},
        {"name": "currency", "type": "string"},
        {"name": "decimals", "type": "uint8"},
        {"name": "quotedAt", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "justificationHash", "type": "bytes32"},
        {"name": "chainId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"}
    ]
}


# AIP-4 Delivery Proof Types

DELIVERY_PROOF_TYPES = {
    "DeliveryProof": [
        {"name": "txId", "type": "bytes32"},
        {"name": "contentHash", "type": "bytes32"},
        {"name": "timestamp", "type": "uint256"},
        {"name": "deliveryUrl", "type": "string"}
    ]
}


class MessageSigner:
    """EIP-712 message signer for ACTP protocol.

    Provides cryptographic signing for:
    - Quote requests (AIP-2)
    - Quote responses (AIP-2)
    - Delivery proofs (AIP-4)
    - Generic ACTP messages

    Reference: TypeScript SDK MessageSigner.ts
    """

    def __init__(self, private_key: str, chain_id: Optional[int] = None):
        """Initialize message signer.

        Args:
            private_key: Private key (0x-prefixed hex string)
            chain_id: Optional chain ID (defaults to 84532 for Base Sepolia)
        """
        self.account = Account.from_key(private_key)
        self.chain_id = chain_id or 84532  # Default to Base Sepolia
        self.domain: Optional[Dict[str, Any]] = None

    def init_domain(self, kernel_address: str, chain_id: Optional[int] = None, name: str = "ACTP", version: str = "1.0") -> None:
        """Initialize EIP-712 domain (must be called before signing).

        Args:
            kernel_address: ACTPKernel contract address (verifying contract)
            chain_id: Optional chain ID (defaults to instance chain_id)
            name: Protocol name (default "ACTP")
            version: Protocol version (default "1.0")

        Raises:
            ValidationError: If kernel_address is invalid
        """
        if not Web3.is_address(kernel_address):
            raise ValidationError("kernel_address must be a valid Ethereum address")

        resolved_chain_id = chain_id or self.chain_id

        self.domain = get_domain(
            name=name,
            version=version,
            chain_id=resolved_chain_id,
            verifying_contract=kernel_address
        )

    def sign_quote(self, message: Dict[str, Any]) -> str:
        """Sign a quote message using EIP-712 (AIP-2).

        Args:
            message: Quote message dict with fields:
                - txId: Transaction ID (bytes32 hex string)
                - provider: Provider DID (e.g., "did:ethr:0x...")
                - consumer: Consumer DID
                - quotedAmount: Quoted price (string, base units)
                - originalAmount: Original offer (string, base units)
                - maxPrice: Maximum acceptable price (string, base units)
                - currency: Token symbol (e.g., "USDC")
                - decimals: Token decimals (e.g., 6)
                - quotedAt: Quote timestamp (unix seconds)
                - expiresAt: Expiry timestamp (unix seconds)
                - justificationHash: Keccak256 hash of justification JSON (bytes32)
                - chainId: Chain ID
                - nonce: Monotonic nonce

        Returns:
            EIP-712 signature (0x-prefixed hex string, 130 chars)

        Raises:
            ValueError: If domain not initialized

        Example:
            >>> signer = MessageSigner(private_key="0x...")
            >>> signer.init_domain(kernel_address="0x...")
            >>> message = {
            ...     "txId": "0x123...",
            ...     "provider": "did:ethr:0xProvider...",
            ...     "consumer": "did:ethr:0xConsumer...",
            ...     "quotedAmount": "1000000",
            ...     "originalAmount": "900000",
            ...     "maxPrice": "1500000",
            ...     "currency": "USDC",
            ...     "decimals": 6,
            ...     "quotedAt": 1234567890,
            ...     "expiresAt": 1234571490,
            ...     "justificationHash": "0x000...",
            ...     "chainId": 84532,
            ...     "nonce": 1
            ... }
            >>> signature = signer.sign_quote(message)

        Reference:
            - AIP-2 §3.1, §3.2 (Quote Message Schema)
            - TypeScript SDK: MessageSigner.signQuoteResponse()
        """
        if not self.domain:
            raise ValueError("Domain not initialized. Call init_domain() first.")

        # Build EIP-712 typed data
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                **AIP2_QUOTE_TYPES
            },
            "primaryType": "PriceQuote",
            "domain": self.domain,
            "message": message
        }

        # Sign using eth_account's encode_typed_data
        signable_message = encode_typed_data(full_message=typed_data)
        signed_message = self.account.sign_message(signable_message)

        return signed_message.signature.hex()

    def sign_delivery_proof(self, message: Dict[str, Any]) -> str:
        """Sign a delivery proof using EIP-712 (AIP-4).

        Args:
            message: Delivery proof dict with fields:
                - txId: Transaction ID (bytes32 hex string)
                - contentHash: Keccak256 hash of deliverable (bytes32)
                - timestamp: Delivery timestamp (unix milliseconds)
                - deliveryUrl: Optional IPFS/Arweave URL (string)

        Returns:
            EIP-712 signature (0x-prefixed hex string)

        Raises:
            ValueError: If domain not initialized

        Example:
            >>> signer = MessageSigner(private_key="0x...")
            >>> signer.init_domain(kernel_address="0x...")
            >>> proof = {
            ...     "txId": "0x123...",
            ...     "contentHash": "0xabc...",
            ...     "timestamp": 1234567890123,
            ...     "deliveryUrl": "ipfs://Qm..."
            ... }
            >>> signature = signer.sign_delivery_proof(proof)

        Reference:
            - AIP-4 (Delivery Proof and EAS Attestation Standard)
            - TypeScript SDK: MessageSigner.signDeliveryProof()
        """
        if not self.domain:
            raise ValueError("Domain not initialized. Call init_domain() first.")

        # Build EIP-712 typed data
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                **DELIVERY_PROOF_TYPES
            },
            "primaryType": "DeliveryProof",
            "domain": self.domain,
            "message": message
        }

        # Sign using eth_account's encode_typed_data
        signable_message = encode_typed_data(full_message=typed_data)
        signed_message = self.account.sign_message(signable_message)

        return signed_message.signature.hex()

    def verify_signature(self, message: Dict[str, Any], signature: str, message_types: Dict[str, Any], primary_type: str, expected_signer: str) -> bool:
        """Verify EIP-712 signature.

        Args:
            message: Message data dict
            signature: EIP-712 signature (0x-prefixed hex string)
            message_types: EIP-712 type definitions (e.g., AIP2_QUOTE_TYPES)
            primary_type: Primary type name (e.g., "PriceQuote")
            expected_signer: Expected signer address (0x-prefixed)

        Returns:
            True if signature is valid and matches expected signer

        Raises:
            ValueError: If domain not initialized
            ValidationError: If expected_signer is invalid address

        Example:
            >>> signer = MessageSigner(private_key="0x...")
            >>> signer.init_domain(kernel_address="0x...")
            >>> is_valid = signer.verify_signature(
            ...     message=quote_message,
            ...     signature="0x...",
            ...     message_types=AIP2_QUOTE_TYPES,
            ...     primary_type="PriceQuote",
            ...     expected_signer="0xProvider..."
            ... )

        Reference:
            - TypeScript SDK: MessageSigner.verifySignature()
        """
        if not self.domain:
            raise ValueError("Domain not initialized. Call init_domain() first.")

        if not Web3.is_address(expected_signer):
            raise ValidationError("expected_signer must be a valid Ethereum address")

        # Build EIP-712 typed data
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                **message_types
            },
            "primaryType": primary_type,
            "domain": self.domain,
            "message": message
        }

        # Recover signer address
        try:
            signable_message = encode_typed_data(full_message=typed_data)
            recovered_address = Account.recover_message(signable_message, signature=signature)

            # Compare addresses (case-insensitive)
            return recovered_address.lower() == expected_signer.lower()
        except Exception:
            # Signature verification failed
            return False

    @property
    def address(self) -> ChecksumAddress:
        """Get signer's Ethereum address.

        Returns:
            Checksummed Ethereum address
        """
        return self.account.address

    @staticmethod
    def did_to_address(did: str) -> str:
        """Convert DID to Ethereum address.

        Supports formats:
        - did:ethr:0x... (simple)
        - did:ethr:84532:0x... (with chain ID)

        Args:
            did: DID string (e.g., "did:ethr:0x123...")

        Returns:
            Ethereum address (0x-prefixed)

        Raises:
            ValueError: If DID format is invalid

        Example:
            >>> MessageSigner.did_to_address("did:ethr:0x1234...")
            "0x1234..."
            >>> MessageSigner.did_to_address("did:ethr:84532:0x1234...")
            "0x1234..."
        """
        if did.startswith("did:ethr:"):
            # Remove "did:ethr:" prefix
            parts = did.replace("did:ethr:", "").split(":")

            # Extract address (last part after splitting by ':')
            address = parts[-1]

            # Validate address format
            if address.startswith("0x") and len(address) == 42:
                return address

        raise ValueError(f"Invalid DID format: {did}")

    @staticmethod
    def address_to_did(address: str, chain_id: Optional[int] = None) -> str:
        """Convert Ethereum address to DID.

        Args:
            address: Ethereum address (0x-prefixed)
            chain_id: Optional chain ID (if provided, formats as did:ethr:{chainId}:0x...)

        Returns:
            DID string (e.g., "did:ethr:0x..." or "did:ethr:84532:0x...")

        Raises:
            ValidationError: If address is invalid

        Example:
            >>> MessageSigner.address_to_did("0x1234...")
            "did:ethr:0x1234..."
            >>> MessageSigner.address_to_did("0x1234...", chain_id=84532)
            "did:ethr:84532:0x1234..."
        """
        if not Web3.is_address(address):
            raise ValidationError("address must be a valid Ethereum address")

        if chain_id:
            return f"did:ethr:{chain_id}:{address}"
        return f"did:ethr:{address}"
