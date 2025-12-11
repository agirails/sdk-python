"""Proof Generator - Content hashing and delivery proofs.

This module provides cryptographic content hashing and delivery proof generation
for the ACTP protocol (AIP-4).

Reference:
- Yellow Paper §11.4.1 (Content Hashing)
- Yellow Paper §8.2 (Delivery Proof Schema)
- TypeScript SDK: ProofGenerator.ts
"""

from typing import Dict, Any, Optional, Union
from web3 import Web3
from eth_abi import encode


class ProofGenerator:
    """Content hashing and delivery proof generation.

    Provides methods for:
    - Hashing deliverable content (Keccak256)
    - Generating delivery proofs (AIP-4 schema)
    - Encoding/decoding proofs for on-chain submission
    - Verifying deliverable integrity

    Reference: TypeScript SDK ProofGenerator.ts
    """

    @staticmethod
    def hash_content(content: Union[str, bytes]) -> str:
        """Hash deliverable content using Keccak256.

        Args:
            content: Content to hash (string or bytes)

        Returns:
            Keccak256 hash (0x-prefixed hex string, 66 chars)

        Example:
            >>> proof_gen = ProofGenerator()
            >>> content_hash = proof_gen.hash_content("Hello, world!")
            >>> print(content_hash)
            "0x315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"

        Reference:
            - Yellow Paper §11.4.1 (Content Hashing)
            - TypeScript SDK: ProofGenerator.hashContent()
        """
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        return Web3.keccak(content_bytes).hex()

    @staticmethod
    def generate_delivery_proof(
        tx_id: str,
        deliverable: Union[str, bytes],
        delivery_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate delivery proof (AIP-4).

        Creates a delivery proof with:
        - Content hash (Keccak256)
        - Timestamp (current time in milliseconds)
        - Optional delivery URL (IPFS/Arweave)
        - Metadata (size, mimeType, etc.)

        Args:
            tx_id: Transaction ID (bytes32 hex string)
            deliverable: Content to deliver (string or bytes)
            delivery_url: Optional storage URL (e.g., "ipfs://Qm...")
            metadata: Optional metadata dict (user fields)

        Returns:
            Delivery proof dict with schema:
            {
                "type": "delivery.proof",
                "txId": "0x...",
                "contentHash": "0x...",
                "timestamp": 1234567890123,
                "deliveryUrl": "ipfs://...",  # Optional
                "metadata": {
                    "size": 1024,
                    "mimeType": "application/json",
                    ... user fields ...
                }
            }

        Example:
            >>> proof_gen = ProofGenerator()
            >>> proof = proof_gen.generate_delivery_proof(
            ...     tx_id="0x123...",
            ...     deliverable="Translation result",
            ...     delivery_url="ipfs://QmHash...",
            ...     metadata={"language": "es", "wordCount": 150}
            ... )
            >>> print(proof["contentHash"])
            "0xabc..."

        Reference:
            - Yellow Paper §8.2 (Delivery Proof Schema)
            - AIP-4 (Delivery Proof and EAS Attestation Standard)
            - TypeScript SDK: ProofGenerator.generateDeliveryProof()
        """
        import time

        # Hash the content
        content_hash = ProofGenerator.hash_content(deliverable)

        # Calculate size
        if isinstance(deliverable, str):
            size = len(deliverable.encode('utf-8'))
        else:
            size = len(deliverable)

        # Build metadata (user fields + computed fields)
        metadata = metadata or {}

        # Extract user-supplied fields (exclude reserved computed fields)
        user_metadata = {k: v for k, v in metadata.items() if k not in ("size", "mimeType")}

        # Enforce computed fields (cannot be spoofed)
        final_metadata = {
            **user_metadata,
            "size": size,
            "mimeType": metadata.get("mimeType", "application/octet-stream")  # Fallback
        }

        # Build delivery proof
        proof = {
            "type": "delivery.proof",  # Required per AIP-4
            "txId": tx_id,
            "contentHash": content_hash,
            "timestamp": int(time.time() * 1000),  # Milliseconds
            "metadata": final_metadata
        }

        # Add optional delivery URL
        if delivery_url:
            proof["deliveryUrl"] = delivery_url

        return proof

    @staticmethod
    def encode_proof(proof: Dict[str, Any]) -> bytes:
        """Encode proof for on-chain submission.

        Encodes proof as ABI-encoded bytes:
        - txId: bytes32
        - contentHash: bytes32
        - timestamp: uint256

        Args:
            proof: Delivery proof dict (from generate_delivery_proof)

        Returns:
            ABI-encoded proof bytes (96 bytes: 32 + 32 + 32)

        Example:
            >>> proof_gen = ProofGenerator()
            >>> proof = proof_gen.generate_delivery_proof(...)
            >>> encoded = proof_gen.encode_proof(proof)
            >>> print(len(encoded))
            96

        Reference:
            - TypeScript SDK: ProofGenerator.encodeProof()
        """
        tx_id = proof["txId"]
        content_hash = proof["contentHash"]
        timestamp = proof["timestamp"]

        # Encode as bytes32 + bytes32 + uint256
        encoded = encode(
            ["bytes32", "bytes32", "uint256"],
            [
                bytes.fromhex(tx_id[2:]),  # Remove 0x prefix
                bytes.fromhex(content_hash[2:]),
                timestamp
            ]
        )

        return encoded

    @staticmethod
    def decode_proof(proof_data: bytes) -> Dict[str, Any]:
        """Decode proof from on-chain data.

        Args:
            proof_data: ABI-encoded proof bytes (96 bytes)

        Returns:
            Decoded proof dict with:
            {
                "txId": "0x...",
                "contentHash": "0x...",
                "timestamp": 1234567890123
            }

        Example:
            >>> proof_gen = ProofGenerator()
            >>> decoded = proof_gen.decode_proof(encoded_bytes)
            >>> print(decoded["txId"])
            "0x123..."

        Reference:
            - TypeScript SDK: ProofGenerator.decodeProof()
        """
        from eth_abi import decode

        # Decode bytes32 + bytes32 + uint256
        tx_id_bytes, content_hash_bytes, timestamp = decode(
            ["bytes32", "bytes32", "uint256"],
            proof_data
        )

        return {
            "txId": "0x" + tx_id_bytes.hex(),
            "contentHash": "0x" + content_hash_bytes.hex(),
            "timestamp": timestamp
        }

    @staticmethod
    def verify_deliverable(deliverable: Union[str, bytes], expected_hash: str) -> bool:
        """Verify deliverable matches expected hash.

        Args:
            deliverable: Content to verify (string or bytes)
            expected_hash: Expected Keccak256 hash (0x-prefixed)

        Returns:
            True if hash matches, False otherwise

        Example:
            >>> proof_gen = ProofGenerator()
            >>> is_valid = proof_gen.verify_deliverable(
            ...     deliverable="Hello, world!",
            ...     expected_hash="0x315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
            ... )
            >>> print(is_valid)
            True

        Reference:
            - TypeScript SDK: ProofGenerator.verifyDeliverable()
        """
        actual_hash = ProofGenerator.hash_content(deliverable)
        return actual_hash.lower() == expected_hash.lower()

    @staticmethod
    async def hash_from_url(url: str) -> str:
        """Generate content hash from URL (for IPFS/Arweave).

        Note: This is an async method requiring aiohttp.

        Args:
            url: URL to fetch content from

        Returns:
            Keccak256 hash of fetched content (0x-prefixed)

        Raises:
            ValidationError: If URL is potentially unsafe (SSRF protection)
            Exception: If fetch fails or content is invalid

        Example:
            >>> import asyncio
            >>> proof_gen = ProofGenerator()
            >>> content_hash = await proof_gen.hash_from_url("https://example.com/file.txt")

        Reference:
            - TypeScript SDK: ProofGenerator.hashFromUrl()
        """
        # Import SSRF protection
        from .client import _validate_endpoint_url

        # Validate URL before fetching (blocks localhost, private IPs)
        _validate_endpoint_url(url, "url")

        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp is required for hash_from_url. Install with: pip install aiohttp")

        # Set timeout to prevent DoS (30 seconds total)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Failed to fetch content from {url}: HTTP {response.status}")

                content_bytes = await response.read()
                return ProofGenerator.hash_content(content_bytes)
