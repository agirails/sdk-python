"""
DID Manager for AGIRAILS SDK.

Provides DID (Decentralized Identifier) management:
- DID creation and resolution
- DID Document management
- Verification method handling
- Service endpoint management

DIDs provide decentralized identity for agents in the ACTP protocol.

Example:
    >>> from agirails.protocol import DIDManager
    >>> manager = DIDManager(private_key, network="base-sepolia")
    >>> did = manager.create_did()
    >>> doc = manager.create_did_document(endpoint="https://api.example.com")
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

try:
    from eth_account import Account
    from eth_account.signers.local import LocalAccount

    HAS_ETH_ACCOUNT = True
except ImportError:
    HAS_ETH_ACCOUNT = False
    Account = None  # type: ignore[misc, assignment]
    LocalAccount = None  # type: ignore[misc, assignment]

from agirails.types.did import (
    AgentDID,
    DIDDocument,
    DIDMethod,
    DIDNetwork,
    is_valid_did,
    parse_did,
)


@dataclass
class VerificationMethod:
    """
    DID Verification Method.

    Attributes:
        id: Verification method identifier
        type_: Type of verification method
        controller: DID that controls this method
        public_key_hex: Public key in hex format
        public_key_multibase: Public key in multibase format
    """

    id: str
    type_: str
    controller: str
    public_key_hex: str = ""
    public_key_multibase: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result: Dict[str, Any] = {
            "id": self.id,
            "type": self.type_,
            "controller": self.controller,
        }
        if self.public_key_hex:
            result["publicKeyHex"] = self.public_key_hex
        if self.public_key_multibase:
            result["publicKeyMultibase"] = self.public_key_multibase
        return result


@dataclass
class ServiceEndpoint:
    """
    DID Service Endpoint.

    Attributes:
        id: Service endpoint identifier
        type_: Type of service
        service_endpoint: URL or endpoint object
        description: Optional description
    """

    id: str
    type_: str
    service_endpoint: Union[str, Dict[str, Any]]
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result: Dict[str, Any] = {
            "id": self.id,
            "type": self.type_,
            "serviceEndpoint": self.service_endpoint,
        }
        if self.description:
            result["description"] = self.description
        return result


# Default Universal Resolver URL
DEFAULT_RESOLVER_URL = "https://uniresolver.io/1.0/identifiers"


class DIDResolver:
    """
    DID Resolver for looking up DID Documents.

    Resolves DIDs from various sources:
    - On-chain (AgentRegistry)
    - Local cache
    - HTTP endpoints

    Example:
        >>> resolver = DIDResolver()
        >>> doc = await resolver.resolve("did:agirails:base-sepolia:0x...")
    """

    def __init__(
        self,
        cache_ttl: int = 300,
        http_timeout: float = 10.0,
        resolver_url: str = DEFAULT_RESOLVER_URL,
        max_concurrent_requests: int = 10,
    ) -> None:
        """
        Initialize DIDResolver.

        Args:
            cache_ttl: Cache TTL in seconds
            http_timeout: HTTP request timeout
            resolver_url: Base URL for Universal Resolver (default: uniresolver.io)
            max_concurrent_requests: Maximum concurrent HTTP requests (rate limiting)
        """
        self._cache: Dict[str, tuple] = {}  # did -> (document, timestamp)
        self._cache_ttl = cache_ttl
        self._http_timeout = http_timeout
        self._resolver_url = resolver_url
        self._max_concurrent = max_concurrent_requests
        self._http_semaphore: Optional[Any] = None  # Lazy-initialized asyncio.Semaphore

    def _is_cache_valid(self, did: str) -> bool:
        """Check if cached document is still valid."""
        if did not in self._cache:
            return False
        _, timestamp = self._cache[did]
        return (time.time() - timestamp) < self._cache_ttl

    def _get_from_cache(self, did: str) -> Optional[DIDDocument]:
        """Get document from cache."""
        if self._is_cache_valid(did):
            doc, _ = self._cache[did]
            return doc
        return None

    def _set_cache(self, did: str, doc: DIDDocument) -> None:
        """Set document in cache."""
        self._cache[did] = (doc, time.time())

    def clear_cache(self) -> None:
        """Clear the resolution cache."""
        self._cache.clear()

    async def resolve(
        self,
        did: str,
        use_cache: bool = True,
    ) -> Optional[DIDDocument]:
        """
        Resolve a DID to its DID Document.

        Args:
            did: DID string to resolve
            use_cache: Whether to use cached results

        Returns:
            DID Document or None if not found
        """
        if use_cache:
            cached = self._get_from_cache(did)
            if cached:
                return cached

        # Parse DID
        parsed = parse_did(did)
        if not parsed:
            return None

        method, network, identifier = parsed

        # Resolve based on method
        if method == "agirails":
            doc = await self._resolve_agirails(did, network, identifier)
        elif method == "key":
            doc = self._resolve_key(did, identifier)
        elif method == "eth":
            doc = await self._resolve_eth(did, identifier)
        else:
            # Try HTTP resolution as fallback
            doc = await self._resolve_http(did)

        if doc and use_cache:
            self._set_cache(did, doc)

        return doc

    async def _resolve_agirails(
        self,
        did: str,
        network: str,
        identifier: str,
    ) -> Optional[DIDDocument]:
        """Resolve AGIRAILS DID (from AgentRegistry)."""
        # For now, create a minimal document
        # Full implementation would query AgentRegistry
        agent_did = AgentDID(method="agirails", network=network, identifier=identifier)

        return DIDDocument(
            id=agent_did,
            verification_method=[
                {
                    "id": f"{did}#key-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": did,
                    "blockchainAccountId": f"eip155:{network}:{identifier}",
                }
            ],
            authentication=[f"{did}#key-1"],
        )

    def _resolve_key(self, did: str, identifier: str) -> Optional[DIDDocument]:
        """Resolve did:key DID."""
        agent_did = AgentDID(method="key", network="", identifier=identifier)

        return DIDDocument(
            id=agent_did,
            verification_method=[
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": identifier,
                }
            ],
            authentication=[f"{did}#key-1"],
        )

    async def _resolve_eth(self, did: str, identifier: str) -> Optional[DIDDocument]:
        """Resolve did:eth DID."""
        # Simplified: create document from Ethereum address
        agent_did = AgentDID(method="eth", network="mainnet", identifier=identifier)

        return DIDDocument(
            id=agent_did,
            verification_method=[
                {
                    "id": f"{did}#key-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": did,
                    "blockchainAccountId": f"eip155:1:{identifier}",
                }
            ],
            authentication=[f"{did}#key-1"],
        )

    async def _get_semaphore(self) -> Any:
        """Get or create the HTTP semaphore for rate limiting."""
        if self._http_semaphore is None:
            import asyncio
            self._http_semaphore = asyncio.Semaphore(self._max_concurrent)
        return self._http_semaphore

    async def _resolve_http(self, did: str) -> Optional[DIDDocument]:
        """Resolve DID via HTTP (Universal Resolver)."""
        try:
            import aiohttp

            # Use configured resolver URL
            url = f"{self._resolver_url}/{did}"

            # Rate limit concurrent requests
            semaphore = await self._get_semaphore()
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=self._http_timeout) as response:
                        if response.status != 200:
                            return None

                        data = await response.json()
                        if "didDocument" in data:
                            return DIDDocument.from_dict(data["didDocument"])

        except Exception:
            pass

        return None


class DIDManager:
    """
    DID Manager for creating and managing agent identities.

    Provides methods to create DIDs, DID Documents, and manage
    verification methods and service endpoints.

    Args:
        private_key: Ethereum private key (optional for read-only)
        network: Network for DIDs (default: "base-sepolia")
        resolver: Optional DID resolver

    Example:
        >>> manager = DIDManager(private_key, network="base-sepolia")
        >>> did = manager.create_did()
        >>> print(did)  # did:agirails:base-sepolia:0x...
    """

    def __init__(
        self,
        private_key: Optional[str] = None,
        network: str = "base-sepolia",
        resolver: Optional[DIDResolver] = None,
    ) -> None:
        self._network = network
        self._resolver = resolver or DIDResolver()
        self._account: Optional[LocalAccount] = None

        if private_key and HAS_ETH_ACCOUNT:
            self._account = Account.from_key(private_key)  # type: ignore[union-attr]

    @property
    def address(self) -> Optional[str]:
        """Get the associated Ethereum address."""
        if self._account:
            return self._account.address
        return None

    @property
    def did(self) -> Optional[AgentDID]:
        """Get the DID for this manager's address."""
        if self._account:
            return self.create_did()
        return None

    @property
    def resolver(self) -> DIDResolver:
        """Get the DID resolver."""
        return self._resolver

    def create_did(
        self,
        address: Optional[str] = None,
        method: str = "agirails",
    ) -> AgentDID:
        """
        Create a DID for an Ethereum address.

        Args:
            address: Ethereum address (uses manager's address if not provided)
            method: DID method (default: "agirails")

        Returns:
            AgentDID

        Raises:
            ValueError: If no address provided and manager has no account
        """
        if address is None:
            if self._account:
                address = self._account.address
            else:
                raise ValueError("No address provided and manager has no account")

        return AgentDID.from_address(
            address=address,
            network=self._network,
            method=method,
        )

    def create_did_document(
        self,
        did: Optional[AgentDID] = None,
        endpoint: Optional[str] = None,
        service_types: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DIDDocument:
        """
        Create a DID Document for an agent.

        Args:
            did: Agent DID (uses manager's DID if not provided)
            endpoint: Agent API endpoint URL
            service_types: List of supported service types
            metadata: Additional metadata

        Returns:
            DIDDocument
        """
        if did is None:
            did = self.did
        if did is None:
            raise ValueError("No DID provided and manager has no account")

        did_string = str(did)

        # Create verification methods
        verification_methods = [
            {
                "id": f"{did_string}#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did_string,
                "blockchainAccountId": f"eip155:{self._get_chain_id()}:{did.identifier}",
            }
        ]

        # Add public key if available
        if self._account:
            pub_key = self._get_public_key_hex()
            if pub_key:
                verification_methods[0]["publicKeyHex"] = pub_key

        # Create service endpoints
        services = []
        if endpoint:
            services.append({
                "id": f"{did_string}#agent-api",
                "type": "AgentAPI",
                "serviceEndpoint": endpoint,
            })

        if service_types:
            for i, service_type in enumerate(service_types):
                services.append({
                    "id": f"{did_string}#service-{i}",
                    "type": service_type,
                    "serviceEndpoint": f"{endpoint}/services/{service_type}" if endpoint else "",
                })

        return DIDDocument(
            id=did,
            verification_method=verification_methods,
            authentication=[f"{did_string}#key-1"],
            service=services if services else None,
            metadata=metadata,
        )

    def _get_chain_id(self) -> str:
        """Get chain ID for the network."""
        chain_ids = {
            "mainnet": "1",
            "base": "8453",
            "base-sepolia": "84532",
            "local": "31337",
            "mock": "0",
        }
        return chain_ids.get(self._network, "0")

    def _get_public_key_hex(self) -> Optional[str]:
        """Get public key in hex format."""
        if not self._account:
            return None

        try:
            # Get public key from account
            # This requires eth_keys
            from eth_keys import keys

            private_key = keys.PrivateKey(self._account.key)
            public_key = private_key.public_key
            return public_key.to_hex()
        except ImportError:
            return None

    async def resolve(self, did: str) -> Optional[DIDDocument]:
        """
        Resolve a DID to its DID Document.

        Args:
            did: DID string to resolve

        Returns:
            DID Document or None if not found
        """
        return await self._resolver.resolve(did)

    def verify_did_ownership(
        self,
        did: str,
        signature: str,
        message: str,
    ) -> bool:
        """
        Verify that a signature was made by the DID owner.

        Args:
            did: DID to verify
            signature: Signature hex string
            message: Message that was signed

        Returns:
            True if signature is valid for DID owner
        """
        if not HAS_ETH_ACCOUNT:
            raise ImportError(
                "eth_account required for signature verification. "
                "Install with: pip install eth-account"
            )

        # Parse DID
        parsed = parse_did(did)
        if not parsed:
            return False

        _, _, identifier = parsed

        try:
            from eth_account.messages import encode_defunct

            message_hash = encode_defunct(text=message)
            recovered = Account.recover_message(  # type: ignore[union-attr]
                message_hash,
                signature=bytes.fromhex(signature.replace("0x", "")),
            )

            return recovered.lower() == identifier.lower()
        except Exception:
            return False

    def sign_for_did(self, message: str) -> str:
        """
        Sign a message with this manager's key.

        Args:
            message: Message to sign

        Returns:
            Signature hex string

        Raises:
            ValueError: If manager has no account
        """
        if not self._account:
            raise ValueError("Manager has no account for signing")

        if not HAS_ETH_ACCOUNT:
            raise ImportError(
                "eth_account required for signing. "
                "Install with: pip install eth-account"
            )

        from eth_account.messages import encode_defunct

        message_hash = encode_defunct(text=message)
        signed = self._account.sign_message(message_hash)
        return "0x" + signed.signature.hex()


def create_did_from_address(
    address: str,
    network: str = "base-sepolia",
    method: str = "agirails",
) -> str:
    """
    Create a DID string from an Ethereum address.

    Args:
        address: Ethereum address
        network: Network identifier
        method: DID method

    Returns:
        DID string
    """
    did = AgentDID.from_address(address, network=network, method=method)
    return str(did)


def did_to_address(did: str) -> Optional[str]:
    """
    Extract Ethereum address from a DID.

    Args:
        did: DID string

    Returns:
        Ethereum address or None if invalid DID
    """
    parsed = parse_did(did)
    if parsed:
        return parsed[2]  # identifier
    return None


__all__ = [
    "DIDManager",
    "DIDResolver",
    "VerificationMethod",
    "ServiceEndpoint",
    "create_did_from_address",
    "did_to_address",
    "HAS_ETH_ACCOUNT",
    "DEFAULT_RESOLVER_URL",
]
