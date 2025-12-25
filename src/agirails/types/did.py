"""
Decentralized Identifier (DID) types for AGIRAILS SDK.

Provides types for agent identity management using DIDs.
DIDs are used to identify agents in a decentralized manner,
independent of any central authority.

DID Format: did:agirails:<network>:<address>

Example:
    >>> did = AgentDID.from_address("0x1234...", network="base-sepolia")
    >>> print(did)  # did:agirails:base-sepolia:0x1234...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class DIDMethod(Enum):
    """Supported DID methods."""

    AGIRAILS = "agirails"
    ETH = "eth"
    KEY = "key"


class DIDNetwork(Enum):
    """Supported networks for DIDs."""

    MAINNET = "mainnet"
    BASE = "base"
    BASE_SEPOLIA = "base-sepolia"
    LOCAL = "local"
    MOCK = "mock"


# DID pattern: did:<method>:<network>:<identifier>
DID_PATTERN = re.compile(
    r"^did:([a-z]+):([a-z0-9-]+):([a-zA-Z0-9]+)$"
)


@dataclass
class AgentDID:
    """
    Decentralized Identifier for an agent.

    Attributes:
        method: DID method (e.g., "agirails")
        network: Network identifier (e.g., "base-sepolia")
        identifier: Unique identifier (typically Ethereum address)
    """

    method: str
    network: str
    identifier: str

    def __str__(self) -> str:
        """Get the full DID string."""
        return f"did:{self.method}:{self.network}:{self.identifier}"

    def __repr__(self) -> str:
        """String representation."""
        return f"AgentDID({self})"

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if isinstance(other, AgentDID):
            return str(self) == str(other)
        if isinstance(other, str):
            return str(self) == other
        return False

    def __hash__(self) -> int:
        """Make hashable."""
        return hash(str(self))

    @classmethod
    def from_string(cls, did_string: str) -> AgentDID:
        """
        Parse a DID from string.

        Args:
            did_string: Full DID string (e.g., "did:agirails:base:0x...")

        Returns:
            Parsed AgentDID

        Raises:
            ValueError: If DID format is invalid
        """
        match = DID_PATTERN.match(did_string)
        if not match:
            raise ValueError(f"Invalid DID format: {did_string}")

        method, network, identifier = match.groups()
        return cls(method=method, network=network, identifier=identifier)

    @classmethod
    def from_address(
        cls,
        address: str,
        *,
        network: str = "base-sepolia",
        method: str = "agirails",
    ) -> AgentDID:
        """
        Create a DID from an Ethereum address.

        Args:
            address: Ethereum address (0x prefixed)
            network: Network identifier
            method: DID method

        Returns:
            AgentDID for the address
        """
        # Normalize address
        if not address.startswith("0x"):
            address = f"0x{address}"

        return cls(method=method, network=network, identifier=address)

    @property
    def address(self) -> str:
        """Get the Ethereum address from the DID."""
        return self.identifier

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary."""
        return {
            "method": self.method,
            "network": self.network,
            "identifier": self.identifier,
            "did": str(self),
        }


@dataclass
class DIDDocument:
    """
    DID Document containing agent identity information.

    Follows W3C DID Core specification with AGIRAILS extensions.

    Attributes:
        id: The DID identifier
        controller: DID of the controller (usually same as id)
        verification_method: List of verification methods
        authentication: Authentication methods
        service: Service endpoints
        created: Document creation time
        updated: Last update time
        metadata: Additional metadata
    """

    id: AgentDID
    controller: Optional[AgentDID] = None
    verification_method: Optional[List[Dict[str, Any]]] = None
    authentication: Optional[List[str]] = None
    service: Optional[List[Dict[str, Any]]] = None
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Set defaults."""
        if self.controller is None:
            self.controller = self.id
        if self.created is None:
            self.created = datetime.now()
        if self.updated is None:
            self.updated = self.created

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to W3C DID Document format.

        Returns:
            Dictionary in DID Document format
        """
        doc: Dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://agirails.io/ns/did/v1",
            ],
            "id": str(self.id),
            "controller": str(self.controller) if self.controller else str(self.id),
        }

        if self.verification_method:
            doc["verificationMethod"] = self.verification_method

        if self.authentication:
            doc["authentication"] = self.authentication

        if self.service:
            doc["service"] = self.service

        if self.created:
            doc["created"] = self.created.isoformat()

        if self.updated:
            doc["updated"] = self.updated.isoformat()

        if self.metadata:
            doc["metadata"] = self.metadata

        return doc

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DIDDocument:
        """
        Create DIDDocument from dictionary.

        Args:
            data: Dictionary in DID Document format

        Returns:
            DIDDocument instance
        """
        did = AgentDID.from_string(data["id"])
        controller = None
        if "controller" in data:
            controller = AgentDID.from_string(data["controller"])

        created = None
        if "created" in data:
            created = datetime.fromisoformat(data["created"])

        updated = None
        if "updated" in data:
            updated = datetime.fromisoformat(data["updated"])

        return cls(
            id=did,
            controller=controller,
            verification_method=data.get("verificationMethod"),
            authentication=data.get("authentication"),
            service=data.get("service"),
            created=created,
            updated=updated,
            metadata=data.get("metadata"),
        )


def is_valid_did(did_string: str) -> bool:
    """
    Check if a string is a valid DID.

    Args:
        did_string: String to check

    Returns:
        True if valid DID format
    """
    return DID_PATTERN.match(did_string) is not None


def parse_did(did_string: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a DID string into components.

    Args:
        did_string: DID string to parse

    Returns:
        Tuple of (method, network, identifier) or None if invalid
    """
    match = DID_PATTERN.match(did_string)
    if match:
        return match.groups()  # type: ignore
    return None
