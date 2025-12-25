"""
Service directory for AGIRAILS Level 0 API.

Provides:
- ServiceDirectory: Registry for service discovery
- ServiceEntry: Metadata about a registered service
- ServiceQuery: Query parameters for finding services

The ServiceDirectory acts as a local registry for services that
providers offer. It supports registration, deregistration, and
discovery of services by name or capabilities.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterator, List, Optional, Dict


@dataclass
class ServiceEntry:
    """
    Metadata about a registered service.

    Attributes:
        name: Unique service identifier
        description: Human-readable description
        capabilities: List of capability tags (e.g., ["gpt-4", "streaming"])
        schema: Optional JSON schema for input validation
        provider_address: Ethereum address of the provider
        registered_at: When the service was registered
        metadata: Additional metadata dictionary
    """

    name: str
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    schema: Optional[Dict[str, Any]] = None
    provider_address: Optional[str] = None
    registered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        """Check if service has a specific capability."""
        return capability.lower() in [c.lower() for c in self.capabilities]

    def has_all_capabilities(self, capabilities: List[str]) -> bool:
        """Check if service has all specified capabilities."""
        return all(self.has_capability(c) for c in capabilities)

    def has_any_capability(self, capabilities: List[str]) -> bool:
        """Check if service has any of the specified capabilities."""
        return any(self.has_capability(c) for c in capabilities)


@dataclass
class ServiceQuery:
    """
    Query parameters for finding services.

    Attributes:
        name: Exact service name match
        name_pattern: Pattern to match service names (supports * wildcard)
        capabilities: Required capabilities (all must match)
        any_capabilities: At least one of these capabilities must match
        provider_address: Filter by provider address
        custom: Custom filter function
    """

    name: Optional[str] = None
    name_pattern: Optional[str] = None
    capabilities: Optional[List[str]] = None
    any_capabilities: Optional[List[str]] = None
    provider_address: Optional[str] = None
    custom: Optional[Callable[[ServiceEntry], bool]] = None

    def matches(self, entry: ServiceEntry) -> bool:
        """
        Check if a service entry matches this query.

        Args:
            entry: Service entry to check

        Returns:
            True if entry matches all query criteria
        """
        # Check exact name match
        if self.name is not None and entry.name != self.name:
            return False

        # Check name pattern (supports * wildcard)
        if self.name_pattern is not None:
            if not self._match_pattern(entry.name, self.name_pattern):
                return False

        # Check required capabilities (all must match)
        if self.capabilities is not None:
            if not entry.has_all_capabilities(self.capabilities):
                return False

        # Check any capabilities (at least one must match)
        if self.any_capabilities is not None:
            if not entry.has_any_capability(self.any_capabilities):
                return False

        # Check provider address
        if self.provider_address is not None:
            if entry.provider_address != self.provider_address:
                return False

        # Check custom filter
        if self.custom is not None:
            if not self.custom(entry):
                return False

        return True

    def _match_pattern(self, name: str, pattern: str) -> bool:
        """
        Match name against pattern with wildcard support.

        Supports:
        - * matches any number of characters
        - ? matches single character

        Args:
            name: Service name to check
            pattern: Pattern with optional wildcards

        Returns:
            True if name matches pattern
        """
        import fnmatch

        return fnmatch.fnmatch(name.lower(), pattern.lower())


class ServiceDirectory:
    """
    Registry for service discovery.

    Thread-safe registry that stores service metadata and supports
    discovery by name, capabilities, or custom queries.

    Example:
        >>> directory = ServiceDirectory()
        >>> directory.register(
        ...     "text-generation",
        ...     description="Generate text using GPT-4",
        ...     capabilities=["gpt-4", "streaming"]
        ... )
        >>> entry = directory.get("text-generation")
        >>> services = directory.find(ServiceQuery(capabilities=["gpt-4"]))
    """

    def __init__(self) -> None:
        """Initialize empty service directory."""
        self._services: Dict[str, ServiceEntry] = {}
        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        description: str = "",
        capabilities: Optional[List[str]] = None,
        schema: Optional[Dict[str, Any]] = None,
        provider_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ServiceEntry:
        """
        Register a service in the directory.

        Args:
            name: Unique service identifier
            description: Human-readable description
            capabilities: List of capability tags
            schema: Optional JSON schema for input validation
            provider_address: Ethereum address of the provider
            metadata: Additional metadata dictionary

        Returns:
            The created ServiceEntry

        Raises:
            ValueError: If service name is empty or already registered
        """
        if not name:
            raise ValueError("Service name cannot be empty")

        with self._lock:
            if name in self._services:
                raise ValueError(f"Service '{name}' is already registered")

            entry = ServiceEntry(
                name=name,
                description=description,
                capabilities=capabilities or [],
                schema=schema,
                provider_address=provider_address,
                metadata=metadata or {},
            )
            self._services[name] = entry
            return entry

    def unregister(self, name: str) -> bool:
        """
        Remove a service from the directory.

        Args:
            name: Service identifier to remove

        Returns:
            True if service was removed, False if not found
        """
        with self._lock:
            if name in self._services:
                del self._services[name]
                return True
            return False

    def get(self, name: str) -> Optional[ServiceEntry]:
        """
        Get a service by exact name.

        Args:
            name: Service identifier

        Returns:
            ServiceEntry if found, None otherwise
        """
        with self._lock:
            return self._services.get(name)

    def has(self, name: str) -> bool:
        """
        Check if a service is registered.

        Args:
            name: Service identifier

        Returns:
            True if service exists
        """
        with self._lock:
            return name in self._services

    def find(self, query: ServiceQuery) -> List[ServiceEntry]:
        """
        Find services matching a query.

        Args:
            query: Query parameters

        Returns:
            List of matching ServiceEntry objects
        """
        with self._lock:
            return [
                entry for entry in self._services.values() if query.matches(entry)
            ]

    def find_by_capability(self, capability: str) -> List[ServiceEntry]:
        """
        Find services with a specific capability.

        Args:
            capability: Capability tag to search for

        Returns:
            List of matching ServiceEntry objects
        """
        return self.find(ServiceQuery(capabilities=[capability]))

    def find_by_pattern(self, pattern: str) -> List[ServiceEntry]:
        """
        Find services matching a name pattern.

        Args:
            pattern: Name pattern with wildcards (* or ?)

        Returns:
            List of matching ServiceEntry objects
        """
        return self.find(ServiceQuery(name_pattern=pattern))

    def list_all(self) -> List[ServiceEntry]:
        """
        Get all registered services.

        Returns:
            List of all ServiceEntry objects
        """
        with self._lock:
            return list(self._services.values())

    def list_names(self) -> List[str]:
        """
        Get all registered service names.

        Returns:
            List of service names
        """
        with self._lock:
            return list(self._services.keys())

    def count(self) -> int:
        """
        Get the number of registered services.

        Returns:
            Number of services
        """
        with self._lock:
            return len(self._services)

    def clear(self) -> None:
        """Remove all services from the directory."""
        with self._lock:
            self._services.clear()

    def update(
        self,
        name: str,
        description: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        schema: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[ServiceEntry]:
        """
        Update an existing service entry.

        Args:
            name: Service identifier to update
            description: New description (if provided)
            capabilities: New capabilities list (if provided)
            schema: New schema (if provided)
            metadata: Metadata to merge (if provided)

        Returns:
            Updated ServiceEntry if found, None otherwise
        """
        with self._lock:
            entry = self._services.get(name)
            if entry is None:
                return None

            if description is not None:
                entry.description = description
            if capabilities is not None:
                entry.capabilities = capabilities
            if schema is not None:
                entry.schema = schema
            if metadata is not None:
                entry.metadata.update(metadata)

            return entry

    def __contains__(self, name: str) -> bool:
        """Support 'in' operator."""
        return self.has(name)

    def __len__(self) -> int:
        """Support len() function."""
        return self.count()

    def __iter__(self) -> Iterator[ServiceEntry]:
        """Support iteration over services."""
        with self._lock:
            return iter(list(self._services.values()))

    def __repr__(self) -> str:
        """String representation."""
        return f"ServiceDirectory({self.count()} services)"


# Global service directory instance
_global_directory: Optional[ServiceDirectory] = None
_global_lock = threading.Lock()


def get_global_directory() -> ServiceDirectory:
    """
    Get the global service directory instance.

    Creates a new instance on first call (singleton pattern).

    Returns:
        Global ServiceDirectory instance
    """
    global _global_directory
    if _global_directory is None:
        with _global_lock:
            if _global_directory is None:
                _global_directory = ServiceDirectory()
    return _global_directory


def reset_global_directory() -> None:
    """
    Reset the global service directory.

    Clears all registered services. Mainly useful for testing.
    """
    global _global_directory
    with _global_lock:
        if _global_directory is not None:
            _global_directory.clear()
        _global_directory = None
