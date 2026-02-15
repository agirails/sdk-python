"""
AdapterRegistry - Central registry for payment adapters.

Manages the collection of available adapters and provides
methods for registration, lookup, and priority-based retrieval.

1:1 port of TypeScript SDK AdapterRegistry.ts.

@module adapters/AdapterRegistry
"""

from __future__ import annotations

from typing import Dict, List, Optional

from agirails.adapters.i_adapter import IAdapter


class AdapterRegistry:
    """
    AdapterRegistry - Central registry for managing available adapters.

    The registry maintains a collection of adapters indexed by their ID.
    It provides methods for:
    - Registration and unregistration
    - Lookup by ID
    - Priority-sorted retrieval

    Example::

        registry = AdapterRegistry()

        # Register adapters
        registry.register(basic_adapter)
        registry.register(standard_adapter)

        # Lookup by ID
        adapter = registry.get('basic')

        # Get all adapters sorted by priority
        adapters = registry.get_by_priority()
    """

    def __init__(self) -> None:
        """Initialize an empty adapter registry."""
        self._adapters: Dict[str, IAdapter] = {}

    def register(self, adapter: IAdapter) -> None:
        """
        Register an adapter.

        If an adapter with the same ID already exists, it will be replaced.

        Args:
            adapter: Adapter to register.

        Raises:
            ValueError: If adapter has no metadata.id.
        """
        if not hasattr(adapter, "metadata") or not adapter.metadata or not adapter.metadata.id:
            raise ValueError("Cannot register adapter without metadata.id")
        self._adapters[adapter.metadata.id] = adapter

    def unregister(self, adapter_id: str) -> bool:
        """
        Unregister an adapter by ID.

        Args:
            adapter_id: Adapter ID to remove.

        Returns:
            True if adapter was found and removed, False otherwise.
        """
        if adapter_id in self._adapters:
            del self._adapters[adapter_id]
            return True
        return False

    def get(self, adapter_id: str) -> Optional[IAdapter]:
        """
        Get an adapter by ID.

        Args:
            adapter_id: Adapter ID to look up.

        Returns:
            The adapter or None if not found.
        """
        return self._adapters.get(adapter_id)

    def get_all(self) -> List[IAdapter]:
        """
        Get all registered adapters.

        Returns adapters in insertion order.

        Returns:
            List of all registered adapters.
        """
        return list(self._adapters.values())

    def has(self, adapter_id: str) -> bool:
        """
        Check if an adapter is registered.

        Args:
            adapter_id: Adapter ID to check.

        Returns:
            True if adapter is registered.
        """
        return adapter_id in self._adapters

    def get_by_priority(self) -> List[IAdapter]:
        """
        Get adapters sorted by priority (highest first).

        Higher priority adapters are tried first during selection.

        Returns:
            List of adapters sorted by priority descending.
        """
        return sorted(self.get_all(), key=lambda a: a.metadata.priority, reverse=True)

    @property
    def size(self) -> int:
        """
        Get the number of registered adapters.

        Returns:
            Number of adapters.
        """
        return len(self._adapters)

    def get_ids(self) -> List[str]:
        """
        Get all adapter IDs.

        Returns:
            List of adapter IDs.
        """
        return list(self._adapters.keys())

    def clear(self) -> None:
        """
        Clear all registered adapters.

        Primarily useful for testing.
        """
        self._adapters.clear()
