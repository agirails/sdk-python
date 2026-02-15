"""
IAdapter - Common interface (Protocol) for all payment adapters.

This protocol defines the contract that all payment adapters must implement,
enabling the AdapterRouter to select and use any adapter interchangeably.

CRITICAL ACTP COMPLIANCE:
- pay() creates transaction + locks escrow -> state = COMMITTED
- Caller must transition to IN_PROGRESS before work
- Caller must transition to DELIVERED with proof after work
- Caller must call release() to settle (NO auto-settle)

@module adapters/i_adapter
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from agirails.adapters.types import AdapterMetadata, UnifiedPayParams


@runtime_checkable
class IAdapter(Protocol):
    """
    Common interface for all payment adapters.

    Implementations include:
    - BasicAdapter: High-level, opinionated API
    - StandardAdapter: Balanced control API
    - X402Adapter: HTTP 402 Payment Required protocol
    - ERC8004Adapter: Identity-based payments

    Example::

        class CustomAdapter:
            metadata = AdapterMetadata(
                id='custom',
                priority=50,
                uses_escrow=True,
                supports_disputes=True,
                release_required=True,
            )

            def can_handle(self, params: UnifiedPayParams) -> bool:
                return True

            def validate(self, params: UnifiedPayParams) -> None:
                pass

            async def pay(self, params: UnifiedPayParams) -> Any:
                ...
    """

    @property
    def metadata(self) -> AdapterMetadata:
        """Adapter metadata describing capabilities."""
        ...

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """
        Check if this adapter can handle the given parameters.

        Used by AdapterRouter to filter adapters that are capable
        of processing a specific payment request.

        Args:
            params: Payment parameters to check.

        Returns:
            True if adapter can handle these params.
        """
        ...

    def validate(self, params: UnifiedPayParams) -> None:
        """
        Validate parameters before execution.

        Called by AdapterRouter before routing to ensure
        parameters are valid for this specific adapter.

        Args:
            params: Parameters to validate.

        Raises:
            ValidationError: If params are invalid.
        """
        ...

    async def pay(self, params: UnifiedPayParams) -> Any:
        """
        Execute payment through this adapter.

        IMPORTANT: Returns with state=COMMITTED, NOT settled.
        Caller must follow ACTP lifecycle.

        Args:
            params: Unified payment parameters.

        Returns:
            Payment result (adapter-specific).

        Raises:
            ValidationError: If params are invalid.
        """
        ...
