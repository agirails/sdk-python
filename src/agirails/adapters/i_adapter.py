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

from typing import Any, Optional, Protocol, runtime_checkable

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

    async def get_status(self, tx_id: str) -> Any:
        """
        Get transaction status by ID, with action hints.

        Mirrors TS ``IAdapter.getStatus`` (IAdapter.ts:208). Returns a
        ``TransactionStatus`` (current state plus what can be done next).

        Args:
            tx_id: Transaction ID.

        Returns:
            Transaction status with action hints.

        Raises:
            Exception: If the transaction is not found.
        """
        ...

    async def start_work(self, tx_id: str) -> None:
        """
        Transition to IN_PROGRESS (provider starts work).

        Mirrors TS ``IAdapter.startWork`` (IAdapter.ts:225). ACTP requires this
        explicit transition before delivery.

        Args:
            tx_id: Transaction ID.
        """
        ...

    async def deliver(self, tx_id: str, proof: Optional[str] = None) -> None:
        """
        Transition to DELIVERED (provider completes work).

        Mirrors TS ``IAdapter.deliver`` (IAdapter.ts:241). When no proof is
        supplied, adapters encode the transaction's dispute window as proof.

        Args:
            tx_id: Transaction ID.
            proof: Optional delivery proof (ABI-encoded dispute window).
        """
        ...

    async def release(
        self, escrow_id: str, attestation_uid: Optional[str] = None
    ) -> None:
        """
        Release escrow funds (EXPLICIT settlement).

        Mirrors TS ``IAdapter.release`` (IAdapter.ts:260). This is the ONLY way
        to settle — there is NO auto-settle.

        Args:
            escrow_id: Escrow ID (usually same as txId).
            attestation_uid: Optional attestation UID for verification.
        """
        ...
