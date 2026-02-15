"""
AdapterRouter - Intelligent adapter selection with guard-rails.

The router selects the best adapter for each payment based on:
- Explicit adapter preference
- Required capabilities (escrow, disputes, identity)
- Recipient type (address vs HTTP endpoint vs agent ID)
- Adapter priority

SECURITY: All parameters are validated before selection.
SECURITY: All adapters must enforce explicit release (no auto-settle).

1:1 port of TypeScript SDK AdapterRouter.ts.

@module adapters/AdapterRouter
"""

from __future__ import annotations

from typing import Any, List, Optional, Protocol
from urllib.parse import urlparse

from agirails.adapters.adapter_registry import AdapterRegistry
from agirails.adapters.i_adapter import IAdapter
from agirails.adapters.types import AdapterSelectionResult, UnifiedPayParams
from agirails.errors import ValidationError


# ============================================================================
# ERC-8004 Bridge Protocol (for dependency injection)
# ============================================================================


class ERC8004BridgeLike(Protocol):
    """Protocol for ERC-8004 bridge implementations."""

    async def get_agent_wallet(self, agent_id: str) -> str:
        """Resolve an agent ID to a wallet address."""
        ...


# ============================================================================
# Constants
# ============================================================================

MAX_DESCRIPTION_LENGTH = 1000
MAX_UINT256 = 2**256


# ============================================================================
# AdapterRouter
# ============================================================================


class AdapterRouter:
    """
    AdapterRouter - Intelligent adapter selection with guard-rails.

    Selection logic (in order):
    1. Validate params (throws if invalid)
    2. Explicit adapter requested -> use it
    3. Escrow/dispute required -> find compatible adapter (strict)
    4. HTTP endpoint -> X402Adapter (when available)
    5. ERC-8004 identity -> ERC8004Adapter (when available)
    6. First adapter by priority that canHandle
    7. Fallback to 'basic'
    8. Raise if nothing found

    Example::

        registry = AdapterRegistry()
        registry.register(basic_adapter)
        registry.register(standard_adapter)

        router = AdapterRouter(registry)

        # Auto-select best adapter
        adapter = router.select(UnifiedPayParams(to='0x...', amount='100'))

        # Explicit adapter request
        adapter = router.select(UnifiedPayParams(
            to='0x...',
            amount='100',
            metadata={'preferred_adapter': 'standard'}
        ))
    """

    def __init__(
        self,
        registry: AdapterRegistry,
        erc8004_bridge: Optional[ERC8004BridgeLike] = None,
    ) -> None:
        """
        Creates a new AdapterRouter instance.

        Args:
            registry: AdapterRegistry containing available adapters.
            erc8004_bridge: Optional ERC-8004 bridge for agent ID resolution.
        """
        self._registry = registry
        self._erc8004_bridge = erc8004_bridge

    def set_erc8004_bridge(self, bridge: ERC8004BridgeLike) -> None:
        """
        Set the ERC-8004 bridge for agent ID resolution.

        Args:
            bridge: ERC8004Bridge instance.
        """
        self._erc8004_bridge = bridge

    def select(self, params: UnifiedPayParams) -> IAdapter:
        """
        Select the best adapter for the given payment parameters.

        Args:
            params: Unified payment parameters.

        Returns:
            The selected adapter.

        Raises:
            ValidationError: If params are invalid.
            RuntimeError: If no suitable adapter found.
        """
        # GUARD-RAIL: Validate all params first
        self._validate_params(params)

        metadata = params.metadata or {}

        # 1. Explicit adapter requested
        preferred = metadata.get("preferred_adapter") if isinstance(metadata, dict) else None
        if preferred:
            adapter = self._registry.get(preferred)
            if not adapter:
                available = ", ".join(self._registry.get_ids()) or "none"
                raise RuntimeError(
                    f"Preferred adapter '{preferred}' not found. "
                    f"Available adapters: {available}"
                )
            # Verify adapter can handle these params
            adapter.validate(params)
            return adapter

        # 2. Escrow/dispute required -> STRICT enforcement
        requires_escrow = (
            metadata.get("requires_escrow") if isinstance(metadata, dict) else None
        )
        requires_dispute = (
            metadata.get("requires_dispute") if isinstance(metadata, dict) else None
        )

        if requires_escrow or requires_dispute:
            # First try standard adapter
            standard = self._registry.get("standard")
            if standard and standard.can_handle(params):
                return standard

            # Find any adapter that meets the capability requirements
            compatible = [
                adapter
                for adapter in self._registry.get_by_priority()
                if (not requires_escrow or adapter.metadata.uses_escrow)
                and (not requires_dispute or adapter.metadata.supports_disputes)
                and adapter.can_handle(params)
            ]

            if compatible:
                return compatible[0]

            # STRICT: No compatible adapter found - raise instead of falling through
            requirements = []
            if requires_escrow:
                requirements.append("escrow")
            if requires_dispute:
                requirements.append("dispute resolution")
            available = ", ".join(self._registry.get_ids()) or "none"
            raise RuntimeError(
                f"No adapter found that supports required capabilities: "
                f"{', '.join(requirements)}. Available adapters: {available}"
            )

        # 3. HTTP endpoint -> x402 (when registered)
        if self.is_http_endpoint(params.to):
            x402 = self._registry.get("x402")
            if x402 and x402.can_handle(params):
                return x402
            raise RuntimeError(
                f"HTTP endpoint '{params.to}' requires X402Adapter, "
                "but it is not registered. Configure X402Adapter with a wallet "
                "provider first (e.g. client.register_adapter(x402_adapter))."
            )

        # 4. ERC-8004 identity -> erc8004 (when registered)
        identity = metadata.get("identity") if isinstance(metadata, dict) else None
        if identity and hasattr(identity, "type") and identity.type == "erc8004":
            erc8004 = self._registry.get("erc8004")
            if erc8004 and erc8004.can_handle(params):
                return erc8004

        # 5. Find first adapter that can handle it (by priority)
        for adapter in self._registry.get_by_priority():
            if adapter.can_handle(params):
                return adapter

        # 6. Default to basic as last resort
        basic = self._registry.get("basic")
        if basic:
            return basic

        available = ", ".join(self._registry.get_ids()) or "none"
        raise RuntimeError(
            f"No suitable adapter found for params. "
            f"Available adapters: {available}"
        )

    def _validate_params(self, params: UnifiedPayParams) -> None:
        """
        Validate payment parameters.

        GUARD-RAIL: Performs strict validation before any adapter selection.

        Args:
            params: Parameters to validate.

        Raises:
            ValidationError: If params are invalid.
        """
        # Basic required fields
        if not params.to:
            raise ValidationError("Invalid payment params: to is required")

        if params.amount is None:
            raise ValidationError("Invalid payment params: amount is required")

        # Security checks on 'to' field
        if isinstance(params.to, str):
            # Check for path traversal attempts
            if ".." in params.to:
                raise ValidationError(
                    "Invalid recipient: path traversal characters not allowed"
                )

            # Check for script injection attempts
            if "<" in params.to or ">" in params.to:
                raise ValidationError(
                    "Invalid recipient: HTML/script characters not allowed"
                )

            # Check for null bytes
            if "\0" in params.to:
                raise ValidationError("Invalid recipient: null bytes not allowed")

        # Validate description if provided
        if params.description and len(params.description) > MAX_DESCRIPTION_LENGTH:
            raise ValidationError(
                f"Description too long: maximum {MAX_DESCRIPTION_LENGTH} characters"
            )

    @staticmethod
    def is_http_endpoint(to: str) -> bool:
        """
        Check if a string is an HTTP/HTTPS endpoint.

        Args:
            to: Recipient string to check.

        Returns:
            True if it's an HTTP endpoint.
        """
        try:
            parsed = urlparse(to)
            return parsed.scheme in ("http", "https")
        except Exception:
            return False

    @staticmethod
    def is_erc8004_agent_id(to: str) -> bool:
        """
        Check if a string looks like an ERC-8004 agent ID.

        Agent IDs are numeric strings (uint256) that are:
        - NOT Ethereum addresses (0x-prefixed)
        - NOT URLs (http/https)
        - Valid as int in range [0, 2^256)

        Args:
            to: Recipient string to check.

        Returns:
            True if it looks like an agent ID.
        """
        if not to or not isinstance(to, str):
            return False

        # Not an Ethereum address
        if to.startswith("0x"):
            return False

        # Not a URL
        if "://" in to or to.startswith("http"):
            return False

        # Must be a valid uint256
        try:
            val = int(to)
            return 0 <= val < MAX_UINT256
        except (ValueError, TypeError):
            return False

    def get_compatible_adapters(self, params: UnifiedPayParams) -> List[IAdapter]:
        """
        Get all adapters that can handle the given params.

        Useful for debugging or letting users choose from multiple options.

        Args:
            params: Payment parameters.

        Returns:
            List of adapters that can handle params.
        """
        self._validate_params(params)
        result = []
        for adapter in self._registry.get_all():
            try:
                if adapter.can_handle(params):
                    result.append(adapter)
            except Exception:
                pass
        return result

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """
        Check if any adapter can handle the given params.

        Args:
            params: Payment parameters.

        Returns:
            True if at least one adapter can handle.
        """
        try:
            self._validate_params(params)
            return len(self.get_compatible_adapters(params)) > 0
        except Exception:
            return False

    # ======================================================================
    # ERC-8004 Agent ID Resolution
    # ======================================================================

    async def select_and_resolve(
        self, params: UnifiedPayParams
    ) -> AdapterSelectionResult:
        """
        Select adapter AND resolve ERC-8004 agent IDs.

        This is the recommended method for payment flows. It:
        1. Checks if ``to`` is an ERC-8004 agent ID (numeric string)
        2. If so, resolves it to a wallet address via ERC8004Bridge
        3. Stores the original agentId in erc8004_agent_id field
        4. Selects the appropriate adapter

        Args:
            params: Unified payment parameters.

        Returns:
            Selection result with resolved params.

        Raises:
            ValidationError: If params invalid or agent not found.

        Example::

            result = await router.select_and_resolve(
                UnifiedPayParams(to='12345', amount='100')
            )
            # result.resolved_params.to is now the wallet address
            # result.resolved_params.erc8004_agent_id is '12345'
        """
        # Check if 'to' is an ERC-8004 agent ID
        if self.is_erc8004_agent_id(params.to):
            if not self._erc8004_bridge:
                raise ValidationError(
                    f"Cannot resolve ERC-8004 agent ID '{params.to}': "
                    "ERC-8004 resolution requires testnet or mainnet mode. "
                    "Use a wallet address (0x...) in mock mode, or switch to "
                    "testnet/mainnet."
                )

            try:
                # Resolve agent ID to wallet address
                wallet = await self._erc8004_bridge.get_agent_wallet(params.to)

                # Create resolved params with wallet and stored agentId
                resolved_params = UnifiedPayParams(
                    to=wallet,
                    amount=params.amount,
                    deadline=params.deadline,
                    description=params.description,
                    service_hash=params.service_hash,
                    metadata=params.metadata,
                    erc8004_agent_id=params.to,
                )

                # Select adapter for resolved params
                adapter = self.select(resolved_params)

                return AdapterSelectionResult(
                    adapter=adapter,
                    resolved_params=resolved_params,
                    was_agent_id_resolved=True,
                )
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(
                    f"Failed to resolve ERC-8004 agent '{params.to}': {e}"
                )

        # Not an agent ID - proceed normally
        adapter = self.select(params)
        return AdapterSelectionResult(
            adapter=adapter,
            resolved_params=params,
            was_agent_id_resolved=False,
        )
