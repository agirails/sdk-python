"""
AGIRAILS SDK Client.

The main entry point for the AGIRAILS SDK. ACTPClient provides a factory pattern
for creating clients with different modes (mock, testnet, mainnet) and unified
access to all ACTP functionality through adapters.

Usage:
    >>> from agirails import ACTPClient
    >>>
    >>> # Mock mode for testing
    >>> client = await ACTPClient.create(
    ...     mode="mock",
    ...     requester_address="0x1234..."
    ... )
    >>>
    >>> # Use the basic API
    >>> result = await client.basic.pay({"to": "0x...", "amount": 100})
    >>>
    >>> # Or the standard API
    >>> tx_id = await client.standard.create_transaction(...)
    >>>
    >>> # Or direct runtime access (advanced)
    >>> await client.runtime.transition_state(tx_id, "DELIVERED")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Literal, Optional, Union

from agirails.adapters.basic import BasicAdapter
from agirails.adapters.standard import StandardAdapter
from agirails.errors import ValidationError
from agirails.utils.helpers import Address

if TYPE_CHECKING:
    from agirails.runtime.base import IACTPRuntime


ACTPClientMode = Literal["mock", "testnet", "mainnet"]


@dataclass
class ACTPClientInfo:
    """
    Client information.

    Contains read-only information about the client configuration.
    """

    mode: ACTPClientMode
    address: str
    state_directory: Optional[Path] = None


@dataclass
class ACTPClientConfig:
    """
    Configuration for ACTPClient.create().

    Args:
        mode: Client mode ("mock", "testnet", "mainnet")
        requester_address: Requester's Ethereum address
        state_directory: Directory for mock state (mock mode only)
        private_key: Private key for signing (testnet/mainnet)
        rpc_url: RPC URL for blockchain (testnet/mainnet)
        contracts: Contract addresses override
        gas_settings: Gas configuration override
        eas_config: EAS configuration
        require_attestation: Require attestation for releases
        runtime: Custom runtime instance (overrides mode)
    """

    mode: ACTPClientMode = "mock"
    requester_address: str = ""
    state_directory: Optional[Path] = None
    private_key: Optional[str] = None
    rpc_url: Optional[str] = None
    contracts: Optional[Dict[str, str]] = None
    gas_settings: Optional[Dict[str, Any]] = None
    eas_config: Optional[Dict[str, Any]] = None
    require_attestation: bool = False
    runtime: Optional[IACTPRuntime] = None


class ACTPClient:
    """
    Main client for AGIRAILS SDK.

    Provides unified access to ACTP functionality through:
    - basic: Simple pay() API
    - standard: Full lifecycle control
    - advanced: Direct runtime access
    - runtime: Raw runtime interface

    Use the async create() factory method to instantiate.
    """

    def __init__(
        self,
        runtime: IACTPRuntime,
        requester_address: str,
        info: ACTPClientInfo,
        eas_helper: Optional[object] = None,
    ) -> None:
        """
        Initialize ACTPClient.

        Do not call directly - use ACTPClient.create() instead.

        Args:
            runtime: ACTP runtime instance
            requester_address: Requester's address
            info: Client information
            eas_helper: Optional EAS helper
        """
        self._runtime = runtime
        self._requester_address = requester_address.lower()
        self._info = info
        self._eas_helper = eas_helper

        # Initialize adapters
        self._basic = BasicAdapter(runtime, requester_address, eas_helper)
        self._standard = StandardAdapter(runtime, requester_address, eas_helper)

    @classmethod
    async def create(
        cls,
        mode: Optional[ACTPClientMode] = None,
        requester_address: Optional[str] = None,
        state_directory: Optional[Union[Path, str]] = None,
        private_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        config: Optional[ACTPClientConfig] = None,
        **kwargs: Any,
    ) -> "ACTPClient":
        """
        Create an ACTPClient instance.

        Factory method that initializes the appropriate runtime based on mode.

        Args:
            mode: Client mode ("mock", "testnet", "mainnet")
            requester_address: Requester's Ethereum address
            state_directory: Directory for mock state (Path or string)
            private_key: Private key for signing (testnet/mainnet)
            rpc_url: RPC URL for blockchain (testnet/mainnet)
            config: Full configuration object (alternative to individual args)
            **kwargs: Additional configuration passed to config

        Returns:
            Configured ACTPClient instance

        Raises:
            ValidationError: If configuration is invalid

        Examples:
            >>> # Mock mode (for testing)
            >>> client = await ACTPClient.create(
            ...     mode="mock",
            ...     requester_address="0x1234..."
            ... )
            >>>
            >>> # With custom state directory
            >>> client = await ACTPClient.create(
            ...     mode="mock",
            ...     requester_address="0x1234...",
            ...     state_directory="./my-state"
            ... )
            >>>
            >>> # Using config object
            >>> config = ACTPClientConfig(
            ...     mode="mock",
            ...     requester_address="0x1234..."
            ... )
            >>> client = await ACTPClient.create(config=config)
        """
        # Build config from arguments
        if config is None:
            config = ACTPClientConfig(
                mode=mode or "mock",
                requester_address=requester_address or "",
                state_directory=Path(state_directory) if state_directory else None,
                private_key=private_key,
                rpc_url=rpc_url,
                **kwargs,
            )

        # Validate requester address
        if not config.requester_address:
            raise ValidationError(
                message="requester_address is required",
                details={"field": "requester_address"},
            )

        if not Address.is_valid(config.requester_address):
            raise ValidationError(
                message="Invalid requester_address: must be 0x followed by 40 hex characters",
                details={"field": "requester_address", "value": config.requester_address},
            )

        # Normalize address
        requester = Address.normalize(config.requester_address)

        # Create runtime based on mode
        runtime: IACTPRuntime
        eas_helper = None

        if config.runtime is not None:
            # Use provided runtime
            runtime = config.runtime
            # Check if runtime has eas_helper
            if hasattr(config.runtime, "eas_helper"):
                eas_helper = config.runtime.eas_helper
        elif config.mode == "mock":
            runtime = await cls._create_mock_runtime(config)
        elif config.mode in ("testnet", "mainnet"):
            runtime, eas_helper = await cls._create_blockchain_runtime(config)
        else:
            raise ValidationError(
                message=f"Invalid mode: {config.mode}",
                details={"field": "mode", "value": config.mode, "allowed": ["mock", "testnet", "mainnet"]},
            )

        # Create info
        info = ACTPClientInfo(
            mode=config.mode,
            address=requester,
            state_directory=config.state_directory,
        )

        return cls(runtime, requester, info, eas_helper)

    @classmethod
    async def _create_mock_runtime(cls, config: ACTPClientConfig) -> IACTPRuntime:
        """Create mock runtime."""
        from agirails.runtime.mock_runtime import MockRuntime
        from agirails.runtime.mock_state_manager import MockStateManager

        # Determine state directory
        if config.state_directory:
            state_dir = config.state_directory
        else:
            state_dir = Path.cwd() / ".actp"

        state_manager = MockStateManager(state_directory=state_dir)
        runtime = MockRuntime(state_manager=state_manager)

        # Initialize with requester balance if mock
        await runtime.mint_tokens(config.requester_address, "1000000000000")  # $1M USDC

        return runtime

    @classmethod
    async def _create_blockchain_runtime(
        cls, config: ACTPClientConfig
    ) -> tuple["IACTPRuntime", Optional[object]]:
        """
        Create blockchain runtime for testnet/mainnet.

        Returns:
            Tuple of (runtime, eas_helper)
        """
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        # Validate private key
        if not config.private_key:
            raise ValidationError(
                message="private_key is required for testnet/mainnet mode",
                details={"field": "private_key", "mode": config.mode},
            )

        # Map mode to network name
        network_name = "base-sepolia" if config.mode == "testnet" else "base"

        # Create EAS helper if config provided or attestation required
        eas_helper = None
        if config.eas_config or config.require_attestation:
            try:
                from agirails.protocol.eas import EASHelper
                from agirails.utils.used_attestation_tracker import (
                    create_used_attestation_tracker,
                )

                # Create attestation tracker (persistent if state_directory provided)
                tracker = create_used_attestation_tracker(
                    str(config.state_directory) if config.state_directory else None
                )

                eas_helper = await EASHelper.create(
                    private_key=config.private_key,
                    network=network_name,
                    rpc_url=config.rpc_url,
                    attestation_tracker=tracker,
                )
            except ImportError:
                # web3 not installed - skip EAS
                pass

        # Create blockchain runtime with EAS helper
        runtime = await BlockchainRuntime.create(
            private_key=config.private_key,
            network=network_name,
            rpc_url=config.rpc_url,
            eas_helper=eas_helper,
        )

        return runtime, eas_helper

    @property
    def basic(self) -> BasicAdapter:
        """
        Get basic adapter for simple transactions.

        Example:
            >>> result = await client.basic.pay({
            ...     "to": "0x...",
            ...     "amount": 100
            ... })
        """
        return self._basic

    @property
    def standard(self) -> StandardAdapter:
        """
        Get standard adapter for full lifecycle control.

        Example:
            >>> tx_id = await client.standard.create_transaction(...)
            >>> escrow_id = await client.standard.link_escrow(tx_id)
        """
        return self._standard

    @property
    def advanced(self) -> IACTPRuntime:
        """
        Get advanced (raw runtime) access.

        Alias for runtime property. Use for direct runtime operations.
        """
        return self._runtime

    @property
    def runtime(self) -> IACTPRuntime:
        """
        Get underlying runtime.

        Provides direct access to all runtime operations.
        """
        return self._runtime

    @property
    def info(self) -> ACTPClientInfo:
        """Get client information."""
        return self._info

    def get_address(self) -> str:
        """
        Get requester address.

        Returns:
            Normalized requester address
        """
        return self._requester_address

    @property
    def address(self) -> str:
        """
        Alias for requester_address (for Provider compatibility).

        Returns:
            Normalized requester address
        """
        return self._requester_address

    def get_mode(self) -> ACTPClientMode:
        """
        Get client mode.

        Returns:
            Current mode ("mock", "testnet", "mainnet")
        """
        return self._info.mode

    async def reset(self) -> None:
        """
        Reset all state (mock mode only).

        Clears all transactions, escrows, and balances.

        Raises:
            RuntimeError: If not in mock mode
        """
        if self._info.mode != "mock":
            raise RuntimeError("reset() is only available in mock mode")

        await self._runtime.reset()
        # Re-mint initial balance
        await self._runtime.mint_tokens(self._requester_address, "1000000000000")

    async def mint_tokens(self, address: str, amount: Union[str, int, float]) -> None:
        """
        Mint tokens to an address (mock mode only).

        Args:
            address: Address to mint to
            amount: Amount in USDC

        Raises:
            RuntimeError: If not in mock mode
        """
        if self._info.mode != "mock":
            raise RuntimeError("mint_tokens() is only available in mock mode")

        # Validate address
        if not Address.is_valid(address):
            raise ValidationError(
                message="Invalid address",
                details={"field": "address", "value": address},
            )

        # Parse amount
        from agirails.utils.helpers import USDC
        amount_wei = str(USDC.to_wei(amount))

        await self._runtime.mint_tokens(Address.normalize(address), amount_wei)

    async def get_balance(self, address: Optional[str] = None) -> str:
        """
        Get USDC balance.

        Args:
            address: Address to check (default: requester)

        Returns:
            Balance in USDC (formatted string like "100.00")
        """
        if address is None:
            address = self._requester_address
        else:
            address = Address.normalize(address)

        balance_wei = await self._runtime.get_balance(address)

        from agirails.utils.helpers import USDC
        return USDC.from_wei(balance_wei)

    def __repr__(self) -> str:
        """
        Safe string representation (no private keys).
        """
        return (
            f"ACTPClient("
            f"mode={self._info.mode!r}, "
            f"address={Address.truncate(self._requester_address)})"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        return self.__repr__()
