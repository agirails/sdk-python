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

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Literal, Optional, Union

from agirails.adapters.adapter_registry import AdapterRegistry
from agirails.adapters.adapter_router import AdapterRouter
from agirails.adapters.basic import BasicAdapter
from agirails.adapters.standard import StandardAdapter
from agirails.adapters.types import UnifiedPayParams
from agirails.errors import ValidationError
from agirails.settle.settle_on_interact import SettleOnInteract
from agirails.utils.helpers import Address
from agirails.utils.logger import Logger

_logger = Logger("agirails.client")

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
    # AIP-12: Wallet mode (parity with TS SDK).
    # - "auto": construct AutoWalletProvider (Coinbase Smart Wallet + Paymaster,
    #   gasless flow). Requires CDP_API_KEY or PIMLICO_API_KEY env so the
    #   network config can resolve a bundler+paymaster URL pair. When "auto"
    #   is selected, requester_address is auto-derived from the Smart Wallet
    #   counterfactual address and does NOT need to be provided.
    # - "eoa": explicit EOA path from private_key. Caller still provides
    #   requester_address (matching the signer).
    # - None (default): preserves pre-3.0.0 behavior — caller wires its own
    #   wallet provider via the ACTPClient() wallet_provider kwarg, or relies
    #   on private_key for EOA signing without AA infra.
    wallet: Optional[str] = None  # Literal["auto", "eoa"] | None


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
        wallet_provider: Optional[object] = None,
        contract_addresses: Optional[object] = None,
    ) -> None:
        """
        Initialize ACTPClient.

        Do not call directly - use ACTPClient.create() instead.

        Args:
            runtime: ACTP runtime instance
            requester_address: Requester's address
            info: Client information
            eas_helper: Optional EAS helper
            wallet_provider: Optional wallet provider (AutoWalletProvider or
                EOAWalletProvider). When set together with
                ``contract_addresses`` and ``pay_actp_batched`` support,
                ``client.basic.pay()`` routes EVM-address payments through a
                single batched UserOp (approve + createTransaction +
                linkEscrow) so msg.sender == Smart Wallet == requester.
            contract_addresses: Optional :class:`ContractAddresses` (from
                ``agirails.wallet.aa.transaction_batcher``) holding ``usdc``,
                ``actp_kernel``, ``escrow_vault``. Required alongside
                ``wallet_provider`` to enable the batched ACTP payment path.
        """
        self._runtime = runtime
        self._requester_address = requester_address.lower()
        self._info = info
        self._eas_helper = eas_helper
        self._wallet_provider = wallet_provider
        self._contract_addresses = contract_addresses

        # Initialize adapters — wire wallet_provider + contract_addresses
        # into BasicAdapter so AIP-12 batched payments are used when
        # available, matching the TS createSmartWalletRouter pattern.
        self._basic = BasicAdapter(
            runtime,
            requester_address,
            eas_helper,
            wallet_provider=wallet_provider,
            contract_addresses=contract_addresses,
        )
        self._standard = StandardAdapter(
            runtime,
            requester_address,
            eas_helper,
            wallet_provider=wallet_provider,
            contract_addresses=contract_addresses,
        )

        # Initialize registry and router
        self._registry = AdapterRegistry()
        self._registry.register(self._basic)
        self._registry.register(self._standard)
        self._router = AdapterRouter(self._registry)

        # Try to register optional adapters (x402, erc8004)
        self._try_register_optional_adapters()

        # Settle-on-interact: sweep expired DELIVERED transactions on each interaction.
        # requester_address is the local agent's address — it acts as provider in
        # start_work/deliver flows, so the sweep finds expired provider-side transactions.
        self._settle_on_interact = SettleOnInteract(runtime, requester_address)

    def _try_register_optional_adapters(self) -> None:
        """Auto-register optional components if dependencies are available.

        NOTE: X402Adapter auto-registration runs in ``ACTPClient.create()``
        (not here) because it needs the resolved network config. Callers
        constructing the client via ``__init__`` directly can still pass a
        wallet provider and call ``register_adapter()`` themselves, or use
        the ``_maybe_register_x402`` helper.

        ERC-8004 bridge IS auto-registered here (read-only, no wallet needed).
        """
        # ERC-8004 bridge for agent ID resolution (read-only)
        try:
            from agirails.erc8004.bridge import ERC8004Bridge

            bridge = ERC8004Bridge()
            self._router.set_erc8004_bridge(bridge)
        except (ImportError, Exception):
            pass

    def register_adapter(self, adapter: Any) -> None:
        """Register a custom adapter with the router.

        Args:
            adapter: Adapter implementing IAdapter protocol.
        """
        self._registry.register(adapter)

    @classmethod
    async def create(
        cls,
        mode: Optional[ACTPClientMode] = None,
        requester_address: Optional[str] = None,
        state_directory: Optional[Union[Path, str]] = None,
        private_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        wallet: Optional[str] = None,
        config: Optional[ACTPClientConfig] = None,
        **kwargs: Any,
    ) -> "ACTPClient":
        """
        Create an ACTPClient instance.

        Factory method that initializes the appropriate runtime based on mode.

        Args:
            mode: Client mode ("mock", "testnet", "mainnet")
            requester_address: Requester's Ethereum address. When wallet="auto"
                this is auto-derived from the Smart Wallet and can be omitted.
            state_directory: Directory for mock state (Path or string)
            private_key: Private key for signing (testnet/mainnet)
            rpc_url: RPC URL for blockchain (testnet/mainnet)
            wallet: Wallet mode. "auto" = construct AutoWalletProvider
                (Coinbase Smart Wallet + Paymaster, gasless). "eoa" = force
                EOA path. None (default) = legacy behavior, caller wires
                its own wallet provider.
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
                wallet=wallet,
                **kwargs,
            )

        # AIP-12: auto-construct Smart Wallet provider when wallet="auto".
        # Must run BEFORE requester_address validation because the Smart
        # Wallet address is derived from the signer's counterfactual address
        # and supplied back into config.requester_address.
        wallet_provider: Optional[object] = None
        if config.wallet == "auto":
            wallet_provider = await cls._build_auto_wallet_provider(config)
            # Override (or fill in) requester_address with the Smart Wallet address.
            config.requester_address = wallet_provider.get_address()

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

        # Resolve contract_addresses for AIP-12 batched payments. Required
        # alongside wallet_provider so BasicAdapter can route via
        # pay_actp_batched (1 UserOp = approve + createTransaction +
        # linkEscrow). Only meaningful on testnet/mainnet — mock mode has
        # no on-chain contracts to address.
        contract_addresses: Optional[object] = None
        if wallet_provider is not None and config.mode in ("testnet", "mainnet"):
            from agirails.config.networks import get_network
            from agirails.wallet.aa.transaction_batcher import (
                ContractAddresses as AAContractAddresses,
            )
            network_name = (
                "base-sepolia" if config.mode == "testnet" else "base-mainnet"
            )
            network = get_network(network_name)
            contract_addresses = AAContractAddresses(
                usdc=network.contracts.usdc,
                actp_kernel=network.contracts.actp_kernel,
                escrow_vault=network.contracts.escrow_vault,
            )

        client = cls(
            runtime,
            requester,
            info,
            eas_helper,
            wallet_provider=wallet_provider,
            contract_addresses=contract_addresses,
        )

        # AIP-12 parity: Auto-register X402Adapter when wallet_provider is
        # configured for a real network. TS SDK gates on signTypedData (x402
        # v2 EIP-712 path); Python X402Adapter is the legacy direct-transfer
        # variant, so we gate on send_transaction + testnet/mainnet network
        # so we have a USDC address and a network label to register with.
        # Best-effort: any failure is logged and skipped, matching TS.
        if wallet_provider is not None and config.mode in ("testnet", "mainnet"):
            cls._maybe_register_x402(client, config, wallet_provider, requester)

        return client

    @classmethod
    async def _build_auto_wallet_provider(
        cls, config: ACTPClientConfig
    ) -> object:
        """Build AutoWalletProvider from config (wallet='auto' path).

        Mirrors the TS SDK ACTPClient.create() AA initialization:
        - Requires testnet or mainnet mode (mock has no on-chain kernel)
        - Requires private_key (signer that owns the Smart Wallet)
        - Reads bundler/paymaster URLs from network config (Coinbase
          primary, Pimlico backup)
        - Derives Smart Wallet counterfactual address from signer
        """
        # Imports here so mock-mode-only callers don't pay the AA import cost.
        from web3 import Web3
        from agirails.config.networks import get_network
        from agirails.wallet.auto_wallet_provider import (
            AutoWalletConfig,
            AutoWalletProvider,
        )

        if config.mode not in ("testnet", "mainnet"):
            raise ValidationError(
                message=(
                    'wallet="auto" requires mode in ("testnet", "mainnet"). '
                    "Mock mode has no on-chain kernel for Smart Wallet routing."
                ),
                details={"field": "wallet", "mode": config.mode},
            )
        if not config.private_key:
            raise ValidationError(
                message=(
                    'wallet="auto" requires private_key — the EOA that '
                    "signs UserOps as owner of the Smart Wallet."
                ),
                details={"field": "private_key"},
            )

        network_name = (
            "base-sepolia" if config.mode == "testnet" else "base-mainnet"
        )
        network = get_network(network_name)

        if network.aa is None:
            raise ValidationError(
                message=(
                    f"Network {network_name!r} has no aa config; "
                    'wallet="auto" needs bundler + paymaster endpoints.'
                ),
                details={"field": "network.aa", "network": network_name},
            )

        bundler_primary = network.aa.bundler_urls.get(
            "coinbase"
        ) or network.aa.bundler_urls.get("pimlico")
        paymaster_primary = network.aa.paymaster_urls.get(
            "coinbase"
        ) or network.aa.paymaster_urls.get("pimlico")
        # When both providers are configured, the other becomes the backup.
        bundler_backup = (
            network.aa.bundler_urls.get("pimlico")
            if network.aa.bundler_urls.get("coinbase")
            and network.aa.bundler_urls.get("pimlico")
            else None
        )
        paymaster_backup = (
            network.aa.paymaster_urls.get("pimlico")
            if network.aa.paymaster_urls.get("coinbase")
            and network.aa.paymaster_urls.get("pimlico")
            else None
        )

        if not bundler_primary or not paymaster_primary:
            raise ValidationError(
                message=(
                    "AA bundler/paymaster endpoints are not configured. "
                    "Set one of: CDP_API_KEY, PIMLICO_API_KEY, or explicit "
                    "CDP_BUNDLER_URL / PIMLICO_BUNDLER_URL env vars."
                ),
                details={"field": "network.aa.bundler_urls"},
            )

        rpc_url = config.rpc_url or network.rpc_url
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = await asyncio.to_thread(lambda: w3.eth.chain_id)

        return await AutoWalletProvider.create(
            AutoWalletConfig(
                private_key=config.private_key,
                w3=w3,
                chain_id=chain_id,
                actp_kernel_address=network.contracts.actp_kernel,
                bundler_primary_url=bundler_primary,
                bundler_backup_url=bundler_backup,
                paymaster_primary_url=paymaster_primary,
                paymaster_backup_url=paymaster_backup,
            )
        )

    @classmethod
    def _maybe_register_x402(
        cls,
        client: "ACTPClient",
        config: ACTPClientConfig,
        wallet_provider: object,
        requester_address: str,
    ) -> None:
        """Best-effort X402Adapter auto-registration.

        Mirrors TS SDK ACTPClient, which auto-registers ``X402Adapter`` when the
        wallet provider supports EIP-712 signing (``signTypedData``). When the
        provider exposes ``sign_typed_data`` we wire the NATIVE x402 v2 adapter
        (EIP-3009 / Permit2). Providers that only expose ``send_transaction``
        fall back to the legacy direct-transfer adapter for backward compat.

        Failures are logged and swallowed so the SDK still works without
        x402 routing — users can always register their own X402Adapter
        instance via :py:meth:`register_adapter`.
        """
        try:
            has_sign_typed = callable(getattr(wallet_provider, "sign_typed_data", None))
            if not has_sign_typed and not hasattr(wallet_provider, "send_transaction"):
                _logger.debug(
                    "X402Adapter auto-registration skipped: wallet provider "
                    "implements neither sign_typed_data nor send_transaction"
                )
                return

            from agirails.adapters.x402_adapter import (
                X402Adapter,
                X402AdapterConfig,
            )
            from agirails.config.networks import get_network

            network_name = (
                "base-sepolia" if config.mode == "testnet" else "base-mainnet"
            )

            if has_sign_typed:
                # Native x402 v2 (TS parity). Defaults keep the opt-in safety
                # gate (empty allowed_hosts => per-call opt-in required) and the
                # canonical-USDC asset allowlist, so this NEVER auto-pays an
                # arbitrary HTTPS URL.
                adapter = X402Adapter(
                    requester_address=requester_address,
                    config=X402AdapterConfig(wallet_provider=wallet_provider),
                )
                client.register_adapter(adapter)
                _logger.debug(
                    f"x402 v2 X402Adapter auto-registered for {network_name} "
                    "(native EIP-3009/Permit2)"
                )
                return

            # Legacy fallback: direct USDC.transfer via send_transaction.
            network = get_network(network_name)
            usdc_address = network.contracts.usdc
            rpc_url = config.rpc_url or network.rpc_url

            transfer_fn = cls._build_x402_transfer_fn(
                wallet_provider, usdc_address, rpc_url
            )

            adapter = X402Adapter(
                requester_address=requester_address,
                config=X402AdapterConfig(
                    expected_network=network_name,
                    transfer_fn=transfer_fn,
                ),
            )
            client.register_adapter(adapter)
            _logger.debug(
                f"Legacy X402Adapter auto-registered for {network_name} "
                f"(usdc={usdc_address})"
            )
        except Exception as exc:
            _logger.warn(
                f"X402Adapter auto-registration skipped: {exc}"
            )

    @staticmethod
    def _build_x402_transfer_fn(
        wallet_provider: object,
        usdc_address: str,
        rpc_url: str,
    ) -> Any:
        """Build an x402 ``transfer_fn(to, amount) -> tx_hash`` closure.

        The closure encodes ``USDC.transfer(to, amount)`` calldata using
        the bundled USDC ABI and submits it via the wallet provider's
        ``send_transaction`` method. Returns the receipt hash, which the
        X402Adapter sends back to the provider as proof of payment.
        """
        import json
        from web3 import Web3
        from agirails.wallet.auto_wallet_provider import TransactionRequest

        abi_path = Path(__file__).parent / "abis" / "usdc.json"
        usdc_abi = json.loads(abi_path.read_text())
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        usdc_contract = w3.eth.contract(
            address=Web3.to_checksum_address(usdc_address), abi=usdc_abi
        )

        async def transfer_fn(to: str, amount: str) -> str:
            calldata = usdc_contract.encode_abi(
                "transfer",
                args=[Web3.to_checksum_address(to), int(amount)],
            )
            receipt = await wallet_provider.send_transaction(  # type: ignore[attr-defined]
                TransactionRequest(to=usdc_address, data=calldata, value="0")
            )
            return receipt.hash

        return transfer_fn

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
        network_name = "base-sepolia" if config.mode == "testnet" else "base-mainnet"

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
    def router(self) -> AdapterRouter:
        """Get the adapter router for custom adapter selection."""
        return self._router

    async def pay(self, params: Union[UnifiedPayParams, dict]) -> Any:
        """
        Unified pay method — routes through AdapterRouter.

        Accepts Ethereum addresses, HTTP endpoints (x402), or ERC-8004 agent IDs.
        Selects the best adapter based on recipient type and metadata hints.

        Smart Wallet routing fix: when walletProvider with batched support is
        available AND the target is an Ethereum address, routes to BasicAdapter
        (which has payACTPBatched) instead of StandardAdapter (which would cause
        "Requester mismatch" on-chain).

        Args:
            params: UnifiedPayParams or dict with to, amount, etc.

        Returns:
            Payment result from the selected adapter.

        Raises:
            ValidationError: If params are invalid.
            RuntimeError: If no suitable adapter found.
        """
        self._settle_on_interact.trigger()

        if isinstance(params, dict):
            params = UnifiedPayParams(**params)

        selection = await self._router.select_and_resolve(params)
        resolved = selection.resolved_params
        adapter = selection.adapter

        # Smart Wallet routing fix (1:1 with TypeScript SDK):
        # ONLY when a walletProvider with batched support is active AND
        # the target is an Ethereum address, override to BasicAdapter.
        # Otherwise respect the router's adapter selection.
        has_batched = (
            self._wallet_provider is not None
            and hasattr(self._wallet_provider, 'pay_actp_batched')
        )
        if has_batched and self._basic.can_handle(resolved):
            return await self._basic.pay(resolved)

        return await adapter.pay(resolved)

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
