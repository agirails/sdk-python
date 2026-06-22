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


def _extract_tx_id(result: Any) -> Optional[str]:
    """Pull a txId out of an adapter pay() result (dataclass or dict).

    BasicAdapter returns ``BasicPayResult`` (``.tx_id``); StandardAdapter and
    x402 return dicts keyed ``"tx_id"`` / ``"txId"``. Returns ``None`` when no
    id is present (the tracker no-ops on falsy ids, matching TS).
    """
    if result is None:
        return None
    tx_id = getattr(result, "tx_id", None)
    if tx_id:
        return tx_id
    if isinstance(result, dict):
        return result.get("tx_id") or result.get("txId")
    return None


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

    # Cap for the txId -> adapter map (mirrors TS MAX_TX_MAP_SIZE).
    _MAX_TX_MAP_SIZE = 10_000

    def __init__(
        self,
        runtime: IACTPRuntime,
        requester_address: str,
        info: ACTPClientInfo,
        eas_helper: Optional[object] = None,
        wallet_provider: Optional[object] = None,
        contract_addresses: Optional[object] = None,
        reputation_reporter: Optional[object] = None,
        lazy_scenario: str = "none",
        pending_publish: Optional[object] = None,
        agent_registry_address: Optional[str] = None,
        network_id: Optional[str] = None,
        erc8004_identity_registry_address: Optional[str] = None,
        pending_is_stale: bool = False,
        dispute_client: Optional[object] = None,
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
            reputation_reporter: Optional ERC-8004 ReputationReporter. When
                present, ``release()`` reports settlement outcomes (non-blocking).
            lazy_scenario: Lazy-publish activation scenario ("A"/"B1"/"B2"/
                "C"/"none"). Consumed by ``get_activation_calls()``.
            pending_publish: Cached :class:`PendingPublishData` for lazy publish.
            agent_registry_address: AgentRegistry address (lazy activation).
            network_id: Network identifier ("base-sepolia"/"base-mainnet") for
                chain-scoped pending-publish operations.
            erc8004_identity_registry_address: ERC-8004 Identity Registry
                address (first-time identity mint, scenario A).
            pending_is_stale: When True, AGIRAILS.md changed since the last
                ``actp publish`` so lazy activation is skipped (TS
                ``pendingIsStale``, ACTPClient.ts:1088-1117).
        """
        self._runtime = runtime
        self._requester_address = requester_address.lower()
        self._info = info
        self._eas_helper = eas_helper
        self._wallet_provider = wallet_provider
        self._contract_addresses = contract_addresses
        self._reputation_reporter = reputation_reporter

        # AIP-14b dispute facade (PRD P2-9). Present (non-None) only when the
        # dispute contract addresses are configured for the network (Phase 6+);
        # None on mock mode and pre-deployment networks, so existing flows are
        # unaffected. Composes BondEscalation + CompositeMediator +
        # EvaluatorClient + UMAHelper + DisputeSplitIndexer behind one object.
        # PARITY: TS ``client.dispute`` (ACTPClient.ts). For the legacy
        # single-shot kernel path see ``ACTPKernel.raise_dispute`` /
        # ``resolve_dispute`` (their docstrings steer here).
        self.dispute = dispute_client

        # Lazy-publish state (consumed by get_activation_calls()).
        self._lazy_scenario = lazy_scenario
        self._pending_publish = pending_publish
        self._agent_registry_address = agent_registry_address
        self._network_id = network_id
        self._erc8004_identity_registry_address = erc8004_identity_registry_address
        self._pending_is_stale = pending_is_stale

        # Maps txId -> adapter that handled it, for adapter-aware get_status
        # routing. Bounded at _MAX_TX_MAP_SIZE (mirrors TS txAdapterMap).
        self._tx_adapter_map: "dict[str, Any]" = {}

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

        # Smart Wallet router for encoding/sending state transitions via UserOps.
        # None when the wallet provider doesn't support batching (EOA / mock).
        # Mirrors TS createSmartWalletRouter on the client itself.
        from agirails.wallet.smart_wallet_router import (
            SmartWalletContractAddresses,
            create_smart_wallet_router,
        )

        self._smart_wallet_router: Optional[object] = None
        if wallet_provider is not None and contract_addresses is not None:
            router_contracts = SmartWalletContractAddresses(
                usdc=contract_addresses.usdc,
                actp_kernel=contract_addresses.actp_kernel,
                escrow_vault=contract_addresses.escrow_vault,
            )
            self._smart_wallet_router = create_smart_wallet_router(
                wallet_provider, router_contracts, runtime, eas_helper
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
        #
        # Pass self._standard as the release router (TS ACTPClient.ts:711-716) so
        # AA-enabled providers settle through SmartWalletRouter (Paymaster) rather
        # than reverting on raw-EOA gas. StandardAdapter.release_escrow falls
        # through to runtime.release_escrow on EOA / mock, preserving prior
        # behaviour.
        self._settle_on_interact = SettleOnInteract(
            runtime,
            requester_address,
            release_router=self._standard,
        )

    def _try_register_optional_adapters(self) -> None:
        """Auto-register optional components if dependencies are available.

        NOTE: X402Adapter auto-registration runs in ``ACTPClient.create()``
        (not here) because it needs the resolved network config. Callers
        constructing the client via ``__init__`` directly can still pass a
        wallet provider and call ``register_adapter()`` themselves, or use
        the ``_maybe_register_x402`` helper.

        ERC-8004 bridge IS auto-registered here (read-only, no wallet needed).
        """
        # ERC-8004 bridge for agent ID resolution (read-only).
        #
        # BUGFIX (TS parity, ACTPClient.ts:1046-1052): the bridge MUST be
        # constructed with the mode-derived network so a testnet/mock client
        # resolves agent IDs against the TESTNET registry, not mainnet. TS
        # derives `erc8004Network` from `config.mode` (testnet -> 'base-sepolia',
        # else -> 'base') and passes it to `new ERC8004Bridge({ network, rpcUrl })`.
        # Constructing the bridge with no config (the prior Python behaviour)
        # silently defaulted to base-mainnet, so testnet/mock agent-ID lookups
        # hit the wrong chain. We thread `self._network_id` (set in __init__)
        # into ERC8004BridgeConfig.
        try:
            from agirails.erc8004.bridge import ERC8004Bridge
            from agirails.types.erc8004 import ERC8004BridgeConfig

            bridge = ERC8004Bridge(
                ERC8004BridgeConfig(network=self._erc8004_network())
            )
            self._router.set_erc8004_bridge(bridge)
        except (ImportError, Exception):
            pass

    def _erc8004_network(self) -> str:
        """Resolve the ERC-8004 network literal for the bridge.

        Mirrors TS ``erc8004Network`` derivation (ACTPClient.ts:1047-1048):
        testnet -> 'base-sepolia', mainnet -> 'base' (Python's literal is
        'base-mainnet'). Mock mode has no on-chain bridge in TS; here we keep
        a bridge for read-only agent-ID resolution and default it to
        'base-sepolia' (testnet) so mock callers never hit mainnet by accident.
        """
        mode = self._info.mode
        if mode == "mainnet":
            return "base-mainnet"
        # testnet, mock, or unknown -> testnet registry (never mainnet default).
        return "base-sepolia"

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
        #
        # Lazy-publish gas-gate state (TS ACTPClient.ts:766-767, 918-1006).
        # Populated by _apply_lazy_publish_gate when the auto wallet is built.
        wallet_provider: Optional[object] = None
        lazy_scenario: str = "none"
        lazy_pending: Optional[object] = None
        pending_is_stale: bool = False
        if config.wallet == "auto":
            wallet_provider = await cls._build_auto_wallet_provider(config)

            # Gas-gate (TS ACTPClient.ts:918-1006): only grant the gas-sponsored
            # AutoWallet when the agent has an on-chain config, a pending publish,
            # or a buyer-link marker; otherwise fall back to an EOA wallet so
            # unregistered agents do not receive free Paymaster gas. The gate may
            # REPLACE wallet_provider with an EOA provider and reset the lazy state.
            (
                wallet_provider,
                lazy_scenario,
                lazy_pending,
            ) = await cls._apply_lazy_publish_gate(config, wallet_provider)

            # Override (or fill in) requester_address with the chosen provider's
            # address (Smart Wallet when auto, signer EOA on fallback).
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
        network_id: Optional[str] = None
        agent_registry_address: Optional[str] = None
        erc8004_identity_registry_address: Optional[str] = None
        if config.mode in ("testnet", "mainnet"):
            from agirails.config.networks import get_network

            network_id = (
                "base-sepolia" if config.mode == "testnet" else "base-mainnet"
            )
            network = get_network(network_id)
            agent_registry_address = getattr(
                network.contracts, "agent_registry", None
            )
            erc8004_identity_registry_address = getattr(
                network.contracts, "erc8004_identity_registry", None
            )

        if wallet_provider is not None and config.mode in ("testnet", "mainnet"):
            from agirails.config.networks import get_network
            from agirails.wallet.aa.transaction_batcher import (
                ContractAddresses as AAContractAddresses,
            )
            network_name = network_id or (
                "base-sepolia" if config.mode == "testnet" else "base-mainnet"
            )
            network = get_network(network_name)
            contract_addresses = AAContractAddresses(
                usdc=network.contracts.usdc,
                actp_kernel=network.contracts.actp_kernel,
                escrow_vault=network.contracts.escrow_vault,
            )

        # ERC-8004 REPUTATION: wire a reporter for settlement-outcome reporting
        # on real networks. Mirrors TS ACTPClient.create() (ACTPClient.ts:1054-1058):
        # network derived from mode (testnet -> base-sepolia, else -> base-mainnet),
        # signed with the same private key. Best-effort — never blocks create().
        reputation_reporter: Optional[object] = None
        if config.mode in ("testnet", "mainnet") and config.private_key:
            try:
                from agirails.erc8004.reputation_reporter import ReputationReporter
                from agirails.types.erc8004 import ReputationReporterConfig

                reputation_reporter = ReputationReporter(
                    ReputationReporterConfig(
                        network=network_id,  # type: ignore[arg-type]
                        private_key=config.private_key,
                        rpc_url=config.rpc_url,
                    )
                )
            except Exception as exc:  # pragma: no cover - best-effort
                _logger.warn(f"ReputationReporter wiring skipped: {exc}")

        # AIP-14b DISPUTE FACADE (PRD P2-9): wire client.dispute ONLY when the
        # dispute contracts are configured for this network. Addresses are None
        # until Phase 6 (testnet) / later (mainnet), so on undeployed networks
        # this stays None and existing flows are unchanged. Best-effort — a
        # wiring failure must never block create(). Mirrors TS ACTPClient.create
        # (present iff the dispute addresses are configured).
        dispute_client: Optional[object] = None
        if config.mode in ("testnet", "mainnet"):
            try:
                from agirails.config.networks import get_network as _get_network

                _net = _get_network(
                    network_id
                    or ("base-sepolia" if config.mode == "testnet" else "base-mainnet")
                )
                _contracts = _net.contracts
                if getattr(_contracts, "bond_escalation", None) and getattr(
                    _contracts, "composite_mediator", None
                ):
                    from agirails.dispute.dispute_client import DisputeClient

                    # runtime is a BlockchainRuntime on real networks; it exposes
                    # `.w3` and `.account` (blockchain_runtime.py:179-180).
                    _w3 = getattr(runtime, "w3", None)
                    _account = getattr(runtime, "account", None)
                    if _w3 is not None:
                        dispute_client = DisputeClient.from_config(
                            _w3, _account, _net
                        )
            except Exception as exc:  # pragma: no cover - best-effort
                _logger.warn(f"DisputeClient wiring skipped: {exc}")

        # Staleness check (TS ACTPClient.ts:1088-1108): recompute the local
        # AGIRAILS.md hash; if it differs from the pending publish's configHash
        # the cached publish is stale, so lazy activation is skipped. Best-effort
        # — never blocks create().
        if lazy_pending is not None and lazy_scenario not in ("none", "C"):
            try:
                import os as _os

                md_path = Path(_os.getcwd()) / "AGIRAILS.md"
                if md_path.exists():
                    from agirails.config.agirailsmd import compute_config_hash

                    content = md_path.read_text(encoding="utf-8")
                    hash_result = compute_config_hash(content)
                    current_hash = getattr(
                        hash_result, "config_hash", None
                    ) or (
                        hash_result.get("config_hash")
                        if isinstance(hash_result, dict)
                        else None
                    )
                    pending_hash = getattr(lazy_pending, "config_hash", None)
                    if current_hash is not None and current_hash != pending_hash:
                        pending_is_stale = True
                        _logger.warn(
                            "AGIRAILS.md changed since last publish. Activation "
                            'skipped. Run "actp publish" to update.'
                        )
            except Exception:
                # Best-effort: staleness check must not block operation.
                pass

        client = cls(
            runtime,
            requester,
            info,
            eas_helper,
            wallet_provider=wallet_provider,
            contract_addresses=contract_addresses,
            reputation_reporter=reputation_reporter,
            lazy_scenario=lazy_scenario,
            pending_publish=lazy_pending,
            agent_registry_address=agent_registry_address,
            network_id=network_id,
            erc8004_identity_registry_address=erc8004_identity_registry_address,
            pending_is_stale=pending_is_stale,
            dispute_client=dispute_client,
        )

        # Drift detection: non-blocking AGIRAILS.md sync check on startup
        # (TS ACTPClient.ts:1119-1124). Mock mode short-circuits inside
        # check_config_drift; for real networks we fire it as a detached task
        # so it never blocks create() and swallows all errors.
        if config.mode != "mock":
            try:
                loop = asyncio.get_running_loop()

                async def _safe_drift() -> None:
                    try:
                        await client.check_config_drift(config)
                    except Exception:
                        pass

                # Hold a reference so the detached task is not GC'd mid-flight
                # (CPython only keeps weak refs to pending tasks).
                client._drift_task = loop.create_task(_safe_drift())
            except RuntimeError:
                # No running loop (sync context) — skip; drift is non-critical.
                pass

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

    @staticmethod
    def _detect_lazy_publish_scenario(
        on_chain: Any,
        pending: Optional[object],
    ) -> str:
        """Detect the lazy-publish activation scenario.

        Byte-identical to ``agirails.cli.commands.publish.detect_lazy_publish_scenario``
        and TS ``detectLazyPublishScenario`` (ACTPClient.ts:132-155). Inlined
        here so the gas-gate does not pull in CLI deps (typer / cli.main) at
        client-create time.

        Decision matrix:
          - A:    not registered + has pending -> first-time activation
          - B1:   registered + pending hash != on-chain hash + not listed
          - B2:   registered + pending hash != on-chain hash + already listed
          - C:    pending hash == on-chain hash -> stale pending, delete it
          - none: no pending publish
        """
        if pending is None:
            return "none"
        if not on_chain.is_registered:
            return "A"
        if getattr(pending, "config_hash", None) != on_chain.config_hash:
            return "B1" if not on_chain.listed else "B2"
        return "C"

    @classmethod
    async def _apply_lazy_publish_gate(
        cls,
        config: ACTPClientConfig,
        auto_wallet: object,
    ) -> "tuple[object, str, Optional[object]]":
        """Decide whether the gas-sponsored AutoWallet may be used.

        Mirrors TS ACTPClient.create() gas-gate (ACTPClient.ts:918-1006).

        The gate grants the AutoWallet only when at least one of these holds:
          - the agent already has an on-chain config (configHash != ZERO), or
          - a pending-publish file exists (the agent ran ``actp publish``), or
          - a buyer-link marker exists (AIP-18 DEC-8 pure-buyer gasless leg).
        Otherwise it FALLS BACK to an EOA wallet (gas NOT sponsored) so an
        unregistered agent never receives free Paymaster gas.

        Returns:
            ``(wallet_provider, lazy_scenario, lazy_pending)``:
              - ``wallet_provider``: the AutoWallet (gate passed) or an
                EOAWalletProvider (fallback).
              - ``lazy_scenario``: ``"A"/"B1"/"B2"/"C"/"none"`` activation
                scenario (always ``"none"`` on EOA fallback).
              - ``lazy_pending``: cached pending-publish data, or ``None``.
        """
        from web3 import Web3

        from agirails.config.buyer_link import load_buyer_link
        from agirails.config.networks import get_network
        from agirails.config.on_chain_state import (
            ZERO_HASH,
            get_on_chain_agent_state,
        )
        from agirails.config.pending_publish import (
            delete_pending_publish,
            load_pending_publish,
        )

        network_name = (
            "base-sepolia" if config.mode == "testnet" else "base-mainnet"
        )
        network = get_network(network_name)
        registry_addr = getattr(network.contracts, "agent_registry", None)
        rpc_url = config.rpc_url or network.rpc_url

        smart_wallet_address = auto_wallet.get_address()  # type: ignore[attr-defined]

        lazy_scenario: str = "none"
        lazy_pending: Optional[object] = None

        # Load pending publish (may be None) — chain-scoped (TS 924-929).
        try:
            lazy_pending = load_pending_publish(network_name)
        except Exception:
            lazy_pending = None

        # Load buyer-link marker (may be None). A pure buyer (intent: pay) links
        # instead of registering, so it has no on-chain configHash and no
        # pending-publish — this marker lets the gate grant the gas-sponsored
        # AutoWallet anyway (AIP-18 DEC-8). It triggers NO lazy on-chain
        # activation (lazy_pending stays None) (TS 931-942).
        buyer_link: Optional[object] = None
        try:
            buyer_link = load_buyer_link(network_name)
        except Exception:
            buyer_link = None

        use_auto_wallet = False

        if registry_addr:
            try:
                on_chain_state = await asyncio.to_thread(
                    get_on_chain_agent_state,
                    smart_wallet_address,
                    network_name,
                    rpc_url,
                )
                lazy_scenario = cls._detect_lazy_publish_scenario(
                    on_chain_state, lazy_pending
                )

                # Scenario C: stale pending — delete immediately (TS 953-958).
                if lazy_scenario == "C":
                    delete_pending_publish(network=network_name)
                    lazy_pending = None
                    lazy_scenario = "none"

                # Gate (TS 960-973): configHash != ZERO || pending || buyer link.
                has_on_chain_config = on_chain_state.config_hash != ZERO_HASH
                has_pending_publish = lazy_pending is not None
                is_linked_buyer = buyer_link is not None

                if has_on_chain_config or has_pending_publish or is_linked_buyer:
                    use_auto_wallet = True
            except Exception:
                # Registry check failed (e.g. RPC down). Fail-open ONLY if a
                # pending publish or buyer link exists (legitimate `actp publish`
                # intent); fail-closed otherwise to deny unregistered agents free
                # gas (TS 974-985).
                if lazy_pending or buyer_link:
                    use_auto_wallet = True
                    _logger.warn(
                        "AgentRegistry check failed, but pending publish / "
                        "buyer link found — proceeding with AA."
                    )
                else:
                    _logger.warn(
                        "AgentRegistry check failed and no pending publish — "
                        "falling back to EOA."
                    )
        else:
            # No registry deployed — skip check (early testnet) (TS 986-989).
            use_auto_wallet = True

        if use_auto_wallet:
            return auto_wallet, lazy_scenario, lazy_pending

        # Fallback: EOA wallet (gas NOT sponsored). Reset lazy state since we
        # are not using the auto wallet (TS 994-1006).
        _logger.warn(
            "Agent not published on AgentRegistry and no pending publish "
            "found. Falling back to EOA wallet (gas not sponsored). "
            'Run "actp publish" for gas-free transactions.'
        )
        from agirails.wallet.eoa_wallet_provider import EOAWalletProvider

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = await asyncio.to_thread(lambda: w3.eth.chain_id)
        eoa = EOAWalletProvider(
            private_key=config.private_key,  # type: ignore[arg-type]
            w3=w3,
            chain_id=chain_id,
        )
        return eoa, "none", None

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
            result = await self._basic.pay(resolved)
            self._track_tx_adapter(_extract_tx_id(result), self._basic)
            return result

        result = await adapter.pay(resolved)
        self._track_tx_adapter(_extract_tx_id(result), adapter)
        return result

    async def route_url_payment(
        self, params: Union[UnifiedPayParams, dict]
    ) -> Any:
        """
        Route URL recipients through non-basic adapters (e.g. x402).

        Used by BasicAdapter to avoid validating URLs as Ethereum addresses.
        Mirrors TS ``ACTPClient.routeUrlPayment`` (ACTPClient.ts:1394-1407).

        Args:
            params: UnifiedPayParams (or dict) with an HTTPS ``to`` endpoint.

        Returns:
            Payment result from the URL-capable adapter.

        Raises:
            ValidationError: If no URL-capable adapter is registered.
        """
        if isinstance(params, dict):
            params = UnifiedPayParams(**params)

        selection = await self._router.select_and_resolve(params)
        adapter = selection.adapter
        resolved = selection.resolved_params

        if adapter.metadata.id == "basic":
            raise ValidationError(
                message=(
                    f'No URL-capable adapter found for "{params.to}". '
                    "Register X402Adapter and use an HTTPS endpoint."
                ),
                details={"to": params.to},
            )

        url_result = await adapter.pay(resolved)
        self._track_tx_adapter(_extract_tx_id(url_result), adapter)
        return url_result

    def _track_tx_adapter(self, tx_id: Optional[str], adapter: Any) -> None:
        """Track which adapter handled a txId, with bounded eviction.

        Mirrors TS ``trackTxAdapter`` (ACTPClient.ts:1444-1451).
        """
        if not tx_id:
            return
        self._tx_adapter_map[tx_id] = adapter
        if len(self._tx_adapter_map) > self._MAX_TX_MAP_SIZE:
            # Evict the oldest insertion (dicts preserve insertion order).
            oldest = next(iter(self._tx_adapter_map))
            self._tx_adapter_map.pop(oldest, None)

    async def get_status(self, tx_id: str) -> Any:
        """
        Get transaction status by ID.

        Routes to the adapter that originally handled the payment. Falls back
        to StandardAdapter for txIds created in prior sessions (not in map).
        If StandardAdapter reports "not found" AND x402 is registered, appends
        a hint that the txId may be a stateless x402 payment from a prior run.

        Mirrors TS ``ACTPClient.getStatus`` (ACTPClient.ts:1419-1441).

        Args:
            tx_id: Transaction ID.

        Returns:
            TransactionStatus.

        Raises:
            RuntimeError: If transaction not found.
        """
        adapter = self._tx_adapter_map.get(tx_id)
        if adapter is not None:
            return await adapter.get_status(tx_id)

        try:
            return await self._standard.get_status(tx_id)
        except Exception as err:
            msg = str(err)
            if "not found" in msg.lower() and self._registry.has("x402"):
                raise RuntimeError(
                    f"Transaction {tx_id} not found. "
                    "x402 payments are stateless — status is not retained "
                    "across SDK process restarts. If this txId originated in "
                    "a previous run, query the on-chain receipt directly."
                )
            raise

    async def start_work(self, tx_id: str) -> None:
        """
        Transition to IN_PROGRESS (provider starts work).

        When Smart Wallet is active, routes through the wallet provider so
        msg.sender == Smart Wallet. Mirrors TS ``ACTPClient.startWork``
        (ACTPClient.ts:1475-1482).

        Args:
            tx_id: Transaction ID.
        """
        self._settle_on_interact.trigger()
        router = self._smart_wallet_router
        if router is not None and router.should_route():
            from agirails.runtime.types import State

            await router.send_transition(
                tx_id, State.IN_PROGRESS.value, "0x", label="startWork"
            )
            return
        await self._runtime.transition_state(tx_id, "IN_PROGRESS")

    async def deliver(
        self, tx_id: str, dispute_window_seconds: Optional[int] = None
    ) -> None:
        """
        Transition to DELIVERED (provider completes work).

        When no ``dispute_window_seconds`` is provided, uses the transaction's
        actual disputeWindow from creation time. When Smart Wallet is active and
        the tx is still COMMITTED, batches startWork + deliver in one UserOp.
        Mirrors TS ``ACTPClient.deliver`` (ACTPClient.ts:1507-1551).

        Args:
            tx_id: Transaction ID.
            dispute_window_seconds: Optional dispute-window override (seconds).

        Raises:
            RuntimeError: If transaction not found, or DELIVERED step fails.
        """
        self._settle_on_interact.trigger()

        tx = await self._runtime.get_transaction(tx_id)
        if tx is None:
            raise RuntimeError(f"Transaction {tx_id} not found")

        from eth_abi import encode as abi_encode

        from agirails.runtime.types import State

        effective_dispute_window = (
            dispute_window_seconds
            if dispute_window_seconds is not None
            else tx.dispute_window
        )
        proof = "0x" + abi_encode(["uint256"], [int(effective_dispute_window)]).hex()

        state_str = tx.state.value if hasattr(tx.state, "value") else str(tx.state)

        router = self._smart_wallet_router
        if router is not None and router.should_route():
            # When using Smart Wallet, batch startWork + deliver if still COMMITTED.
            if state_str == "COMMITTED":
                start_work_tx = router.encode_transition_state_tx(
                    tx_id, State.IN_PROGRESS.value
                )
                deliver_tx = router.encode_transition_state_tx(
                    tx_id, State.DELIVERED.value, proof
                )
                receipt = await self._wallet_provider.send_batch_transaction(
                    [start_work_tx, deliver_tx]
                )
                if not receipt.success:
                    raise RuntimeError(f"deliver (batch) UserOp failed: {receipt.hash}")
            else:
                await router.send_transition(
                    tx_id, State.DELIVERED.value, proof, label="deliver"
                )
            return

        # Legacy EOA/mock flow — two-step: COMMITTED -> IN_PROGRESS -> DELIVERED
        if state_str == "COMMITTED":
            await self._runtime.transition_state(tx_id, "IN_PROGRESS")
        try:
            await self._runtime.transition_state(tx_id, "DELIVERED", proof)
        except Exception as e:
            raise RuntimeError(
                f"deliver() failed at DELIVERED step — transaction {tx_id} is "
                f"now IN_PROGRESS. Call deliver() again to complete. "
                f"Original error: {e}"
            )

    async def release(
        self, escrow_id: str, attestation_uid: Optional[str] = None
    ) -> None:
        """
        Release escrow funds (EXPLICIT settlement).

        MUST be called after the dispute window expires or the requester
        approves. This is the ONLY way to settle — NO auto-settle. If an
        ERC-8004 agent ID was set during transaction creation, also reports
        the settlement to the Reputation Registry (non-blocking).

        When Smart Wallet is active, routes through the wallet provider.
        Mirrors TS ``ACTPClient.release`` (ACTPClient.ts:1577-1614).

        Args:
            escrow_id: Escrow ID (usually same as txId).
            attestation_uid: Optional attestation UID for verification.
        """
        from agirails.wallet.smart_wallet_router import SmartWalletRouter

        tx_id = SmartWalletRouter.extract_tx_id(escrow_id)

        # Get transaction to find agentId (for reputation reporting).
        tx = await self._runtime.get_transaction(tx_id)
        agent_id = getattr(tx, "agent_id", None) if tx is not None else None

        # Idempotence: a mock lazy auto-release may have already settled the tx
        # on the read above (MockRuntime parity). On real chains get_transaction
        # never auto-settles, so this is a no-op there. If already SETTLED, the
        # escrow is released — skip the redundant settle (which would raise
        # SETTLED->SETTLED) but still fire the reputation report below.
        _st = getattr(tx, "state", None) if tx is not None else None
        _st_val = getattr(_st, "value", _st)
        already_settled = _st_val == "SETTLED" or _st_val == 5

        # Release escrow (the critical operation).
        router = self._smart_wallet_router
        if already_settled:
            pass  # auto-released on read; nothing left to settle
        elif router is not None and router.should_route():
            await router.validate_release_preconditions(tx if tx is not None else tx_id)
            await router.verify_release_attestation(tx_id, attestation_uid)
            await router.send_settle(tx_id)
        else:
            await self._runtime.release_escrow(escrow_id, attestation_uid or "")

        # ERC-8004 REPUTATION: report settlement if an agent ID exists.
        # Non-blocking — fire and forget (settlement already succeeded).
        if (
            self._reputation_reporter is not None
            and agent_id is not None
            and str(agent_id) != "0"
        ):
            try:
                result = await self._reputation_reporter.report_settlement(
                    agent_id=str(agent_id),
                    tx_id=tx_id,
                )
                if result:
                    _logger.info(
                        f"[ERC8004] Settlement reported for agent {agent_id}: "
                        f"{getattr(result, 'tx_hash', '')}"
                    )
            except Exception:
                # Errors already logged by the reporter — silently ignore.
                pass

    def get_registered_adapters(self) -> list:
        """
        Get all registered adapter IDs.

        Mirrors TS ``ACTPClient.getRegisteredAdapters`` (ACTPClient.ts:1645-1647).

        Returns:
            List of adapter IDs, e.g. ``["basic", "standard", "x402"]``.
        """
        return self._registry.get_ids()

    def get_reputation_reporter(self) -> Optional[object]:
        """
        Get the ERC-8004 Reputation Reporter instance.

        Only wired in testnet/mainnet modes; returns ``None`` in mock mode.
        Mirrors TS ``ACTPClient.getReputationReporter`` (ACTPClient.ts:1670-1672).

        Returns:
            ReputationReporter or ``None``.
        """
        return self._reputation_reporter

    def get_wallet_provider(self) -> Optional[object]:
        """
        Get the wallet provider instance (AIP-12).

        Only set in testnet/mainnet modes; returns ``None`` in mock mode.
        Mirrors TS ``ACTPClient.getWalletProvider`` (ACTPClient.ts:1683-1685).

        Returns:
            IWalletProvider (Auto or EOA) or ``None``.
        """
        return self._wallet_provider

    def get_activation_calls(self) -> Dict[str, Any]:
        """
        Get activation calls for lazy publish.

        Returns ``SmartWalletCall[]`` to prepend to the first payment UserOp,
        plus an ``on_success`` callback that deletes pending-publish.json.
        Returns empty calls when no activation is needed (scenario C/none) or
        the pending config is stale. Mirrors TS ``ACTPClient.getActivationCalls``
        (ACTPClient.ts:1696-1736).

        Returns:
            Dict with ``calls`` (List[SmartWalletCall]) and ``on_success`` (callable).
        """
        def _noop() -> None:
            return None

        if (
            self._lazy_scenario in ("none", "C")
            or not self._agent_registry_address
        ):
            return {"calls": [], "on_success": _noop}

        # Staleness check: AGIRAILS.md changed since last publish -> skip.
        if self._pending_is_stale:
            return {"calls": [], "on_success": _noop}

        pending = self._pending_publish
        if not pending:
            return {"calls": [], "on_success": _noop}

        from agirails.wallet.aa.transaction_batcher import (
            ActivationBatchParams,
            ServiceDescriptor,
            build_activation_batch,
        )

        params = ActivationBatchParams(
            scenario=self._lazy_scenario,  # type: ignore[arg-type]
            agent_registry_address=self._agent_registry_address,
            cid=pending.cid,
            config_hash=pending.config_hash,
            listed=True,
        )

        # For scenario A, thread registration params from pending publish.
        if self._lazy_scenario == "A":
            params.endpoint = pending.endpoint
            params.service_descriptors = [
                ServiceDescriptor(
                    service_type_hash=sd.service_type_hash,
                    service_type=sd.service_type,
                    schema_uri=sd.schema_uri,
                    min_price=int(sd.min_price),
                    max_price=int(sd.max_price),
                    avg_completion_time=sd.avg_completion_time,
                    metadata_cid=sd.metadata_cid,
                )
                for sd in (pending.service_descriptors or [])
            ]

        calls = build_activation_batch(params)

        def _on_success() -> None:
            try:
                from agirails.config.pending_publish import delete_pending_publish

                delete_pending_publish(network=self._network_id)
            except Exception:
                pass
            self._lazy_scenario = "none"
            self._pending_publish = None

        return {"calls": calls, "on_success": _on_success}

    def to_json(self) -> Dict[str, Any]:
        """
        Custom JSON serialization that excludes sensitive data.

        Prevents accidental private-key exposure when the client is serialized.
        Mirrors TS ``ACTPClient.toJSON`` (ACTPClient.ts:1236-1245).

        Returns:
            Safe serializable dict with sensitive data removed.
        """
        return {
            "mode": self._info.mode,
            "address": self._info.address,
            "stateDirectory": (
                str(self._info.state_directory)
                if self._info.state_directory is not None
                else None
            ),
            "isInitialized": True,
            "_warning": (
                "Sensitive data (privateKey, signer) excluded for security"
            ),
        }

    async def check_config_drift(
        self, config: Optional[ACTPClientConfig] = None
    ) -> None:
        """
        Non-blocking config sync / drift detection on startup (Faza B).

        Best-effort: pulls a newer web edit into the local identity file when
        auto-sync is enabled and the file carries a slug; otherwise emits a
        warning-only drift notice. Never blocks agent operation and swallows
        all errors. Mirrors TS ``ACTPClient.checkConfigDrift``
        (ACTPClient.ts:1753-1869) in its safe (read-only) direction.

        Args:
            config: Optional client config (for requester_address / mode).
        """
        try:
            import os
            from pathlib import Path

            if config is None:
                config = ACTPClientConfig(
                    mode=self._info.mode,
                    requester_address=self._info.address,
                )

            if config.mode == "mock":
                return

            # Resolve the identity file the agent publishes ({slug}.md) via the
            # .actp identity pointer, falling back to AGIRAILS.md.
            cwd = Path.cwd()
            identity_path = cwd / "AGIRAILS.md"
            try:
                import json as _json

                actp_dir = Path(os.environ.get("ACTP_DIR") or (cwd / ".actp"))
                cfg_path = actp_dir / "config.json"
                if cfg_path.exists():
                    cfg = _json.loads(cfg_path.read_text())
                    identity = cfg.get("identity")
                    if identity:
                        p = cwd / identity
                        if p.exists():
                            identity_path = p
            except Exception:
                pass

            if not identity_path.exists():
                return

            from agirails.config.networks import get_network

            network_name = (
                "base-sepolia" if config.mode == "testnet" else "base-mainnet"
            )
            network = get_network(network_name)
            if not getattr(network.contracts, "agent_registry", None):
                return  # No registry on this network.

            content = identity_path.read_text()
            from agirails.config.agirailsmd import (
                compute_config_hash,
                parse_agirails_md,
            )

            parsed = parse_agirails_md(content)
            frontmatter = getattr(parsed, "frontmatter", {}) or {}

            # AIP-18 DEC-3: a pure buyer (intent: pay) is never anchored
            # on-chain — chain drift/reconcile does not apply, so skip.
            agent_block = frontmatter.get("agent") if isinstance(frontmatter, dict) else None
            intent_val = None
            if isinstance(frontmatter, dict):
                intent_val = frontmatter.get("intent")
            if not intent_val and isinstance(agent_block, dict):
                intent_val = agent_block.get("intent")
            if isinstance(intent_val, str) and intent_val.lower() == "pay":
                return

            # Warning-only drift detection (the push direction stays with
            # `actp publish` — we never auto-spend gas at startup).
            hash_result = compute_config_hash(content)
            local_hash = getattr(hash_result, "config_hash", None) or (
                hash_result.get("config_hash") if isinstance(hash_result, dict) else None
            )
            has_config_hash = bool(
                frontmatter.get("config_hash") if isinstance(frontmatter, dict) else None
            )
            is_template = not has_config_hash

            from agirails.config.on_chain_state import get_on_chain_config_state

            agent_address = config.requester_address or self._info.address
            on_chain_state = await asyncio.to_thread(
                get_on_chain_config_state,
                agent_address,
                network_name,
                config.rpc_url,
            )
            on_chain_hash = on_chain_state.config_hash

            zero_hash = "0x" + "0" * 64
            if not on_chain_hash or on_chain_hash == zero_hash:
                if is_template:
                    _logger.info(
                        "[AGIRAILS] AGIRAILS.md loaded (template mode). "
                        'Run "actp publish" to register and sync on-chain.'
                    )
                else:
                    _logger.warn(
                        "[AGIRAILS] Config not published on-chain. Run: actp publish"
                    )
            elif on_chain_hash != local_hash:
                _logger.warn(
                    "[AGIRAILS] Local identity file differs from on-chain. "
                    "Run: actp diff"
                )
        except Exception:
            # Silently ignore — drift detection is best-effort.
            pass

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
