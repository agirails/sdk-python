"""Network configuration for AGIRAILS SDK.

This module contains network configurations for supported blockchains.
Environment variables take priority over hardcoded defaults.

Environment Variables:
    BASE_SEPOLIA_RPC - Custom RPC for Base Sepolia testnet
    BASE_MAINNET_RPC - Custom RPC for Base Mainnet
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

from agirails.errors import ValidationError


# ============================================================================
# Account Abstraction (ERC-4337) Configuration
# ============================================================================

# Canonical addresses (same on all EVM chains)
ENTRYPOINT_V06 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
SMART_WALLET_FACTORY = "0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842"


def _resolve_coinbase_rpc_url(network_path: str, override_env: str, *, fallback_key: str = "2txciN85t41erCjveqgNnXYyHRcoo5xP") -> str:
    """Resolve Coinbase bundler/paymaster RPC URL.

    Priority: env override → CDP_API_KEY → hardcoded fallback key.
    Env var naming matches TS SDK networks.ts (CDP_API_KEY, NOT CDP_CLIENT_KEY).
    """
    override = os.environ.get(override_env, "").strip()
    if override:
        return override
    cdp_key = os.environ.get("CDP_API_KEY", "").strip() or fallback_key
    return f"https://api.developer.coinbase.com/rpc/v1/{network_path}/{cdp_key}"


def _resolve_pimlico_rpc_url(chain_id: int) -> str:
    """Resolve Pimlico bundler/paymaster RPC URL. Empty string if no API key."""
    api_key = os.environ.get("PIMLICO_API_KEY", "").strip()
    if not api_key:
        return ""
    return f"https://api.pimlico.io/v2/{chain_id}/rpc?apikey={api_key}"


@dataclass(frozen=True)
class AAConfig:
    """Account Abstraction (ERC-4337) configuration for a network."""

    entry_point: str
    smart_wallet_factory: str
    bundler_urls: Dict[str, str]
    paymaster_urls: Dict[str, str]


# ============================================================================
# RPC URL Configuration
# ============================================================================
# Environment variables take priority over hardcoded defaults.
# This prevents accidental API key leakage if developers modify this file.
# Public RPC endpoints are used as fallbacks for ease of use.
# ============================================================================

BASE_SEPOLIA_RPC_URL = os.environ.get("BASE_SEPOLIA_RPC", "https://sepolia.base.org")
BASE_MAINNET_RPC_URL = os.environ.get("BASE_MAINNET_RPC", "https://mainnet.base.org")


def using_public_rpc(network: str) -> bool:
    """True when the active network falls back to the bundled PUBLIC RPC.

    Mirrors TS ``usingPublicRpc`` (config/networks.ts:31-36). Returns True when
    no ``BASE_SEPOLIA_RPC`` / ``BASE_MAINNET_RPC`` override is set for the
    network in use. Public RPCs serve one-shot transactions fine but cap
    ``eth_getLogs`` (~2000 blocks) and garbage-collect long-lived filters — so a
    24/7 provider listener that watches on-chain may silently miss jobs.
    Long-running listeners should warn on this.

    Args:
        network: Network name (e.g. 'base-sepolia', 'base-mainnet', 'mock').

    Returns:
        True if the bundled public RPC is being used (no env override).
    """
    n = network.lower()
    if "mock" in n:
        return False
    if "mainnet" in n:
        return not os.environ.get("BASE_MAINNET_RPC")
    # testnet / base-sepolia / default
    return not os.environ.get("BASE_SEPOLIA_RPC")


@dataclass(frozen=True)
class ContractAddresses:
    """Contract addresses for a network."""

    actp_kernel: str
    escrow_vault: str
    usdc: str
    eas: str
    eas_schema_registry: str
    agent_registry: Optional[str] = None
    archive_treasury: Optional[str] = None
    identity_registry: Optional[str] = None  # AIP-7 (Sepolia only; ERC-1056 DID registry)
    x402_relay: Optional[str] = None  # deprecated since SDK 3.3.0 (zero on mainnet V3)
    erc8004_identity_registry: Optional[str] = None  # ERC-8004 canonical CREATE2 (same on all chains)


@dataclass(frozen=True)
class EASConfig:
    """EAS (Ethereum Attestation Service) configuration."""

    delivery_schema_uid: str


@dataclass(frozen=True)
class GasSettings:
    """Gas settings for transactions."""

    max_fee_per_gas: int  # in wei
    max_priority_fee_per_gas: int  # in wei


@dataclass(frozen=True)
class NetworkConfig:
    """Network configuration."""

    name: str
    chain_id: int
    rpc_url: str
    block_explorer: str
    contracts: ContractAddresses
    eas: EASConfig
    gas_settings: GasSettings
    # SECURITY: Maximum transaction amount in USDC (human-readable, e.g., 100 = $100)
    # Limits exposure on unaudited mainnet contracts. None = no limit (testnet).
    max_transaction_amount: Optional[int] = None
    # Account Abstraction config (None for mock network)
    aa: Optional[AAConfig] = None
    # Deploy block of the ACTPKernel contract on this chain. Consumed by
    # ``BlockchainRuntime.get_all_transactions()`` as the lower-bound floor
    # for initial event-log scans (since 3.0.0). The runtime picks
    # ``max(deployment_block, latest - 50_000)`` so newly-deployed
    # contracts scan only the small slice from deploy → now, and older
    # contracts still get the 50k-block heuristic cap. ``None`` means
    # "deploy block unknown" — runtime falls back to the bare 50k window.
    actp_kernel_deployment_block: Optional[int] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "chainId": self.chain_id,
            "rpcUrl": self.rpc_url,
            "blockExplorer": self.block_explorer,
            "contracts": {
                "actpKernel": self.contracts.actp_kernel,
                "escrowVault": self.contracts.escrow_vault,
                "usdc": self.contracts.usdc,
                "eas": self.contracts.eas,
                "easSchemaRegistry": self.contracts.eas_schema_registry,
                "agentRegistry": self.contracts.agent_registry,
                "archiveTreasury": self.contracts.archive_treasury,
                "identityRegistry": self.contracts.identity_registry,
                "x402Relay": self.contracts.x402_relay,
                "erc8004IdentityRegistry": self.contracts.erc8004_identity_registry,
            },
            "eas": {
                "deliverySchemaUID": self.eas.delivery_schema_uid,
            },
            "gasSettings": {
                "maxFeePerGas": self.gas_settings.max_fee_per_gas,
                "maxPriorityFeePerGas": self.gas_settings.max_priority_fee_per_gas,
            },
        }


# ============================================================================
# Base Sepolia Testnet Configuration
# ============================================================================
# Redeployed 2026-05-19 (V4): solc 0.8.34, INV-30 disputeBondBpsLocked,
# AIP-14 dispute bonds, M-2 mediator timelock fix. Aligns Sepolia ABI shape
# with mainnet V3. All 4 contracts Sourcify EXACT_MATCH verified.
# See actp-kernel deployments/base-sepolia.json for deploy block, tx hashes,
# Sourcify match IDs.
# ============================================================================

BASE_SEPOLIA = NetworkConfig(
    name="Base Sepolia",
    chain_id=84532,
    rpc_url=BASE_SEPOLIA_RPC_URL,
    block_explorer="https://sepolia.basescan.org",
    contracts=ContractAddresses(
        actp_kernel="0x9d25A874f046185d9237Cd4954C88D2B74B0021b",
        escrow_vault="0x7dF07327090efcA73DCBa70414aA3131Fc6d2efB",
        usdc="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",  # MockUSDC
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry="0xD91F9aBfBf60b4a2Fd5317ab0cDF3F44faB5D656",
        archive_treasury="0x2eE4f7bE289fc9EFC2F9f2D6E53e50abDF23A3eb",
        identity_registry="0xce9749c768b425fab0daa0331047d1340ec99a88",  # AGIRAILSIdentityRegistry
        x402_relay="0x110b25bb3d45c40dfcf34bb451aa7069b2a1cb3b",  # deprecated since SDK 3.3.0
        erc8004_identity_registry="0x8004A818BFB912233c491871b3d84c89A494BD9e",
    ),
    eas=EASConfig(
        # Deployed 2025-11-23 - AIP-4 delivery proof schema
        delivery_schema_uid="0x1b0ebdf0bd20c28ec9d5362571ce8715a55f46e81c3de2f9b0d8e1b95fb5ffce"
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=2_000_000_000,  # 2 gwei
        max_priority_fee_per_gas=1_000_000_000,  # 1 gwei
    ),
    actp_kernel_deployment_block=41_725_686,  # V4 deploy on 2026-05-19
    aa=AAConfig(
        entry_point=ENTRYPOINT_V06,
        smart_wallet_factory=SMART_WALLET_FACTORY,
        bundler_urls={
            "coinbase": _resolve_coinbase_rpc_url("base-sepolia", "CDP_BUNDLER_URL"),
            "pimlico": _resolve_pimlico_rpc_url(84532),
        },
        paymaster_urls={
            "coinbase": _resolve_coinbase_rpc_url("base-sepolia", "CDP_PAYMASTER_URL"),
            "pimlico": _resolve_pimlico_rpc_url(84532),
        },
    ),
)


# ============================================================================
# Base Mainnet Configuration
# ============================================================================
# Redeployed 2026-05-19 (V3): solc 0.8.34, INV-30 disputeBondBpsLocked,
# AIP-14 dispute bonds, MIN_FEE on-chain, M-2 mediator timelock fix.
# Admin / pauser / feeRecipient: Treasury Safe 2-of-4 (0x61fE58E9…b7f2).
# All 4 contracts Sourcify EXACT_MATCH verified.
# Note: X402Relay NOT redeployed on mainnet V3 — x402 v2 routes payments
# directly buyer→seller via @x402/fetch + facilitator (zero AGIRAILS fee).
# See actp-kernel deployments/base-mainnet.json for deploy details.
# ============================================================================

BASE_MAINNET = NetworkConfig(
    name="Base Mainnet",
    chain_id=8453,
    rpc_url=BASE_MAINNET_RPC_URL,
    block_explorer="https://basescan.org",
    contracts=ContractAddresses(
        actp_kernel="0x048c811352e8a3fECd5b0Ec4AA2c2b94083CC842",
        escrow_vault="0x262D5912A9612F0c66dA5d13B4E678D50ebC44b5",
        usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Official USDC on Base
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry="0x64Cb18bfb3CC1aCb1370a3B01613391D3561a009",
        archive_treasury="0x6159A80Ce8362aBB2307FbaB4Ed4D3F4A4231Acc",
        # identity_registry: not deployed on mainnet (Sepolia-only AGIRAILSIdentityRegistry)
        # x402_relay: deprecated, NOT redeployed in V3 stack
        erc8004_identity_registry="0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    ),
    eas=EASConfig(
        delivery_schema_uid="0x166501e7476e2fcf9214c4c5144533c2957d56fe59d639effc1719a0658d9c9a"
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=500_000_000,  # 0.5 gwei
        max_priority_fee_per_gas=100_000_000,  # 0.1 gwei
    ),
    # SECURITY: $1,000 max tx limit on mainnet (None on testnet).
    max_transaction_amount=1000,
    actp_kernel_deployment_block=46_212_266,  # V3 deploy on 2026-05-19
    aa=AAConfig(
        entry_point=ENTRYPOINT_V06,
        smart_wallet_factory=SMART_WALLET_FACTORY,
        bundler_urls={
            "coinbase": _resolve_coinbase_rpc_url("base", "CDP_BUNDLER_URL"),
            "pimlico": _resolve_pimlico_rpc_url(8453),
        },
        paymaster_urls={
            "coinbase": _resolve_coinbase_rpc_url("base", "CDP_PAYMASTER_URL"),
            "pimlico": _resolve_pimlico_rpc_url(8453),
        },
    ),
)


# ============================================================================
# Network Registry
# ============================================================================

NETWORKS: Dict[str, NetworkConfig] = {
    "base-sepolia": BASE_SEPOLIA,
    "base-mainnet": BASE_MAINNET,
}


def get_network(network: str) -> NetworkConfig:
    """Get network configuration by name.

    Args:
        network: Network name (e.g., 'base-sepolia', 'base-mainnet')

    Returns:
        NetworkConfig for the requested network

    Raises:
        ValidationError: If network is unknown or contracts not deployed
    """
    config = NETWORKS.get(network)
    if config is None:
        supported = ", ".join(NETWORKS.keys())
        raise ValidationError(
            f"Unknown network: {network}. Supported networks: {supported}",
            field="network",
            value=network,
        )

    # Validate that contracts are deployed
    validate_network_config(config)

    return config


def is_valid_network(network: str) -> bool:
    """Check if network name is valid.

    Args:
        network: Network name to check

    Returns:
        True if network is supported
    """
    return network in NETWORKS


ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def validate_network_config(config: NetworkConfig) -> None:
    """Validate that contract addresses are deployed.

    Args:
        config: Network configuration to validate

    Raises:
        ValidationError: If any required contract is not deployed
    """
    errors = []

    if config.contracts.actp_kernel == ZERO_ADDRESS:
        errors.append("ACTPKernel address is zero - contracts not yet deployed")

    if config.contracts.escrow_vault == ZERO_ADDRESS:
        errors.append("EscrowVault address is zero - contracts not yet deployed")

    if config.contracts.usdc == ZERO_ADDRESS:
        errors.append("USDC address is zero - token not configured")

    if errors:
        error_list = "\n  - ".join(errors)
        raise ValidationError(
            f"Network configuration error for {config.name} (chainId: {config.chain_id}):\n"
            f"  - {error_list}\n\n"
            f"Contracts must be deployed before using the SDK. Please:\n"
            f"  1. Deploy contracts to {config.name}\n"
            f"  2. Update agirails/config/networks.py with deployed addresses",
            field="network",
            value=config.name,
        )
