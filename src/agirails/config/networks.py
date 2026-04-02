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


@dataclass(frozen=True)
class ContractAddresses:
    """Contract addresses for a network."""

    actp_kernel: str
    escrow_vault: str
    usdc: str
    eas: str
    eas_schema_registry: str
    agent_registry: Optional[str] = None


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
# Redeployed 2026-02-06 with agentId support, AgentRegistry v2 2026-02-09
# ============================================================================

BASE_SEPOLIA = NetworkConfig(
    name="Base Sepolia",
    chain_id=84532,
    rpc_url=BASE_SEPOLIA_RPC_URL,
    block_explorer="https://sepolia.basescan.org",
    contracts=ContractAddresses(
        actp_kernel="0x90a1Bcc218c148F63D036aB2f7B5329C9ee7868d",
        escrow_vault="0xA336967F4481EeE4A8Bb59e35423D273fbf9f5e7",
        usdc="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",  # MockUSDC
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry="0x7403426a720f91ea155405e3b63d16aa40a46f98",  # AIP-7 v2
    ),
    eas=EASConfig(
        # Deployed 2025-11-23 - AIP-4 delivery proof schema
        delivery_schema_uid="0x1b0ebdf0bd20c28ec9d5362571ce8715a55f46e81c3de2f9b0d8e1b95fb5ffce"
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=2_000_000_000,  # 2 gwei
        max_priority_fee_per_gas=1_000_000_000,  # 1 gwei
    ),
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
# Redeployed 2026-02-09 with agentId + AgentRegistry v2
# ============================================================================

BASE_MAINNET = NetworkConfig(
    name="Base Mainnet",
    chain_id=8453,
    rpc_url=BASE_MAINNET_RPC_URL,
    block_explorer="https://basescan.org",
    contracts=ContractAddresses(
        actp_kernel="0x132B9eB321dBB57c828B083844287171BDC92d29",
        escrow_vault="0x6aAF45882c4b0dD34130ecC790bb5Ec6be7fFb99",
        usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Official USDC on Base
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry="0x6fB222CF3DDdf37Bcb248EE7BBBA42Fb41901de8",
    ),
    eas=EASConfig(
        delivery_schema_uid="0x166501e7476e2fcf9214c4c5144533c2957d56fe59d639effc1719a0658d9c9a"
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=500_000_000,  # 0.5 gwei
        max_priority_fee_per_gas=100_000_000,  # 0.1 gwei
    ),
    # Security audit passed February 2026 — no findings. No transaction limit.
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
