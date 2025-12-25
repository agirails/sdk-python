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
# Redeployed 2025-12-10 by Arha (new deployer wallet 0x42a2f11555b9363fb7ebdcdc76d7cb26e01dcb00)
# ============================================================================

BASE_SEPOLIA = NetworkConfig(
    name="Base Sepolia",
    chain_id=84532,
    rpc_url=BASE_SEPOLIA_RPC_URL,
    block_explorer="https://sepolia.basescan.org",
    contracts=ContractAddresses(
        actp_kernel="0xD199070F8e9FB9a127F6Fe730Bc13300B4b3d962",
        escrow_vault="0x948b9Ea081C4Cec1E112Af2e539224c531d4d585",
        usdc="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",  # MockUSDC
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry="0xFed6914Aa70c0a53E9c7Cc4d2Ae159e4748fb09D",  # AIP-7
    ),
    eas=EASConfig(
        # Deployed 2025-11-23 - AIP-4 delivery proof schema
        delivery_schema_uid="0x1b0ebdf0bd20c28ec9d5362571ce8715a55f46e81c3de2f9b0d8e1b95fb5ffce"
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=2_000_000_000,  # 2 gwei
        max_priority_fee_per_gas=1_000_000_000,  # 1 gwei
    ),
)


# ============================================================================
# Base Mainnet Configuration
# ============================================================================
# WARNING: Mainnet contracts are NOT YET DEPLOYED.
# Using 'base-mainnet' will throw an error until contracts are deployed.
# Use 'base-sepolia' for testnet development.
# ============================================================================

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ZERO_BYTES32 = "0x" + "0" * 64

BASE_MAINNET = NetworkConfig(
    name="Base Mainnet",
    chain_id=8453,
    rpc_url=BASE_MAINNET_RPC_URL,
    block_explorer="https://basescan.org",
    contracts=ContractAddresses(
        actp_kernel=ZERO_ADDRESS,  # NOT DEPLOYED
        escrow_vault=ZERO_ADDRESS,  # NOT DEPLOYED
        usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Official USDC on Base
        eas="0x4200000000000000000000000000000000000021",  # Base native EAS
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        agent_registry=None,  # NOT DEPLOYED
    ),
    eas=EASConfig(
        delivery_schema_uid=ZERO_BYTES32  # NOT DEPLOYED
    ),
    gas_settings=GasSettings(
        max_fee_per_gas=500_000_000,  # 0.5 gwei
        max_priority_fee_per_gas=100_000_000,  # 0.1 gwei
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
