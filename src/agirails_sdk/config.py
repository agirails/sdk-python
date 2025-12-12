from dataclasses import dataclass
from enum import Enum
from typing import Optional

__all__ = ["Network", "NetworkConfig", "NETWORKS", "get_network_config"]


class Network(str, Enum):
    BASE_SEPOLIA = "base-sepolia"
    BASE = "base"


@dataclass
class NetworkConfig:
    name: Network
    chain_id: int
    rpc_url: str
    actp_kernel: str
    escrow_vault: str
    usdc: str
    eas: str
    eas_schema_registry: str
    delivery_schema_uid: str
    agent_registry: str


NETWORKS: dict[Network, NetworkConfig] = {
    Network.BASE_SEPOLIA: NetworkConfig(
        name=Network.BASE_SEPOLIA,
        chain_id=84532,
        rpc_url="https://sepolia.base.org",
        # Redeployed 2025-12-10 by Arha (new deployer wallet 0x42a2f11555b9363fb7ebdcdc76d7cb26e01dcb00)
        actp_kernel="0xD199070F8e9FB9a127F6Fe730Bc13300B4b3d962",
        escrow_vault="0x948b9Ea081C4Cec1E112Af2e539224c531d4d585",
        usdc="0x444b4e1A65949AB2ac75979D5d0166Eb7A248Ccb",
        eas="0x4200000000000000000000000000000000000021",
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        delivery_schema_uid="0x1b0ebdf0bd20c28ec9d5362571ce8715a55f46e81c3de2f9b0d8e1b95fb5ffce",
        agent_registry="0xFed6914Aa70c0a53E9c7Cc4d2Ae159e4748fb09D",  # AIP-7 deployed 2025-12-11
    ),
    Network.BASE: NetworkConfig(
        name=Network.BASE,
        chain_id=8453,
        rpc_url="https://mainnet.base.org",
        actp_kernel="0x0000000000000000000000000000000000000000",  # TODO: update when live
        escrow_vault="0x0000000000000000000000000000000000000000",
        usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        eas="0x4200000000000000000000000000000000000021",
        eas_schema_registry="0x4200000000000000000000000000000000000020",
        delivery_schema_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
        agent_registry="0x0000000000000000000000000000000000000000",
    ),
}


def get_network_config(network: Network, rpc_url: Optional[str] = None) -> NetworkConfig:
    cfg = NETWORKS[network]
    if rpc_url:
        return NetworkConfig(
            name=cfg.name,
            chain_id=cfg.chain_id,
            rpc_url=rpc_url,
            actp_kernel=cfg.actp_kernel,
            escrow_vault=cfg.escrow_vault,
            usdc=cfg.usdc,
            eas=cfg.eas,
            eas_schema_registry=cfg.eas_schema_registry,
            delivery_schema_uid=cfg.delivery_schema_uid,
            agent_registry=cfg.agent_registry,
        )
    return cfg
