"""Shared on-chain state models and reader functions.

Provides two state models:
- OnChainConfigState: lightweight (config hash + CID), for diff/pull
- OnChainAgentState: full struct (registered_at + config_hash + listed), for publish scenario detection

Extracts duplicated _get_on_chain_reader() from diff.py and pull.py into a shared module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

ZERO_HASH = "0x" + "0" * 64


class OnChainStateError(Exception):
    """Raised when on-chain state cannot be read due to RPC/network errors.

    Callers should catch this and distinguish it from "not registered"
    (which returns default state with ZERO_HASH / registered_at=0).
    """


@dataclass
class OnChainConfigState:
    """Minimal config state for diff/pull operations.

    Backward-compatible replacement for OnChainConfigReader in sync_operations.py.
    """

    config_hash: str
    config_cid: str

    @property
    def has_config(self) -> bool:
        return self.config_hash != ZERO_HASH and self.config_cid != ""


@dataclass
class OnChainAgentState:
    """Full agent state for publish scenario detection (TS parity).

    Maps to TS: OnChainAgentState { registeredAt, configHash, listed }
    from ACTPClient.ts. Uses full getAgent() struct call.
    """

    registered_at: int  # uint256 timestamp, 0 = not registered
    config_hash: str  # bytes32
    listed: bool  # marketplace listing flag
    config_cid: str = ""  # also available from getAgent()

    @property
    def is_registered(self) -> bool:
        return self.registered_at > 0


def get_on_chain_config_state(
    address: str,
    network: str,
    rpc_url: Optional[str] = None,
) -> OnChainConfigState:
    """Read config hash + CID via separate getConfigHash()/getConfigCID() calls.

    Lightweight — used by diff.py and pull.py where only hash+CID matter.
    Extracted from duplicated _get_on_chain_reader() in diff.py/pull.py.
    """
    try:
        from agirails.config.networks import get_network

        net_config = get_network(network)
        if not net_config.contracts.agent_registry:
            return OnChainConfigState(config_hash=ZERO_HASH, config_cid="")

        try:
            from web3 import Web3

            rpc = rpc_url or net_config.rpc_url
            w3 = Web3(Web3.HTTPProvider(rpc))

            abi = [
                {
                    "type": "function",
                    "name": "getConfigHash",
                    "inputs": [{"name": "agentAddress", "type": "address"}],
                    "outputs": [{"name": "", "type": "bytes32"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "getConfigCID",
                    "inputs": [{"name": "agentAddress", "type": "address"}],
                    "outputs": [{"name": "", "type": "string"}],
                    "stateMutability": "view",
                },
            ]

            contract = w3.eth.contract(
                address=w3.to_checksum_address(net_config.contracts.agent_registry),
                abi=abi,
            )

            config_hash_bytes = contract.functions.getConfigHash(
                w3.to_checksum_address(address)
            ).call()
            config_hash = "0x" + config_hash_bytes.hex()

            config_cid = contract.functions.getConfigCID(
                w3.to_checksum_address(address)
            ).call()

            return OnChainConfigState(config_hash=config_hash, config_cid=config_cid)

        except ImportError:
            # web3 not installed — return defaults (no on-chain access)
            return OnChainConfigState(config_hash=ZERO_HASH, config_cid="")
        except Exception as e:
            raise OnChainStateError(
                f"Failed to read config state from {network}: {e}"
            ) from e

    except ImportError:
        return OnChainConfigState(config_hash=ZERO_HASH, config_cid="")
    except OnChainStateError:
        raise
    except Exception as e:
        raise OnChainStateError(
            f"Failed to initialize on-chain reader for {network}: {e}"
        ) from e


# Full getAgent() struct ABI — matches TS getOnChainAgentState() in ACTPClient.ts
_GET_AGENT_ABI = [
    {
        "type": "function",
        "name": "getAgent",
        "inputs": [{"name": "agentAddress", "type": "address"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "agentAddress", "type": "address"},
                    {"name": "did", "type": "string"},
                    {"name": "endpoint", "type": "string"},
                    {"name": "serviceTypes", "type": "bytes32[]"},
                    {"name": "stakedAmount", "type": "uint256"},
                    {"name": "reputationScore", "type": "uint256"},
                    {"name": "totalTransactions", "type": "uint256"},
                    {"name": "disputedTransactions", "type": "uint256"},
                    {"name": "totalVolumeUSDC", "type": "uint256"},
                    {"name": "registeredAt", "type": "uint256"},
                    {"name": "updatedAt", "type": "uint256"},
                    {"name": "isActive", "type": "bool"},
                    {"name": "configHash", "type": "bytes32"},
                    {"name": "configCID", "type": "string"},
                    {"name": "listed", "type": "bool"},
                ],
            }
        ],
        "stateMutability": "view",
    }
]


def get_on_chain_agent_state(
    address: str,
    network: str,
    rpc_url: Optional[str] = None,
) -> OnChainAgentState:
    """Read full agent state via getAgent() struct call.

    Used by publish scenario detection where registered_at + listed are needed
    for A/B1/B2/C scenario discrimination.
    """
    try:
        from agirails.config.networks import get_network

        net_config = get_network(network)
        if not net_config.contracts.agent_registry:
            return OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)

        try:
            from web3 import Web3

            rpc = rpc_url or net_config.rpc_url
            w3 = Web3(Web3.HTTPProvider(rpc))

            contract = w3.eth.contract(
                address=w3.to_checksum_address(net_config.contracts.agent_registry),
                abi=_GET_AGENT_ABI,
            )

            profile = contract.functions.getAgent(
                w3.to_checksum_address(address)
            ).call()

            # Tuple fields match ABI order
            registered_at = profile[9]  # registeredAt
            config_hash_bytes = profile[12]  # configHash
            config_cid = profile[13]  # configCID
            listed = profile[14]  # listed

            config_hash = "0x" + (config_hash_bytes.hex() if isinstance(config_hash_bytes, bytes) else str(config_hash_bytes))

            return OnChainAgentState(
                registered_at=int(registered_at),
                config_hash=config_hash,
                listed=bool(listed),
                config_cid=config_cid,
            )

        except ImportError:
            return OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
        except Exception as e:
            raise OnChainStateError(
                f"Failed to read agent state from {network}: {e}"
            ) from e

    except ImportError:
        return OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
    except OnChainStateError:
        raise
    except Exception as e:
        raise OnChainStateError(
            f"Failed to initialize on-chain reader for {network}: {e}"
        ) from e


__all__ = [
    "OnChainConfigState",
    "OnChainAgentState",
    "OnChainStateError",
    "get_on_chain_config_state",
    "get_on_chain_agent_state",
    "ZERO_HASH",
]
