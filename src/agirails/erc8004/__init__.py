"""
ERC-8004 Bridge and Reputation Reporter for AGIRAILS SDK.

Provides:
- ERC8004Bridge: Resolve agent identity, wallet, and metadata from on-chain registries.
- ReputationReporter: Report ACTP settlement/dispute outcomes to the reputation registry.

Example:
    >>> from agirails.erc8004 import ERC8004Bridge, ReputationReporter
    >>> from agirails.types.erc8004 import ERC8004BridgeConfig
    >>>
    >>> bridge = ERC8004Bridge(ERC8004BridgeConfig(network="base-mainnet"))
    >>> agent = await bridge.resolve_agent("42")
    >>> print(agent.wallet)
"""

from agirails.erc8004.bridge import ERC8004Bridge
from agirails.erc8004.reputation_reporter import ReputationReporter

__all__ = [
    "ERC8004Bridge",
    "ReputationReporter",
]
