"""
ERC-8004 Identity Bridge.

Resolves agent identity, wallet address, and metadata from the canonical
ERC-8004 Identity Registry on Base L2. Uses a 1-minute in-memory cache
to reduce RPC calls.

Usage:
    >>> from agirails.erc8004 import ERC8004Bridge
    >>> from agirails.types.erc8004 import ERC8004BridgeConfig
    >>>
    >>> bridge = ERC8004Bridge(ERC8004BridgeConfig(network="base-sepolia"))
    >>> agent = await bridge.resolve_agent("42")
    >>> print(agent.wallet, agent.metadata.name)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from web3 import Web3

from agirails.types.erc8004 import (
    ERC8004_DEFAULT_RPC,
    ERC8004_IDENTITY_ABI,
    ERC8004_IDENTITY_REGISTRY,
    ERC8004Agent,
    ERC8004AgentMetadata,
    ERC8004BridgeConfig,
    ERC8004Error,
    ERC8004ErrorCode,
    is_valid_address,
    is_valid_erc8004_agent_id,
)

logger = logging.getLogger(__name__)


class ERC8004Bridge:
    """
    Bridge to the ERC-8004 Identity Registry.

    Resolves agent IDs to owner addresses, wallet addresses, agent URIs,
    and off-chain metadata. Results are cached with a configurable TTL
    (default 60 seconds).
    """

    def __init__(
        self,
        config: Optional[ERC8004BridgeConfig] = None,
        *,
        contract: Any = None,
    ) -> None:
        """
        Initialize the bridge.

        Args:
            config: Bridge configuration. Defaults to base-mainnet with public RPC.
            contract: Optional injected contract instance (for testing).
        """
        self._config = config or ERC8004BridgeConfig()
        self._cache: Dict[str, Tuple[ERC8004Agent, float]] = {}

        if contract is not None:
            # Test injection — skip web3 setup
            self._contract = contract
            self._w3: Optional[Web3] = None
        else:
            rpc_url = self._config.rpc_url or ERC8004_DEFAULT_RPC[self._config.network]
            self._w3 = Web3(Web3.HTTPProvider(rpc_url))
            registry_address = ERC8004_IDENTITY_REGISTRY[self._config.network]
            self._contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(registry_address),
                abi=ERC8004_IDENTITY_ABI,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify_agent(self, agent_id: str) -> bool:
        """
        Check whether an agent exists on-chain.

        Args:
            agent_id: Numeric token ID as a string.

        Returns:
            True if the agent exists, False otherwise.
        """
        # Fast path: cached
        cached = self._get_cached(agent_id)
        if cached is not None:
            return True

        if not self._is_valid_agent_id(agent_id):
            return False

        try:
            self._contract.functions.ownerOf(int(agent_id)).call()
            return True
        except Exception:
            return False

    async def get_agent_wallet(self, agent_id: str) -> str:
        """
        Resolve the payment wallet for an agent.

        Args:
            agent_id: Numeric token ID as a string.

        Returns:
            Checksummed wallet address.

        Raises:
            ERC8004Error: If agent not found or invalid ID.
        """
        agent = await self.resolve_agent(agent_id)
        return agent.wallet

    async def resolve_agent(self, agent_id: str) -> ERC8004Agent:
        """
        Fully resolve an agent: owner, URI, metadata, wallet.

        Wallet priority: metadata.payment_address > metadata.wallet > owner.

        Args:
            agent_id: Numeric token ID as a string.

        Returns:
            Resolved ERC8004Agent.

        Raises:
            ERC8004Error: If agent ID is invalid or agent not found.
        """
        # Cache check
        cached = self._get_cached(agent_id)
        if cached is not None:
            return cached

        # Validate
        if not self._is_valid_agent_id(agent_id):
            raise ERC8004Error(
                ERC8004ErrorCode.INVALID_AGENT_ID,
                f"Invalid agent ID: {agent_id}",
                {"agent_id": agent_id},
            )

        token_id = int(agent_id)

        # Fetch owner
        try:
            owner: str = self._contract.functions.ownerOf(token_id).call()
            owner = Web3.to_checksum_address(owner)
        except Exception as exc:
            raise ERC8004Error(
                ERC8004ErrorCode.AGENT_NOT_FOUND,
                f"Agent {agent_id} not found on-chain",
                {"agent_id": agent_id, "error": str(exc)},
            ) from exc

        # Fetch agent URI
        try:
            agent_uri: str = self._contract.functions.getAgentURI(token_id).call()
        except Exception:
            agent_uri = ""

        # Fetch metadata (never throws)
        metadata = await self._fetch_metadata(agent_uri)

        # Determine wallet with priority
        wallet = owner
        if metadata is not None:
            if metadata.payment_address and self._is_valid_address(metadata.payment_address):
                wallet = Web3.to_checksum_address(metadata.payment_address)
            elif metadata.wallet and self._is_valid_address(metadata.wallet):
                wallet = Web3.to_checksum_address(metadata.wallet)

        agent = ERC8004Agent(
            agent_id=str(agent_id),
            owner=owner,
            wallet=wallet,
            agent_uri=agent_uri,
            metadata=metadata,
            network=self._config.network,
        )

        # Cache
        self._cache[str(agent_id)] = (agent, time.monotonic())
        return agent

    async def get_agents_by_owner(self, owner: str) -> List[str]:
        """
        List all agent IDs owned by an address.

        Args:
            owner: Checksummed Ethereum address.

        Returns:
            List of agent ID strings.

        Raises:
            ERC8004Error: On invalid address or network error.
        """
        if not self._is_valid_address(owner):
            raise ERC8004Error(
                ERC8004ErrorCode.NETWORK_ERROR,
                f"Invalid owner address: {owner}",
                {"owner": owner},
            )

        try:
            checksum = Web3.to_checksum_address(owner)
            balance: int = self._contract.functions.balanceOf(checksum).call()
            agent_ids: List[str] = []
            for idx in range(balance):
                token_id: int = self._contract.functions.tokenOfOwnerByIndex(
                    checksum, idx
                ).call()
                agent_ids.append(str(token_id))
            return agent_ids
        except Exception as exc:
            raise ERC8004Error(
                ERC8004ErrorCode.NETWORK_ERROR,
                f"Failed to fetch agents for owner {owner}",
                {"owner": owner, "error": str(exc)},
            ) from exc

    def clear_cache(self) -> None:
        """Clear the entire agent cache."""
        self._cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with 'size', 'keys', and 'ttl_seconds'.
        """
        now = time.monotonic()
        valid = {
            k: v
            for k, (v, ts) in self._cache.items()
            if (now - ts) < self._config.cache_ttl_seconds
        }
        return {
            "size": len(valid),
            "keys": list(valid.keys()),
            "ttl_seconds": self._config.cache_ttl_seconds,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_valid_agent_id(agent_id: str) -> bool:
        return is_valid_erc8004_agent_id(agent_id)

    @staticmethod
    def _is_valid_address(address: str) -> bool:
        return is_valid_address(address)

    def _get_cached(self, agent_id: str) -> Optional[ERC8004Agent]:
        """Return cached agent if present and not expired."""
        entry = self._cache.get(str(agent_id))
        if entry is None:
            return None
        agent, ts = entry
        if (time.monotonic() - ts) >= self._config.cache_ttl_seconds:
            del self._cache[str(agent_id)]
            return None
        return agent

    async def _fetch_metadata(self, uri: str) -> Optional[ERC8004AgentMetadata]:
        """
        Fetch and parse agent metadata from a URI.

        Converts ipfs:// URIs to the configured IPFS gateway.
        Never throws — returns None on any failure.
        """
        if not uri:
            return None

        fetch_url = uri
        if uri.startswith("ipfs://"):
            cid_path = uri[len("ipfs://"):]
            fetch_url = f"{self._config.ipfs_gateway}{cid_path}"

        try:
            async with httpx.AsyncClient(timeout=self._config.metadata_timeout) as client:
                resp = await client.get(fetch_url)
                resp.raise_for_status()
                data = resp.json()

            return ERC8004AgentMetadata(
                name=data.get("name"),
                description=data.get("description"),
                wallet=data.get("wallet"),
                payment_address=data.get("paymentAddress") or data.get("payment_address"),
                services=data.get("services", []),
                image=data.get("image"),
                external_url=data.get("external_url"),
                raw=data,
            )
        except Exception as exc:
            logger.debug("Metadata fetch failed for URI %s: %s", uri, exc)
            return None
