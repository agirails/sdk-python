"""
Tests for ERC-8004 Identity Bridge.

Uses mock contracts (Protocol classes) to avoid real RPC calls.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from agirails.erc8004.bridge import ERC8004Bridge
from agirails.types.erc8004 import (
    ERC8004Agent,
    ERC8004BridgeConfig,
    ERC8004Error,
    ERC8004ErrorCode,
)


# ---------------------------------------------------------------------------
# Mock contract helpers
# ---------------------------------------------------------------------------

MOCK_OWNER = "0x1111111111111111111111111111111111111111"
MOCK_OWNER_CHECKSUMMED = "0x1111111111111111111111111111111111111111"
MOCK_WALLET = "0x2222222222222222222222222222222222222222"
MOCK_PAYMENT_ADDR = "0x3333333333333333333333333333333333333333"


class MockCallable:
    """Simulates a contract function call result."""

    def __init__(self, value: Any = None, *, raises: Optional[Exception] = None):
        self._value = value
        self._raises = raises

    def call(self) -> Any:
        if self._raises:
            raise self._raises
        return self._value


class MockFunctions:
    """Mock for contract.functions with configurable agents."""

    def __init__(self, agents: Optional[Dict[int, Dict[str, Any]]] = None):
        self._agents: Dict[int, Dict[str, Any]] = agents or {}

    def ownerOf(self, token_id: int) -> MockCallable:
        if token_id not in self._agents:
            return MockCallable(raises=Exception("ERC721: invalid token ID"))
        return MockCallable(self._agents[token_id]["owner"])

    def getAgentURI(self, token_id: int) -> MockCallable:
        if token_id not in self._agents:
            return MockCallable(raises=Exception("ERC721: invalid token ID"))
        return MockCallable(self._agents[token_id].get("uri", ""))

    def balanceOf(self, owner: str) -> MockCallable:
        count = sum(1 for a in self._agents.values() if a["owner"].lower() == owner.lower())
        return MockCallable(count)

    def tokenOfOwnerByIndex(self, owner: str, index: int) -> MockCallable:
        owned = [
            tid for tid, a in self._agents.items() if a["owner"].lower() == owner.lower()
        ]
        if index >= len(owned):
            return MockCallable(raises=Exception("ERC721Enumerable: out of bounds"))
        return MockCallable(owned[index])


class MockContract:
    """Mock ERC-8004 Identity Registry contract."""

    def __init__(self, agents: Optional[Dict[int, Dict[str, Any]]] = None):
        self.functions = MockFunctions(agents)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_bridge(
    agents: Optional[Dict[int, Dict[str, Any]]] = None,
    cache_ttl: int = 60,
) -> ERC8004Bridge:
    """Create a bridge with a mock contract."""
    contract = MockContract(agents or {})
    config = ERC8004BridgeConfig(
        network="base-sepolia",
        cache_ttl_seconds=cache_ttl,
    )
    return ERC8004Bridge(config, contract=contract)


METADATA_JSON = {
    "name": "TestAgent",
    "description": "A test agent",
    "wallet": MOCK_WALLET,
    "paymentAddress": MOCK_PAYMENT_ADDR,
    "services": [{"type": "text-generation"}],
}


# ---------------------------------------------------------------------------
# Tests: verify_agent
# ---------------------------------------------------------------------------


class TestVerifyAgent:
    async def test_returns_true_for_existing_agent(self):
        bridge = _make_bridge({42: {"owner": MOCK_OWNER}})
        assert await bridge.verify_agent("42") is True

    async def test_returns_false_for_nonexistent_agent(self):
        bridge = _make_bridge({})
        assert await bridge.verify_agent("999") is False

    async def test_returns_false_for_invalid_agent_id(self):
        bridge = _make_bridge({42: {"owner": MOCK_OWNER}})
        assert await bridge.verify_agent("not-a-number") is False
        assert await bridge.verify_agent("-1") is False
        assert await bridge.verify_agent("") is False

    async def test_uses_cache(self):
        bridge = _make_bridge({42: {"owner": MOCK_OWNER, "uri": ""}})
        # Resolve to populate cache
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=None):
            await bridge.resolve_agent("42")
        # Now verify should use cache (even if contract were removed)
        bridge._contract = MockContract({})
        assert await bridge.verify_agent("42") is True


# ---------------------------------------------------------------------------
# Tests: get_agent_wallet
# ---------------------------------------------------------------------------


class TestGetAgentWallet:
    async def test_returns_owner_when_no_metadata(self):
        bridge = _make_bridge({42: {"owner": MOCK_OWNER, "uri": ""}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=None):
            wallet = await bridge.get_agent_wallet("42")
        from web3 import Web3

        assert wallet == Web3.to_checksum_address(MOCK_OWNER)

    async def test_raises_for_nonexistent_agent(self):
        bridge = _make_bridge({})
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.get_agent_wallet("999")
        assert exc_info.value.code == ERC8004ErrorCode.AGENT_NOT_FOUND


# ---------------------------------------------------------------------------
# Tests: resolve_agent — wallet priority
# ---------------------------------------------------------------------------


class TestResolveAgentWalletPriority:
    async def test_payment_address_takes_highest_priority(self):
        """paymentAddress > wallet > owner"""
        from agirails.types.erc8004 import ERC8004AgentMetadata

        meta = ERC8004AgentMetadata(
            wallet=MOCK_WALLET,
            payment_address=MOCK_PAYMENT_ADDR,
        )
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": "https://example.com/meta.json"}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=meta):
            agent = await bridge.resolve_agent("1")
        from web3 import Web3

        assert agent.wallet == Web3.to_checksum_address(MOCK_PAYMENT_ADDR)

    async def test_wallet_used_when_no_payment_address(self):
        from agirails.types.erc8004 import ERC8004AgentMetadata

        meta = ERC8004AgentMetadata(wallet=MOCK_WALLET)
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": "https://example.com/meta.json"}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=meta):
            agent = await bridge.resolve_agent("1")
        from web3 import Web3

        assert agent.wallet == Web3.to_checksum_address(MOCK_WALLET)

    async def test_owner_used_when_no_wallet_fields(self):
        from agirails.types.erc8004 import ERC8004AgentMetadata

        meta = ERC8004AgentMetadata(name="NoWallet")
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": "https://example.com/meta.json"}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=meta):
            agent = await bridge.resolve_agent("1")
        from web3 import Web3

        assert agent.wallet == Web3.to_checksum_address(MOCK_OWNER)

    async def test_owner_used_when_metadata_is_none(self):
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": ""}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=None):
            agent = await bridge.resolve_agent("1")
        from web3 import Web3

        assert agent.wallet == Web3.to_checksum_address(MOCK_OWNER)


# ---------------------------------------------------------------------------
# Tests: resolve_agent — validation & errors
# ---------------------------------------------------------------------------


class TestResolveAgentErrors:
    async def test_invalid_agent_id_raises(self):
        bridge = _make_bridge({})
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("abc")
        assert exc_info.value.code == ERC8004ErrorCode.INVALID_AGENT_ID

    async def test_agent_not_found_raises(self):
        bridge = _make_bridge({})
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("999")
        assert exc_info.value.code == ERC8004ErrorCode.AGENT_NOT_FOUND

    async def test_resolve_populates_all_fields(self):
        from agirails.types.erc8004 import ERC8004AgentMetadata

        meta = ERC8004AgentMetadata(
            name="MyAgent",
            description="desc",
            wallet=MOCK_WALLET,
        )
        bridge = _make_bridge({7: {"owner": MOCK_OWNER, "uri": "https://example.com/7.json"}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=meta):
            agent = await bridge.resolve_agent("7")

        assert agent.agent_id == "7"
        assert agent.agent_uri == "https://example.com/7.json"
        assert agent.metadata is not None
        assert agent.metadata.name == "MyAgent"
        assert agent.network == "base-sepolia"


# ---------------------------------------------------------------------------
# Tests: cache
# ---------------------------------------------------------------------------


class TestCache:
    async def test_cache_ttl_expiry(self):
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": ""}}, cache_ttl=1)
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=None):
            await bridge.resolve_agent("1")

        # Should be cached
        stats = bridge.get_cache_stats()
        assert stats["size"] == 1

        # Wait for TTL
        time.sleep(1.1)

        stats = bridge.get_cache_stats()
        assert stats["size"] == 0

    async def test_clear_cache(self):
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": ""}})
        with patch.object(bridge, "_fetch_metadata", new_callable=AsyncMock, return_value=None):
            await bridge.resolve_agent("1")

        assert bridge.get_cache_stats()["size"] == 1
        bridge.clear_cache()
        assert bridge.get_cache_stats()["size"] == 0


# ---------------------------------------------------------------------------
# Tests: IPFS URI conversion
# ---------------------------------------------------------------------------


class TestIPFSConversion:
    async def test_ipfs_uri_converted_to_gateway(self):
        """Verify ipfs:// URIs are rewritten to the configured gateway."""
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": "ipfs://QmHash123/meta.json"}})

        captured_urls: List[str] = []

        async def mock_fetch(uri: str):
            captured_urls.append(uri)
            return None

        # Patch the _fetch_metadata to capture what URL it gets
        # We actually need to test the internal conversion, so let's
        # test at a lower level by calling _fetch_metadata directly
        # with a mock httpx client
        import httpx
        from unittest.mock import MagicMock

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"name": "Test"}
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await bridge._fetch_metadata("ipfs://QmHash123/meta.json")

            # Verify the gateway URL was used
            call_args = mock_client.get.call_args
            assert "https://ipfs.io/ipfs/QmHash123/meta.json" in str(call_args)


# ---------------------------------------------------------------------------
# Tests: metadata fetch failure
# ---------------------------------------------------------------------------


class TestMetadataFetchFailure:
    async def test_returns_none_on_http_error(self):
        bridge = _make_bridge({1: {"owner": MOCK_OWNER, "uri": "https://example.com/bad.json"}})
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
            mock_client_cls.return_value = mock_client

            result = await bridge._fetch_metadata("https://example.com/bad.json")
            assert result is None

    async def test_returns_none_on_empty_uri(self):
        bridge = _make_bridge({})
        result = await bridge._fetch_metadata("")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: get_agents_by_owner
# ---------------------------------------------------------------------------


class TestGetAgentsByOwner:
    async def test_returns_agent_ids_for_owner(self):
        bridge = _make_bridge({
            10: {"owner": MOCK_OWNER},
            20: {"owner": MOCK_OWNER},
            30: {"owner": "0x4444444444444444444444444444444444444444"},
        })
        agents = await bridge.get_agents_by_owner(MOCK_OWNER)
        assert set(agents) == {"10", "20"}

    async def test_returns_empty_for_unknown_owner(self):
        bridge = _make_bridge({10: {"owner": MOCK_OWNER}})
        agents = await bridge.get_agents_by_owner(
            "0x5555555555555555555555555555555555555555"
        )
        assert agents == []

    async def test_raises_on_invalid_address(self):
        bridge = _make_bridge({})
        with pytest.raises(ERC8004Error):
            await bridge.get_agents_by_owner("not-an-address")
