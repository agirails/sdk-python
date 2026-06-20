"""Parity tests for ERC8004Bridge.resolve_agent error distinction (TS v4.8.0).

PARITY: ERC8004Bridge.ts:233-269. ``resolve_agent`` must distinguish a genuine
"token does not exist" revert (AGENT_NOT_FOUND) from an RPC/network failure
(NETWORK_ERROR), and treat a zero-address owner as not-found.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from agirails.erc8004.bridge import ERC8004Bridge
from agirails.types.erc8004 import (
    ERC8004BridgeConfig,
    ERC8004Error,
    ERC8004ErrorCode,
)


ZERO = "0x0000000000000000000000000000000000000000"
OWNER = "0x" + "a" * 40


class _Callable:
    def __init__(self, value: Any = None, raises: Optional[BaseException] = None):
        self._value = value
        self._raises = raises

    def call(self) -> Any:
        if self._raises is not None:
            raise self._raises
        return self._value


class _Functions:
    """Configurable contract.functions: owner value or raising ownerOf."""

    def __init__(self, owner_value: Any = None, owner_raises: Optional[BaseException] = None):
        self._owner_value = owner_value
        self._owner_raises = owner_raises

    def ownerOf(self, token_id: int) -> _Callable:
        return _Callable(value=self._owner_value, raises=self._owner_raises)

    def getAgentURI(self, token_id: int) -> _Callable:
        return _Callable(value="")


class _Contract:
    def __init__(self, **kwargs):
        self.functions = _Functions(**kwargs)


def _make_bridge(**kwargs) -> ERC8004Bridge:
    config = ERC8004BridgeConfig(network="base-sepolia", cache_ttl_seconds=60)
    return ERC8004Bridge(config, contract=_Contract(**kwargs))


class TestResolveAgentErrorDistinction:
    async def test_token_not_found_raises_agent_not_found(self):
        bridge = _make_bridge(owner_raises=Exception("execution reverted: ERC721NonexistentToken(7)"))
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("7")
        assert exc_info.value.code == ERC8004ErrorCode.AGENT_NOT_FOUND

    async def test_invalid_token_message_raises_agent_not_found(self):
        bridge = _make_bridge(owner_raises=Exception("ERC721: invalid token ID"))
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("99")
        assert exc_info.value.code == ERC8004ErrorCode.AGENT_NOT_FOUND

    async def test_rpc_failure_raises_network_error(self):
        bridge = _make_bridge(owner_raises=Exception("Connection refused: max retries exceeded"))
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("7")
        # Must NOT be misclassified as AGENT_NOT_FOUND.
        assert exc_info.value.code == ERC8004ErrorCode.NETWORK_ERROR

    async def test_timeout_raises_network_error(self):
        bridge = _make_bridge(owner_raises=TimeoutError("read timed out"))
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("7")
        assert exc_info.value.code == ERC8004ErrorCode.NETWORK_ERROR

    async def test_zero_address_owner_raises_agent_not_found(self):
        bridge = _make_bridge(owner_value=ZERO)
        with pytest.raises(ERC8004Error) as exc_info:
            await bridge.resolve_agent("7")
        assert exc_info.value.code == ERC8004ErrorCode.AGENT_NOT_FOUND

    async def test_valid_owner_resolves(self):
        bridge = _make_bridge(owner_value=OWNER)
        agent = await bridge.resolve_agent("7")
        assert agent.owner.lower() == OWNER.lower()
        assert agent.wallet.lower() == OWNER.lower()  # falls back to owner
