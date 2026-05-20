"""Tests for BlockchainRuntime.get_all_transactions from_block defaulting.

Pins the contract that ``actp_kernel_deployment_block`` from
NetworkConfig actually bounds the event scan window — previously this
field was surfaced but ``get_all_transactions`` ignored it and scanned
a fixed ``latest - 50_000`` slice.
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from dataclasses import replace

from agirails.config.networks import get_network
from agirails.runtime.blockchain_runtime import BlockchainRuntime


def _make_runtime(deploy_block: int | None) -> BlockchainRuntime:
    """Build a BlockchainRuntime stub with just the surface get_all_transactions touches."""
    # Copy a real network config and override deploy_block to avoid
    # re-declaring every required field as the schema grows.
    cfg = replace(
        get_network("base-sepolia"),
        actp_kernel_deployment_block=deploy_block,
    )
    rt = BlockchainRuntime.__new__(BlockchainRuntime)
    rt.config = cfg
    # Minimal stand-ins for what the method touches.
    rt.events = MagicMock()
    rt.events.get_events = AsyncMock(return_value=[])
    rt.w3 = MagicMock()
    # AsyncWeb3.eth.block_number returns an awaitable that resolves to int.
    # Subclass FakeEth so each test can set ._latest_block freely.
    rt.w3.eth = _FakeEth()
    return rt


class _FakeEth:
    """Stand-in for ``AsyncWeb3.eth`` — only ``block_number`` is exercised."""

    _latest_block: int = 0
    _raise: Optional[BaseException] = None

    def __getattribute__(self, name):
        if name == "block_number":
            raise_exc = object.__getattribute__(self, "_raise")
            if raise_exc is not None:
                async def _raise_coro():
                    raise raise_exc
                return _raise_coro()
            value = object.__getattribute__(self, "_latest_block")

            async def _coro():
                return value
            return _coro()
        return object.__getattribute__(self, name)


class TestFromBlockDefault:
    @pytest.mark.asyncio
    async def test_deploy_block_is_floor_when_inside_50k_window(self):
        """When the contract is younger than 50k blocks (recent deploy),
        the deploy block wins and the scan starts there."""
        rt = _make_runtime(deploy_block=46_212_266)
        # latest just 1000 blocks past deploy → heuristic floor = 46_211_266
        # deploy floor = 46_212_266 → max = 46_212_266 (deploy wins)
        rt.w3.eth._latest_block = 46_213_266
        observed: dict = {}

        async def fake_get_events(filt, *, from_block):
            observed["from_block"] = from_block
            return []

        rt.events.get_events = fake_get_events
        await rt.get_all_transactions()
        assert observed["from_block"] == 46_212_266

    @pytest.mark.asyncio
    async def test_heuristic_wins_when_contract_is_older_than_50k_blocks(self):
        """For long-running mainnet deploys (>50k blocks old), the
        50k heuristic still caps scan distance — we don't pull every
        event back to deploy day."""
        rt = _make_runtime(deploy_block=46_212_266)
        rt.w3.eth._latest_block = 50_000_000  # ~3.78M past deploy
        observed: dict = {}

        async def fake_get_events(filt, *, from_block):
            observed["from_block"] = from_block
            return []

        rt.events.get_events = fake_get_events
        await rt.get_all_transactions()
        # max(50_000_000 - 50_000, 46_212_266) = 49_950_000
        assert observed["from_block"] == 49_950_000

    @pytest.mark.asyncio
    async def test_no_deploy_block_falls_back_to_heuristic_only(self):
        """Backward-compat: networks without a deploy block configured
        still get the legacy 50k window."""
        rt = _make_runtime(deploy_block=None)
        rt.w3.eth._latest_block = 100_000
        observed: dict = {}

        async def fake_get_events(filt, *, from_block):
            observed["from_block"] = from_block
            return []

        rt.events.get_events = fake_get_events
        await rt.get_all_transactions()
        # max(100_000 - 50_000, 0) = 50_000
        assert observed["from_block"] == 50_000

    @pytest.mark.asyncio
    async def test_rpc_failure_falls_back_to_deploy_block(self):
        """When block_number RPC fails we still respect the deploy floor."""
        rt = _make_runtime(deploy_block=46_212_266)

        rt.w3.eth._raise = RuntimeError("rpc down")
        observed: dict = {}

        async def fake_get_events(filt, *, from_block):
            observed["from_block"] = from_block
            return []

        rt.events.get_events = fake_get_events
        await rt.get_all_transactions()
        assert observed["from_block"] == 46_212_266

    @pytest.mark.asyncio
    async def test_explicit_from_block_overrides_default(self):
        rt = _make_runtime(deploy_block=46_212_266)
        rt.w3.eth.block_number = 50_000_000
        observed: dict = {}

        async def fake_get_events(filt, *, from_block):
            observed["from_block"] = from_block
            return []

        rt.events.get_events = fake_get_events
        await rt.get_all_transactions(from_block=12345)
        # User override wins; deploy/heuristic ignored.
        assert observed["from_block"] == 12345
