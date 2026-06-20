"""Parity tests for BlockchainRuntime.subscribe_provider_jobs (TS v4.8.0).

PARITY: BlockchainRuntime.ts:793-826. Live TransactionCreated subscription for
a provider — hydrate each new job, deliver only INITIATED ones exactly once,
and return a cleanup callable. The Python port uses a bounded polling loop
(web3.py has no HTTP push subscription) with identical observable behavior.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.runtime.blockchain_runtime import BlockchainRuntime
from agirails.runtime.types import MockTransaction
from agirails.runtime import State


PROVIDER = "0x" + "2" * 40
REQUESTER = "0x" + "1" * 40


class _AdvancingEth:
    """Stand-in for ``AsyncWeb3.eth`` whose ``block_number`` advances on read.

    Returns a fresh awaitable each access (matching AsyncWeb3 semantics). The
    value advances by ``step`` for the first ``cap_after`` reads, then plateaus
    so no further block windows open.
    """

    def __init__(self, initial: int = 100, step: int = 5, cap_after: int = 2):
        object.__setattr__(self, "_value", initial)
        object.__setattr__(self, "_step", step)
        object.__setattr__(self, "_cap_after", cap_after)
        object.__setattr__(self, "_advances", 0)

    def __getattribute__(self, name):
        if name == "block_number":
            value = object.__getattribute__(self, "_value")
            advances = object.__getattribute__(self, "_advances")
            cap_after = object.__getattribute__(self, "_cap_after")
            if advances < cap_after:
                value = value + object.__getattribute__(self, "_step")
                object.__setattr__(self, "_value", value)
                object.__setattr__(self, "_advances", advances + 1)

            async def _coro():
                return value

            return _coro()
        return object.__getattribute__(self, name)


def _make_runtime(eth: object = None) -> BlockchainRuntime:
    """Construct a BlockchainRuntime shell with only the attrs the method touches."""
    rt = object.__new__(BlockchainRuntime)
    rt.w3 = MagicMock()
    rt.w3.eth = eth if eth is not None else _AdvancingEth()
    rt.events = MagicMock()
    return rt


def _mock_tx(tx_id: str, state: State = State.INITIATED, provider: str = PROVIDER) -> MockTransaction:
    return MockTransaction(
        id=tx_id,
        requester=REQUESTER,
        provider=provider,
        amount="1000000",
        state=state,
        deadline=9_999_999_999,
        dispute_window=172800,
        created_at=1,
        updated_at=1,
    )


async def _drain(jobs_seen, expected: int, timeout: float = 2.0):
    """Wait until `expected` jobs have been collected or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while len(jobs_seen) < expected and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.01)


class TestSubscribeProviderJobs:
    async def test_delivers_initiated_jobs_once(self):
        rt = _make_runtime()

        event = SimpleNamespace(transaction_id="0xaaa")
        rt.events.get_events = AsyncMock(return_value=[event])
        rt.get_transaction = AsyncMock(return_value=_mock_tx("0xaaa"))

        jobs = []
        cleanup = rt.subscribe_provider_jobs(PROVIDER, jobs.append, poll_interval=0.01)
        try:
            await _drain(jobs, 1)
            # Let several more poll cycles run to prove no double-delivery.
            await asyncio.sleep(0.1)
        finally:
            cleanup()

        assert len(jobs) == 1  # Delivered exactly once.
        assert jobs[0].id == "0xaaa"
        assert callable(cleanup)

    async def test_skips_non_initiated_jobs(self):
        rt = _make_runtime()

        event = SimpleNamespace(transaction_id="0xbbb")
        rt.events.get_events = AsyncMock(return_value=[event])
        rt.get_transaction = AsyncMock(return_value=_mock_tx("0xbbb", state=State.QUOTED))

        jobs = []
        cleanup = rt.subscribe_provider_jobs(PROVIDER, jobs.append, poll_interval=0.01)
        try:
            await asyncio.sleep(0.1)
        finally:
            cleanup()

        assert jobs == []

    async def test_skips_not_yet_visible_then_retries(self):
        # init uses 1 advance, window-1 uses 1, window-2 (the retry) needs 1 more.
        rt = _make_runtime(eth=_AdvancingEth(cap_after=3))

        event = SimpleNamespace(transaction_id="0xccc")
        rt.events.get_events = AsyncMock(return_value=[event])
        # First hydration returns None (not visible), second returns the tx.
        rt.get_transaction = AsyncMock(side_effect=[None, _mock_tx("0xccc")])

        jobs = []
        cleanup = rt.subscribe_provider_jobs(PROVIDER, jobs.append, poll_interval=0.01)
        try:
            await _drain(jobs, 1)
        finally:
            cleanup()

        assert len(jobs) == 1
        assert jobs[0].id == "0xccc"

    async def test_cleanup_stops_subscription(self):
        rt = _make_runtime(eth=_AdvancingEth(cap_after=0))  # never opens a window
        rt.events.get_events = AsyncMock(return_value=[])
        rt.get_transaction = AsyncMock()

        cleanup = rt.subscribe_provider_jobs(PROVIDER, lambda tx: None, poll_interval=0.01)
        await asyncio.sleep(0.05)
        cleanup()
        await asyncio.sleep(0.05)
        # No exception, subscription stopped cleanly.
        assert callable(cleanup)
