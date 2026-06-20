"""Parity tests for EventMonitor adaptive eth_getLogs chunking (TS v4.8.0).

PARITY: EventMonitor.ts:182-207 (queryFilterChunked + isBlockRangeError). The
Python ``EventMonitor`` recursively halves the block window on a range-limit
error and re-raises genuine errors (never swallows them).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.protocol.events import EventMonitor


def _make_monitor() -> EventMonitor:
    return EventMonitor(MagicMock(), MagicMock(), MagicMock())


# ---------------------------------------------------------------------------
# _is_block_range_error heuristic
# ---------------------------------------------------------------------------


class TestIsBlockRangeError:
    @pytest.mark.parametrize(
        "msg",
        [
            "query returned more than 10000 results",
            "block range is too wide",
            "eth_getLogs range too large",
            "you can make eth_getLogs requests with up to a 2000 block range",
            "response size exceeded",
            "query timeout exceeded",
            "limit exceeded",
            "error code -32600",
            "error code -32005",
        ],
    )
    def test_range_errors_detected(self, msg):
        assert EventMonitor._is_block_range_error(Exception(msg)) is True

    @pytest.mark.parametrize(
        "msg",
        ["connection refused", "nonce too low", "execution reverted", "timeout"],
    )
    def test_non_range_errors_not_detected(self, msg):
        # Note "timeout" alone is NOT a range marker ("query timeout" is).
        assert EventMonitor._is_block_range_error(Exception(msg)) is False


# ---------------------------------------------------------------------------
# _query_logs_chunked halving
# ---------------------------------------------------------------------------


class _ChunkingEvent:
    """Mock event whose getLogs rejects windows wider than `cap` blocks."""

    def __init__(self, cap: int, logs_at: dict[int, list]):
        self.cap = cap
        self.logs_at = logs_at  # from_block -> logs for single-block windows
        self.calls: list[tuple[int, int]] = []

    def create_filter(self, *, fromBlock: int, toBlock: int):
        self.calls.append((fromBlock, toBlock))
        span = toBlock - fromBlock + 1
        entries = []
        if span <= self.cap:
            for b in range(fromBlock, toBlock + 1):
                entries.extend(self.logs_at.get(b, []))

        async def get_all_entries():
            if span > self.cap:
                raise Exception("query returned more than 10000 results, block range too large")
            return entries

        return MagicMock(get_all_entries=AsyncMock(side_effect=get_all_entries))


class TestQueryLogsChunked:
    async def test_halves_window_until_under_cap(self):
        monitor = _make_monitor()
        # Cap of 1 block per request; logs at blocks 3 and 6.
        event = _ChunkingEvent(cap=1, logs_at={3: ["log-a"], 6: ["log-b"]})

        logs = await monitor._query_logs_chunked(event, 0, 7)

        # All single-block windows eventually succeed; both logs collected.
        assert logs == ["log-a", "log-b"]
        # The very first call is the full [0,7] window (which fails then splits).
        assert event.calls[0] == (0, 7)

    async def test_single_block_range_error_propagates(self):
        monitor = _make_monitor()

        event = MagicMock()
        event.create_filter.return_value = MagicMock(
            get_all_entries=AsyncMock(side_effect=Exception("block range too large"))
        )

        # from_block == to_block → cannot split → genuine error re-raised.
        with pytest.raises(Exception) as exc_info:
            await monitor._query_logs_chunked(event, 5, 5)
        assert "block range" in str(exc_info.value)

    async def test_non_range_error_propagates_without_splitting(self):
        monitor = _make_monitor()

        event = MagicMock()
        event.create_filter.return_value = MagicMock(
            get_all_entries=AsyncMock(side_effect=Exception("connection refused"))
        )

        with pytest.raises(Exception) as exc_info:
            await monitor._query_logs_chunked(event, 0, 1000)
        assert "connection refused" in str(exc_info.value)
        # Only ONE call — a non-range error must not trigger halving.
        assert event.create_filter.call_count == 1


# ---------------------------------------------------------------------------
# _query_event_logs bound handling
# ---------------------------------------------------------------------------


class TestQueryEventLogs:
    async def test_string_bounds_skip_chunking(self):
        monitor = _make_monitor()
        event = MagicMock()
        event.create_filter.return_value = MagicMock(
            get_all_entries=AsyncMock(return_value=["x"])
        )

        logs = await monitor._query_event_logs(event, "earliest", "latest")
        assert logs == ["x"]
        event.create_filter.assert_called_once_with(fromBlock="earliest", toBlock="latest")

    async def test_numeric_bounds_use_chunked_path(self):
        monitor = _make_monitor()
        event = _ChunkingEvent(cap=1000, logs_at={10: ["y"]})

        logs = await monitor._query_event_logs(event, 0, 100)
        assert logs == ["y"]
