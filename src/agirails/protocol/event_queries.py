"""Adaptive AsyncWeb3 event queries shared by protocol event monitors."""

from typing import Any, Union

from web3.types import LogReceipt


class EventLogQueries:
    """Query async event filters, splitting oversized numeric block windows."""

    _BLOCK_RANGE_ERROR_MARKERS = (
        "block range",
        "range is too",
        "range too",
        "up to a",
        "more than",
        "response size",
        "query timeout",
        "limit exceeded",
        "-32600",
        "-32005",
    )

    @classmethod
    def _is_block_range_error(cls, err: BaseException) -> bool:
        message = str(err).lower()
        return any(marker in message for marker in cls._BLOCK_RANGE_ERROR_MARKERS)

    async def _query_logs_chunked(
        self, event_obj: Any, from_block: int, to_block: int
    ) -> list[LogReceipt]:
        try:
            log_filter = await event_obj.create_filter(from_block=from_block, to_block=to_block)
            return await log_filter.get_all_entries()
        except Exception as err:
            if from_block >= to_block or not self._is_block_range_error(err):
                raise
            mid = (from_block + to_block) // 2
            lower = await self._query_logs_chunked(event_obj, from_block, mid)
            upper = await self._query_logs_chunked(event_obj, mid + 1, to_block)
            return [*lower, *upper]

    async def _query_event_logs(
        self, event_obj: Any, from_block: Union[int, str], to_block: Union[int, str]
    ) -> list[LogReceipt]:
        if isinstance(from_block, int) and isinstance(to_block, int):
            return await self._query_logs_chunked(event_obj, from_block, to_block)
        log_filter = await event_obj.create_filter(from_block=from_block, to_block=to_block)
        return await log_filter.get_all_entries()
