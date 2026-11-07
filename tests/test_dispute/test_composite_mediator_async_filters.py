"""Exercise public mediator reads through real AsyncWeb3 event filters."""

import asyncio
from contextlib import suppress

import pytest
from eth_abi import encode
from eth_utils.abi import event_abi_to_log_topic
from web3 import AsyncWeb3, Web3
from web3.providers import AsyncBaseProvider

from agirails.dispute.composite_mediator import CompositeMediator

ADDRESS = Web3.to_checksum_address("0x" + "11" * 20)
REQUESTER = Web3.to_checksum_address("0x" + "22" * 20)
PROVIDER = Web3.to_checksum_address("0x" + "33" * 20)
TX_ID = "0x" + "44" * 32
TX_HASH = "0x" + "55" * 32


class SplitLogs(AsyncBaseProvider):
    def __init__(self, failures=0):
        super().__init__()
        self.failures = failures
        self.queries = []
        self.block_reads = 0
        self.filters = {}
        event = next(
            x for x in CompositeMediator._load_abi() if x.get("name") == "DisputeSplitRecorded"
        )
        self.log = {
            "address": ADDRESS,
            "topics": [Web3.to_hex(event_abi_to_log_topic(event)), TX_ID]
            + [Web3.to_hex(encode(["address"], [a])) for a in [REQUESTER, PROVIDER]],
            "data": Web3.to_hex(encode(["uint16"], [3700])),
            "blockNumber": "0xa",
            "transactionHash": TX_HASH,
            "transactionIndex": "0x0",
            "blockHash": "0x" + "66" * 32,
            "logIndex": "0x2",
            "removed": False,
        }

    async def make_request(self, method, params):
        if method == "eth_chainId":
            result = "0x7a69"
        elif method == "eth_blockNumber":
            self.block_reads += 1
            result = "0x9" if self.block_reads == 1 else "0xa"
        elif method == "eth_newFilter":
            query = params[0]
            self.queries.append(query)
            result = hex(len(self.queries))
            self.filters[result] = query
        elif method == "eth_getFilterLogs":
            if self.failures:
                self.failures -= 1
                raise ConnectionError("local filter read unavailable")
            query = self.filters[params[0]]
            matching = all(
                topic is None or topic.lower() == self.log["topics"][i].lower()
                for i, topic in enumerate(query["topics"])
            )
            result = [self.log] if matching else []
        else:
            raise AssertionError("Unexpected RPC operation: " + method)
        return {"jsonrpc": "2.0", "id": 1, "result": result}


def client(failures=0):
    provider = SplitLogs(failures)
    w3 = AsyncWeb3(provider)
    contract = w3.eth.contract(address=ADDRESS, abi=CompositeMediator._load_abi())
    return CompositeMediator(contract, ADDRESS), provider


@pytest.mark.parametrize("bounds", [(0, 10), ("earliest", "latest")])
@pytest.mark.asyncio
async def test_history_decodes_real_log_with_all_indexed_filters(bounds):
    mediator, provider = client()
    events = await mediator.get_split_recorded_events(
        tx_id=TX_ID,
        requester=REQUESTER,
        provider=PROVIDER,
        from_block=bounds[0],
        to_block=bounds[1],
    )
    assert len(events) == 1
    event = events[0]
    assert (event.tx_id, event.requester, event.provider) == (TX_ID, REQUESTER, PROVIDER)
    assert (event.split_bps, event.block_number, event.log_index) == (3700, 10, 2)
    assert event.transaction_hash == TX_HASH
    query = provider.queries[0]
    assert list(query["topics"]) == provider.log["topics"]
    expected = [hex(x) if isinstance(x, int) else x for x in bounds]
    assert [query["fromBlock"], query["toBlock"]] == expected


@pytest.mark.asyncio
async def test_history_preserves_empty_result_for_nonmatching_transaction():
    mediator, _ = client()
    assert await mediator.get_split_recorded_events(tx_id="0x" + "77" * 32) == []


@pytest.mark.asyncio
async def test_history_propagates_real_provider_read_failure():
    mediator, _ = client(failures=1)
    with pytest.raises(ConnectionError, match="local filter read unavailable"):
        await mediator.get_split_recorded_events(from_block=0, to_block=10)


@pytest.mark.parametrize("failures", [0, 1])
@pytest.mark.asyncio
async def test_watcher_delivers_decoded_event_and_retries_same_range_after_read_error(failures):
    mediator, provider = client(failures)
    delivered = asyncio.get_running_loop().create_future()
    task = mediator.on_dispute_split_recorded(delivered.set_result, poll_interval=0.005)
    try:
        event = await asyncio.wait_for(delivered, timeout=1)
        assert (event.tx_id, event.split_bps, event.block_number) == (TX_ID, 3700, 10)
        assert (event.requester, event.provider, event.transaction_hash) == (
            REQUESTER,
            PROVIDER,
            TX_HASH,
        )
        assert len(provider.queries) == failures + 1
        assert all(q["fromBlock"] == q["toBlock"] == "0xa" for q in provider.queries)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    assert task.done()
