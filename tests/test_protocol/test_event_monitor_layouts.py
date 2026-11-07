"""Descriptor compatibility through real AsyncWeb3 filter encoding and decoding."""

from unittest.mock import AsyncMock

import pytest
from eth_abi import encode
from eth_utils.abi import event_abi_to_log_topic
from web3 import AsyncWeb3, Web3
from web3.providers import AsyncBaseProvider

from agirails.config.networks import BASE_MAINNET, BASE_SEPOLIA
from agirails.protocol.events import EventMonitor
from agirails.protocol.kernel import ACTPKernel
from agirails.runtime.blockchain_runtime import BlockchainRuntime
from tests.test_runtime.test_subscribe_provider_jobs_4_8_0 import _mock_tx

REQUESTER = Web3.to_checksum_address("0x" + "11" * 20)
PROVIDER = Web3.to_checksum_address("0x" + "22" * 20)
TX_ID = bytes.fromhex("33" * 32)
AGREEMENT = bytes.fromhex("44" * 32)


def event_abi(filename, name, legacy=False):
    item = next(
        x
        for x in EventMonitor._load_abi(filename)
        if x.get("type") == "event" and x["name"] == name
    )
    if legacy:
        item = {**item, "inputs": [x for x in item["inputs"] if x["name"] != "agreementHash"]}
    return item


def raw_log(abi, address, values, block, index):
    indexed = [x for x in abi["inputs"] if x["indexed"]]
    plain = [x for x in abi["inputs"] if not x["indexed"]]
    return {
        "address": Web3.to_checksum_address(address),
        "topics": [Web3.to_hex(event_abi_to_log_topic(abi))]
        + [Web3.to_hex(encode([x["type"]], [values[x["name"]]])) for x in indexed],
        "data": Web3.to_hex(encode([x["type"] for x in plain], [values[x["name"]] for x in plain])),
        "blockNumber": hex(block),
        "transactionHash": "0x" + "55" * 32,
        "transactionIndex": "0x0",
        "blockHash": "0x" + "66" * 32,
        "logIndex": hex(index),
        "removed": False,
    }


class LocalLogs(AsyncBaseProvider):
    def __init__(self, config, cap=None):
        super().__init__()
        self.config = config
        self.cap = cap
        self.requests = []
        self.filters = {}
        self.logs = []
        self.fail_reads = False

    async def make_request(self, method, params):
        self.requests.append((method, params))
        if method == "eth_chainId":
            result = hex(self.config.chain_id)
        elif method == "eth_blockNumber":
            result = "0xc"
        elif method == "eth_newFilter":
            query = params[0]
            lower = int(query["fromBlock"], 16) if str(query["fromBlock"]).startswith("0x") else 0
            upper = int(query["toBlock"], 16) if str(query["toBlock"]).startswith("0x") else 12
            if self.cap and upper - lower + 1 > self.cap:
                return {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32005, "message": "block range too wide"},
                }
            result = hex(len(self.filters) + 1)
            self.filters[result] = (query, lower, upper)
        elif method == "eth_getFilterLogs":
            if self.fail_reads:
                raise ConnectionError("local fixture unavailable")
            query, lower, upper = self.filters[params[0]]
            addresses = (
                query["address"] if isinstance(query["address"], list) else [query["address"]]
            )
            topic = query["topics"][0]
            result = [
                x
                for x in self.logs
                if x["address"].lower() in [a.lower() for a in addresses]
                and x["topics"][0].lower() == topic.lower()
                and lower <= int(x["blockNumber"], 16) <= upper
            ]
        else:
            raise AssertionError("Unexpected RPC operation: " + method)
        return {"jsonrpc": "2.0", "id": 1, "result": result}


def setup_monitor(config, factory, cap=None):
    provider = LocalLogs(config, cap)
    w3 = AsyncWeb3(provider)
    if factory == "config":
        monitor = EventMonitor.from_config(w3, config)
    else:
        escrow = w3.eth.contract(
            address=w3.to_checksum_address(config.contracts.escrow_vault),
            abi=EventMonitor._load_abi("escrow_vault.json"),
        )
        if factory == "wrapped":
            account = w3.eth.account.from_key("0x" + "01" * 32)
            kernel = ACTPKernel.from_config(w3, account, config).contract
        else:
            kernel = w3.eth.contract(
                address=w3.to_checksum_address(config.contracts.actp_kernel),
                abi=EventMonitor._load_abi("actp_kernel.json"),
            )
        monitor = EventMonitor(kernel, escrow, w3)
    return monitor, provider, w3


def add_logs(provider, legacy):
    created = event_abi("actp_kernel.json", "TransactionCreated", legacy)
    provider.logs = [
        raw_log(
            created,
            provider.config.contracts.actp_kernel,
            {
                "transactionId": TX_ID,
                "requester": REQUESTER,
                "provider": PROVIDER,
                "amount": 50000,
                "serviceHash": bytes.fromhex("77" * 32),
                "deadline": 9999999999,
                "timestamp": 1700000000,
                "agentId": 42,
                "agreementHash": AGREEMENT,
            },
            10,
            0,
        ),
        raw_log(
            event_abi("actp_kernel.json", "StateTransitioned"),
            provider.config.contracts.actp_kernel,
            {
                "transactionId": TX_ID,
                "oldState": 0,
                "newState": 1,
                "triggeredBy": PROVIDER,
                "timestamp": 1700000001,
            },
            11,
            0,
        ),
        raw_log(
            event_abi("escrow_vault.json", "EscrowCreated"),
            provider.config.contracts.escrow_vault,
            {
                "escrowId": bytes.fromhex("88" * 32),
                "requester": REQUESTER,
                "provider": PROVIDER,
                "amount": 50000,
            },
            12,
            0,
        ),
    ]
    return created


@pytest.mark.parametrize("config,legacy", [(BASE_MAINNET, True), (BASE_SEPOLIA, False)])
@pytest.mark.parametrize("factory", ["config", "direct", "wrapped"])
def test_factory_selects_descriptor_event_topic_without_mutating_packaged_abi(
    config, legacy, factory
):
    monitor, _, _ = setup_monitor(config, factory)
    selected = next(x for x in monitor.kernel_contract.abi if x.get("name") == "TransactionCreated")
    assert event_abi_to_log_topic(selected) == event_abi_to_log_topic(
        event_abi("actp_kernel.json", "TransactionCreated", legacy)
    )
    assert len(event_abi("actp_kernel.json", "TransactionCreated")["inputs"]) == 9


@pytest.mark.asyncio
@pytest.mark.parametrize("config,legacy", [(BASE_MAINNET, True), (BASE_SEPOLIA, False)])
@pytest.mark.parametrize("factory", ["config", "direct", "wrapped"])
@pytest.mark.parametrize("bounds", [(10, 12), ("earliest", "latest")])
async def test_actual_encoded_logs_survive_get_events_and_other_events(
    config, legacy, factory, bounds
):
    monitor, provider, _ = setup_monitor(config, factory)
    created_abi = add_logs(provider, legacy)
    events = await monitor.get_events(from_block=bounds[0], to_block=bounds[1])
    assert [x.event_type.value for x in events] == [
        "TransactionCreated",
        "StateTransitioned",
        "EscrowCreated",
    ]
    created, state, escrow = events
    assert created.transaction_id == "0x" + TX_ID.hex()
    assert (
        created.requester == REQUESTER and created.provider == PROVIDER and created.amount == 50000
    )
    assert created.raw_data["agentId"] == 42 and created.raw_data["serviceHash"] == bytes.fromhex(
        "77" * 32
    )
    assert created.raw_data.get("agreementHash") == (None if legacy else AGREEMENT)
    assert (
        state.actor == PROVIDER and state.previous_state.value == 0 and state.new_state.value == 1
    )
    assert escrow.amount == 50000 and escrow.provider == PROVIDER
    queried_topics = [
        p[0]["topics"][0] for method, p in provider.requests if method == "eth_newFilter"
    ]
    assert Web3.to_hex(event_abi_to_log_topic(created_abi)) in queried_topics


@pytest.mark.asyncio
@pytest.mark.parametrize("config,legacy", [(BASE_MAINNET, True), (BASE_SEPOLIA, False)])
@pytest.mark.parametrize("factory", ["config", "direct", "wrapped"])
async def test_provider_discovery_uses_real_encoded_event_monitor(config, legacy, factory):
    monitor, provider, w3 = setup_monitor(config, factory)
    add_logs(provider, legacy)
    runtime = BlockchainRuntime.__new__(BlockchainRuntime)
    runtime.events, runtime.w3 = monitor, w3
    tx = _mock_tx("0x" + TX_ID.hex(), provider=PROVIDER)
    runtime.get_transaction = AsyncMock(return_value=tx)
    assert await runtime.get_transactions_by_provider(PROVIDER.lower()) == [tx]
    runtime.get_transaction.assert_awaited_once_with("0x" + TX_ID.hex())
    assert await runtime.get_transactions_by_provider("0x" + "99" * 20) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("config,legacy", [(BASE_MAINNET, True), (BASE_SEPOLIA, False)])
async def test_real_async_filters_preserve_chunking_and_rpc_failure(config, legacy):
    monitor, provider, _ = setup_monitor(config, "config", cap=1)
    add_logs(provider, legacy)
    events = await monitor.get_events(from_block=10, to_block=12)
    assert len(events) == 3
    provider.fail_reads = True
    with pytest.raises(ConnectionError, match="local fixture unavailable"):
        await monitor.get_events(from_block=10, to_block=10)
