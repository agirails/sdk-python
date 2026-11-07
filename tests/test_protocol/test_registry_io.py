"""AgentRegistry public reads and writes through real AsyncWeb3 encoding."""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from eth_account import Account
from web3 import AsyncWeb3

from agirails.errors import ValidationError, TransactionRevertedError
from agirails.protocol.agent_registry import AgentRegistry, ServiceDescriptor, _load_agent_registry_abi, compute_service_type_hash
from tests.helpers.contract_rpc import ContractRPC

ACCOUNT = Account.from_key("0x" + "11" * 32)
ADDRESS = "0x" + "22" * 20
HASH = "0x" + "ab" * 32


@pytest_asyncio.fixture
async def registry():
    rpc = ContractRPC()
    w3 = AsyncWeb3(rpc)
    abi = _load_agent_registry_abi()
    rpc.register(abi)
    wrapper = AgentRegistry(w3.eth.contract(address=ADDRESS, abi=abi), ACCOUNT, w3, 84532)
    return rpc, wrapper


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args,wire,expected", [
    ("update_endpoint", ["https://agent.example/new"], "updateEndpoint", ("https://agent.example/new",)),
    ("add_service_type", ["echo"], "addServiceType", ("echo",)),
    ("remove_service_type", ["echo"], "removeServiceType", (bytes.fromhex(compute_service_type_hash("echo")[2:]),)),
    ("remove_service_type", [HASH], "removeServiceType", (bytes.fromhex(HASH[2:]),)),
    ("set_active_status", [False], "setActiveStatus", (False,)),
    ("set_listed", [True], "setListed", (True,)),
    ("publish_config", ["bafy-config", HASH], "publishConfig", ("bafy-config", bytes.fromhex(HASH[2:]))),
])
async def test_registry_writes_have_correct_signed_wire_values(registry, method, args, wire, expected):
    rpc, client = registry
    receipt = await getattr(client, method)(*args)
    assert receipt.success is True
    assert rpc.sent[-1][0:2] == (wire, expected)
    assert Account.recover_transaction(rpc.sent[-1][2]) == ACCOUNT.address
    assert client.address == ACCOUNT.address
    assert client.contract_address == ADDRESS


@pytest.mark.asyncio
async def test_register_agent_includes_descriptors_and_canonical_service_hash(registry):
    rpc, client = registry
    descriptor = ServiceDescriptor("echo", min_price=50_000, max_price=1_000_000)
    receipt = await client.register_agent("https://agent.example", [descriptor])
    assert receipt.success is True
    name, args, raw = rpc.sent[-1]
    assert name == "registerAgent"
    assert args[0] == "https://agent.example"
    assert args[1][0][0] == bytes.fromhex(compute_service_type_hash("echo")[2:])
    assert args[1][0][3:5] == (50_000, 1_000_000)


@pytest.mark.asyncio
@pytest.mark.parametrize("cid,hash_", [("", HASH), ("x" * 129, HASH), ("bafy", ""), ("bafy", "0x" + "00" * 32), ("bafy", "0xwrong")])
async def test_invalid_publish_inputs_never_send_a_transaction(registry, cid, hash_):
    rpc, client = registry
    with pytest.raises(ValidationError):
        await client.publish_config(cid, hash_)
    assert rpc.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args", [("set_listed", [True]), ("publish_config", ["bafy", HASH])])
async def test_not_registered_errors_keep_actionable_context(registry, monkeypatch, method, args):
    rpc, client = registry
    monkeypatch.setattr(client, "_build_transaction", AsyncMock(side_effect=RuntimeError("Not registered")))
    with pytest.raises(TransactionRevertedError, match="Register first"):
        await getattr(client, method)(*args)
    assert rpc.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("service", ["echo", HASH])
async def test_service_queries_hash_names_and_preserve_pagination(registry, service):
    rpc, client = registry
    rpc.reply("supportsService", True)
    rpc.reply("queryAgentsByService", [ADDRESS])
    rpc.reply("getServiceDescriptors", [(bytes.fromhex(HASH[2:]), "echo", "https://schema.example", 1, 2, 60, "bafy")])
    assert await client.supports_service(ADDRESS, service) is True
    assert [x.lower() for x in await client.query_agents_by_service(service, 80, 2, 5)] == [ADDRESS.lower()]
    assert rpc.calls[-1][1][1:] == (80, 2, 5)
    descriptors = await client.get_service_descriptors(ADDRESS)
    assert descriptors[0].service_type == "echo"
    assert descriptors[0].min_price == 1


@pytest.mark.asyncio
async def test_profiles_decode_config_and_reputation_from_rpc(registry):
    rpc, client = registry
    profile = (ADDRESS, "did:eth:agent", "https://agent.example", [bytes.fromhex(HASH[2:])], 0, 9500, 20, 2, 50_000_000, 1700000000, 1700000001, True, bytes.fromhex(HASH[2:]), "bafy-config", True)
    rpc.reply("getAgent", profile)
    rpc.reply("getAgentByDID", profile)
    assert await client.is_registered(ADDRESS) is True
    agent = await client.get_agent(ADDRESS)
    assert agent.to_dict()["configHash"] == HASH
    assert agent.reputation_percentage == 95
    assert agent.dispute_rate == 10
    assert agent.total_volume_usdc_human == 50
    assert (await client.get_agent_by_did("did:eth:agent")).config_cid == "bafy-config"
    rpc.reply("queryAgentsByService", [ADDRESS])
    assert len(await client.find_providers_for_service("echo", 80)) == 1
    rpc.reply("getAgent", (*profile[:11], False, *profile[12:]))
    assert await client.find_providers_for_service("echo", 80) == []
    assert len(await client.find_providers_for_service("echo", 80, active_only=False)) == 1
