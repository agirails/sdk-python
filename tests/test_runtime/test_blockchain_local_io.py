"""Testnet-shaped SDK path against a local JSON-RPC transport, never a live chain."""

import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from eth_account import Account
from web3 import AsyncWeb3

from agirails.client import ACTPClient, ACTPClientConfig
from agirails.config.networks import BASE_SEPOLIA
from agirails.errors import ValidationError, TransactionError, DisputeWindowActiveError
from agirails.runtime.base import CreateTransactionParams
from agirails.runtime.blockchain_runtime import BlockchainRuntime
from agirails.runtime.types import State
from tests.helpers.contract_rpc import ContractRPC
from tests.test_protocol.test_event_monitor_layouts import event_abi, raw_log

KEY = "0x" + "11" * 32
ACCOUNT = Account.from_key(KEY)
PROVIDER = "0x" + "22" * 20
TX = "0x" + "ab" * 32
ZERO = bytes(32)


@pytest_asyncio.fixture
async def runtime(monkeypatch):
    rpc = ContractRPC()
    monkeypatch.setattr(AsyncWeb3, "AsyncHTTPProvider", lambda url: rpc)
    instance = await BlockchainRuntime.create(KEY, network=BASE_SEPOLIA, rpc_rate_limit=1000)
    for abi in [instance.kernel.contract.abi, instance.escrow.contract.abi, instance.escrow.usdc_contract.abi]:
        rpc.register(abi)
    return rpc, instance


def view_tuple(state=0, requester=ACCOUNT.address):
    return (
        bytes.fromhex(TX[2:]), requester, PROVIDER, state, 1_000_000,
        1700000000, 1700000100, 1900000000, bytes.fromhex(TX[2:]),
        BASE_SEPOLIA.contracts.escrow_vault, bytes.fromhex(TX[2:]), ZERO,
        172800, ZERO, 100, 500, 1000, 42, 43, "0x" + "00" * 20, 0, ZERO, ZERO,
    )


@pytest.mark.asyncio
async def test_runtime_initialization_and_readback_are_bound_to_testnet(runtime):
    rpc, instance = runtime
    assert instance.address == ACCOUNT.address
    assert await instance.get_chain_id() == 84532
    assert await instance.get_block_number() == 10
    assert instance.rate_limiter is not None
    assert await instance.time.now_async() == rpc.timestamp
    assert instance.time.now() == rpc.timestamp
    rpc.reply("getTransaction", view_tuple())
    tx = await instance.get_transaction(TX)
    assert tx.id == TX
    assert tx.requester.lower() == ACCOUNT.address.lower()
    assert tx.state == State.INITIATED
    assert tx.amount == "1000000"
    assert tx.platform_fee_bps_locked == 100
    assert tx.agent_id == 42
    assert tx.requester_agent_id == 43
    rpc.reply("getTransaction", view_tuple(requester="0x" + "00" * 20))
    assert await instance.get_transaction(TX) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("chain", [1, 8453])
async def test_wrong_chain_is_rejected_before_a_transaction(monkeypatch, chain):
    rpc = ContractRPC()
    rpc.chain_id = chain
    monkeypatch.setattr(AsyncWeb3, "AsyncHTTPProvider", lambda url: rpc)
    with pytest.raises(ValidationError, match="Chain ID mismatch"):
        await BlockchainRuntime.create(KEY, BASE_SEPOLIA)
    assert rpc.sent == []


@pytest.mark.asyncio
async def test_creation_encodes_expected_principal_and_extracts_real_abi_event(runtime):
    rpc, instance = runtime
    values = {
        "transactionId": bytes.fromhex(TX[2:]), "requester": ACCOUNT.address,
        "provider": PROVIDER, "amount": 1_000_000, "serviceHash": bytes.fromhex(TX[2:]),
        "deadline": 1900000000, "timestamp": rpc.timestamp, "agentId": 42,
        "requesterAgentId": 0, "agreementHash": ZERO,
    }
    rpc.logs = [raw_log(event_abi("actp_kernel.json", "TransactionCreated"), BASE_SEPOLIA.contracts.actp_kernel, values, 10, 0)]
    params = CreateTransactionParams(requester=ACCOUNT.address, provider=PROVIDER, amount="1000000", deadline=1900000000, service_description=TX, agent_id=42)
    assert await instance.create_transaction(params) == TX
    assert rpc.sent[-1][0] == "createTransaction"
    assert 1_000_000 in rpc.sent[-1][1]
    assert Account.recover_transaction(rpc.sent[-1][2]) == ACCOUNT.address
    params.deadline = rpc.timestamp
    count = len(rpc.sent)
    with pytest.raises(ValidationError, match="future"):
        await instance.create_transaction(params)
    assert len(rpc.sent) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("state,accepted", [(0, True), (1, True), (2, False), (5, False)])
async def test_link_escrow_approves_principal_only_for_allowed_states(runtime, state, accepted):
    rpc, instance = runtime
    rpc.reply("getTransaction", view_tuple(state))
    if not accepted:
        with pytest.raises(TransactionError, match="Cannot link escrow"):
            await instance.link_escrow(TX, "1000000")
        assert rpc.sent == []
        return
    assert await instance.link_escrow(TX, "1000000") == TX
    assert [name for name, _, _ in rpc.sent] == ["approve", "linkEscrow"]
    assert rpc.sent[0][1][-1] == 1_000_000


@pytest.mark.asyncio
@pytest.mark.parametrize("proof,wire", [(None, b""), ("0x1234", b"\x12\x34"), ("text", b"text")])
async def test_state_proof_wire_encoding(runtime, proof, wire):
    rpc, instance = runtime
    await instance.transition_state(TX, State.QUOTED, proof)
    assert rpc.sent[-1][0] == "transitionState"
    assert rpc.sent[-1][1] == (bytes.fromhex(TX[2:]), 1, wire)


@pytest.mark.asyncio
async def test_balances_allowances_and_nonce_controls_use_the_shared_runtime(runtime):
    rpc, instance = runtime
    rpc.reply("balanceOf", 2_500_000)
    rpc.reply("remaining", 750_000)
    rpc.reply("paused", False)
    rpc.reply("platformFeeBps", 100)
    assert await instance.get_balance(PROVIDER) == "2500000"
    assert await instance.get_usdc_balance(PROVIDER) == 2_500_000
    assert await instance.get_escrow_balance(TX) == "750000"
    await instance.approve_usdc(500_000)
    assert rpc.sent[-1][0] == "approve"
    assert await instance.sync_nonce() == rpc.nonce
    assert await instance.wait_for_confirmations(timeout=0) is True
    assert await instance.is_paused() is False
    assert await instance.get_platform_fee_bps() == 100


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["missing", "INITIATED", "window", "verified", "bad_attestation", "no_verifier"])
async def test_release_preconditions_and_attestation_failure_prevent_invalid_settlement(runtime, monkeypatch, status):
    rpc, instance = runtime
    tx = SimpleNamespace(state="DELIVERED", completed_at=1, dispute_window=1)
    if status == "missing":
        tx = None
    elif status == "INITIATED":
        tx.state = "INITIATED"
    elif status == "window":
        tx.completed_at = rpc.timestamp
        tx.dispute_window = 100
    monkeypatch.setattr(instance, "get_transaction", AsyncMock(return_value=tx))
    transition = AsyncMock()
    monkeypatch.setattr(instance, "transition_state", transition)
    uid = TX if status in ("verified", "bad_attestation", "no_verifier") else None
    if status in ("verified", "bad_attestation"):
        verify = AsyncMock(side_effect=RuntimeError("invalid local fixture") if status == "bad_attestation" else None)
        instance.eas_helper = SimpleNamespace(verify_and_record_for_release=verify)
    if status in ("missing", "INITIATED", "bad_attestation"):
        with pytest.raises(TransactionError):
            await instance.release_escrow(TX, uid)
        transition.assert_not_awaited()
    elif status == "window":
        with pytest.raises(DisputeWindowActiveError):
            await instance.release_escrow(TX, uid)
        transition.assert_not_awaited()
    else:
        await instance.release_escrow(TX, uid)
        transition.assert_awaited_once_with(TX, State.SETTLED)


@pytest.mark.asyncio
async def test_client_can_bootstrap_the_testnet_runtime_with_a_controlled_provider(runtime, tmp_path, monkeypatch):
    rpc, _ = runtime
    monkeypatch.chdir(tmp_path)
    client = await ACTPClient.create(mode="testnet", requester_address=ACCOUNT.address, private_key=KEY, wallet="eoa", state_directory=str(tmp_path / "state"), rpc_url="http://local-fixture.invalid")
    rpc.register(client.runtime.escrow.usdc_contract.abi)
    rpc.reply("balanceOf", 2_500_000)
    assert await client.get_balance() == "2.50"
    assert client.address == ACCOUNT.address.lower()
    assert client.runtime.config.chain_id == 84532
    await client._drift_task


@pytest.mark.asyncio
@pytest.mark.parametrize("intent,config_hash,onchain", [("pay", False, "zero"), ("earn", False, "zero"), ("earn", True, "zero"), ("earn", True, "different")])
async def test_config_drift_is_observational_and_never_sends_a_transaction(runtime, tmp_path, monkeypatch, intent, config_hash, onchain):
    rpc, instance = runtime
    monkeypatch.chdir(tmp_path)
    client = await ACTPClient.create(requester_address=ACCOUNT.address, config=ACTPClientConfig(mode="testnet", requester_address=ACCOUNT.address, runtime=instance))
    await client._drift_task
    text = f"---\nname: local\nintent: {intent}\n" + ("config_hash: example\n" if config_hash else "") + "---\n# local\n"
    (tmp_path / "AGIRAILS.md").write_text(text)
    module = importlib.import_module("agirails.config.on_chain_state")
    monkeypatch.setattr(module, "get_on_chain_config_state", lambda *a: SimpleNamespace(config_hash="0x" + ("00" if onchain == "zero" else "aa") * 32))
    await client.check_config_drift()
    assert rpc.sent == []
