"""Real ABI encoding/decoding and signatures over a controlled JSON-RPC ledger."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from eth_abi import decode
from eth_account import Account
from web3 import AsyncWeb3, Web3

from agirails.config.networks import BASE_SEPOLIA
from agirails.protocol.eas import EAS_ABI, SCHEMA_REGISTRY_ABI, EASHelper
from agirails.protocol.escrow import CreateEscrowParams, EscrowVault
from agirails.protocol.nonce import NonceManager, NonceManagerPool
from tests.helpers.contract_rpc import ContractRPC

TX = "0x" + "ab" * 32
UID = "0x" + "cd" * 32
OTHER = Web3.to_checksum_address("0x" + "22" * 20)
ACCOUNT = Account.from_key("0x" + "11" * 32)


@pytest_asyncio.fixture
async def ledger():
    rpc = ContractRPC()
    return rpc, AsyncWeb3(rpc)


@pytest.fixture
def escrow(ledger):
    rpc, w3 = ledger
    vault = EscrowVault.from_config(w3, ACCOUNT, BASE_SEPOLIA)
    rpc.register(vault.contract.abi)
    rpc.register(vault.usdc_contract.abi)
    return rpc, vault


@pytest.mark.asyncio
@pytest.mark.parametrize("approve", [False, True])
async def test_create_escrow_sends_exact_principal_and_distinct_transactions(escrow, approve):
    rpc, vault = escrow
    params = CreateEscrowParams(ACCOUNT.address, OTHER, 1_250_000, TX)
    assert await vault.create_escrow(params, auto_approve=approve) == TX
    assert [x[0] for x in rpc.sent] == (["approve", "createEscrow"] if approve else ["createEscrow"])
    assert rpc.sent[-1][1] == (bytes.fromhex(TX[2:]), ACCOUNT.address.lower(), OTHER.lower(), 1_250_000)
    if approve:
        assert rpc.sent[0][1] == (vault.contract.address.lower(), 1_250_000)
    assert all(Account.recover_transaction(raw) == ACCOUNT.address for _, _, raw in rpc.sent)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,wire,amount", [
    ("payout", "payout", 250_000),
    ("payout_to_provider", "payoutToProvider", 350_000),
    ("refund_to_requester", "refundToRequester", 450_000),
])
async def test_payout_writes_encode_recipient_amount_and_return_receipt(escrow, method, wire, amount):
    rpc, vault = escrow
    args = [TX, OTHER, amount] if method == "payout" else [TX, amount]
    paid, receipt = await getattr(vault, method)(*args)
    assert paid == amount
    assert receipt.success is True
    assert receipt.gas_used == 50_000
    assert rpc.sent[0][0] == wire
    assert rpc.sent[0][1][-1] == amount
    assert rpc.sent[0][1][0] == bytes.fromhex(TX[2:])
    assert Account.recover_transaction(rpc.sent[0][2]) == ACCOUNT.address


@pytest.mark.asyncio
async def test_escrow_queries_decode_accounting_and_contract_addresses(escrow):
    rpc, vault = escrow
    rpc.reply("escrows", ACCOUNT.address, OTHER, 1_000_000, 250_000, True)
    rpc.reply("remaining", 750_000)
    rpc.reply("verifyEscrow", True, 750_000)
    rpc.reply("balanceOf", 5_000_000)
    rpc.reply("allowance", 2_000_000)
    rpc.reply("token", BASE_SEPOLIA.contracts.usdc)
    rpc.reply("kernel", BASE_SEPOLIA.contracts.actp_kernel)
    info = await vault.get_escrow(TX)
    assert info.to_dict()["remainingUsdc"] == 0.75
    assert info.amount_usdc == 1
    assert await vault.get_remaining(TX) == 750_000
    assert await vault.verify_escrow(TX, ACCOUNT.address, OTHER, 1_000_000) == (True, 750_000)
    assert await vault.get_usdc_balance() == 5_000_000
    assert await vault.get_usdc_balance(OTHER) == 5_000_000
    assert await vault.get_usdc_allowance() == 2_000_000
    assert await vault.get_usdc_allowance(OTHER, ACCOUNT.address) == 2_000_000
    assert (await vault.get_token_address()).lower() == BASE_SEPOLIA.contracts.usdc.lower()
    assert (await vault.get_kernel_address()).lower() == BASE_SEPOLIA.contracts.actp_kernel.lower()


@pytest.fixture
def eas(ledger):
    rpc, w3 = ledger
    rpc.register(EAS_ABI)
    rpc.register(SCHEMA_REGISTRY_ABI)
    helper = EASHelper(
        w3.eth.contract(address=BASE_SEPOLIA.contracts.eas, abi=EAS_ABI),
        w3.eth.contract(address=BASE_SEPOLIA.contracts.eas_schema_registry, abi=SCHEMA_REGISTRY_ABI),
        ACCOUNT, w3, 84532, UID,
    )
    rpc.logs = [{
        "address": BASE_SEPOLIA.contracts.eas, "topics": ["0x" + "ef" * 32, UID],
        "data": "0x", "blockNumber": "0xa", "transactionHash": TX,
        "transactionIndex": "0x0", "blockHash": "0x" + "bb" * 32,
        "logIndex": "0x0", "removed": False,
    }]
    return rpc, helper


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["aip4", "aip6"])
async def test_delivery_attestation_serializes_the_schema_and_signed_data(eas, version):
    rpc, helper = eas
    if version == "aip4":
        uid = await helper.create_delivery_attestation_aip4(TX, TX, OTHER)
    else:
        uid = await helper.create_delivery_attestation(TX, "bafy-delivery", TX)
    assert uid == UID
    name, args, raw = rpc.sent[-1]
    assert name == "attest"
    assert args[0][0] == bytes.fromhex(UID[2:])
    recipient, expiry, revocable, ref, payload, value = args[0][1]
    assert recipient == (OTHER if version == "aip4" else ACCOUNT.address).lower()
    assert (expiry, revocable, ref, value) == (0, True, bytes(32), 0)
    types = ["bytes32", "bytes32", "address", "uint64"] if version == "aip4" else ["bytes32", "string", "bytes32", "uint256"]
    fields = decode(types, payload)
    assert fields[0] == bytes.fromhex(TX[2:])
    assert fields[1] == (bytes.fromhex(TX[2:]) if version == "aip4" else "bafy-delivery")
    assert Account.recover_transaction(raw) == ACCOUNT.address


@pytest.mark.asyncio
async def test_eas_schema_revocation_and_reads_preserve_wire_values(eas):
    rpc, helper = eas
    assert await helper.register_schema("bytes32 resultHash") == UID
    assert rpc.sent[-1][0] == "register"
    assert rpc.sent[-1][1][0] == "bytes32 resultHash"
    receipt = await helper.revoke_attestation(UID)
    assert receipt.success is True
    assert rpc.sent[-1][0] == "revoke"
    rpc.reply("isAttestationValid", False)
    assert await helper.is_attestation_valid(UID) is False
    rpc.reply("getSchema", (bytes.fromhex(UID[2:]), OTHER, True, "bytes32 resultHash"))
    schema = await helper.get_schema(UID)
    assert schema.uid == UID
    assert schema.revocable is True
    assert schema.schema == "bytes32 resultHash"


@pytest.mark.asyncio
async def test_eas_absent_uid_and_missing_receipt_events_fail_explicitly(eas):
    rpc, helper = eas
    rpc.logs = []
    with pytest.raises(ValueError, match="extract attestation UID"):
        await helper.create_delivery_attestation(TX, "bafy-result", TX)
    with pytest.raises(ValueError, match="extract schema UID"):
        await helper.register_schema("bytes32 resultHash")
    helper._delivery_schema_uid = ""
    with pytest.raises(ValueError, match="not configured"):
        await helper.create_delivery_attestation(TX, "bafy-result", TX)
    with pytest.raises(ValueError, match="not configured"):
        await helper.create_delivery_attestation_aip4(TX, TX, OTHER)
    with pytest.raises(ValueError, match="required"):
        await helper.revoke_attestation(UID)


@pytest.mark.asyncio
async def test_nonce_reservations_are_unique_and_release_only_rewinds_the_tail(ledger):
    rpc, w3 = ledger
    manager = NonceManager(w3, ACCOUNT.address)
    values = await asyncio.gather(*(manager.get_nonce() for _ in range(20)))
    assert sorted(values) == list(range(3, 23))
    await manager.release_nonce(22)
    assert await manager.get_nonce() == 22
    await manager.release_nonce(5)
    assert await manager.peek_nonce() == 23
    snapshot = manager.get_pending_nonces()
    snapshot.clear()
    assert manager.get_pending_count() == 19
    rpc.nonce = 30
    assert await manager.sync() == 30
    assert manager.get_pending_count() == 0
    assert await manager.wait_for_confirmations(timeout=0) is True
    assert await manager.reset() == 30


@pytest.mark.asyncio
async def test_nonce_pool_keeps_accounts_separate_and_reports_confirmation_timeouts(ledger):
    rpc, w3 = ledger
    pool = NonceManagerPool(w3)
    assert await pool.get_nonce(ACCOUNT.address) == 3
    assert await pool.get_nonce(OTHER) == 3
    await pool.release_nonce(ACCOUNT.address, 3)
    assert await pool.get_nonce(ACCOUNT.address) == 3
    await pool.confirm_nonce(OTHER, 3)
    assert await pool.sync(OTHER) == 4
    manager = await pool._get_or_create_manager(ACCOUNT.address)
    assert await manager.wait_for_confirmations(timeout=-1, poll_interval=0) is False
    rpc.nonce = 5
    assert await manager.wait_for_confirmations(timeout=1, poll_interval=0) is True
    await pool.reset(OTHER)
    await pool.reset()
    await pool.confirm_nonce("0x" + "33" * 20, 1)
    await pool.release_nonce("0x" + "33" * 20, 1)
