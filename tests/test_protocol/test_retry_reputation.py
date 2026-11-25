"""retryReputation(bytes32), added by the b08c0c6 kernel: vendored ABI and ACTPKernel.retry_reputation."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from eth_utils import keccak

from agirails.protocol.kernel import ACTPKernel

ABI_PATH = Path(__file__).resolve().parents[2] / "src" / "agirails" / "abis" / "actp_kernel.json"
TX_ID = "0x" + "99" * 32
RETRY_REPUTATION_GAS_FLOOR = 240_000


def _kernel_with_retry(estimate=None, estimate_error=None):
    fn = MagicMock()
    fn.estimate_gas = AsyncMock(return_value=estimate, side_effect=estimate_error)
    fn.build_transaction = AsyncMock(return_value={"to": "0x" + "aa" * 20})
    contract = MagicMock()
    contract.functions.retryReputation.return_value = fn
    account = MagicMock()
    account.address = "0x" + "11" * 20
    w3 = MagicMock()
    w3.eth.send_raw_transaction = AsyncMock()
    kernel = ACTPKernel(contract, account, w3, 84532)
    kernel._build_tx_params = AsyncMock(return_value={})
    kernel._sign_and_send = AsyncMock(return_value="0x" + "cd" * 32)
    kernel._to_receipt = MagicMock(return_value="receipt")
    return kernel, contract, fn, account, w3


def test_vendored_abi_exposes_retry_reputation():
    abi = json.loads(ABI_PATH.read_text())
    entries = [e for e in abi if e.get("type") == "function" and e.get("name") == "retryReputation"]
    assert len(entries) == 1
    assert [i["type"] for i in entries[0]["inputs"]] == ["bytes32"]
    assert entries[0]["outputs"] == [] and entries[0]["stateMutability"] == "nonpayable"
    signature = f"{entries[0]['name']}({','.join(i['type'] for i in entries[0]['inputs'])})"
    assert keccak(text=signature)[:4].hex() == "adef3f4b"


@pytest.mark.asyncio
async def test_retry_reputation_sends_for_the_transaction_with_buffered_estimate():
    kernel, contract, fn, _, _ = _kernel_with_retry(estimate=210_000)

    assert await kernel.retry_reputation(TX_ID) == "receipt"

    contract.functions.retryReputation.assert_called_once_with(bytes.fromhex("99" * 32))
    kernel._build_tx_params.assert_awaited_once_with(gas_limit=(210_000 * 115 + 99) // 100)
    kernel._sign_and_send.assert_awaited_once()


@pytest.mark.asyncio
async def test_retry_reputation_keeps_the_240k_floor_for_the_fixed_150k_registry_call():
    kernel, _, _, _, _ = _kernel_with_retry(estimate=51_697)

    await kernel.retry_reputation(TX_ID)

    kernel._build_tx_params.assert_awaited_once_with(gas_limit=RETRY_REPUTATION_GAS_FLOOR)


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["No reputation outcome", "Tx missing"])
async def test_retry_reputation_estimation_revert_never_signs_or_broadcasts(reason):
    kernel, _, fn, account, w3 = _kernel_with_retry(estimate_error=Exception(reason))

    with pytest.raises(Exception, match=reason):
        await kernel.retry_reputation(TX_ID)

    kernel._sign_and_send.assert_not_awaited()
    account.sign_transaction.assert_not_called()
    w3.eth.send_raw_transaction.assert_not_awaited()
    fn.build_transaction.assert_not_called()
