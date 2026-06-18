"""
Tests for AutoWalletProvider.create_actp_transaction() and the
pay_actp_batched() ACTP nonce-collision retry loop.

Mirrors:
- sdk-js/src/wallet/AutoWalletProvider.createACTPTransaction.test.ts
- sdk-js/src/wallet/AutoWalletProvider.ts:366-483 (pay retry + createACTPTransaction)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from eth_account import Account
from web3 import Web3

from agirails.wallet.aa.constants import SmartWalletCall
from agirails.wallet.aa.transaction_batcher import (
    ContractAddresses,
    compute_transaction_id,
)
from agirails.wallet.auto_wallet_provider import (
    AutoWalletConfig,
    AutoWalletProvider,
    BatchedPayParams,
    CreateACTPTransactionParams,
    TransactionReceipt,
)


TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_CHAIN_ID = 84532
SMART_WALLET = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

PROVIDER_ADDR = "0x" + "11" * 20
REQUESTER_ADDR = "0x" + "22" * 20
KERNEL_ADDR = "0x" + "44" * 20
ZERO_HASH = "0x" + "00" * 32

CONTRACTS = ContractAddresses(
    usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    actp_kernel=KERNEL_ADDR,
    escrow_vault="0x262D5912A9612F0c66dA5d13B4E678D50ebC44b5",
)


def _make_provider() -> AutoWalletProvider:
    w3 = MagicMock()
    w3.to_checksum_address = Web3.to_checksum_address
    config = AutoWalletConfig(
        private_key=TEST_PRIVATE_KEY,
        w3=w3,
        chain_id=TEST_CHAIN_ID,
        actp_kernel_address=KERNEL_ADDR,
        bundler_primary_url="https://bundler.test",
        paymaster_primary_url="https://paymaster.test",
    )
    return AutoWalletProvider(config, SMART_WALLET, is_deployed=True)


def _passthrough_enqueue(ep_nonce: int, actp_nonce: int):
    """Build an async enqueue replacement that calls fn with fixed nonces."""

    async def _enqueue(fn, increments_actp_nonce):
        return await _run_enqueue(fn, ep_nonce, actp_nonce)

    return _enqueue


def _base_create_params(**overrides) -> CreateACTPTransactionParams:
    params = dict(
        provider=PROVIDER_ADDR,
        requester=REQUESTER_ADDR,
        amount="1000000",
        deadline=1_900_000_000,
        dispute_window=172800,
        service_hash=ZERO_HASH,
        agent_id="0",
        contracts={"actp_kernel": KERNEL_ADDR},
    )
    params.update(overrides)
    return CreateACTPTransactionParams(**params)


class TestCreateACTPTransaction:
    """AutoWalletProvider.create_actp_transaction()."""

    @pytest.mark.asyncio
    async def test_precomputes_tx_id_using_actp_nonce(self) -> None:
        provider = _make_provider()
        # enqueue passes actpNonce=3, entryPointNonce=5 like the TS mock.
        provider._nonce_manager.enqueue = _passthrough_enqueue(5, 3)
        provider._submit_user_op = AsyncMock(
            return_value=TransactionReceipt(hash="0xreceipt", success=True)
        )

        result = await provider.create_actp_transaction(_base_create_params())

        expected = compute_transaction_id(
            REQUESTER_ADDR, PROVIDER_ADDR, "1000000", ZERO_HASH, 3
        )
        assert result.tx_id == expected
        assert result.receipt.success is True
        assert result.receipt.hash == "0xreceipt"

    @pytest.mark.asyncio
    async def test_passes_increments_actp_nonce_true(self) -> None:
        provider = _make_provider()
        captured = {}

        async def _enqueue(fn, increments_actp_nonce):
            captured["inc"] = increments_actp_nonce
            return await _run_enqueue(fn, 5, 3)

        provider._nonce_manager.enqueue = _enqueue
        provider._submit_user_op = AsyncMock(
            return_value=TransactionReceipt(hash="0x", success=True)
        )

        await provider.create_actp_transaction(_base_create_params())
        assert captured["inc"] is True

    @pytest.mark.asyncio
    async def test_submits_single_call_user_op(self) -> None:
        provider = _make_provider()
        provider._nonce_manager.enqueue = _passthrough_enqueue(5, 3)
        submit = AsyncMock(
            return_value=TransactionReceipt(hash="0x", success=True)
        )
        provider._submit_user_op = submit

        await provider.create_actp_transaction(_base_create_params())

        assert submit.await_count == 1
        calls, ep_nonce = submit.await_args.args
        assert len(calls) == 1  # only createTransaction, not the 3-call batch
        assert Web3.to_checksum_address(calls[0].target) == Web3.to_checksum_address(
            KERNEL_ADDR
        )
        assert calls[0].value == 0
        assert ep_nonce == 5

    @pytest.mark.asyncio
    async def test_encodes_correct_create_transaction_calldata(self) -> None:
        from eth_abi import decode as abi_decode

        provider = _make_provider()
        provider._nonce_manager.enqueue = _passthrough_enqueue(5, 3)
        submit = AsyncMock(return_value=TransactionReceipt(hash="0x", success=True))
        provider._submit_user_op = submit

        service_hash = "0x" + Web3.keccak(text="test service").hex().replace("0x", "")
        await provider.create_actp_transaction(
            _base_create_params(service_hash=service_hash, agent_id="42")
        )

        calls, _ = submit.await_args.args
        data = bytes.fromhex(calls[0].data[2:])[4:]  # strip 0x + 4-byte selector
        decoded = abi_decode(
            ["address", "address", "uint256", "uint256", "uint256", "bytes32", "uint256", "uint256"],
            data,
        )
        assert Web3.to_checksum_address(decoded[0]) == Web3.to_checksum_address(PROVIDER_ADDR)
        assert Web3.to_checksum_address(decoded[1]) == Web3.to_checksum_address(REQUESTER_ADDR)
        assert decoded[2] == 1000000
        assert decoded[3] == 1_900_000_000
        assert decoded[4] == 172800
        assert "0x" + decoded[5].hex() == service_hash
        assert decoded[6] == 42

    @pytest.mark.asyncio
    async def test_returns_failure_receipt_without_throwing(self) -> None:
        provider = _make_provider()
        provider._nonce_manager.enqueue = _passthrough_enqueue(5, 3)
        provider._submit_user_op = AsyncMock(
            return_value=TransactionReceipt(hash="0xfailed", success=False)
        )

        result = await provider.create_actp_transaction(_base_create_params())
        assert result.receipt.success is False
        assert result.receipt.hash == "0xfailed"
        assert result.tx_id  # still pre-computed on failure

    @pytest.mark.asyncio
    async def test_propagates_submit_errors(self) -> None:
        provider = _make_provider()
        provider._nonce_manager.enqueue = _passthrough_enqueue(5, 3)
        provider._submit_user_op = AsyncMock(side_effect=RuntimeError("bundler unreachable"))

        with pytest.raises(RuntimeError, match="bundler unreachable"):
            await provider.create_actp_transaction(_base_create_params())


class TestPayACTPBatchedNonceCollisionRetry:
    """pay_actp_batched ACTP nonce-collision retry loop (AutoWalletProvider.ts:366-437)."""

    @pytest.mark.asyncio
    async def test_retries_on_escrow_id_collision_then_succeeds(self) -> None:
        provider = _make_provider()
        # Real nonce-manager mutex; mock the chain reads.
        provider._nonce_manager.read_entry_point_nonce = AsyncMock(return_value=11)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=5)

        calls = {"n": 0}

        async def submit(all_calls, ep_nonce):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("execution reverted: Escrow ID already used")
            return TransactionReceipt(hash="0xok", success=True)

        provider._submit_user_op = submit

        params = BatchedPayParams(
            provider=PROVIDER_ADDR,
            requester=SMART_WALLET,
            amount="1000000",
            deadline=1_900_000_000,
            dispute_window=86400,
            service_hash=ZERO_HASH,
            agent_id="0",
            contracts=CONTRACTS,
        )

        result = await provider.pay_actp_batched(params)
        assert result.success is True
        assert result.hash == "0xok"
        assert calls["n"] == 2  # one collision, one success
        # Cache pinned to candidate+1 == 6+1 (nonce 5 collided, bumped to 6, succeeded)
        assert provider._nonce_manager._cached_actp_nonce == 7

    @pytest.mark.asyncio
    async def test_matches_abi_hex_collision_revert(self) -> None:
        provider = _make_provider()
        provider._nonce_manager.read_entry_point_nonce = AsyncMock(return_value=11)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=0)

        calls = {"n": 0}

        async def submit(all_calls, ep_nonce):
            calls["n"] += 1
            if calls["n"] == 1:
                # ABI-encoded "Escrow ID already used"
                raise RuntimeError(
                    "reverted 0x...457363726f7720494420616c72656164792075736564"
                )
            return TransactionReceipt(hash="0xok", success=True)

        provider._submit_user_op = submit

        params = BatchedPayParams(
            provider=PROVIDER_ADDR,
            requester=SMART_WALLET,
            amount="1000000",
            deadline=1_900_000_000,
            dispute_window=86400,
            service_hash=ZERO_HASH,
            agent_id="0",
            contracts=CONTRACTS,
        )

        result = await provider.pay_actp_batched(params)
        assert result.success is True
        assert calls["n"] == 2

    @pytest.mark.asyncio
    async def test_non_collision_error_propagates_immediately(self) -> None:
        provider = _make_provider()
        provider._nonce_manager.read_entry_point_nonce = AsyncMock(return_value=11)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=0)

        provider._submit_user_op = AsyncMock(
            side_effect=RuntimeError("AA21 didn't pay prefund")
        )

        params = BatchedPayParams(
            provider=PROVIDER_ADDR,
            requester=SMART_WALLET,
            amount="1000000",
            deadline=1_900_000_000,
            dispute_window=86400,
            service_hash=ZERO_HASH,
            agent_id="0",
            contracts=CONTRACTS,
        )

        with pytest.raises(RuntimeError, match="didn't pay prefund"):
            await provider.pay_actp_batched(params)


async def _run_enqueue(fn, ep_nonce: int, actp_nonce: int):
    """Mimic DualNonceManager.enqueue: call fn with nonces, return result."""
    from agirails.wallet.aa.dual_nonce_manager import NonceSet

    out = await fn(NonceSet(entry_point_nonce=ep_nonce, actp_nonce=actp_nonce))
    return out.result
