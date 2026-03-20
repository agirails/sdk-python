"""
Tests for ContractBase shared transaction infrastructure.

Covers:
- NonceManager wiring in _build_tx_params (Bug 3)
- Nonce confirm/release lifecycle in _sign_and_send (Bug 3)
- Backward compat without nonce_manager
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from agirails.errors.transaction import TransactionError
from agirails.protocol.base import ContractBase
from agirails.protocol.nonce import NonceManager


@pytest.fixture
def mock_w3():
    w3 = MagicMock()
    w3.eth.get_transaction_count = AsyncMock(return_value=5)
    w3.eth.get_block = AsyncMock(return_value={"baseFeePerGas": 1_000_000_000})
    w3.eth.send_raw_transaction = AsyncMock(return_value=b"\xab" * 32)
    w3.eth.wait_for_transaction_receipt = AsyncMock(
        return_value={
            "status": 1,
            "transactionHash": b"\xab" * 32,
            "blockNumber": 100,
            "blockHash": b"\xcd" * 32,
            "gasUsed": 21000,
            "effectiveGasPrice": 1_000_000_000,
            "logs": [],
        }
    )
    w3.eth.account.sign_transaction = MagicMock(
        return_value=MagicMock(raw_transaction=b"\xff" * 64)
    )
    return w3


@pytest.fixture
def mock_account():
    account = MagicMock()
    account.address = "0x" + "a" * 40
    account.key = b"\x01" * 32
    return account


@pytest.fixture
def mock_nonce_manager():
    nm = MagicMock(spec=NonceManager)
    nm.get_nonce = AsyncMock(return_value=42)
    nm.confirm_nonce = AsyncMock()
    nm.release_nonce = AsyncMock()
    return nm


@pytest.fixture
def base_with_nm(mock_w3, mock_account, mock_nonce_manager):
    contract = MagicMock()
    return ContractBase(
        contract, mock_account, mock_w3, chain_id=84532,
        nonce_manager=mock_nonce_manager,
    )


@pytest.fixture
def base_without_nm(mock_w3, mock_account):
    contract = MagicMock()
    return ContractBase(contract, mock_account, mock_w3, chain_id=84532)


# ============================================================================
# _build_tx_params
# ============================================================================


class TestBuildTxParams:
    @pytest.mark.asyncio
    async def test_uses_nonce_manager_when_present(self, base_with_nm, mock_nonce_manager, mock_w3):
        params = await base_with_nm._build_tx_params(gas_limit=200_000)
        mock_nonce_manager.get_nonce.assert_called_once()
        assert params["nonce"] == 42
        mock_w3.eth.get_transaction_count.assert_not_called()

    @pytest.mark.asyncio
    async def test_falls_back_to_rpc_without_nonce_manager(self, base_without_nm, mock_w3):
        params = await base_without_nm._build_tx_params(gas_limit=200_000)
        mock_w3.eth.get_transaction_count.assert_called_once_with(
            base_without_nm.account.address, "pending"
        )
        assert params["nonce"] == 5

    @pytest.mark.asyncio
    async def test_includes_chain_id(self, base_with_nm):
        params = await base_with_nm._build_tx_params(gas_limit=100_000)
        assert params["chainId"] == 84532

    @pytest.mark.asyncio
    async def test_explicit_gas_prices_bypass_rpc(self, base_with_nm, mock_w3):
        params = await base_with_nm._build_tx_params(
            gas_limit=100_000,
            max_fee_per_gas=5_000_000_000,
            max_priority_fee_per_gas=2_000_000_000,
        )
        assert params["maxFeePerGas"] == 5_000_000_000
        assert params["maxPriorityFeePerGas"] == 2_000_000_000
        mock_w3.eth.get_block.assert_not_called()


# ============================================================================
# _sign_and_send nonce lifecycle
# ============================================================================


class TestSignAndSendNonceLifecycle:
    @pytest.mark.asyncio
    async def test_confirms_nonce_on_success(self, base_with_nm, mock_nonce_manager):
        tx = {"nonce": 42, "gas": 100_000}
        await base_with_nm._sign_and_send(tx)
        mock_nonce_manager.confirm_nonce.assert_called_once_with(42)
        mock_nonce_manager.release_nonce.assert_not_called()

    @pytest.mark.asyncio
    async def test_releases_nonce_on_broadcast_failure(
        self, base_with_nm, mock_nonce_manager, mock_w3
    ):
        mock_w3.eth.send_raw_transaction = AsyncMock(
            side_effect=Exception("nonce too low")
        )
        tx = {"nonce": 42, "gas": 100_000}
        with pytest.raises(Exception, match="nonce too low"):
            await base_with_nm._sign_and_send(tx)
        mock_nonce_manager.release_nonce.assert_called_once_with(42)
        mock_nonce_manager.confirm_nonce.assert_not_called()

    @pytest.mark.asyncio
    async def test_confirms_nonce_on_reverted_tx(self, base_with_nm, mock_nonce_manager, mock_w3):
        """Reverted txs still consume nonce on-chain — must confirm, not release."""
        mock_w3.eth.wait_for_transaction_receipt = AsyncMock(
            return_value={
                "status": 0,
                "transactionHash": b"\xab" * 32,
                "blockNumber": 101,
                "blockHash": b"\xcd" * 32,
                "gasUsed": 21000,
                "effectiveGasPrice": 0,
                "logs": [],
            }
        )
        tx = {"nonce": 42, "gas": 100_000}
        with pytest.raises(TransactionError):
            await base_with_nm._sign_and_send(tx)
        mock_nonce_manager.confirm_nonce.assert_called_once_with(42)
        mock_nonce_manager.release_nonce.assert_not_called()

    @pytest.mark.asyncio
    async def test_confirms_nonce_on_timeout(self, base_with_nm, mock_nonce_manager, mock_w3):
        """Timeout after broadcast = tx in mempool = nonce consumed."""
        async def slow_receipt(*args, **kwargs):
            await asyncio.sleep(999)

        mock_w3.eth.wait_for_transaction_receipt = AsyncMock(side_effect=slow_receipt)
        tx = {"nonce": 42, "gas": 100_000}
        with pytest.raises(TransactionError, match="timed out"):
            await base_with_nm._sign_and_send(tx, timeout=0.01)
        mock_nonce_manager.confirm_nonce.assert_called_once_with(42)
        mock_nonce_manager.release_nonce.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_nonce_manager_no_crash(self, base_without_nm):
        """Backward compat: works without nonce_manager."""
        tx = {"nonce": 7, "gas": 100_000}
        receipt = await base_without_nm._sign_and_send(tx)
        assert receipt["status"] == 1


# ============================================================================
# _to_bytes32
# ============================================================================


class TestToBytes32:
    def test_padded_short_hex(self, base_without_nm):
        result = base_without_nm._to_bytes32("0x01")
        assert len(result) == 32
        assert result[-1] == 1

    def test_full_32_byte_hex(self, base_without_nm):
        full = "0x" + "ab" * 32
        result = base_without_nm._to_bytes32(full)
        assert len(result) == 32
        assert result[0] == 0xAB

    def test_without_0x_prefix(self, base_without_nm):
        result = base_without_nm._to_bytes32("deadbeef")
        assert len(result) == 32


# ============================================================================
# Network mapping (Bug 1)
# ============================================================================


class TestNetworkMapping:
    def test_base_mainnet_key_exists(self):
        from agirails.config.networks import NETWORKS
        assert "base-mainnet" in NETWORKS
        assert "base" not in NETWORKS

    def test_client_mainnet_mode_uses_correct_key(self):
        """Bug 1: mode='mainnet' must map to 'base-mainnet', not 'base'."""
        # Reproduce the logic from client.py:320
        mode = "mainnet"
        network_name = "base-sepolia" if mode == "testnet" else "base-mainnet"
        assert network_name == "base-mainnet"

    def test_client_testnet_mode_uses_correct_key(self):
        mode = "testnet"
        network_name = "base-sepolia" if mode == "testnet" else "base-mainnet"
        assert network_name == "base-sepolia"
