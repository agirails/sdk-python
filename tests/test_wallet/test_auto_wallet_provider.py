"""
Tests for AutoWalletProvider -- Tier 1 (Auto) wallet.

Covers:
- Factory creates with counterfactual address
- Wallet info (tier=auto, batching=true, gas_sponsored=true)
- pay_actp_batched flow (mocked bundler/paymaster)
- Prepend activation calls
- Mark deployed after first success
- send_batch_transaction
- Error handling
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from eth_account import Account
from web3 import Web3

from agirails.wallet.aa.constants import SmartWalletCall, GasEstimate, PaymasterResponse
from agirails.wallet.aa.bundler_client import BundlerClient, BundlerConfig, UserOpReceipt
from agirails.wallet.aa.paymaster_client import PaymasterClient, PaymasterConfig
from agirails.wallet.aa.transaction_batcher import ContractAddresses
from agirails.wallet.auto_wallet_provider import (
    AutoWalletConfig,
    AutoWalletProvider,
    BatchedPayParams,
    BatchedPayResult,
    TransactionReceipt,
    TransactionRequest,
    WalletInfo,
)


# ============================================================================
# Fixtures
# ============================================================================

TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_SIGNER = Account.from_key(TEST_PRIVATE_KEY)
TEST_CHAIN_ID = 84532
SMART_WALLET = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

CONTRACTS = ContractAddresses(
    usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    actp_kernel="0x132B9eB321dBB57c828B083844287171BDC92d29",
    escrow_vault="0x6aAF45882c4b0dD34130ecC790bb5Ec6be7fFb99",
)


def _make_mock_w3() -> MagicMock:
    """Create a mock Web3 instance."""
    w3 = MagicMock()
    w3.eth.fee_history.return_value = {
        "baseFeePerGas": [1000000000],
        "reward": [[500000000]],
    }
    w3.to_checksum_address = Web3.to_checksum_address
    return w3


def _make_provider(
    is_deployed: bool = True,
    smart_wallet: str = SMART_WALLET,
) -> AutoWalletProvider:
    """Create an AutoWalletProvider with mocked dependencies."""
    w3 = _make_mock_w3()

    config = AutoWalletConfig(
        private_key=TEST_PRIVATE_KEY,
        w3=w3,
        chain_id=TEST_CHAIN_ID,
        actp_kernel_address=CONTRACTS.actp_kernel,
        bundler_primary_url="https://bundler.test",
        paymaster_primary_url="https://paymaster.test",
    )

    provider = AutoWalletProvider(config, smart_wallet, is_deployed)
    return provider


# ============================================================================
# Tests
# ============================================================================


class TestAutoWalletProviderInit:
    """Tests for AutoWalletProvider initialization."""

    def test_get_address(self) -> None:
        """get_address returns Smart Wallet address."""
        provider = _make_provider()
        assert provider.get_address() == SMART_WALLET

    def test_wallet_info(self) -> None:
        """Wallet info has correct tier, batching, gas_sponsored."""
        provider = _make_provider()
        info = provider.get_wallet_info()
        assert info.tier == "auto"
        assert info.supports_batching is True
        assert info.gas_sponsored is True
        assert info.chain_id == TEST_CHAIN_ID
        assert info.address == SMART_WALLET

    def test_is_deployed_flag(self) -> None:
        """get_is_deployed reflects initialization state."""
        deployed = _make_provider(is_deployed=True)
        assert deployed.get_is_deployed() is True

        not_deployed = _make_provider(is_deployed=False)
        assert not_deployed.get_is_deployed() is False


class TestAutoWalletProviderFactory:
    """Tests for AutoWalletProvider.create() factory."""

    @pytest.mark.asyncio
    async def test_create_computes_address(self) -> None:
        """Factory computes counterfactual address from signer."""
        w3 = _make_mock_w3()
        w3.eth.get_code.return_value = b""

        expected_addr = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

        with patch(
            "agirails.wallet.auto_wallet_provider.compute_smart_wallet_address",
            new_callable=AsyncMock,
            return_value=expected_addr,
        ):
            config = AutoWalletConfig(
                private_key=TEST_PRIVATE_KEY,
                w3=w3,
                chain_id=TEST_CHAIN_ID,
                actp_kernel_address=CONTRACTS.actp_kernel,
                bundler_primary_url="https://bundler.test",
                paymaster_primary_url="https://paymaster.test",
            )
            provider = await AutoWalletProvider.create(config)

        assert provider.get_address() == expected_addr
        assert provider.get_is_deployed() is False

    @pytest.mark.asyncio
    async def test_create_detects_deployed(self) -> None:
        """Factory detects already-deployed wallet."""
        w3 = _make_mock_w3()
        w3.eth.get_code.return_value = b"\x60\x80"  # Non-empty bytecode

        with patch(
            "agirails.wallet.auto_wallet_provider.compute_smart_wallet_address",
            new_callable=AsyncMock,
            return_value=SMART_WALLET,
        ):
            config = AutoWalletConfig(
                private_key=TEST_PRIVATE_KEY,
                w3=w3,
                chain_id=TEST_CHAIN_ID,
                actp_kernel_address=CONTRACTS.actp_kernel,
                bundler_primary_url="https://bundler.test",
                paymaster_primary_url="https://paymaster.test",
            )
            provider = await AutoWalletProvider.create(config)

        assert provider.get_is_deployed() is True


class TestAutoWalletProviderPayment:
    """Tests for payment flows."""

    @pytest.mark.asyncio
    async def test_pay_actp_batched_success(self) -> None:
        """pay_actp_batched submits UserOp and returns txId."""
        provider = _make_provider(is_deployed=True)

        # Mock bundler
        provider._bundler.estimate_user_operation_gas = AsyncMock(
            return_value=GasEstimate(
                call_gas_limit=100000,
                verification_gas_limit=200000,
                pre_verification_gas=50000,
            )
        )
        provider._bundler.send_user_operation = AsyncMock(return_value="0xuserophash")
        provider._bundler.wait_for_receipt = AsyncMock(
            return_value=UserOpReceipt(
                user_op_hash="0xuserophash",
                transaction_hash="0xtxhash123",
                block_number=100,
                success=True,
            )
        )

        # Mock paymaster
        provider._paymaster.get_paymaster_stub_data = AsyncMock(
            return_value=PaymasterResponse(paymaster_and_data="0xaabbccdd")
        )
        provider._paymaster.get_paymaster_data = AsyncMock(
            return_value=PaymasterResponse(paymaster_and_data="0xeeff0011")
        )

        # Mock nonce manager to pass through
        provider._nonce_manager._read_entry_point_nonce = AsyncMock(return_value=0)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=5)

        params = BatchedPayParams(
            provider="0x2222222222222222222222222222222222222222",
            requester=SMART_WALLET,
            amount="1000000",
            deadline=1999999999,
            dispute_window=86400,
            service_hash="0x" + "ab" * 32,
            agent_id="0",
            contracts=CONTRACTS,
        )

        result = await provider.pay_actp_batched(params)

        assert result.success is True
        assert result.hash == "0xtxhash123"
        assert result.tx_id.startswith("0x")

    @pytest.mark.asyncio
    async def test_pay_actp_batched_with_prepend(self) -> None:
        """pay_actp_batched prepends activation calls."""
        provider = _make_provider(is_deployed=True)

        # Mock all external calls
        provider._bundler.estimate_user_operation_gas = AsyncMock(
            return_value=GasEstimate(100000, 200000, 50000)
        )
        provider._bundler.send_user_operation = AsyncMock(return_value="0xhash")
        provider._bundler.wait_for_receipt = AsyncMock(
            return_value=UserOpReceipt("0xhash", "0xtxhash", 100, True)
        )
        provider._paymaster.get_paymaster_stub_data = AsyncMock(
            return_value=PaymasterResponse("0xaabb")
        )
        provider._paymaster.get_paymaster_data = AsyncMock(
            return_value=PaymasterResponse("0xccdd")
        )
        provider._nonce_manager._read_entry_point_nonce = AsyncMock(return_value=0)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=0)

        prepend = [
            SmartWalletCall(
                target="0x6fB222CF3DDdf37Bcb248EE7BBBA42Fb41901de8",
                value=0,
                data="0xaabbccdd",
            )
        ]

        params = BatchedPayParams(
            provider="0x2222222222222222222222222222222222222222",
            requester=SMART_WALLET,
            amount="1000000",
            deadline=1999999999,
            dispute_window=86400,
            service_hash="0x" + "ab" * 32,
            agent_id="0",
            contracts=CONTRACTS,
        )

        result = await provider.pay_actp_batched(params, prepend_calls=prepend)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_marks_deployed_after_first_success(self) -> None:
        """Provider sets is_deployed=True after first successful UserOp."""
        provider = _make_provider(is_deployed=False)
        assert provider.get_is_deployed() is False

        # Mock all external calls
        provider._bundler.estimate_user_operation_gas = AsyncMock(
            return_value=GasEstimate(100000, 200000, 50000)
        )
        provider._bundler.send_user_operation = AsyncMock(return_value="0xhash")
        provider._bundler.wait_for_receipt = AsyncMock(
            return_value=UserOpReceipt("0xhash", "0xtxhash", 100, True)
        )
        provider._paymaster.get_paymaster_stub_data = AsyncMock(
            return_value=PaymasterResponse("0xaabb")
        )
        provider._paymaster.get_paymaster_data = AsyncMock(
            return_value=PaymasterResponse("0xccdd")
        )
        provider._nonce_manager._read_entry_point_nonce = AsyncMock(return_value=0)
        provider._nonce_manager._read_actp_nonce = AsyncMock(return_value=0)

        txs = [TransactionRequest(to=SMART_WALLET, data="0xdeadbeef")]
        await provider.send_batch_transaction(txs)

        assert provider.get_is_deployed() is True

    @pytest.mark.asyncio
    async def test_send_batch_empty_raises(self) -> None:
        """send_batch_transaction with empty list raises ValueError."""
        provider = _make_provider()
        with pytest.raises(ValueError, match="at least one"):
            await provider.send_batch_transaction([])


class TestAutoWalletProviderNonceManager:
    """Tests for nonce manager access."""

    def test_get_nonce_manager(self) -> None:
        """get_nonce_manager returns the internal DualNonceManager."""
        provider = _make_provider()
        mgr = provider.get_nonce_manager()
        assert mgr is not None
        assert mgr is provider._nonce_manager
