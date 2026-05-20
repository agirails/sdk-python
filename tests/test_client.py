"""
Tests for ACTPClient.

Tests for:
- ACTPClient.create() factory method
- Mock mode initialization
- Adapter access
- Balance and token operations
- Reset functionality
"""

import tempfile
from pathlib import Path

import pytest

from agirails import ACTPClient, ACTPClientConfig, ValidationError
from agirails.utils.helpers import Address


class TestACTPClientCreate:
    """Tests for ACTPClient.create() factory."""

    @pytest.fixture
    def requester_address(self):
        """Valid requester address."""
        return "0x" + "a" * 40

    @pytest.mark.asyncio
    async def test_create_mock_mode(self, requester_address):
        """Create client in mock mode."""
        client = await ACTPClient.create(
            mode="mock",
            requester_address=requester_address,
        )

        assert client is not None
        assert client.get_mode() == "mock"
        assert client.get_address() == requester_address.lower()

    @pytest.mark.asyncio
    async def test_create_with_custom_state_directory(self, requester_address):
        """Create with custom state directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = await ACTPClient.create(
                mode="mock",
                requester_address=requester_address,
                state_directory=tmpdir,
            )

            assert client.info.state_directory == Path(tmpdir)

    @pytest.mark.asyncio
    async def test_create_with_config_object(self, requester_address):
        """Create using config object."""
        config = ACTPClientConfig(
            mode="mock",
            requester_address=requester_address,
        )

        client = await ACTPClient.create(config=config)
        assert client.get_mode() == "mock"

    @pytest.mark.asyncio
    async def test_create_missing_address(self):
        """Missing requester_address should raise."""
        with pytest.raises(ValidationError, match="requester_address is required"):
            await ACTPClient.create(mode="mock")

    @pytest.mark.asyncio
    async def test_create_invalid_address(self):
        """Invalid address format should raise."""
        with pytest.raises(ValidationError, match="Invalid requester_address"):
            await ACTPClient.create(
                mode="mock",
                requester_address="invalid",
            )

    @pytest.mark.asyncio
    async def test_create_normalizes_address(self, requester_address):
        """Address should be normalized to lowercase."""
        upper_address = requester_address.upper().replace("0X", "0x")
        client = await ACTPClient.create(
            mode="mock",
            requester_address=upper_address,
        )

        assert client.get_address() == requester_address.lower()


class TestACTPClientAdapters:
    """Tests for adapter access."""

    @pytest.fixture
    async def client(self):
        """Create a test client."""
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_basic_adapter(self, client):
        """Access basic adapter."""
        assert client.basic is not None
        assert hasattr(client.basic, "pay")

    @pytest.mark.asyncio
    async def test_standard_adapter(self, client):
        """Access standard adapter."""
        assert client.standard is not None
        assert hasattr(client.standard, "create_transaction")

    @pytest.mark.asyncio
    async def test_advanced_same_as_runtime(self, client):
        """advanced should be same as runtime."""
        assert client.advanced is client.runtime


class TestBasicAdapterSmartWalletRouting:
    """Tests for AIP-12 BasicAdapter batched UserOp routing via wallet_provider."""

    @pytest.mark.asyncio
    async def test_pay_routes_via_pay_actp_batched_when_wired(self):
        """When wallet_provider + contract_addresses are wired, pay() uses
        the batched UserOp path and never touches runtime.create_transaction.
        Verifies on-chain msg.sender == requester guarantee."""
        from unittest.mock import AsyncMock, MagicMock

        from agirails.adapters.basic import BasicAdapter, BasicPayParams
        from agirails.wallet.aa.transaction_batcher import ContractAddresses
        from agirails.wallet.auto_wallet_provider import BatchedPayResult

        runtime = MagicMock()
        runtime.create_transaction = AsyncMock(
            side_effect=AssertionError(
                "runtime.create_transaction MUST NOT be called when "
                "pay_actp_batched is available"
            )
        )
        runtime.link_escrow = AsyncMock(
            side_effect=AssertionError("link_escrow MUST NOT be called")
        )
        runtime.get_transaction = AsyncMock(return_value=None)
        runtime.maxTransactionAmount = None

        wallet = MagicMock()
        wallet.pay_actp_batched = AsyncMock(
            return_value=BatchedPayResult(
                tx_id="0x" + "a" * 64,
                hash="0x" + "b" * 64,
                success=True,
            )
        )

        contracts = ContractAddresses(
            usdc="0x" + "1" * 40,
            actp_kernel="0x" + "2" * 40,
            escrow_vault="0x" + "3" * 40,
        )
        sw_address = "0x" + "7" * 40

        adapter = BasicAdapter(
            runtime,
            sw_address,
            None,
            wallet_provider=wallet,
            contract_addresses=contracts,
        )
        result = await adapter.pay(
            BasicPayParams(to="0x" + "4" * 40, amount="1.50", deadline="1h")
        )

        assert wallet.pay_actp_batched.call_count == 1
        assert runtime.create_transaction.call_count == 0
        assert result.tx_id == "0x" + "a" * 64
        assert result.state == "COMMITTED"

        # Requester passed to wallet MUST be the Smart Wallet address —
        # this is what the kernel checks via _requesterCheck.
        bp = wallet.pay_actp_batched.call_args.args[0]
        assert bp.requester.lower() == sw_address.lower()
        assert bp.contracts is contracts

    @pytest.mark.asyncio
    async def test_pay_falls_back_to_runtime_without_wallet_provider(self):
        """Legacy EOA / mock path: no wallet_provider → runtime.create_transaction."""
        from unittest.mock import AsyncMock, MagicMock

        from agirails.adapters.basic import BasicAdapter, BasicPayParams

        runtime = MagicMock()
        runtime.create_transaction = AsyncMock(return_value="0x" + "c" * 64)
        runtime.link_escrow = AsyncMock(return_value="0x" + "d" * 64)
        runtime.get_transaction = AsyncMock(return_value=None)
        runtime.maxTransactionAmount = None

        adapter = BasicAdapter(runtime, "0x" + "5" * 40, None)
        result = await adapter.pay(
            BasicPayParams(to="0x" + "6" * 40, amount="2.00", deadline="1h")
        )

        assert runtime.create_transaction.call_count == 1
        assert runtime.link_escrow.call_count == 1
        assert result.tx_id == "0x" + "c" * 64

    @pytest.mark.asyncio
    async def test_pay_falls_back_when_wallet_lacks_pay_actp_batched(self):
        """Wallet provider without pay_actp_batched (EOAWalletProvider) →
        legacy sequential path."""
        from unittest.mock import AsyncMock, MagicMock

        from agirails.adapters.basic import BasicAdapter, BasicPayParams
        from agirails.wallet.aa.transaction_batcher import ContractAddresses

        runtime = MagicMock()
        runtime.create_transaction = AsyncMock(return_value="0x" + "e" * 64)
        runtime.link_escrow = AsyncMock(return_value="0x" + "f" * 64)
        runtime.get_transaction = AsyncMock(return_value=None)
        runtime.maxTransactionAmount = None

        eoa_wallet = object()  # no pay_actp_batched attribute
        contracts = ContractAddresses(
            usdc="0x" + "1" * 40,
            actp_kernel="0x" + "2" * 40,
            escrow_vault="0x" + "3" * 40,
        )

        adapter = BasicAdapter(
            runtime,
            "0x" + "5" * 40,
            None,
            wallet_provider=eoa_wallet,
            contract_addresses=contracts,
        )
        await adapter.pay(
            BasicPayParams(to="0x" + "6" * 40, amount="1.00", deadline="1h")
        )

        assert runtime.create_transaction.call_count == 1


class TestACTPClientX402AutoRegistration:
    """Tests for AIP-12 X402Adapter auto-registration."""

    @pytest.mark.asyncio
    async def test_mock_mode_no_wallet_skips_x402(self):
        """Mock mode without wallet_provider does not register x402."""
        client = await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )
        assert "x402" not in client._registry.get_ids()

    @pytest.mark.asyncio
    async def test_wallet_with_send_transaction_registers_x402(self):
        """Wallet provider with send_transaction triggers x402 auto-registration."""
        from unittest.mock import MagicMock

        from agirails.client import ACTPClientConfig, ACTPClientInfo

        with tempfile.TemporaryDirectory() as tmpdir:
            bootstrap = await ACTPClient.create(
                mode="mock",
                requester_address="0x" + "b" * 40,
                state_directory=tmpdir,
            )
            rt = bootstrap._runtime
            wallet = MagicMock()
            wallet.send_transaction = MagicMock()

            info = ACTPClientInfo(mode="testnet", address="0x" + "c" * 40)
            client = ACTPClient(
                rt, "0x" + "c" * 40, info, None, wallet_provider=wallet
            )
            cfg = ACTPClientConfig(
                mode="testnet",
                requester_address="0x" + "c" * 40,
                rpc_url="https://example.invalid/rpc",
            )
            ACTPClient._maybe_register_x402(client, cfg, wallet, "0x" + "c" * 40)
            assert "x402" in client._registry.get_ids()

    @pytest.mark.asyncio
    async def test_wallet_without_send_transaction_skips_x402(self):
        """Wallet provider missing send_transaction is skipped silently."""
        from agirails.client import ACTPClientConfig, ACTPClientInfo

        with tempfile.TemporaryDirectory() as tmpdir:
            bootstrap = await ACTPClient.create(
                mode="mock",
                requester_address="0x" + "d" * 40,
                state_directory=tmpdir,
            )
            rt = bootstrap._runtime
            bad_wallet = object()  # no send_transaction attribute

            info = ACTPClientInfo(mode="testnet", address="0x" + "e" * 40)
            client = ACTPClient(
                rt, "0x" + "e" * 40, info, None, wallet_provider=bad_wallet
            )
            cfg = ACTPClientConfig(
                mode="testnet",
                requester_address="0x" + "e" * 40,
                rpc_url="https://example.invalid/rpc",
            )
            ACTPClient._maybe_register_x402(client, cfg, bad_wallet, "0x" + "e" * 40)
            assert "x402" not in client._registry.get_ids()


class TestACTPClientBalanceOperations:
    """Tests for balance and token operations."""

    @pytest.fixture
    async def client(self):
        """Create a test client."""
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_get_balance_requester(self, client):
        """Get requester balance."""
        balance = await client.get_balance()
        # Should have initial balance
        assert float(balance) > 0

    @pytest.mark.asyncio
    async def test_get_balance_other_address(self, client):
        """Get balance for other address."""
        # Use unique address to avoid conflicts with other tests
        other = "0x" + "d" * 40
        balance = await client.get_balance(other)
        assert balance == "0.00"

    @pytest.mark.asyncio
    async def test_mint_tokens(self, client):
        """Mint tokens to address."""
        # Use unique address per test
        other = "0x" + "e" * 40

        # Get initial balance (should be 0)
        initial = await client.get_balance(other)
        initial_amount = float(initial)

        await client.mint_tokens(other, 100)
        balance = await client.get_balance(other)

        # Should have increased by 100
        assert float(balance) == initial_amount + 100

    @pytest.mark.asyncio
    async def test_mint_tokens_string_amount(self, client):
        """Mint with string amount."""
        other = "0x" + "c" * 40

        await client.mint_tokens(other, "50.50")
        balance = await client.get_balance(other)

        assert balance == "50.50"


class TestACTPClientReset:
    """Tests for reset functionality."""

    @pytest.fixture
    async def client(self):
        """Create a test client."""
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, client):
        """Reset should clear all state."""
        provider = "0x" + "b" * 40

        # Create a transaction
        result = await client.basic.pay({
            "to": provider,
            "amount": 10,
        })

        assert result.tx_id is not None

        # Reset
        await client.reset()

        # Transaction should be gone
        tx = await client.standard.get_transaction(result.tx_id)
        assert tx is None

    @pytest.mark.asyncio
    async def test_reset_restores_balance(self, client):
        """Reset should restore to default $1M balance."""
        # Start with clean state
        await client.reset()
        initial_balance = await client.get_balance()
        assert initial_balance == "1000000.00"

        # Spend some funds
        await client.basic.pay({
            "to": "0x" + "b" * 40,
            "amount": 100,
        })

        after_spend = await client.get_balance()
        # Balance should have decreased
        assert float(after_spend) < float(initial_balance)

        # Reset - clears all state and mints fresh $1M
        await client.reset()

        restored_balance = await client.get_balance()
        # Should be back to default $1M
        assert restored_balance == "1000000.00"
        assert float(restored_balance) > float(after_spend)


class TestACTPClientRepr:
    """Tests for string representation."""

    @pytest.mark.asyncio
    async def test_repr_doesnt_leak_private_key(self):
        """repr should not contain private key."""
        client = await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

        repr_str = repr(client)
        assert "private_key" not in repr_str.lower()
        assert "secret" not in repr_str.lower()

    @pytest.mark.asyncio
    async def test_repr_contains_mode(self):
        """repr should contain mode."""
        client = await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

        repr_str = repr(client)
        assert "mock" in repr_str

    @pytest.mark.asyncio
    async def test_repr_truncates_address(self):
        """repr should truncate address."""
        client = await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

        repr_str = repr(client)
        assert "..." in repr_str  # Address is truncated
