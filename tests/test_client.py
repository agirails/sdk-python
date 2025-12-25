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
