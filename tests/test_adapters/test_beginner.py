"""
Tests for BeginnerAdapter.

Tests for:
- pay() happy path
- pay() with various parameters
- pay() validation errors
"""

import pytest

from agirails import ACTPClient, ValidationError
from agirails.adapters import BeginnerPayParams


class TestBeginnerPay:
    """Tests for BeginnerAdapter.pay() method."""

    @pytest.fixture
    async def client(self):
        """Create a test client with sufficient balance."""
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        """Valid provider address."""
        return "0x" + "b" * 40

    @pytest.mark.asyncio
    async def test_pay_happy_path(self, client, provider_address):
        """Basic pay() should work."""
        result = await client.beginner.pay({
            "to": provider_address,
            "amount": 100,
        })

        assert result.tx_id is not None
        assert result.tx_id.startswith("0x")
        assert len(result.tx_id) == 66

        assert result.escrow_id is not None
        assert result.state == "COMMITTED"
        assert result.amount == "100000000"  # 100 USDC in wei

    @pytest.mark.asyncio
    async def test_pay_with_dataclass(self, client, provider_address):
        """pay() with BeginnerPayParams dataclass."""
        params = BeginnerPayParams(
            to=provider_address,
            amount="50.50",
            description="Test payment",
        )

        result = await client.beginner.pay(params)

        assert result.tx_id is not None
        assert result.amount == "50500000"

    @pytest.mark.asyncio
    async def test_pay_string_amount(self, client, provider_address):
        """pay() with string amount."""
        result = await client.beginner.pay({
            "to": provider_address,
            "amount": "25.50",
        })

        assert result.amount == "25500000"

    @pytest.mark.asyncio
    async def test_pay_float_amount(self, client, provider_address):
        """pay() with float amount."""
        result = await client.beginner.pay({
            "to": provider_address,
            "amount": 10.25,
        })

        assert result.amount == "10250000"

    @pytest.mark.asyncio
    async def test_pay_with_description(self, client, provider_address):
        """pay() with description."""
        result = await client.beginner.pay({
            "to": provider_address,
            "amount": 50,
            "description": "AI text generation service",
        })

        assert result.tx_id is not None

    @pytest.mark.asyncio
    async def test_pay_with_custom_deadline(self, client, provider_address):
        """pay() with custom deadline."""
        # Get mock runtime's current time
        mock_now = client.runtime.time.now()

        result = await client.beginner.pay({
            "to": provider_address,
            "amount": 50,
            "deadline": "48h",  # 48 hours
        })

        assert result.tx_id is not None
        # Deadline should be approximately 48 hours from mock time
        expected = mock_now + 48 * 3600
        assert abs(result.deadline - expected) < 5

    @pytest.mark.asyncio
    async def test_pay_invalid_address(self, client):
        """pay() with invalid address should raise."""
        with pytest.raises(ValidationError, match="Invalid to"):
            await client.beginner.pay({
                "to": "invalid",
                "amount": 100,
            })

    @pytest.mark.asyncio
    async def test_pay_zero_address(self, client):
        """pay() to zero address should raise."""
        with pytest.raises(ValidationError, match="cannot be zero"):
            await client.beginner.pay({
                "to": "0x" + "0" * 40,
                "amount": 100,
            })

    @pytest.mark.asyncio
    async def test_pay_below_minimum(self, client, provider_address):
        """pay() below minimum amount should raise."""
        with pytest.raises(Exception, match="at least"):
            await client.beginner.pay({
                "to": provider_address,
                "amount": 0.01,  # Below $0.05 minimum
            })

    @pytest.mark.asyncio
    async def test_pay_zero_amount(self, client, provider_address):
        """pay() with zero amount should raise."""
        with pytest.raises(Exception):
            await client.beginner.pay({
                "to": provider_address,
                "amount": 0,
            })


class TestBeginnerGetTransaction:
    """Tests for BeginnerAdapter.get_transaction() method."""

    @pytest.fixture
    async def client(self):
        """Create a test client."""
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    @pytest.mark.asyncio
    async def test_get_transaction(self, client, provider_address):
        """Get transaction after pay()."""
        result = await client.beginner.pay({
            "to": provider_address,
            "amount": 100,
        })

        tx = await client.beginner.get_transaction(result.tx_id)

        assert tx is not None
        assert tx["tx_id"] == result.tx_id
        assert tx["state"] == "COMMITTED"

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self, client):
        """Get non-existent transaction."""
        tx = await client.beginner.get_transaction("0x" + "f" * 64)
        assert tx is None


class TestBeginnerGetBalance:
    """Tests for BeginnerAdapter.get_balance() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_get_balance(self, client):
        """Get requester balance."""
        balance = await client.beginner.get_balance()
        assert float(balance) > 0

    @pytest.mark.asyncio
    async def test_balance_decreases_after_pay(self, client):
        """Balance should decrease after pay()."""
        before = float(await client.beginner.get_balance())

        await client.beginner.pay({
            "to": "0x" + "b" * 40,
            "amount": 100,
        })

        after = float(await client.beginner.get_balance())
        assert after < before
        assert before - after == 100
