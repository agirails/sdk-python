"""
Tests for IntermediateAdapter.

Tests for:
- create_transaction()
- link_escrow()
- transition_state()
- release_escrow()
- get_transaction()
"""

import pytest

from agirails import ACTPClient, ValidationError
from agirails.adapters import IntermediateTransactionParams


class TestIntermediateCreateTransaction:
    """Tests for IntermediateAdapter.create_transaction() method."""

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
    async def test_create_transaction_happy_path(self, client, provider_address):
        """Basic create_transaction() should work."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        assert tx_id is not None
        assert tx_id.startswith("0x")
        assert len(tx_id) == 66

    @pytest.mark.asyncio
    async def test_create_transaction_with_dataclass(self, client, provider_address):
        """create_transaction() with dataclass params."""
        params = IntermediateTransactionParams(
            provider=provider_address,
            amount="50.50",
            deadline="24h",
            description="Test transaction",
        )

        tx_id = await client.intermediate.create_transaction(params)
        assert tx_id is not None

    @pytest.mark.asyncio
    async def test_create_transaction_state_is_initiated(self, client, provider_address):
        """Transaction should start in INITIATED state."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        tx = await client.intermediate.get_transaction(tx_id)
        assert tx is not None
        assert tx.state == "INITIATED"


class TestIntermediateLinkEscrow:
    """Tests for IntermediateAdapter.link_escrow() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    @pytest.mark.asyncio
    async def test_link_escrow_happy_path(self, client, provider_address):
        """link_escrow() should lock funds and return escrow_id."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        escrow_id = await client.intermediate.link_escrow(tx_id)

        assert escrow_id is not None
        assert escrow_id.startswith("0x")

    @pytest.mark.asyncio
    async def test_link_escrow_transitions_to_committed(self, client, provider_address):
        """link_escrow() should transition to COMMITTED."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        await client.intermediate.link_escrow(tx_id)

        tx = await client.intermediate.get_transaction(tx_id)
        assert tx.state == "COMMITTED"

    @pytest.mark.asyncio
    async def test_link_escrow_decreases_balance(self, client, provider_address):
        """link_escrow() should decrease requester balance."""
        before = float(await client.get_balance())

        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })
        await client.intermediate.link_escrow(tx_id)

        after = float(await client.get_balance())
        assert before - after == 100


class TestIntermediateTransitionState:
    """Tests for IntermediateAdapter.transition_state() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    @pytest.fixture
    async def committed_tx(self, client, provider_address):
        """Create a committed transaction."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })
        await client.intermediate.link_escrow(tx_id)
        return tx_id

    @pytest.mark.asyncio
    async def test_transition_to_in_progress(self, client, committed_tx):
        """Transition COMMITTED -> IN_PROGRESS."""
        await client.intermediate.transition_state(committed_tx, "IN_PROGRESS")

        tx = await client.intermediate.get_transaction(committed_tx)
        assert tx.state == "IN_PROGRESS"

    @pytest.mark.asyncio
    async def test_transition_to_delivered(self, client, committed_tx):
        """Transition COMMITTED -> DELIVERED."""
        await client.intermediate.transition_state(committed_tx, "DELIVERED")

        tx = await client.intermediate.get_transaction(committed_tx)
        assert tx.state == "DELIVERED"

    @pytest.mark.asyncio
    async def test_transition_with_proof(self, client, committed_tx):
        """Transition with delivery proof."""
        proof = "0x" + "abc123" * 10 + "abcd"
        await client.intermediate.transition_state(
            committed_tx,
            "DELIVERED",
            proof=proof,
        )

        tx = await client.intermediate.get_transaction(committed_tx)
        assert tx.state == "DELIVERED"
        assert tx.delivery_proof == proof


class TestIntermediateReleaseEscrow:
    """Tests for IntermediateAdapter.release_escrow() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    @pytest.mark.asyncio
    async def test_release_escrow_happy_path(self, client, provider_address):
        """release_escrow() should release funds and settle."""
        # Setup
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
            "dispute_window": 3600,  # 1 hour
        })
        escrow_id = await client.intermediate.link_escrow(tx_id)
        await client.intermediate.transition_state(tx_id, "DELIVERED")

        # Advance time past dispute window
        await client.runtime.time.advance_time(3700)

        # Release
        await client.intermediate.release_escrow(escrow_id)

        # Verify
        tx = await client.intermediate.get_transaction(tx_id)
        assert tx.state == "SETTLED"

    @pytest.mark.asyncio
    async def test_release_escrow_funds_to_provider(self, client, provider_address):
        """release_escrow() should transfer funds to provider."""
        # Use unique provider to avoid shared state issues
        unique_provider = "0x" + "f" * 40

        # Get initial balance
        before_balance = await client.get_balance(unique_provider)
        before_amount = float(before_balance)

        tx_id = await client.intermediate.create_transaction({
            "provider": unique_provider,
            "amount": 100,
            "dispute_window": 3600,
        })
        escrow_id = await client.intermediate.link_escrow(tx_id)
        await client.intermediate.transition_state(tx_id, "DELIVERED")
        await client.runtime.time.advance_time(3700)
        await client.intermediate.release_escrow(escrow_id)

        # Verify provider got funds (increased by ~99 after 1% fee)
        after_balance = await client.get_balance(unique_provider)
        after_amount = float(after_balance)
        assert after_amount > before_amount


class TestIntermediateGetTransaction:
    """Tests for IntermediateAdapter.get_transaction() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    @pytest.mark.asyncio
    async def test_get_transaction_returns_details(self, client, provider_address):
        """get_transaction() should return TransactionDetails."""
        tx_id = await client.intermediate.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        tx = await client.intermediate.get_transaction(tx_id)

        assert tx is not None
        assert tx.id == tx_id
        assert tx.provider == provider_address.lower()
        assert tx.state == "INITIATED"
        assert tx.amount == "100000000"

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self, client):
        """get_transaction() returns None for non-existent."""
        tx = await client.intermediate.get_transaction("0x" + "f" * 64)
        assert tx is None


class TestIntermediateGetAllTransactions:
    """Tests for IntermediateAdapter.get_all_transactions() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_get_all_transactions(self, client):
        """get_all_transactions() should return all."""
        # Reset to get clean state
        await client.reset()

        provider1 = "0x" + "b" * 40
        provider2 = "0x" + "c" * 40

        await client.intermediate.create_transaction({"provider": provider1, "amount": 100})
        await client.intermediate.create_transaction({"provider": provider2, "amount": 200})

        txs = await client.intermediate.get_all_transactions()

        assert len(txs) == 2


class TestIntermediateGetTransactionsByProvider:
    """Tests for IntermediateAdapter.get_transactions_by_provider() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.mark.asyncio
    async def test_filter_by_provider(self, client):
        """Filter transactions by provider."""
        # Reset to get clean state
        await client.reset()

        provider1 = "0x" + "b" * 40
        provider2 = "0x" + "c" * 40

        await client.intermediate.create_transaction({"provider": provider1, "amount": 100})
        await client.intermediate.create_transaction({"provider": provider1, "amount": 200})
        await client.intermediate.create_transaction({"provider": provider2, "amount": 300})

        txs = await client.intermediate.get_transactions_by_provider(provider1)

        assert len(txs) == 2
        for tx in txs:
            assert tx.provider == provider1.lower()

    @pytest.mark.asyncio
    async def test_filter_by_state(self, client):
        """Filter by state."""
        # Reset to get clean state
        await client.reset()

        provider = "0x" + "b" * 40

        tx1 = await client.intermediate.create_transaction({"provider": provider, "amount": 100})
        tx2 = await client.intermediate.create_transaction({"provider": provider, "amount": 200})
        await client.intermediate.link_escrow(tx1)  # tx1 becomes COMMITTED

        txs = await client.intermediate.get_transactions_by_provider(
            provider,
            state="COMMITTED",
        )

        assert len(txs) == 1
        assert txs[0].id == tx1
