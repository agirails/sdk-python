"""
Tests for StandardAdapter.

Tests for:
- create_transaction()
- link_escrow()
- transition_state()
- release_escrow()
- get_transaction()
"""

import pytest

from agirails import ACTPClient, ValidationError
from agirails.adapters import StandardTransactionParams


class TestStandardCreateTransaction:
    """Tests for StandardAdapter.create_transaction() method."""

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
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        assert tx_id is not None
        assert tx_id.startswith("0x")
        assert len(tx_id) == 66

    @pytest.mark.asyncio
    async def test_create_transaction_with_dataclass(self, client, provider_address):
        """create_transaction() with dataclass params."""
        params = StandardTransactionParams(
            provider=provider_address,
            amount="50.50",
            deadline="+24h",  # TS canonical "+Nh" form
            description="Test transaction",
        )

        tx_id = await client.standard.create_transaction(params)
        assert tx_id is not None

    @pytest.mark.asyncio
    async def test_create_transaction_state_is_initiated(self, client, provider_address):
        """Transaction should start in INITIATED state."""
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        tx = await client.standard.get_transaction(tx_id)
        assert tx is not None
        assert tx.state == "INITIATED"


class TestStandardLinkEscrow:
    """Tests for StandardAdapter.link_escrow() method."""

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
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        escrow_id = await client.standard.link_escrow(tx_id)

        assert escrow_id is not None
        assert escrow_id.startswith("0x")

    @pytest.mark.asyncio
    async def test_link_escrow_transitions_to_committed(self, client, provider_address):
        """link_escrow() should transition to COMMITTED."""
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        await client.standard.link_escrow(tx_id)

        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "COMMITTED"

    @pytest.mark.asyncio
    async def test_link_escrow_decreases_balance(self, client, provider_address):
        """link_escrow() should decrease requester balance."""
        before = float(await client.get_balance())

        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })
        await client.standard.link_escrow(tx_id)

        after = float(await client.get_balance())
        assert before - after == 100



class TestStandardAcceptQuote:
    """Tests for StandardAdapter.accept_quote() method."""

    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(
            mode="mock",
            requester_address="0x" + "a" * 40,
        )

    @pytest.fixture
    def provider_address(self):
        return "0x" + "b" * 40

    async def _create_quoted_tx(self, client, provider_address):
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })
        await client._runtime.transition_state(tx_id, "QUOTED")
        return tx_id

    @pytest.mark.asyncio
    async def test_accept_quote_user_friendly_amount(self, client, provider_address):
        """accept_quote() should parse user-friendly amount and stay QUOTED."""
        tx_id = await self._create_quoted_tx(client, provider_address)

        await client.standard.accept_quote(tx_id, "150")  # 150 USDC

        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "QUOTED"
        assert tx.amount == "150000000"  # parse_amount converts to wei

    @pytest.mark.asyncio
    async def test_accept_quote_numeric_amount(self, client, provider_address):
        """accept_quote() should accept numeric input."""
        tx_id = await self._create_quoted_tx(client, provider_address)

        await client.standard.accept_quote(tx_id, 200)

        tx = await client.standard.get_transaction(tx_id)
        assert tx.amount == "200000000"

    @pytest.mark.asyncio
    async def test_accept_quote_rejects_initiated(self, client, provider_address):
        """accept_quote() should reject from INITIATED state."""
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        with pytest.raises(Exception):
            await client.standard.accept_quote(tx_id, "150")

    @pytest.mark.asyncio
    async def test_accept_quote_full_flow(self, client, provider_address):
        """Full flow: create -> quote -> accept_quote -> link_escrow."""
        tx_id = await self._create_quoted_tx(client, provider_address)

        await client.standard.accept_quote(tx_id, "150")
        await client.standard.link_escrow(tx_id)

        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "COMMITTED"
        assert tx.amount == "150000000"


class TestStandardTransitionState:
    """Tests for StandardAdapter.transition_state() method."""

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
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })
        await client.standard.link_escrow(tx_id)
        return tx_id

    @pytest.mark.asyncio
    async def test_transition_to_in_progress(self, client, committed_tx):
        """Transition COMMITTED -> IN_PROGRESS."""
        await client.standard.transition_state(committed_tx, "IN_PROGRESS")

        tx = await client.standard.get_transaction(committed_tx)
        assert tx.state == "IN_PROGRESS"

    @pytest.mark.asyncio
    async def test_transition_to_delivered(self, client, committed_tx):
        """Transition COMMITTED -> IN_PROGRESS -> DELIVERED (AUDIT FIX: must go through IN_PROGRESS)."""
        # First transition to IN_PROGRESS
        await client.standard.transition_state(committed_tx, "IN_PROGRESS")

        tx = await client.standard.get_transaction(committed_tx)
        assert tx.state == "IN_PROGRESS"

        # Then transition to DELIVERED
        await client.standard.transition_state(committed_tx, "DELIVERED")

        tx = await client.standard.get_transaction(committed_tx)
        assert tx.state == "DELIVERED"

    @pytest.mark.asyncio
    async def test_transition_with_proof(self, client, committed_tx):
        """Transition with delivery proof (AUDIT FIX: must go through IN_PROGRESS)."""
        # First transition to IN_PROGRESS
        await client.standard.transition_state(committed_tx, "IN_PROGRESS")

        # Then transition to DELIVERED with proof
        proof = "0x" + "abc123" * 10 + "abcd"
        await client.standard.transition_state(
            committed_tx,
            "DELIVERED",
            proof=proof,
        )

        tx = await client.standard.get_transaction(committed_tx)
        assert tx.state == "DELIVERED"
        assert tx.delivery_proof == proof

    @pytest.mark.asyncio
    async def test_committed_cannot_skip_to_delivered(self, client, committed_tx):
        """AUDIT FIX: Verify COMMITTED cannot skip directly to DELIVERED."""
        from agirails.errors import InvalidStateTransitionError

        with pytest.raises(InvalidStateTransitionError):
            await client.standard.transition_state(committed_tx, "DELIVERED")

        # Transaction should still be in COMMITTED state
        tx = await client.standard.get_transaction(committed_tx)
        assert tx.state == "COMMITTED"


class TestStandardReleaseEscrow:
    """Tests for StandardAdapter.release_escrow() method."""

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
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
            "dispute_window": 3600,  # 1 hour
        })
        escrow_id = await client.standard.link_escrow(tx_id)
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await client.standard.transition_state(tx_id, "IN_PROGRESS")
        await client.standard.transition_state(tx_id, "DELIVERED")

        # Advance time past dispute window
        await client.runtime.time.advance_time(3700)

        # Release
        await client.standard.release_escrow(escrow_id)

        # Verify
        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "SETTLED"

    @pytest.mark.asyncio
    async def test_release_escrow_funds_to_provider(self, client, provider_address):
        """release_escrow() should transfer funds to provider."""
        # Use unique provider to avoid shared state issues
        unique_provider = "0x" + "f" * 40

        # Get initial balance
        before_balance = await client.get_balance(unique_provider)
        before_amount = float(before_balance)

        tx_id = await client.standard.create_transaction({
            "provider": unique_provider,
            "amount": 100,
            "dispute_window": 3600,
        })
        escrow_id = await client.standard.link_escrow(tx_id)
        # AUDIT FIX: Must go through IN_PROGRESS before DELIVERED
        await client.standard.transition_state(tx_id, "IN_PROGRESS")
        await client.standard.transition_state(tx_id, "DELIVERED")
        await client.runtime.time.advance_time(3700)
        await client.standard.release_escrow(escrow_id)

        # Verify provider got funds (increased by ~99 after 1% fee)
        after_balance = await client.get_balance(unique_provider)
        after_amount = float(after_balance)
        assert after_amount > before_amount


class TestStandardGetTransaction:
    """Tests for StandardAdapter.get_transaction() method."""

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
        tx_id = await client.standard.create_transaction({
            "provider": provider_address,
            "amount": 100,
        })

        tx = await client.standard.get_transaction(tx_id)

        assert tx is not None
        assert tx.id == tx_id
        assert tx.provider == provider_address.lower()
        assert tx.state == "INITIATED"
        assert tx.amount == "100000000"

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self, client):
        """get_transaction() returns None for non-existent."""
        tx = await client.standard.get_transaction("0x" + "f" * 64)
        assert tx is None


class TestStandardGetAllTransactions:
    """Tests for StandardAdapter.get_all_transactions() method."""

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

        await client.standard.create_transaction({"provider": provider1, "amount": 100})
        await client.standard.create_transaction({"provider": provider2, "amount": 200})

        txs = await client.standard.get_all_transactions()

        assert len(txs) == 2


class TestStandardGetTransactionsByProvider:
    """Tests for StandardAdapter.get_transactions_by_provider() method."""

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

        await client.standard.create_transaction({"provider": provider1, "amount": 100})
        await client.standard.create_transaction({"provider": provider1, "amount": 200})
        await client.standard.create_transaction({"provider": provider2, "amount": 300})

        txs = await client.standard.get_transactions_by_provider(provider1)

        assert len(txs) == 2
        for tx in txs:
            assert tx.provider == provider1.lower()

    @pytest.mark.asyncio
    async def test_filter_by_state(self, client):
        """Filter by state."""
        # Reset to get clean state
        await client.reset()

        provider = "0x" + "b" * 40

        tx1 = await client.standard.create_transaction({"provider": provider, "amount": 100})
        tx2 = await client.standard.create_transaction({"provider": provider, "amount": 200})
        await client.standard.link_escrow(tx1)  # tx1 becomes COMMITTED

        txs = await client.standard.get_transactions_by_provider(
            provider,
            state="COMMITTED",
        )

        assert len(txs) == 1
        assert txs[0].id == tx1


class TestStandardLifecycleMethods:
    """Tests for the IAdapter lifecycle methods on StandardAdapter.

    Mirrors TS StandardAdapter.getStatus / startWork / deliver / release
    (StandardAdapter.ts:590-691).
    """

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
    async def test_get_status_committed_can_start_work(self, client, provider_address):
        """COMMITTED -> can_start_work True, others False."""
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100}
        )
        await client.standard.link_escrow(tx_id)

        status = await client.standard.get_status(tx_id)
        assert status.state == "COMMITTED"
        assert status.can_start_work is True
        assert status.can_deliver is False
        assert status.can_release is False
        assert status.can_dispute is False
        assert status.provider == provider_address
        # ISO 8601 deadline string ending in Z
        assert status.deadline is not None and status.deadline.endswith("Z")

    @pytest.mark.asyncio
    async def test_get_status_in_progress_can_deliver(self, client, provider_address):
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100}
        )
        await client.standard.link_escrow(tx_id)
        await client.standard.start_work(tx_id)

        status = await client.standard.get_status(tx_id)
        assert status.state == "IN_PROGRESS"
        assert status.can_deliver is True
        assert status.can_start_work is False

    @pytest.mark.asyncio
    async def test_get_status_delivered_dispute_then_release(self, client, provider_address):
        """DELIVERED within window -> can_dispute; after expiry -> can_release."""
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100, "dispute_window": 3600}
        )
        await client.standard.link_escrow(tx_id)
        await client.standard.start_work(tx_id)
        await client.standard.deliver(tx_id)

        status = await client.standard.get_status(tx_id)
        assert status.state == "DELIVERED"
        assert status.can_dispute is True
        assert status.can_release is False
        assert status.dispute_window_ends is not None

        # Advance past the dispute window. Reading the tx triggers MockRuntime
        # lazy auto-release (TS parity), so the tx is now SETTLED.
        await client.runtime.time.advance_time(3601)
        status2 = await client.standard.get_status(tx_id)
        assert status2.state == "SETTLED"
        assert status2.can_release is False
        assert status2.can_dispute is False

    @pytest.mark.asyncio
    async def test_get_status_not_found_raises(self, client):
        with pytest.raises(RuntimeError, match="not found"):
            await client.standard.get_status("0x" + "f" * 64)

    @pytest.mark.asyncio
    async def test_start_work_transitions_in_progress(self, client, provider_address):
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100}
        )
        await client.standard.link_escrow(tx_id)
        await client.standard.start_work(tx_id)

        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "IN_PROGRESS"

    @pytest.mark.asyncio
    async def test_deliver_defaults_dispute_window_proof(self, client, provider_address):
        """deliver() with no proof uses the tx's own disputeWindow."""
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100}
        )
        await client.standard.link_escrow(tx_id)
        await client.standard.start_work(tx_id)
        await client.standard.deliver(tx_id)

        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "DELIVERED"
        assert tx.delivery_proof is not None

    @pytest.mark.asyncio
    async def test_release_settles_after_window(self, client, provider_address):
        tx_id = await client.standard.create_transaction(
            {"provider": provider_address, "amount": 100, "dispute_window": 3600}
        )
        await client.standard.link_escrow(tx_id)
        await client.standard.start_work(tx_id)
        await client.standard.deliver(tx_id)
        await client.runtime.time.advance_time(3601)

        await client.standard.release(tx_id)
        tx = await client.standard.get_transaction(tx_id)
        assert tx.state == "SETTLED"
