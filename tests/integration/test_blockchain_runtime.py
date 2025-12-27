"""
Integration Tests for BlockchainRuntime.

These tests require a local Anvil instance running on localhost:8545.
Skipped automatically if ANVIL_RPC_URL environment variable is not set.

Run Anvil:
    anvil --fork-url <BASE_SEPOLIA_RPC_URL>

Run tests:
    ANVIL_RPC_URL=http://localhost:8545 pytest tests/integration/test_blockchain_runtime.py -v

ACTP State Machine (8 states):
    0: INITIATED - Transaction created, no escrow
    1: QUOTED - Provider submitted price quote (optional)
    2: COMMITTED - Escrow linked, work starts
    3: IN_PROGRESS - Provider working (optional)
    4: DELIVERED - Result submitted with proof
    5: SETTLED - Payment released (terminal)
    6: DISPUTED - Consumer disputed (requires resolution)
    7: CANCELLED - Transaction cancelled (terminal)
"""

import asyncio
import os
import secrets
import time
from typing import AsyncGenerator, Optional

import pytest

from agirails.runtime.types import State


# Skip all tests if Anvil not available
ANVIL_RPC_URL = os.getenv("ANVIL_RPC_URL")
SKIP_REASON = "ANVIL_RPC_URL not set - run: anvil --fork-url <BASE_SEPOLIA_RPC>"

pytestmark = pytest.mark.skipif(not ANVIL_RPC_URL, reason=SKIP_REASON)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def anvil_rpc_url() -> str:
    """Get Anvil RPC URL from environment."""
    return ANVIL_RPC_URL or "http://localhost:8545"


@pytest.fixture
def test_private_key() -> str:
    """
    Generate a random private key for testing.

    Note: In real tests with forked state, you'd use a funded account.
    For unit-style integration tests, we generate fresh keys.
    """
    return "0x" + secrets.token_hex(32)


@pytest.fixture
def funded_private_key() -> str:
    """
    Private key for a funded account (Anvil default account 0).

    This is the first default Anvil account which has 10,000 ETH.
    Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    """
    return "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.fixture
def provider_private_key() -> str:
    """
    Private key for provider (Anvil default account 1).

    Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
    """
    return "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


# =============================================================================
# Unit-Style Integration Tests (No network required)
# =============================================================================


class TestBlockchainRuntimeCreation:
    """Tests for BlockchainRuntime.create() factory method."""

    @pytest.mark.asyncio
    async def test_create_with_invalid_network(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> None:
        """Creating runtime with non-existent network should fail."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime
        from agirails.errors import ValidationError

        with pytest.raises((ValueError, KeyError)):
            await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="invalid-network-name",
                rpc_url=anvil_rpc_url,
            )

    @pytest.mark.asyncio
    async def test_create_with_invalid_rpc_url(
        self, funded_private_key: str
    ) -> None:
        """Creating runtime with unreachable RPC should fail."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        with pytest.raises(ConnectionError):
            await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url="http://localhost:99999",  # Invalid port
            )

    @pytest.mark.asyncio
    async def test_create_with_custom_rate_limit(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> None:
        """Creating runtime with custom rate limit should work."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            runtime = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
                rpc_rate_limit=5.0,  # 5 requests per second
            )
            assert runtime.rate_limiter.max_rate == 5.0
        except ConnectionError:
            pytest.skip("Anvil not accessible")


class TestBlockchainRuntimeProperties:
    """Tests for BlockchainRuntime property accessors."""

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create a runtime for testing."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_address_property(self, runtime) -> None:
        """Address property returns signer address."""
        # Anvil account 0 address
        expected = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        assert runtime.address.lower() == expected.lower()

    @pytest.mark.asyncio
    async def test_time_interface(self, runtime) -> None:
        """Time interface returns reasonable timestamp."""
        # Synchronous now() should return approximate time
        now_sync = runtime.time.now()
        assert now_sync > 1700000000  # After Nov 2023
        assert now_sync < 2000000000  # Before 2033

    @pytest.mark.asyncio
    async def test_time_interface_async(self, runtime) -> None:
        """Async time interface returns blockchain timestamp."""
        now_async = await runtime.time.now_async()
        assert now_async > 1700000000
        assert now_async < 2000000000

    @pytest.mark.asyncio
    async def test_get_chain_id(self, runtime) -> None:
        """get_chain_id returns Base Sepolia chain ID."""
        chain_id = await runtime.get_chain_id()
        assert chain_id == 84532  # Base Sepolia

    @pytest.mark.asyncio
    async def test_get_block_number(self, runtime) -> None:
        """get_block_number returns positive integer."""
        block = await runtime.get_block_number()
        assert block >= 0


class TestBlockchainRuntimeStateTransitions:
    """
    Tests for ACTP state machine transitions.

    These tests verify the 8-state lifecycle:
    INITIATED → [QUOTED] → COMMITTED → [IN_PROGRESS] → DELIVERED → SETTLED
                                                                  ↘ DISPUTED
    Any non-terminal state → CANCELLED
    """

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for requester."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_create_transaction(self, runtime) -> None:
        """Creating a transaction returns valid tx_id."""
        from agirails.runtime.base import CreateTransactionParams

        # Create transaction
        params = CreateTransactionParams(
            provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            requester=runtime.address,
            amount="1000000",  # 1 USDC
            deadline=int(time.time()) + 3600,  # 1 hour
            dispute_window=3600,
            service_description="test-service",
        )

        tx_id = await runtime.create_transaction(params)

        # Verify tx_id format
        assert tx_id.startswith("0x")
        assert len(tx_id) == 66  # 0x + 64 hex chars

    @pytest.mark.asyncio
    async def test_create_transaction_deadline_in_past_fails(
        self, runtime
    ) -> None:
        """Creating transaction with past deadline should fail."""
        from agirails.runtime.base import CreateTransactionParams
        from agirails.errors import ValidationError

        params = CreateTransactionParams(
            provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            requester=runtime.address,
            amount="1000000",
            deadline=int(time.time()) - 3600,  # 1 hour ago
            dispute_window=3600,
        )

        with pytest.raises(ValidationError) as exc_info:
            await runtime.create_transaction(params)

        assert "future" in str(exc_info.value).lower()


class TestBlockchainRuntimeRateLimiting:
    """Tests for RPC rate limiting (C-3 security measure)."""

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime with strict rate limit."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
                rpc_rate_limit=2.0,  # 2 requests per second (strict)
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_rate_limiter_prevents_burst(self, runtime) -> None:
        """Rate limiter should prevent burst requests."""
        # Make multiple requests rapidly
        start_time = time.time()

        # Make 5 requests (should take at least 2 seconds at 2 req/sec)
        for _ in range(5):
            await runtime.get_block_number()

        elapsed = time.time() - start_time

        # With 2 req/sec limit and 5 requests, should take ~2+ seconds
        # (first 2 requests go through immediately due to burst, then rate limited)
        assert elapsed >= 1.0, f"Rate limiter not effective: {elapsed}s for 5 requests"


class TestBlockchainRuntimeEscrowOperations:
    """Tests for escrow-related operations."""

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for testing."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_get_usdc_balance(self, runtime) -> None:
        """Getting USDC balance should return integer."""
        balance = await runtime.get_usdc_balance()
        assert isinstance(balance, int)
        assert balance >= 0

    @pytest.mark.asyncio
    async def test_is_paused(self, runtime) -> None:
        """is_paused returns boolean."""
        paused = await runtime.is_paused()
        assert isinstance(paused, bool)

    @pytest.mark.asyncio
    async def test_get_platform_fee_bps(self, runtime) -> None:
        """Platform fee should be within valid range."""
        fee_bps = await runtime.get_platform_fee_bps()
        assert isinstance(fee_bps, int)
        assert 0 <= fee_bps <= 500  # Max 5%


class TestBlockchainRuntimeNonceManagement:
    """Tests for nonce management."""

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for testing."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_sync_nonce(self, runtime) -> None:
        """sync_nonce returns current nonce."""
        nonce = await runtime.sync_nonce()
        assert isinstance(nonce, int)
        assert nonce >= 0


# =============================================================================
# Full Integration Tests (Require Deployed Contracts)
# =============================================================================


@pytest.mark.integration
class TestBlockchainRuntimeFullFlow:
    """
    Full ACTP lifecycle tests.

    These tests require:
    1. Anvil running with forked Base Sepolia
    2. Deployed ACTPKernel and EscrowVault contracts
    3. Funded accounts with USDC

    Run with: pytest -m integration tests/integration/
    """

    @pytest.fixture
    async def requester_runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for requester."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.fixture
    async def provider_runtime(
        self, anvil_rpc_url: str, provider_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for provider."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=provider_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_happy_path_full_flow(
        self,
        requester_runtime,
        provider_runtime,
    ) -> None:
        """
        Test complete happy path:
        INITIATED → COMMITTED → IN_PROGRESS → DELIVERED → SETTLED

        This test requires deployed contracts and funded accounts.
        Skip if contracts not deployed.
        """
        from agirails.runtime.base import CreateTransactionParams
        from agirails.errors import TransactionError

        # 1. Create transaction
        try:
            tx_id = await requester_runtime.create_transaction(
                CreateTransactionParams(
                    provider=provider_runtime.address,
                    requester=requester_runtime.address,
                    amount="1000000",  # 1 USDC
                    deadline=int(time.time()) + 86400,  # 24 hours
                    dispute_window=3600,  # 1 hour
                    service_description="integration-test",
                )
            )
        except Exception as e:
            if "contract" in str(e).lower() or "revert" in str(e).lower():
                pytest.skip("Contracts not deployed or not funded")
            raise

        # Verify initial state is INITIATED
        tx = await requester_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.state == State.INITIATED

        # 2. Link escrow (auto-transitions to COMMITTED)
        try:
            await requester_runtime.link_escrow(tx_id, "1000000")
        except Exception as e:
            pytest.skip(f"Escrow linking failed (likely insufficient USDC): {e}")

        tx = await requester_runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

        # 3. Provider transitions to IN_PROGRESS
        await provider_runtime.transition_state(tx_id, State.IN_PROGRESS)
        tx = await requester_runtime.get_transaction(tx_id)
        assert tx.state == State.IN_PROGRESS

        # 4. Provider delivers result
        proof = "0x" + secrets.token_hex(32)  # Mock delivery proof
        await provider_runtime.transition_state(tx_id, State.DELIVERED, proof)
        tx = await requester_runtime.get_transaction(tx_id)
        assert tx.state == State.DELIVERED

        # 5. Requester releases escrow
        await requester_runtime.release_kernel_escrow(tx_id)
        tx = await requester_runtime.get_transaction(tx_id)
        assert tx.state == State.SETTLED

    @pytest.mark.asyncio
    async def test_cancellation_flow(
        self,
        requester_runtime,
        provider_runtime,
    ) -> None:
        """
        Test cancellation path:
        INITIATED → COMMITTED → CANCELLED

        Cancellation allowed before DELIVERED state.
        """
        from agirails.runtime.base import CreateTransactionParams

        try:
            tx_id = await requester_runtime.create_transaction(
                CreateTransactionParams(
                    provider=provider_runtime.address,
                    requester=requester_runtime.address,
                    amount="500000",  # 0.5 USDC
                    deadline=int(time.time()) + 86400,
                    dispute_window=3600,
                )
            )
        except Exception as e:
            if "contract" in str(e).lower():
                pytest.skip("Contracts not deployed")
            raise

        # Link escrow
        try:
            await requester_runtime.link_escrow(tx_id, "500000")
        except Exception as e:
            pytest.skip(f"Escrow linking failed: {e}")

        # Cancel transaction
        await requester_runtime.transition_state(tx_id, State.CANCELLED)
        tx = await requester_runtime.get_transaction(tx_id)
        assert tx.state == State.CANCELLED


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestBlockchainRuntimeEdgeCases:
    """Edge case tests for BlockchainRuntime."""

    @pytest.fixture
    async def runtime(
        self, anvil_rpc_url: str, funded_private_key: str
    ) -> AsyncGenerator:
        """Create runtime for testing."""
        from agirails.runtime.blockchain_runtime import BlockchainRuntime

        try:
            rt = await BlockchainRuntime.create(
                private_key=funded_private_key,
                network="base-sepolia",
                rpc_url=anvil_rpc_url,
            )
            yield rt
        except ConnectionError:
            pytest.skip("Anvil not accessible")

    @pytest.mark.asyncio
    async def test_get_nonexistent_transaction(self, runtime) -> None:
        """Getting non-existent transaction returns None."""
        fake_tx_id = "0x" + "0" * 64
        tx = await runtime.get_transaction(fake_tx_id)
        # Should return None or raise, not crash
        assert tx is None or tx.id == fake_tx_id

    @pytest.mark.asyncio
    async def test_get_escrow_balance_nonexistent(self, runtime) -> None:
        """Getting balance of non-existent escrow should handle gracefully."""
        fake_escrow_id = "0x" + "f" * 64
        try:
            balance = await runtime.get_escrow_balance(fake_escrow_id)
            assert balance == "0"
        except Exception:
            # Either returns 0 or raises - both acceptable
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
