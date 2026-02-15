"""
Tests for DualNonceManager -- EntryPoint + ACTP nonce management.

Covers:
- Sequential execution (mutex)
- ACTP nonce increment on success
- Cache reset on failure
- Fallback to 0 on missing requesterNonces
- Cache invalidation
- Error propagation
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from web3 import Web3

from agirails.wallet.aa.dual_nonce_manager import (
    DualNonceManager,
    EnqueueResult,
    NonceSet,
)
from agirails.wallet.aa.constants import ENTRYPOINT_V06


# ============================================================================
# Fixtures
# ============================================================================

SENDER = "0x1111111111111111111111111111111111111111"
ACTP_KERNEL = "0x2222222222222222222222222222222222222222"


def _make_mock_w3(entry_point_nonce: int = 5, actp_nonce: int = 3) -> MagicMock:
    """Create a mock Web3 instance with contract call mocks."""
    w3 = MagicMock()

    def mock_contract_factory(address, abi):
        contract = MagicMock()
        if any("getNonce" in str(item) for item in abi):
            contract.functions.getNonce.return_value.call.return_value = entry_point_nonce
        elif any("requesterNonces" in str(item) for item in abi):
            contract.functions.requesterNonces.return_value.call.return_value = actp_nonce
        return contract

    w3.eth.contract.side_effect = mock_contract_factory
    # Provide to_checksum_address as a real function
    w3.to_checksum_address = Web3.to_checksum_address
    return w3


def _make_mock_w3_no_nonce(entry_point_nonce: int = 0) -> MagicMock:
    """Create a mock Web3 where requesterNonces fails (older contract)."""
    w3 = MagicMock()

    def mock_contract_factory(address, abi):
        contract = MagicMock()
        if any("getNonce" in str(item) for item in abi):
            contract.functions.getNonce.return_value.call.return_value = entry_point_nonce
        elif any("requesterNonces" in str(item) for item in abi):
            contract.functions.requesterNonces.return_value.call.side_effect = Exception(
                "method not found"
            )
        return contract

    w3.eth.contract.side_effect = mock_contract_factory
    w3.to_checksum_address = Web3.to_checksum_address
    return w3


# ============================================================================
# Tests
# ============================================================================


class TestDualNonceManager:
    """Tests for DualNonceManager."""

    @pytest.mark.asyncio
    async def test_enqueue_provides_correct_nonces(self) -> None:
        """Enqueue callback receives correct nonces from chain."""
        w3 = _make_mock_w3(entry_point_nonce=10, actp_nonce=7)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        received_nonces = None

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            nonlocal received_nonces
            received_nonces = nonces
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback)

        assert received_nonces is not None
        assert received_nonces.entry_point_nonce == 10
        assert received_nonces.actp_nonce == 7

    @pytest.mark.asyncio
    async def test_actp_nonce_increments_on_success(self) -> None:
        """ACTP nonce increments locally after successful operation."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=5)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        # First call: reads nonce=5 from chain
        async def callback1(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 5
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback1, increments_actp_nonce=True)

        # Second call: should use cached nonce=6
        async def callback2(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 6
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback2, increments_actp_nonce=True)

    @pytest.mark.asyncio
    async def test_cache_reset_on_failure(self) -> None:
        """ACTP nonce cache resets on failed operation."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=5)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        # First call succeeds, caches nonce=6
        async def callback1(nonces: NonceSet) -> EnqueueResult[str]:
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback1, increments_actp_nonce=True)

        # Second call fails, should reset cache
        async def callback2(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 6  # cached
            return EnqueueResult(result="fail", success=False)

        await mgr.enqueue(callback2, increments_actp_nonce=True)

        # Third call should re-read from chain (5 again)
        async def callback3(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 5  # re-read from chain
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback3, increments_actp_nonce=True)

    @pytest.mark.asyncio
    async def test_cache_reset_on_exception(self) -> None:
        """ACTP nonce cache resets on exception."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=3)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            raise RuntimeError("Boom!")

        with pytest.raises(RuntimeError, match="Boom"):
            await mgr.enqueue(callback)

        # After exception, cache should be invalidated
        assert mgr._cached_actp_nonce is None

    @pytest.mark.asyncio
    async def test_fallback_to_zero_on_missing_nonce(self) -> None:
        """Falls back to 0 if requesterNonces is not available."""
        w3 = _make_mock_w3_no_nonce(entry_point_nonce=0)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 0
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback)

    @pytest.mark.asyncio
    async def test_invalidate_cache(self) -> None:
        """invalidate_cache forces re-read on next enqueue."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=10)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        # First call caches nonce=10 -> 11
        async def callback1(nonces: NonceSet) -> EnqueueResult[str]:
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback1, increments_actp_nonce=True)

        # Invalidate
        mgr.invalidate_cache()
        assert mgr._cached_actp_nonce is None

    @pytest.mark.asyncio
    async def test_no_actp_increment_when_disabled(self) -> None:
        """ACTP nonce does not increment when increments_actp_nonce=False."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=5)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        async def callback1(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 5
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback1, increments_actp_nonce=False)

        # Nonce should still be 5 (cached but not incremented)
        async def callback2(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 5
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback2, increments_actp_nonce=False)

    @pytest.mark.asyncio
    async def test_sequential_execution(self) -> None:
        """Enqueue ensures sequential execution via mutex."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=0)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)
        execution_order: list[int] = []

        async def make_callback(idx: int):
            async def callback(nonces: NonceSet) -> EnqueueResult[str]:
                execution_order.append(idx)
                await asyncio.sleep(0.01)  # Simulate work
                return EnqueueResult(result=f"task-{idx}", success=True)
            return await mgr.enqueue(callback, increments_actp_nonce=False)

        # Run concurrently
        results = await asyncio.gather(
            make_callback(1),
            make_callback(2),
            make_callback(3),
        )

        # All should complete
        assert len(results) == 3
        # Execution order should be sequential (1,2,3) due to mutex
        assert execution_order == [1, 2, 3]
