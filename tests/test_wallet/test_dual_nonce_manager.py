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
    async def test_derives_nonce_from_events_when_requester_nonces_missing(self) -> None:
        """When requesterNonces is absent, derive ACTP nonce from logs.

        Mirrors TS DualNonceManager.ts:164-210 — count == nonce.
        """
        w3 = _make_mock_w3_no_nonce(entry_point_nonce=0)
        # Deployment-block hint avoids the binary search; latest block via property.
        type(w3.eth).block_number = property(lambda self: 100)
        # get_code: code at hint (50) AND no code at hint-1 (49) → hint accepted.
        w3.eth.get_code.side_effect = lambda addr, block: (
            b"\x60\x80" if block >= 50 else b""
        )
        # 3 TransactionCreated logs for this requester → derived nonce = 3.
        w3.eth.get_logs.return_value = [
            {"logIndex": 0}, {"logIndex": 1}, {"logIndex": 2},
        ]

        mgr = DualNonceManager(
            w3, SENDER, ACTP_KERNEL, known_deployment_block=50
        )

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 3
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback)
        # Topic filter uses the zero-padded (32-byte) requester address.
        filter_params = w3.eth.get_logs.call_args.args[0]
        assert filter_params["address"] == Web3.to_checksum_address(ACTP_KERNEL)
        assert len(filter_params["topics"]) == 3
        requester_topic = filter_params["topics"][2]
        assert requester_topic == "0x" + SENDER.lower().replace("0x", "").rjust(64, "0")

    @pytest.mark.asyncio
    async def test_adaptive_getlogs_chunking_halves_on_range_error(self) -> None:
        """getLogs range errors halve the chunk size instead of failing outright.

        Mirrors TS countRequesterTransactionCreatedEvents (DualNonceManager.ts:300-341).
        """
        w3 = _make_mock_w3_no_nonce(entry_point_nonce=0)
        # Large range so the initial 10k chunk trips the RPC range cap.
        type(w3.eth).block_number = property(lambda self: 100_000)
        w3.eth.get_code.side_effect = lambda addr, block: (
            b"\x60\x80" if block >= 0 else b""
        )

        calls = {"n": 0}

        def get_logs(filter_params):
            calls["n"] += 1
            span = filter_params["toBlock"] - filter_params["fromBlock"] + 1
            # Spans larger than 5000 error; once the chunk size halves it succeeds.
            if span > 5000:
                raise ValueError("query returned more than 10000 results")
            return [{"logIndex": 0}]

        w3.eth.get_logs.side_effect = get_logs

        mgr = DualNonceManager(
            w3, SENDER, ACTP_KERNEL, known_deployment_block=0
        )

        captured = {}

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            captured["nonce"] = nonces.actp_nonce
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback)
        # At least one range error happened (first 10k chunk), then succeeded.
        assert calls["n"] >= 2
        assert captured["nonce"] >= 1

    @pytest.mark.asyncio
    async def test_last_resort_zero_when_event_derivation_fails(self) -> None:
        """Falls back to 0 only when event derivation itself fails."""
        w3 = _make_mock_w3_no_nonce(entry_point_nonce=0)
        type(w3.eth).block_number = property(lambda self: 100)
        # No code anywhere → deployment-block search raises → last-resort 0.
        w3.eth.get_code.side_effect = lambda addr, block: b""

        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 0
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback)

    @pytest.mark.asyncio
    async def test_read_entry_point_nonce_is_public(self) -> None:
        """read_entry_point_nonce is public (TS exposes it for retry loops)."""
        w3 = _make_mock_w3(entry_point_nonce=42, actp_nonce=0)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)
        assert await mgr.read_entry_point_nonce() == 42

    @pytest.mark.asyncio
    async def test_set_cached_actp_nonce_overrides(self) -> None:
        """set_cached_actp_nonce pins the cache (TS DualNonceManager.ts:225-227)."""
        w3 = _make_mock_w3(entry_point_nonce=0, actp_nonce=5)
        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)
        mgr.set_cached_actp_nonce(9)

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            assert nonces.actp_nonce == 9  # uses pinned cache, not chain read
            return EnqueueResult(result="ok", success=True)

        await mgr.enqueue(callback, increments_actp_nonce=False)

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
