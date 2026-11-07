"""
Tests for DualNonceManager -- EntryPoint + ACTP nonce management.

Covers:
- Sequential execution (mutex)
- ACTP nonce increment on success
- Cache reset on failure
- Fail closed (raise) when the ACTP nonce is unprovable (never infer 0)
- Cache invalidation
- Error propagation
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from web3 import Web3
from web3.exceptions import BadFunctionCallOutput

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
            contract.functions.requesterNonces.return_value.call.side_effect = BadFunctionCallOutput(
                "Could not decode contract function call to requesterNonces with return data 0x"
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
    async def test_fail_closed_when_event_derivation_fails(self) -> None:
        """FAIL CLOSED (F38): raise, never silently infer nonce = 0.

        Returning 0 on a scan failure would reset the replay-protection
        counter and enable txId/batch replay, so an unprovable nonce must
        surface an explicit error and leave the cache unset.
        """
        w3 = _make_mock_w3_no_nonce(entry_point_nonce=0)
        type(w3.eth).block_number = property(lambda self: 100)
        # No code anywhere → deployment-block search raises → must fail closed.
        w3.eth.get_code.side_effect = lambda addr, block: b""

        mgr = DualNonceManager(w3, SENDER, ACTP_KERNEL)

        async def callback(nonces: NonceSet) -> EnqueueResult[str]:
            raise AssertionError("callback must not run when nonce is unprovable")

        with pytest.raises(RuntimeError, match="Refusing to infer nonce"):
            await mgr.enqueue(callback)

        # Cache must be left unset so the next attempt re-reads from chain.
        assert mgr._cached_actp_nonce is None

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


@pytest.mark.asyncio
async def test_real_encoded_legacy_and_canonical_history_and_requester_filter():
    from eth_abi import encode

    def creation(agreement, requester, index):
        signature = "TransactionCreated(bytes32,address,address,uint256,bytes32,uint256,uint256,uint256" + (",bytes32)" if agreement else ")")
        types = ["uint256", "bytes32", "uint256", "uint256", "uint256"]
        values = [1, bytes(32), 1, 2, 1]
        if agreement:
            types.append("bytes32")
            values.append(bytes(32))
        return {
            "topics": [Web3.to_hex(Web3.keccak(text=signature)), "0x" + "00" * 32, "0x" + requester[2:].rjust(64, "0"), "0x" + "33" * 32],
            "data": Web3.to_hex(encode(types, values)), "logIndex": index,
        }

    other = "0x" + "33" * 20
    history = [creation(False, SENDER, 0), creation(True, SENDER, 1), creation(False, other, 2)]
    w3 = _make_mock_w3_no_nonce()
    w3.eth.block_number = 10
    w3.eth.get_code.side_effect = lambda address, block: b"\x60" if block >= 1 else b""
    w3.eth.get_logs.side_effect = lambda query: [log for log in history if log["topics"][0] in query["topics"][0] and log["topics"][2] == query["topics"][2]]
    manager = DualNonceManager(w3, SENDER, ACTP_KERNEL, known_deployment_block=1)
    assert await manager._read_actp_nonce() == 2
    fresh = DualNonceManager(w3, "0x" + "44" * 20, ACTP_KERNEL, known_deployment_block=1)
    assert await fresh._read_actp_nonce() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ConnectionError("RPC offline"), TimeoutError("RPC timeout"), ValueError("RPC rate limit")])
async def test_transport_failures_never_enter_legacy_scan(error):
    w3 = _make_mock_w3()
    contract = MagicMock()
    contract.functions.requesterNonces.return_value.call.side_effect = error
    w3.eth.contract.return_value = contract
    w3.eth.contract.side_effect = None
    manager = DualNonceManager(w3, SENDER, ACTP_KERNEL)
    with pytest.raises(RuntimeError, match="refusing to infer"):
        await manager._read_actp_nonce()
    w3.eth.get_logs.assert_not_called()
    assert manager._cached_actp_nonce is None
