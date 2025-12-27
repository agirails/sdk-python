"""
Tests for Concurrent File Locking in MockStateManager.

Day 2 Gate List Tests:
- Concurrent file locking tests (50+ tasks)
- State corruption recovery tests

Security features verified:
- C-2: Operation timeout prevents deadlocks
- Atomic file writes prevent corruption
- File locking serializes concurrent access

References:
- Gate List: 1.4.4 (concurrent locking), 1.4.5 (corruption recovery)
- Top 10 Risks #3: concurrent file access, state corruption
"""

from __future__ import annotations

import asyncio
import gc
import json
import os
import random
import tempfile
import time
from pathlib import Path
from typing import List, Tuple

import pytest

from agirails.runtime.mock_state_manager import MockStateManager, STATE_VERSION
from agirails.runtime.types import (
    MockState,
    MockBlockchain,
    MockTransaction,
    MockEscrow,
    MockEvent,
    State,
)
from agirails.errors import (
    MockStateCorruptedError,
    MockStateVersionError,
    MockStateLockError,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for state files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def manager(temp_dir):
    """Create a MockStateManager with temp directory."""
    return MockStateManager(
        state_directory=temp_dir / ".actp",
        lock_timeout_ms=5000,
        operation_timeout_s=30.0,
    )


# =============================================================================
# Concurrent Access Tests (50+ Tasks)
# =============================================================================


class TestConcurrentFileLocking:
    """Test file locking with 50+ concurrent tasks."""

    @pytest.mark.asyncio
    async def test_50_concurrent_increments(self, manager):
        """
        Gate 1.4.4: 50 concurrent tasks incrementing a counter.

        Each task reads current value, increments, and writes back.
        Final value should be exactly 50 with proper locking.
        """
        # Initialize counter
        initial_state = MockState(balances={"counter": "0"})
        await manager.save(initial_state)

        async def increment(state: MockState) -> MockState:
            current = int(state.balances.get("counter", "0"))
            # Add small random delay to increase chance of race conditions
            await asyncio.sleep(random.uniform(0.001, 0.01))
            state.balances["counter"] = str(current + 1)
            return state

        # Run 50 concurrent increments
        tasks = [manager.with_lock(increment) for _ in range(50)]
        await asyncio.gather(*tasks)

        # Verify final count
        final_state = await manager.load()
        assert final_state.balances["counter"] == "50", (
            f"Expected counter=50, got counter={final_state.balances['counter']}. "
            "This indicates a race condition in file locking."
        )

    @pytest.mark.asyncio
    async def test_100_concurrent_increments(self, manager):
        """
        Extended test: 100 concurrent tasks.

        Stress test for file locking under higher load.
        """
        initial_state = MockState(balances={"counter": "0"})
        await manager.save(initial_state)

        increment_count = 0

        async def increment(state: MockState) -> MockState:
            nonlocal increment_count
            current = int(state.balances.get("counter", "0"))
            await asyncio.sleep(random.uniform(0.001, 0.005))
            state.balances["counter"] = str(current + 1)
            increment_count += 1
            return state

        tasks = [manager.with_lock(increment) for _ in range(100)]
        await asyncio.gather(*tasks)

        final_state = await manager.load()
        assert final_state.balances["counter"] == "100"
        assert increment_count == 100

    @pytest.mark.asyncio
    async def test_concurrent_mixed_operations(self, manager):
        """Test mixed read/write operations concurrently."""
        initial_state = MockState(
            balances={"account_a": "1000", "account_b": "1000"}
        )
        await manager.save(initial_state)

        transfer_count = 0

        async def transfer_a_to_b(state: MockState) -> MockState:
            nonlocal transfer_count
            a_balance = int(state.balances.get("account_a", "0"))
            b_balance = int(state.balances.get("account_b", "0"))

            if a_balance >= 10:
                await asyncio.sleep(random.uniform(0.001, 0.005))
                state.balances["account_a"] = str(a_balance - 10)
                state.balances["account_b"] = str(b_balance + 10)
                transfer_count += 1

            return state

        async def transfer_b_to_a(state: MockState) -> MockState:
            nonlocal transfer_count
            a_balance = int(state.balances.get("account_a", "0"))
            b_balance = int(state.balances.get("account_b", "0"))

            if b_balance >= 10:
                await asyncio.sleep(random.uniform(0.001, 0.005))
                state.balances["account_a"] = str(a_balance + 10)
                state.balances["account_b"] = str(b_balance - 10)
                transfer_count += 1

            return state

        # Run 25 transfers in each direction
        tasks = []
        for _ in range(25):
            tasks.append(manager.with_lock(transfer_a_to_b))
            tasks.append(manager.with_lock(transfer_b_to_a))

        random.shuffle(tasks)
        await asyncio.gather(*tasks)

        # Total balance should be preserved (no money created or destroyed)
        final_state = await manager.load()
        total = int(final_state.balances["account_a"]) + int(final_state.balances["account_b"])
        assert total == 2000, f"Total balance changed: {total} (expected 2000)"

    @pytest.mark.asyncio
    async def test_concurrent_transaction_creation(self, manager):
        """Test creating transactions concurrently."""
        initial_state = MockState()
        await manager.save(initial_state)

        created_tx_ids: List[str] = []
        lock = asyncio.Lock()

        async def create_transaction(index: int) -> MockState:
            async def updater(state: MockState) -> MockState:
                tx_id = f"0x{index:064x}"
                state.transactions[tx_id] = MockTransaction(
                    id=tx_id,
                    requester="0x" + "12" * 20,
                    provider="0x" + "34" * 20,
                    amount=str(index * 1000),
                    state=State.INITIATED,
                    deadline=1700000000 + index,
                    dispute_window=172800,
                    created_at=1700000000,
                    updated_at=1700000000,
                )
                async with lock:
                    created_tx_ids.append(tx_id)
                return state

            return await manager.with_lock(updater)

        # Create 50 transactions concurrently
        tasks = [create_transaction(i) for i in range(50)]
        await asyncio.gather(*tasks)

        # Verify all transactions exist
        final_state = await manager.load()
        assert len(final_state.transactions) == 50
        for tx_id in created_tx_ids:
            assert tx_id in final_state.transactions

    @pytest.mark.asyncio
    async def test_concurrent_escrow_creation(self, manager):
        """Test creating escrows concurrently."""
        initial_state = MockState()
        await manager.save(initial_state)

        async def create_escrow(index: int) -> MockState:
            async def updater(state: MockState) -> MockState:
                escrow_id = f"escrow_{index}"
                state.escrows[escrow_id] = MockEscrow(
                    id=escrow_id,
                    tx_id=f"0x{index:064x}",
                    amount=str(index * 1000),
                    created_at=1700000000,
                    released=False,
                )
                return state

            return await manager.with_lock(updater)

        # Create 50 escrows concurrently
        tasks = [create_escrow(i) for i in range(50)]
        await asyncio.gather(*tasks)

        final_state = await manager.load()
        assert len(final_state.escrows) == 50


class TestConcurrentLockTimeout:
    """Test lock timeout behavior under concurrent access."""

    @pytest.mark.asyncio
    async def test_lock_timeout_when_held_long(self, temp_dir):
        """Test that lock timeout works when lock is held too long."""
        manager = MockStateManager(
            state_directory=temp_dir / ".actp",
            lock_timeout_ms=100,  # Very short timeout
            operation_timeout_s=1.0,
        )

        initial_state = MockState()
        await manager.save(initial_state)

        lock_acquired = asyncio.Event()
        should_release = asyncio.Event()

        async def hold_lock(state: MockState) -> MockState:
            lock_acquired.set()
            await should_release.wait()
            return state

        async def try_acquire(state: MockState) -> MockState:
            return state

        # Start first task that holds the lock
        hold_task = asyncio.create_task(manager.with_lock(hold_lock))
        await lock_acquired.wait()

        # Second task should timeout trying to acquire lock
        with pytest.raises(MockStateLockError):
            await manager.with_lock(try_acquire)

        # Release the first task
        should_release.set()
        await hold_task

    @pytest.mark.asyncio
    async def test_operation_timeout_prevents_deadlock(self, temp_dir):
        """Test that operation timeout prevents deadlocks from hanging callbacks."""
        manager = MockStateManager(
            state_directory=temp_dir / ".actp",
            lock_timeout_ms=5000,
            operation_timeout_s=1.0,  # Short operation timeout
        )

        initial_state = MockState()
        await manager.save(initial_state)

        async def hanging_callback(state: MockState) -> MockState:
            # This callback hangs forever - should be terminated by operation timeout
            await asyncio.sleep(100)
            return state

        with pytest.raises(asyncio.TimeoutError, match="possible deadlock"):
            await manager.with_lock(hanging_callback)


# =============================================================================
# State Corruption Recovery Tests
# =============================================================================


class TestStateCorruptionRecovery:
    """Gate 1.4.5: Test recovery from corrupted state."""

    @pytest.mark.asyncio
    async def test_recover_from_corrupted_json(self, manager):
        """Should raise appropriate error for corrupted JSON."""
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            f.write("{ this is not valid JSON }")

        with pytest.raises(MockStateCorruptedError) as exc_info:
            await manager.load()

        assert "Invalid JSON" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_recover_from_truncated_file(self, manager):
        """Should detect and report truncated file."""
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            f.write('{"version": "2.0.0", "transactions":')  # Truncated

        with pytest.raises(MockStateCorruptedError):
            await manager.load()

    @pytest.mark.asyncio
    async def test_recover_from_empty_file(self, manager):
        """Should handle empty file gracefully."""
        manager._ensure_directory()
        manager.state_file_path.touch()  # Create empty file

        with pytest.raises(MockStateCorruptedError):
            await manager.load()

    @pytest.mark.asyncio
    async def test_recover_from_incompatible_version(self, manager):
        """Should raise error for incompatible version."""
        manager._ensure_directory()
        state_data = {
            "version": "99.0.0",  # Future incompatible version
            "transactions": {},
            "escrows": {},
            "balances": {},
            "events": [],
            "blockchain": {"blockNumber": 0, "timestamp": 0, "blockTime": 2},
        }
        with open(manager.state_file_path, "w") as f:
            json.dump(state_data, f)

        with pytest.raises(MockStateVersionError):
            await manager.load()

    @pytest.mark.asyncio
    async def test_atomic_write_prevents_corruption(self, manager):
        """Atomic write should prevent corruption during save."""
        initial_state = MockState(balances={"test": "1000"})
        await manager.save(initial_state)

        # Verify state is valid
        loaded = await manager.load()
        assert loaded.balances["test"] == "1000"

        # No temp files should be left
        for f in manager._state_directory.iterdir():
            assert not f.suffix == ".tmp", f"Temp file left behind: {f}"

    @pytest.mark.asyncio
    async def test_exception_in_updater_preserves_state(self, manager):
        """Exception in updater should not corrupt state."""
        initial_state = MockState(balances={"safe": "1000"})
        await manager.save(initial_state)

        async def failing_updater(state: MockState) -> MockState:
            state.balances["safe"] = "CORRUPTED"
            raise ValueError("Simulated failure")

        with pytest.raises(ValueError):
            await manager.with_lock(failing_updater)

        # State should be unchanged
        loaded = await manager.load()
        assert loaded.balances["safe"] == "1000"

    @pytest.mark.asyncio
    async def test_recover_after_reset(self, manager):
        """Reset should restore to clean state."""
        # Create corrupted file
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            f.write("corrupted data")

        # Reset should work
        await manager.reset()

        # State should now be valid
        loaded = await manager.load()
        assert loaded.version == STATE_VERSION
        assert len(loaded.transactions) == 0


class TestStateIntegrityUnderConcurrentAccess:
    """Test state integrity when multiple processes access state."""

    @pytest.mark.asyncio
    async def test_state_integrity_after_concurrent_updates(self, manager):
        """
        Verify state integrity after many concurrent updates.

        Each update adds a transaction and updates a counter.
        Final state should have consistent count and transactions.
        """
        initial_state = MockState(balances={"tx_count": "0"})
        await manager.save(initial_state)

        async def add_transaction(index: int) -> MockState:
            async def updater(state: MockState) -> MockState:
                # Update counter
                current_count = int(state.balances.get("tx_count", "0"))
                state.balances["tx_count"] = str(current_count + 1)

                # Add transaction
                tx_id = f"0x{index:064x}"
                state.transactions[tx_id] = MockTransaction(
                    id=tx_id,
                    requester="0x" + "12" * 20,
                    provider="0x" + "34" * 20,
                    amount="1000",
                    state=State.INITIATED,
                    deadline=1700000000,
                    dispute_window=172800,
                    created_at=1700000000,
                    updated_at=1700000000,
                )
                return state

            return await manager.with_lock(updater)

        # Run 50 concurrent updates
        tasks = [add_transaction(i) for i in range(50)]
        await asyncio.gather(*tasks)

        # Verify integrity
        final_state = await manager.load()

        # Counter should match transaction count
        tx_count = int(final_state.balances["tx_count"])
        actual_tx_count = len(final_state.transactions)

        assert tx_count == 50, f"Counter mismatch: {tx_count}"
        assert actual_tx_count == 50, f"Transaction count mismatch: {actual_tx_count}"

    @pytest.mark.asyncio
    async def test_event_ordering_under_concurrent_updates(self, manager):
        """
        Verify events are properly ordered under concurrent access.

        Each update adds a sequentially numbered event.
        Final events should have unique sequence numbers.
        """
        initial_state = MockState()
        await manager.save(initial_state)

        async def add_event(index: int) -> MockState:
            async def updater(state: MockState) -> MockState:
                event_num = len(state.events)
                state.events.append(MockEvent(
                    event_type="test_event",
                    tx_id=f"0x{index:064x}",
                    data={"index": index, "sequence": event_num},
                    block_number=event_num,
                    timestamp=1700000000 + event_num,
                ))
                return state

            return await manager.with_lock(updater)

        tasks = [add_event(i) for i in range(50)]
        await asyncio.gather(*tasks)

        final_state = await manager.load()

        # Should have 50 events
        assert len(final_state.events) == 50

        # Block numbers (used as sequence) should be unique and sequential
        sequences = [e.data.get("sequence", e.block_number) for e in final_state.events]
        assert sorted(sequences) == list(range(50))


# =============================================================================
# Multiple Manager Instance Tests
# =============================================================================


class TestMultipleManagerInstances:
    """Test behavior with multiple MockStateManager instances."""

    @pytest.mark.asyncio
    async def test_multiple_managers_same_file(self, temp_dir):
        """Multiple managers accessing same file should be serialized by lock."""
        state_dir = temp_dir / ".actp"

        manager1 = MockStateManager(state_directory=state_dir)
        manager2 = MockStateManager(state_directory=state_dir)

        # Initialize state
        initial_state = MockState(balances={"counter": "0"})
        await manager1.save(initial_state)

        async def increment_via_manager(mgr: MockStateManager) -> MockState:
            async def updater(state: MockState) -> MockState:
                current = int(state.balances.get("counter", "0"))
                await asyncio.sleep(random.uniform(0.001, 0.005))
                state.balances["counter"] = str(current + 1)
                return state

            return await mgr.with_lock(updater)

        # Interleave updates from both managers
        tasks = []
        for i in range(25):
            tasks.append(increment_via_manager(manager1))
            tasks.append(increment_via_manager(manager2))

        random.shuffle(tasks)
        await asyncio.gather(*tasks)

        # Both managers should see consistent state
        state1 = await manager1.load()
        state2 = await manager2.load()

        assert state1.balances["counter"] == "50"
        assert state2.balances["counter"] == "50"


# =============================================================================
# Performance Tests
# =============================================================================


class TestConcurrentPerformance:
    """Performance benchmarks for concurrent access."""

    @pytest.mark.asyncio
    async def test_throughput_50_concurrent_tasks(self, manager):
        """Measure throughput with 50 concurrent tasks."""
        initial_state = MockState(balances={"counter": "0"})
        await manager.save(initial_state)

        async def increment(state: MockState) -> MockState:
            current = int(state.balances.get("counter", "0"))
            state.balances["counter"] = str(current + 1)
            return state

        start_time = time.time()

        tasks = [manager.with_lock(increment) for _ in range(50)]
        await asyncio.gather(*tasks)

        duration = time.time() - start_time

        # Verify correctness
        final_state = await manager.load()
        assert final_state.balances["counter"] == "50"

        # Log performance (not a hard assertion, but useful for tracking)
        ops_per_second = 50 / duration
        print(f"\nThroughput: {ops_per_second:.2f} ops/sec ({duration:.3f}s for 50 ops)")

        # Should complete in reasonable time (< 10 seconds)
        assert duration < 10.0, f"Too slow: {duration}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
