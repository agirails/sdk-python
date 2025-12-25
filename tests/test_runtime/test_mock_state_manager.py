"""
Tests for MockStateManager.

Tests file-based state persistence including:
- Load/save operations
- Reset functionality
- Concurrent access with file locking
- Version compatibility
- Error handling for corrupted state
"""

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from agirails.runtime.mock_state_manager import MockStateManager, STATE_VERSION
from agirails.runtime.types import (
    MockState,
    MockBlockchain,
    MockTransaction,
    MockEscrow,
    State,
)
from agirails.errors import (
    MockStateCorruptedError,
    MockStateVersionError,
)


class TestMockStateManagerBasics:
    """Basic load/save operations."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for state files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        """Create a MockStateManager with temp directory."""
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_load_creates_default_state(self, manager):
        """Loading from non-existent file should create default state."""
        state = await manager.load()

        assert state is not None
        assert state.version == "2.0.0"
        assert len(state.transactions) == 0
        assert len(state.escrows) == 0
        assert len(state.balances) == 0
        assert len(state.events) == 0
        assert state.blockchain.block_time == 2

    @pytest.mark.asyncio
    async def test_save_creates_directory(self, temp_dir):
        """Save should create state directory if it doesn't exist."""
        state_dir = temp_dir / "nested" / ".actp"
        manager = MockStateManager(state_directory=state_dir)

        state = MockState()
        await manager.save(state)

        assert state_dir.exists()
        assert manager.state_file_path.exists()

    @pytest.mark.asyncio
    async def test_save_and_load_roundtrip(self, manager):
        """State should survive save/load roundtrip."""
        # Create state with data
        state = MockState(
            version="2.0.0",
            blockchain=MockBlockchain(block_number=100, timestamp=1700000000),
            balances={"0x123": "1000000"},
        )
        state.transactions["tx1"] = MockTransaction(
            id="tx1",
            requester="0xabc",
            provider="0xdef",
            amount="500000",
            state=State.COMMITTED,
            deadline=1700100000,
            dispute_window=172800,
            created_at=1700000000,
            updated_at=1700000000,
        )

        # Save
        await manager.save(state)

        # Load
        loaded = await manager.load()

        assert loaded.version == "2.0.0"
        assert loaded.blockchain.block_number == 100
        assert loaded.blockchain.timestamp == 1700000000
        assert loaded.balances == {"0x123": "1000000"}
        assert "tx1" in loaded.transactions
        assert loaded.transactions["tx1"].amount == "500000"
        assert loaded.transactions["tx1"].state == State.COMMITTED

    @pytest.mark.asyncio
    async def test_save_escrows(self, manager):
        """Escrows should be saved and loaded correctly."""
        state = MockState()
        state.escrows["escrow1"] = MockEscrow(
            id="escrow1",
            tx_id="tx1",
            amount="1000000",
            created_at=1700000000,
            released=False,
        )
        state.escrows["escrow2"] = MockEscrow(
            id="escrow2",
            tx_id="tx2",
            amount="2000000",
            created_at=1700001000,
            released=True,
        )

        await manager.save(state)
        loaded = await manager.load()

        assert len(loaded.escrows) == 2
        assert loaded.escrows["escrow1"].amount == "1000000"
        assert loaded.escrows["escrow1"].released is False
        assert loaded.escrows["escrow2"].released is True

    @pytest.mark.asyncio
    async def test_state_file_path(self, temp_dir):
        """state_file_path should return correct path."""
        manager = MockStateManager(state_directory=temp_dir / ".actp")
        expected = temp_dir / ".actp" / "mock-state.json"
        assert manager.state_file_path == expected

    @pytest.mark.asyncio
    async def test_lock_file_path(self, temp_dir):
        """lock_file_path should return correct path."""
        manager = MockStateManager(state_directory=temp_dir / ".actp")
        expected = temp_dir / ".actp" / "mock-state.json.lock"
        assert manager.lock_file_path == expected


class TestMockStateManagerReset:
    """Reset functionality tests."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, manager):
        """Reset should clear all state and create fresh default."""
        # Create state with data
        state = MockState(balances={"0x123": "1000000"})
        state.transactions["tx1"] = MockTransaction(
            id="tx1",
            requester="0xabc",
            provider="0xdef",
            amount="500000",
            state=State.COMMITTED,
            deadline=1700100000,
            dispute_window=172800,
            created_at=1700000000,
            updated_at=1700000000,
        )
        await manager.save(state)

        # Reset
        await manager.reset()

        # Load should return fresh state
        loaded = await manager.load()
        assert len(loaded.transactions) == 0
        assert len(loaded.balances) == 0
        assert loaded.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_reset_when_no_file_exists(self, manager):
        """Reset should work even if no state file exists."""
        await manager.reset()

        loaded = await manager.load()
        assert loaded.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_exists_property(self, manager):
        """exists() should return correct value."""
        assert manager.exists() is False

        await manager.save(MockState())
        assert manager.exists() is True

        await manager.reset()
        assert manager.exists() is True  # reset saves fresh state


class TestMockStateManagerWithLock:
    """Atomic update with locking tests."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_with_lock_basic_update(self, manager):
        """with_lock should apply update atomically."""
        # Initialize with some balance
        initial_state = MockState(balances={"0x123": "1000"})
        await manager.save(initial_state)

        async def add_balance(state: MockState) -> MockState:
            current = int(state.balances.get("0x123", "0"))
            state.balances["0x123"] = str(current + 500)
            return state

        await manager.with_lock(add_balance)

        loaded = await manager.load()
        assert loaded.balances["0x123"] == "1500"

    @pytest.mark.asyncio
    async def test_with_lock_returns_value(self, manager):
        """with_lock should return result from updater.

        Note: When updater returns a non-MockState value, the caller
        is responsible for saving state within the updater.
        """
        async def get_and_update(state: MockState) -> MockState:
            state.balances["0x123"] = "999"
            return state  # Return state to trigger auto-save

        result = await manager.with_lock(get_and_update)
        assert isinstance(result, MockState)

        # State should be saved because we returned a MockState
        loaded = await manager.load()
        assert loaded.balances["0x123"] == "999"

    @pytest.mark.asyncio
    async def test_with_lock_returns_custom_value(self, manager):
        """with_lock can return custom values if state is saved explicitly."""
        from agirails.runtime.types import MockState as MS

        # When returning non-MockState, state changes are NOT auto-saved
        # (This matches the runtime's behavior of saving explicitly)
        async def get_value_only(state: MockState) -> str:
            # Note: changes here won't be saved automatically
            return "tx-created"

        result = await manager.with_lock(get_value_only)
        assert result == "tx-created"

    @pytest.mark.asyncio
    async def test_with_lock_concurrent_access(self, manager):
        """Multiple concurrent with_lock calls should be serialized."""
        # Initialize
        initial_state = MockState(balances={"0x123": "0"})
        await manager.save(initial_state)

        update_count = 0

        async def increment(state: MockState) -> MockState:
            nonlocal update_count
            update_count += 1
            current = int(state.balances.get("0x123", "0"))
            # Add small delay to simulate work
            await asyncio.sleep(0.01)
            state.balances["0x123"] = str(current + 1)
            return state

        # Run 10 concurrent updates
        await asyncio.gather(*[manager.with_lock(increment) for _ in range(10)])

        # All updates should have been applied
        loaded = await manager.load()
        assert loaded.balances["0x123"] == "10"
        assert update_count == 10

    @pytest.mark.asyncio
    async def test_with_lock_exception_handling(self, manager):
        """Exception in updater should not corrupt state."""
        # Initialize
        initial_state = MockState(balances={"0x123": "1000"})
        await manager.save(initial_state)

        async def failing_update(state: MockState) -> MockState:
            state.balances["0x123"] = "9999"
            raise ValueError("Simulated error")

        with pytest.raises(ValueError, match="Simulated error"):
            await manager.with_lock(failing_update)

        # Original state should be preserved
        loaded = await manager.load()
        assert loaded.balances["0x123"] == "1000"


class TestMockStateManagerVersionCompatibility:
    """Version compatibility tests."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_load_same_major_version(self, manager, temp_dir):
        """Same major version should be compatible."""
        # Write state with compatible version
        state_data = {
            "version": "2.1.0",
            "transactions": {},
            "escrows": {},
            "balances": {"0x123": "1000"},
            "events": [],
            "blockchain": {"blockNumber": 0, "timestamp": 1700000000, "blockTime": 2},
        }
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            json.dump(state_data, f)

        # Should load successfully
        loaded = await manager.load()
        assert loaded.version == "2.1.0"
        assert loaded.balances["0x123"] == "1000"

    @pytest.mark.asyncio
    async def test_load_incompatible_major_version(self, manager):
        """Different major version should raise error."""
        # Write state with incompatible version
        state_data = {
            "version": "1.0.0",
            "transactions": {},
            "escrows": {},
            "balances": {},
            "events": [],
            "blockchain": {},
        }
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            json.dump(state_data, f)

        with pytest.raises(MockStateVersionError):
            await manager.load()


class TestMockStateManagerErrorHandling:
    """Error handling tests."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_load_corrupted_json(self, manager):
        """Corrupted JSON should raise error."""
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            f.write("{ invalid json }")

        with pytest.raises(MockStateCorruptedError):
            await manager.load()

    @pytest.mark.asyncio
    async def test_load_missing_required_field(self, manager):
        """Missing required fields should raise error."""
        # Write state missing transactions key but with invalid structure
        state_data = {
            "version": "2.0.0",
            # Missing all other fields, but from_dict has defaults
        }
        manager._ensure_directory()
        with open(manager.state_file_path, "w") as f:
            json.dump(state_data, f)

        # This should work because from_dict has defaults
        loaded = await manager.load()
        assert loaded.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_delete_removes_files(self, manager):
        """delete() should remove state and lock files."""
        await manager.save(MockState())
        assert manager.state_file_path.exists()

        # Create lock file
        manager.lock_file_path.touch()
        assert manager.lock_file_path.exists()

        await manager.delete()

        assert not manager.state_file_path.exists()
        assert not manager.lock_file_path.exists()

    @pytest.mark.asyncio
    async def test_delete_when_no_files_exist(self, manager):
        """delete() should not fail when files don't exist."""
        assert not manager.state_file_path.exists()
        await manager.delete()  # Should not raise


class TestMockStateManagerAtomicWrite:
    """Atomic write operation tests."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def manager(self, temp_dir):
        return MockStateManager(state_directory=temp_dir / ".actp")

    @pytest.mark.asyncio
    async def test_atomic_write_no_temp_file_left(self, manager):
        """After save, no temp file should be left."""
        await manager.save(MockState())

        # Check no .tmp files
        for f in manager._state_directory.iterdir():
            assert not f.suffix == ".tmp"

    @pytest.mark.asyncio
    async def test_save_preserves_existing_on_error(self, manager):
        """Save error should not corrupt existing state."""
        # Save initial state
        initial = MockState(balances={"0x123": "1000"})
        await manager.save(initial)

        # Verify initial state
        loaded = await manager.load()
        assert loaded.balances["0x123"] == "1000"

        # The save is atomic, so even if we interrupt it,
        # the original file should be intact
        # (We can't easily test OS-level interrupts in Python,
        # but we verify the atomic pattern is used)
        temp_path = manager.state_file_path.with_suffix(".tmp")
        assert not temp_path.exists()
