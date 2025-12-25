"""Tests for NonceTracker and NonceManager utilities."""

import pytest
import asyncio
from datetime import datetime, timedelta

from agirails.utils.nonce_tracker import (
    NonceTracker,
    NonceManager,
    NonceEntry,
    NonceStatus,
)


class TestNonceStatus:
    """Tests for NonceStatus enum."""

    def test_status_values(self):
        """Test status string values."""
        assert NonceStatus.AVAILABLE.value == "available"
        assert NonceStatus.PENDING.value == "pending"
        assert NonceStatus.CONFIRMED.value == "confirmed"
        assert NonceStatus.FAILED.value == "failed"
        assert NonceStatus.EXPIRED.value == "expired"


class TestNonceEntry:
    """Tests for NonceEntry dataclass."""

    def test_default_creation(self):
        """Test creating entry with defaults."""
        entry = NonceEntry(nonce=5)
        assert entry.nonce == 5
        assert entry.status == NonceStatus.AVAILABLE
        assert entry.tx_hash is None
        assert entry.confirmed_at is None
        assert entry.expires_at is None
        assert isinstance(entry.created_at, datetime)

    def test_custom_creation(self):
        """Test creating entry with custom values."""
        now = datetime.now()
        expires = now + timedelta(hours=1)
        entry = NonceEntry(
            nonce=10,
            status=NonceStatus.PENDING,
            tx_hash="0x123",
            expires_at=expires,
        )
        assert entry.nonce == 10
        assert entry.status == NonceStatus.PENDING
        assert entry.tx_hash == "0x123"
        assert entry.expires_at == expires


class TestNonceTracker:
    """Tests for NonceTracker."""

    def test_initialization(self):
        """Test tracker initialization."""
        tracker = NonceTracker(address="0x1234567890abcdef")
        assert tracker.address == "0x1234567890abcdef"
        assert tracker.current_nonce == 0
        assert tracker.pending_count == 0

    def test_initialization_with_initial_nonce(self):
        """Test tracker with initial nonce."""
        tracker = NonceTracker(address="0x123", initial_nonce=100)
        assert tracker.current_nonce == 100

    @pytest.mark.asyncio
    async def test_get_next_nonce(self):
        """Test getting next nonce."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        nonce1 = await tracker.get_next_nonce()
        assert nonce1 == 0

        nonce2 = await tracker.get_next_nonce()
        assert nonce2 == 1

        nonce3 = await tracker.get_next_nonce()
        assert nonce3 == 2

        assert tracker.pending_count == 3

    @pytest.mark.asyncio
    async def test_confirm_nonce(self):
        """Test confirming a nonce."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        nonce = await tracker.get_next_nonce()
        assert tracker.is_pending(nonce)

        result = await tracker.confirm_nonce(nonce, "0xabc")
        assert result is True
        assert not tracker.is_pending(nonce)
        assert tracker.is_confirmed(nonce)

    @pytest.mark.asyncio
    async def test_confirm_nonexistent_nonce(self):
        """Test confirming a nonce that doesn't exist."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        result = await tracker.confirm_nonce(999, "0xabc")
        assert result is False

    @pytest.mark.asyncio
    async def test_release_nonce(self):
        """Test releasing a nonce."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        nonce = await tracker.get_next_nonce()
        assert tracker.is_pending(nonce)

        result = await tracker.release_nonce(nonce)
        assert result is True
        assert not tracker.is_pending(nonce)
        assert not tracker.is_confirmed(nonce)

    @pytest.mark.asyncio
    async def test_release_reclaims_last_nonce(self):
        """Test that releasing last nonce reclaims it."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        nonce1 = await tracker.get_next_nonce()  # 0
        nonce2 = await tracker.get_next_nonce()  # 1

        # Release nonce2 (the last one)
        await tracker.release_nonce(nonce2)

        # Next nonce should be 1 again
        nonce3 = await tracker.get_next_nonce()
        assert nonce3 == 1

    @pytest.mark.asyncio
    async def test_fail_nonce(self):
        """Test failing a nonce."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        nonce = await tracker.get_next_nonce()
        result = await tracker.fail_nonce(nonce, "Transaction reverted")
        assert result is True
        assert not tracker.is_pending(nonce)

    @pytest.mark.asyncio
    async def test_max_pending_nonces(self):
        """Test maximum pending nonces limit."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        # Allocate up to max
        for _ in range(NonceTracker.MAX_PENDING_NONCES):
            await tracker.get_next_nonce()

        # Next allocation should fail
        with pytest.raises(RuntimeError, match="Too many pending nonces"):
            await tracker.get_next_nonce()

    @pytest.mark.asyncio
    async def test_get_pending_nonces(self):
        """Test getting list of pending nonces."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        n1 = await tracker.get_next_nonce()
        n2 = await tracker.get_next_nonce()
        n3 = await tracker.get_next_nonce()

        pending = tracker.get_pending_nonces()
        assert set(pending) == {n1, n2, n3}

    @pytest.mark.asyncio
    async def test_get_confirmed_nonces(self):
        """Test getting list of confirmed nonces."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        n1 = await tracker.get_next_nonce()
        n2 = await tracker.get_next_nonce()

        await tracker.confirm_nonce(n1, "0x111")
        await tracker.confirm_nonce(n2, "0x222")

        confirmed = tracker.get_confirmed_nonces()
        assert set(confirmed) == {n1, n2}

    @pytest.mark.asyncio
    async def test_sync_with_chain(self):
        """Test syncing with chain."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        # Allocate some nonces
        await tracker.get_next_nonce()
        await tracker.get_next_nonce()

        # Sync should clean up expired
        result = await tracker.sync_with_chain()
        assert result == tracker.current_nonce
        assert tracker.stats["syncs_performed"] >= 1

    def test_reset(self):
        """Test resetting the tracker."""
        tracker = NonceTracker(address="0x123", initial_nonce=100)
        tracker.reset()

        assert tracker.current_nonce == 0
        assert tracker.pending_count == 0

    def test_repr(self):
        """Test string representation."""
        tracker = NonceTracker(address="0x1234567890abcdef", initial_nonce=5)
        s = repr(tracker)
        assert "0x12345678" in s  # First 10 chars
        assert "current=5" in s

    def test_stats(self):
        """Test statistics tracking."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)
        stats = tracker.stats

        assert stats["nonces_allocated"] == 0
        assert stats["nonces_confirmed"] == 0
        assert stats["nonces_failed"] == 0

    @pytest.mark.asyncio
    async def test_stats_updated(self):
        """Test that stats are updated correctly."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        n1 = await tracker.get_next_nonce()
        n2 = await tracker.get_next_nonce()
        n3 = await tracker.get_next_nonce()

        await tracker.confirm_nonce(n1, "0x111")
        await tracker.fail_nonce(n2)

        stats = tracker.stats
        assert stats["nonces_allocated"] == 3
        assert stats["nonces_confirmed"] == 1
        assert stats["nonces_failed"] == 1

    @pytest.mark.asyncio
    async def test_clear_confirmed(self):
        """Test clearing old confirmed entries."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        # Create and confirm many nonces
        for i in range(150):
            nonce = await tracker.get_next_nonce()
            await tracker.confirm_nonce(nonce, f"0x{i:04x}")

        # Clear, keeping only 100
        cleared = tracker.clear_confirmed(keep_recent=100)
        assert cleared == 50

        # Only 100 most recent should remain
        confirmed = tracker.get_confirmed_nonces(limit=200)
        assert len(confirmed) == 100

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent nonce allocation."""
        tracker = NonceTracker(address="0x123", initial_nonce=0)

        async def allocate_and_confirm():
            nonce = await tracker.get_next_nonce()
            await asyncio.sleep(0.01)
            await tracker.confirm_nonce(nonce, f"0x{nonce:08x}")
            return nonce

        # Run many concurrent allocations
        tasks = [allocate_and_confirm() for _ in range(50)]
        nonces = await asyncio.gather(*tasks)

        # All nonces should be unique
        assert len(set(nonces)) == 50

        # All should be confirmed
        assert tracker.stats["nonces_confirmed"] == 50


class TestNonceManager:
    """Tests for NonceManager."""

    def test_initialization(self):
        """Test manager initialization."""
        manager = NonceManager()
        assert len(manager) == 0
        assert manager.addresses == []

    def test_get_tracker_creates(self):
        """Test that get_tracker creates a new tracker."""
        manager = NonceManager()

        tracker = manager.get_tracker("0x123")
        assert tracker is not None
        assert tracker.address == "0x123"
        assert "0x123" in manager.addresses

    def test_get_tracker_returns_existing(self):
        """Test that get_tracker returns existing tracker."""
        manager = NonceManager()

        tracker1 = manager.get_tracker("0x123")
        tracker2 = manager.get_tracker("0x123")

        assert tracker1 is tracker2

    def test_get_tracker_no_create(self):
        """Test get_tracker with create=False."""
        manager = NonceManager()

        tracker = manager.get_tracker("0x123", create=False)
        assert tracker is None

    def test_case_insensitive(self):
        """Test that addresses are case-insensitive."""
        manager = NonceManager()

        tracker1 = manager.get_tracker("0xABC")
        tracker2 = manager.get_tracker("0xabc")

        assert tracker1 is tracker2

    @pytest.mark.asyncio
    async def test_get_next_nonce(self):
        """Test getting next nonce through manager."""
        manager = NonceManager()

        nonce = await manager.get_next_nonce("0x123")
        assert nonce == 0

    @pytest.mark.asyncio
    async def test_confirm_nonce(self):
        """Test confirming nonce through manager."""
        manager = NonceManager()

        nonce = await manager.get_next_nonce("0x123")
        result = await manager.confirm_nonce("0x123", nonce, "0xabc")
        assert result is True

    @pytest.mark.asyncio
    async def test_release_nonce(self):
        """Test releasing nonce through manager."""
        manager = NonceManager()

        nonce = await manager.get_next_nonce("0x123")
        result = await manager.release_nonce("0x123", nonce)
        assert result is True

    @pytest.mark.asyncio
    async def test_confirm_unknown_address(self):
        """Test confirming nonce for unknown address."""
        manager = NonceManager()

        result = await manager.confirm_nonce("0x999", 5, "0xabc")
        assert result is False

    def test_remove_tracker(self):
        """Test removing a tracker."""
        manager = NonceManager()

        manager.get_tracker("0x123")
        assert len(manager) == 1

        result = manager.remove_tracker("0x123")
        assert result is True
        assert len(manager) == 0

    def test_remove_nonexistent_tracker(self):
        """Test removing a nonexistent tracker."""
        manager = NonceManager()

        result = manager.remove_tracker("0x999")
        assert result is False

    def test_clear(self):
        """Test clearing all trackers."""
        manager = NonceManager()

        manager.get_tracker("0x111")
        manager.get_tracker("0x222")
        manager.get_tracker("0x333")

        manager.clear()
        assert len(manager) == 0

    @pytest.mark.asyncio
    async def test_multiple_addresses(self):
        """Test managing nonces for multiple addresses."""
        manager = NonceManager()

        # Allocate nonces for different addresses
        n1 = await manager.get_next_nonce("0x111")
        n2 = await manager.get_next_nonce("0x222")
        n3 = await manager.get_next_nonce("0x111")

        assert n1 == 0  # First for 0x111
        assert n2 == 0  # First for 0x222
        assert n3 == 1  # Second for 0x111
