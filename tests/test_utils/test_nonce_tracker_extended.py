"""
Extended Coverage Tests for nonce_tracker.py.

These tests cover additional code paths not fully covered in test_nonce_tracker.py:
- NonceTracker.initialize: already initialized, with provider
- NonceTracker.release_nonce: nonce not found, nonce reclamation
- NonceTracker.fail_nonce: nonce not found
- NonceTracker._cleanup_expired: expired entries removal
- NonceTracker.clear_confirmed: when count <= keep_recent
- NonceManager.get_next_nonce: tracker not found
- NonceManager.release_nonce: tracker not found
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from agirails.utils.nonce_tracker import (
    NonceTracker,
    NonceManager,
    NonceEntry,
    NonceStatus,
)


class TestNonceTrackerInitialize:
    """Tests for NonceTracker.initialize()."""

    @pytest.mark.asyncio
    async def test_initialize_already_initialized(self):
        """Return early if already initialized."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=5)
        # Already initialized via initial_nonce

        result = await tracker.initialize()
        assert result == 5  # Returns existing nonce

        # Stats should not change (no new sync)
        assert tracker.stats["syncs_performed"] == 0

    @pytest.mark.asyncio
    async def test_initialize_with_provider(self):
        """Initialize with a provider (mock)."""
        tracker = NonceTracker("0x" + "a" * 40)

        # Mock provider (in real impl would fetch from chain)
        mock_provider = MagicMock()

        result = await tracker.initialize(provider=mock_provider)
        assert result == 0  # Default nonce
        assert tracker.stats["syncs_performed"] == 1

    @pytest.mark.asyncio
    async def test_initialize_sets_initialized_flag(self):
        """Initialize sets _initialized flag."""
        tracker = NonceTracker("0x" + "a" * 40)
        assert not tracker._initialized

        await tracker.initialize()
        assert tracker._initialized

        # Second call should be no-op
        result = await tracker.initialize()
        assert tracker.stats["syncs_performed"] == 1  # Still just 1


class TestNonceTrackerReleaseNonce:
    """Tests for NonceTracker.release_nonce()."""

    @pytest.mark.asyncio
    async def test_release_nonce_not_found(self):
        """Return False when nonce not in pending."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        result = await tracker.release_nonce(999)  # Never allocated
        assert result is False

    @pytest.mark.asyncio
    async def test_release_nonce_reclaims_last_nonce(self):
        """Reclaim nonce if it was the last allocated."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        # Allocate nonce 0
        nonce = await tracker.get_next_nonce()
        assert nonce == 0
        assert tracker.current_nonce == 1

        # Release it - should reclaim since it's the last allocated
        result = await tracker.release_nonce(nonce)
        assert result is True
        assert tracker.current_nonce == 0  # Reclaimed!

    @pytest.mark.asyncio
    async def test_release_nonce_no_reclaim_if_not_last(self):
        """Don't reclaim nonce if not the last allocated."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        # Allocate nonces 0 and 1
        nonce0 = await tracker.get_next_nonce()
        nonce1 = await tracker.get_next_nonce()
        assert tracker.current_nonce == 2

        # Release nonce 0 (not the last)
        result = await tracker.release_nonce(nonce0)
        assert result is True
        assert tracker.current_nonce == 2  # Not reclaimed

    @pytest.mark.asyncio
    async def test_release_nonce_no_reclaim_if_confirmed(self):
        """Don't reclaim nonce if it was confirmed."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        # Allocate and confirm nonce 0
        nonce0 = await tracker.get_next_nonce()
        await tracker.confirm_nonce(nonce0, "0x" + "b" * 64)

        # Allocate nonce 1
        nonce1 = await tracker.get_next_nonce()
        assert tracker.current_nonce == 2

        # Release nonce 1
        result = await tracker.release_nonce(nonce1)
        assert result is True
        # Should reclaim because nonce 0 is confirmed, so nonce 1 is effectively "last"
        assert tracker.current_nonce == 1


class TestNonceTrackerFailNonce:
    """Tests for NonceTracker.fail_nonce()."""

    @pytest.mark.asyncio
    async def test_fail_nonce_not_found(self):
        """Return False when nonce not in pending."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        result = await tracker.fail_nonce(999)  # Never allocated
        assert result is False

    @pytest.mark.asyncio
    async def test_fail_nonce_success(self):
        """Successfully fail a pending nonce."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        nonce = await tracker.get_next_nonce()
        result = await tracker.fail_nonce(nonce, error="tx reverted")

        assert result is True
        assert tracker.stats["nonces_failed"] == 1
        assert not tracker.is_pending(nonce)


class TestNonceTrackerCleanupExpired:
    """Tests for NonceTracker._cleanup_expired()."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_entries(self):
        """Remove expired pending entries."""
        # Create tracker with very short timeout
        tracker = NonceTracker(
            "0x" + "a" * 40,
            initial_nonce=0,
            reservation_timeout=0.01,  # 10ms
        )

        # Allocate a nonce
        nonce = await tracker.get_next_nonce()
        assert tracker.pending_count == 1

        # Wait for expiration
        await asyncio.sleep(0.02)

        # Trigger cleanup via get_next_nonce or sync
        await tracker.sync_with_chain()

        # Entry should be expired and removed
        assert tracker.pending_count == 0
        assert tracker.stats["nonces_expired"] == 1

    @pytest.mark.asyncio
    async def test_cleanup_only_expired(self):
        """Only remove expired entries, keep non-expired."""
        tracker = NonceTracker(
            "0x" + "a" * 40,
            initial_nonce=0,
            reservation_timeout=10.0,  # 10 seconds
        )

        # Allocate nonces
        nonce1 = await tracker.get_next_nonce()
        nonce2 = await tracker.get_next_nonce()

        # Manually expire one entry
        tracker._pending[nonce1].expires_at = datetime.now() - timedelta(seconds=1)

        # Trigger cleanup
        removed = tracker._cleanup_expired()

        assert removed == 1
        assert not tracker.is_pending(nonce1)  # Expired
        assert tracker.is_pending(nonce2)  # Still valid


class TestNonceTrackerClearConfirmed:
    """Tests for NonceTracker.clear_confirmed()."""

    @pytest.mark.asyncio
    async def test_clear_confirmed_not_needed(self):
        """Return 0 when confirmed count <= keep_recent."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        # Confirm 5 nonces
        for i in range(5):
            nonce = await tracker.get_next_nonce()
            await tracker.confirm_nonce(nonce, f"0x{i:064x}")

        # Try to clear with keep_recent=10 (we only have 5)
        removed = tracker.clear_confirmed(keep_recent=10)
        assert removed == 0

    @pytest.mark.asyncio
    async def test_clear_confirmed_removes_old(self):
        """Remove old entries when count > keep_recent."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=0)

        # Confirm 10 nonces
        for i in range(10):
            nonce = await tracker.get_next_nonce()
            await tracker.confirm_nonce(nonce, f"0x{i:064x}")

        # Clear with keep_recent=3
        removed = tracker.clear_confirmed(keep_recent=3)
        assert removed == 7

        # Should have 3 remaining (the most recent)
        confirmed = tracker.get_confirmed_nonces()
        assert len(confirmed) == 3
        assert 9 in confirmed  # Most recent
        assert 8 in confirmed
        assert 7 in confirmed


class TestNonceManagerExtended:
    """Extended tests for NonceManager."""

    @pytest.mark.asyncio
    async def test_get_next_nonce_creates_tracker(self):
        """get_next_nonce creates tracker if needed."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        nonce = await manager.get_next_nonce(address)
        assert nonce == 0

        # Tracker should now exist
        assert address.lower() in manager.addresses

    @pytest.mark.asyncio
    async def test_get_tracker_no_create(self):
        """get_tracker with create=False returns None."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        tracker = manager.get_tracker(address, create=False)
        assert tracker is None

    @pytest.mark.asyncio
    async def test_confirm_nonce_no_tracker(self):
        """confirm_nonce returns False when no tracker."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        result = await manager.confirm_nonce(address, 0, "0x" + "b" * 64)
        assert result is False

    @pytest.mark.asyncio
    async def test_release_nonce_no_tracker(self):
        """release_nonce returns False when no tracker."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        result = await manager.release_nonce(address, 0)
        assert result is False

    @pytest.mark.asyncio
    async def test_release_nonce_with_tracker(self):
        """release_nonce succeeds when tracker exists."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        # First allocate a nonce (creates tracker)
        nonce = await manager.get_next_nonce(address)

        # Now release it
        result = await manager.release_nonce(address, nonce)
        assert result is True

    def test_remove_tracker(self):
        """remove_tracker removes existing tracker."""
        manager = NonceManager()
        address = "0x" + "a" * 40

        # Create tracker
        manager.get_tracker(address)
        assert len(manager) == 1

        # Remove it
        result = manager.remove_tracker(address)
        assert result is True
        assert len(manager) == 0

    def test_remove_tracker_not_found(self):
        """remove_tracker returns False when not found."""
        manager = NonceManager()

        result = manager.remove_tracker("0x" + "a" * 40)
        assert result is False

    def test_clear(self):
        """clear removes all trackers."""
        manager = NonceManager()

        # Create multiple trackers
        manager.get_tracker("0x" + "a" * 40)
        manager.get_tracker("0x" + "b" * 40)
        manager.get_tracker("0x" + "c" * 40)
        assert len(manager) == 3

        manager.clear()
        assert len(manager) == 0


class TestNonceEntry:
    """Tests for NonceEntry dataclass."""

    def test_default_values(self):
        """Test default values."""
        entry = NonceEntry(nonce=0)
        assert entry.nonce == 0
        assert entry.status == NonceStatus.AVAILABLE
        assert entry.tx_hash is None
        assert entry.created_at is not None
        assert entry.confirmed_at is None
        assert entry.expires_at is None

    def test_custom_values(self):
        """Test custom values."""
        now = datetime.now()
        entry = NonceEntry(
            nonce=5,
            status=NonceStatus.CONFIRMED,
            tx_hash="0x123",
            created_at=now,
            confirmed_at=now,
            expires_at=now + timedelta(hours=1),
        )
        assert entry.nonce == 5
        assert entry.status == NonceStatus.CONFIRMED
        assert entry.tx_hash == "0x123"


class TestNonceStatus:
    """Tests for NonceStatus enum."""

    def test_all_statuses(self):
        """Verify all status values."""
        assert NonceStatus.AVAILABLE.value == "available"
        assert NonceStatus.PENDING.value == "pending"
        assert NonceStatus.CONFIRMED.value == "confirmed"
        assert NonceStatus.FAILED.value == "failed"
        assert NonceStatus.EXPIRED.value == "expired"


class TestNonceTrackerRepr:
    """Tests for NonceTracker.__repr__()."""

    def test_repr(self):
        """Test string representation."""
        tracker = NonceTracker("0x" + "a" * 40, initial_nonce=5)
        repr_str = repr(tracker)

        assert "NonceTracker" in repr_str
        assert "0xaaaaaaaa" in repr_str  # First 10 chars (0x + 8 hex)
        assert "current=5" in repr_str
        assert "pending=0" in repr_str
