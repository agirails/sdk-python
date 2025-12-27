"""
Attestation Replay Prevention Tests - Day 3 Gate List.

Gate List Requirements:
- Top 10 Risk #6 (Attestation): Two parallel release calls with same attestation UID
  must result in one success and one failure
- File-based tracker must block replay after app restart

SECURITY: ACTPKernel V1 accepts any attestationUID without validation.
This tracker provides SDK-side protection.

PARITY: Validates behavior matches TypeScript SDK's UsedAttestationTracker.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.utils.used_attestation_tracker import (
    FileBasedUsedAttestationTracker,
    InMemoryUsedAttestationTracker,
    IUsedAttestationTracker,
    create_used_attestation_tracker,
)


class TestAttestationReplayPrevention:
    """Tests for attestation replay attack prevention."""

    @pytest.fixture
    def tracker(self) -> InMemoryUsedAttestationTracker:
        """Create in-memory tracker."""
        return InMemoryUsedAttestationTracker()

    @pytest.fixture
    def temp_dir(self) -> str:
        """Create temporary directory for file-based tracker."""
        with tempfile.TemporaryDirectory() as td:
            yield td

    def _generate_attestation_uid(self, value: int) -> str:
        """Generate a bytes32 attestation UID."""
        return "0x" + format(value, "064x")

    def _generate_tx_id(self, value: int) -> str:
        """Generate a bytes32 transaction ID."""
        return "0x" + format(value, "064x")

    @pytest.mark.asyncio
    async def test_two_parallel_releases_same_attestation(self, tracker):
        """
        Gate 6 (Attestation): Two parallel release calls with same attestation UID.
        One must succeed, one must fail.
        """
        attestation_uid = self._generate_attestation_uid(12345)
        tx_id_1 = self._generate_tx_id(1)
        tx_id_2 = self._generate_tx_id(2)

        results: List[Tuple[str, bool]] = []
        lock = threading.Lock()

        async def attempt_release(tx_id: str):
            result = await tracker.record_usage(attestation_uid, tx_id)
            with lock:
                results.append((tx_id, result))

        # Run both releases concurrently
        await asyncio.gather(
            attempt_release(tx_id_1),
            attempt_release(tx_id_2),
        )

        # Exactly one should succeed
        success_count = sum(1 for _, r in results if r)
        failure_count = sum(1 for _, r in results if not r)

        assert success_count == 1, f"Expected 1 success, got {success_count}"
        assert failure_count == 1, f"Expected 1 failure, got {failure_count}"

    @pytest.mark.asyncio
    async def test_10_parallel_releases_same_attestation(self, tracker):
        """Gate 6: 10 parallel releases with same attestation - only 1 succeeds."""
        attestation_uid = self._generate_attestation_uid(99999)
        results: List[bool] = []
        lock = threading.Lock()

        async def attempt_release(tx_num: int):
            tx_id = self._generate_tx_id(tx_num)
            result = await tracker.record_usage(attestation_uid, tx_id)
            with lock:
                results.append(result)

        # 10 concurrent attempts with different tx_ids
        await asyncio.gather(*[attempt_release(i) for i in range(10)])

        success_count = sum(1 for r in results if r)
        assert success_count == 1, f"Expected exactly 1 success, got {success_count}"

    @pytest.mark.asyncio
    async def test_same_attestation_same_tx_allowed(self, tracker):
        """Gate: Same attestation for same tx is allowed (idempotent)."""
        attestation_uid = self._generate_attestation_uid(11111)
        tx_id = self._generate_tx_id(1)

        # First call should succeed
        result1 = await tracker.record_usage(attestation_uid, tx_id)
        assert result1 is True

        # Second call with same pair should also succeed (idempotent)
        result2 = await tracker.record_usage(attestation_uid, tx_id)
        assert result2 is True

        # Verify it's recorded correctly
        assert tracker.is_valid_for_transaction(attestation_uid, tx_id)

    @pytest.mark.asyncio
    async def test_attestation_blocked_for_different_tx(self, tracker):
        """Gate: Attestation used for tx1 cannot be used for tx2."""
        attestation_uid = self._generate_attestation_uid(22222)
        tx_id_1 = self._generate_tx_id(1)
        tx_id_2 = self._generate_tx_id(2)

        # First tx claims the attestation
        result1 = await tracker.record_usage(attestation_uid, tx_id_1)
        assert result1 is True

        # Second tx tries to use same attestation - should fail
        result2 = await tracker.record_usage(attestation_uid, tx_id_2)
        assert result2 is False

        # Verify attestation is tied to tx1
        assert tracker.is_valid_for_transaction(attestation_uid, tx_id_1)
        assert not tracker.is_valid_for_transaction(attestation_uid, tx_id_2)

    def test_thread_safety_concurrent_access(self, tracker):
        """Gate: Thread-safe under concurrent access."""
        attestation_uid = self._generate_attestation_uid(33333)
        results: List[Tuple[int, bool]] = []
        lock = threading.Lock()

        def attempt_with_tx(tx_num: int):
            tx_id = self._generate_tx_id(tx_num)
            result = tracker.record_usage_sync(attestation_uid, tx_id)
            with lock:
                results.append((tx_num, result))

        # 50 threads trying to use same attestation for different txs
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(attempt_with_tx, i) for i in range(50)]
            concurrent.futures.wait(futures)

        # Exactly one should succeed
        success_count = sum(1 for _, r in results if r)
        assert success_count == 1, f"Expected 1 success, got {success_count}"

        # Find which tx_id won
        winning_tx = next((tx for tx, r in results if r), None)
        assert winning_tx is not None

        # Verify the winning tx owns the attestation
        winning_tx_id = self._generate_tx_id(winning_tx)
        assert tracker.is_valid_for_transaction(attestation_uid, winning_tx_id)

    def test_lru_eviction(self):
        """Gate: LRU eviction when max size reached."""
        max_size = 10
        tracker = InMemoryUsedAttestationTracker(max_size=max_size)

        # Fill up to max size
        for i in range(max_size):
            attestation = self._generate_attestation_uid(i)
            tx_id = self._generate_tx_id(i)
            result = tracker.record_usage_sync(attestation, tx_id)
            assert result is True

        assert tracker.get_count() == max_size

        # Add one more - should evict oldest
        new_attestation = self._generate_attestation_uid(100)
        new_tx_id = self._generate_tx_id(100)
        result = tracker.record_usage_sync(new_attestation, new_tx_id)
        assert result is True

        # Count should still be max_size
        assert tracker.get_count() == max_size

        # First attestation should have been evicted
        first_attestation = self._generate_attestation_uid(0)
        assert tracker.get_usage_for_attestation(first_attestation) is None

        # Last attestation should still be there
        assert tracker.get_usage_for_attestation(new_attestation) is not None

    def test_case_insensitive_comparison(self, tracker):
        """Gate: Attestation UIDs are case-insensitive."""
        attestation_lower = "0x" + "ab" * 32
        attestation_upper = "0x" + "AB" * 32
        attestation_mixed = "0x" + "Ab" * 32
        tx_id = self._generate_tx_id(1)

        # Record with lowercase
        result1 = tracker.record_usage_sync(attestation_lower, tx_id)
        assert result1 is True

        # All case variants should match
        assert tracker.is_valid_for_transaction(attestation_upper, tx_id)
        assert tracker.is_valid_for_transaction(attestation_mixed, tx_id)

        # Different tx should be blocked for all variants
        tx_id_2 = self._generate_tx_id(2)
        assert not tracker.is_valid_for_transaction(attestation_upper, tx_id_2)


class TestFileBasedAttestationTracker:
    """Tests for file-based attestation tracker with persistence."""

    @pytest.fixture
    def temp_dir(self) -> str:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as td:
            yield td

    def _generate_attestation_uid(self, value: int) -> str:
        """Generate a bytes32 attestation UID."""
        return "0x" + format(value, "064x")

    def _generate_tx_id(self, value: int) -> str:
        """Generate a bytes32 transaction ID."""
        return "0x" + format(value, "064x")

    @pytest.mark.asyncio
    async def test_persistence_after_restart(self, temp_dir):
        """
        Gate 6: File-based tracker blocks replay after app restart.
        """
        attestation_uid = self._generate_attestation_uid(44444)
        tx_id = self._generate_tx_id(1)

        # First instance - record usage
        tracker1 = FileBasedUsedAttestationTracker(temp_dir)
        result1 = await tracker1.record_usage(attestation_uid, tx_id)
        assert result1 is True

        # Simulate app restart - create new instance
        tracker2 = FileBasedUsedAttestationTracker(temp_dir)

        # Should still block replay for different tx
        tx_id_2 = self._generate_tx_id(2)
        result2 = await tracker2.record_usage(attestation_uid, tx_id_2)
        assert result2 is False, "Should block replay after restart"

        # Same tx should still be allowed
        assert tracker2.is_valid_for_transaction(attestation_uid, tx_id)

    @pytest.mark.asyncio
    async def test_file_corruption_recovery(self, temp_dir):
        """Gate: Corrupted file raises error (fail closed)."""
        # Create valid tracker first
        tracker = FileBasedUsedAttestationTracker(temp_dir)
        attestation = self._generate_attestation_uid(1)
        tx_id = self._generate_tx_id(1)
        await tracker.record_usage(attestation, tx_id)

        # Corrupt the file
        file_path = Path(temp_dir) / ".actp" / "used-attestations.json"
        with open(file_path, "w") as f:
            f.write("not valid json {{{")

        # New instance should fail to load (fail closed for security)
        with pytest.raises(ValueError, match="Failed to parse"):
            FileBasedUsedAttestationTracker(temp_dir)

    @pytest.mark.asyncio
    async def test_file_too_large(self, temp_dir):
        """Gate: Files exceeding max size are rejected (DoS protection)."""
        # Create directory structure
        actp_dir = Path(temp_dir) / ".actp"
        actp_dir.mkdir(parents=True, exist_ok=True)

        # Create oversized file (>10MB)
        file_path = actp_dir / "used-attestations.json"
        with open(file_path, "w") as f:
            # Write a huge JSON object
            f.write('{"key": "' + "x" * (11 * 1024 * 1024) + '"}')

        with pytest.raises(ValueError, match="exceeds"):
            FileBasedUsedAttestationTracker(temp_dir)

    @pytest.mark.asyncio
    async def test_atomic_write(self, temp_dir):
        """Gate: File writes are atomic (temp + rename)."""
        tracker = FileBasedUsedAttestationTracker(temp_dir)

        file_path = Path(temp_dir) / ".actp" / "used-attestations.json"

        # Record some usages
        for i in range(5):
            attestation = self._generate_attestation_uid(i)
            tx_id = self._generate_tx_id(i)
            await tracker.record_usage(attestation, tx_id)

        # Verify file exists and is valid JSON
        assert file_path.exists()
        with open(file_path) as f:
            data = json.load(f)
        assert len(data) == 5

    @pytest.mark.asyncio
    async def test_clear_removes_file(self, temp_dir):
        """Gate: Clear removes the persistence file."""
        tracker = FileBasedUsedAttestationTracker(temp_dir)
        attestation = self._generate_attestation_uid(1)
        tx_id = self._generate_tx_id(1)
        await tracker.record_usage(attestation, tx_id)

        file_path = Path(temp_dir) / ".actp" / "used-attestations.json"
        assert file_path.exists()

        tracker.clear()

        assert not file_path.exists()

    @pytest.mark.asyncio
    async def test_concurrent_file_writes(self, temp_dir):
        """Gate: Concurrent writes don't corrupt file."""
        tracker = FileBasedUsedAttestationTracker(temp_dir)

        async def record_attestation(num: int):
            attestation = self._generate_attestation_uid(num)
            tx_id = self._generate_tx_id(num)
            return await tracker.record_usage(attestation, tx_id)

        # 20 concurrent writes
        results = await asyncio.gather(*[record_attestation(i) for i in range(20)])

        # All should succeed (different attestations)
        assert all(results)

        # Verify file is valid
        file_path = Path(temp_dir) / ".actp" / "used-attestations.json"
        with open(file_path) as f:
            data = json.load(f)
        assert len(data) == 20

    @pytest.mark.asyncio
    async def test_two_parallel_releases_file_based(self, temp_dir):
        """Gate 6: Two parallel releases with file-based tracker."""
        tracker = FileBasedUsedAttestationTracker(temp_dir)
        attestation_uid = self._generate_attestation_uid(55555)
        tx_id_1 = self._generate_tx_id(1)
        tx_id_2 = self._generate_tx_id(2)

        results = await asyncio.gather(
            tracker.record_usage(attestation_uid, tx_id_1),
            tracker.record_usage(attestation_uid, tx_id_2),
        )

        # Exactly one should succeed
        success_count = sum(1 for r in results if r)
        assert success_count == 1, f"Expected 1 success, got {success_count}"


class TestAttestationTrackerFactory:
    """Tests for attestation tracker factory function."""

    def test_create_in_memory_default(self):
        """Factory creates in-memory tracker when no directory specified."""
        tracker = create_used_attestation_tracker()
        assert isinstance(tracker, InMemoryUsedAttestationTracker)

    def test_create_file_based_with_directory(self):
        """Factory creates file-based tracker when directory specified."""
        with tempfile.TemporaryDirectory() as temp_dir:
            tracker = create_used_attestation_tracker(temp_dir)
            assert isinstance(tracker, FileBasedUsedAttestationTracker)


class TestAttestationEdgeCases:
    """Edge case tests for attestation tracker."""

    @pytest.fixture
    def tracker(self) -> InMemoryUsedAttestationTracker:
        """Create in-memory tracker."""
        return InMemoryUsedAttestationTracker()

    def _generate_attestation_uid(self, value: int) -> str:
        """Generate a bytes32 attestation UID."""
        return "0x" + format(value, "064x")

    def _generate_tx_id(self, value: int) -> str:
        """Generate a bytes32 transaction ID."""
        return "0x" + format(value, "064x")

    def test_zero_attestation_uid(self, tracker):
        """Gate: Zero attestation UID works correctly."""
        attestation = "0x" + "00" * 32
        tx_id = self._generate_tx_id(1)

        result = tracker.record_usage_sync(attestation, tx_id)
        assert result is True
        assert tracker.is_valid_for_transaction(attestation, tx_id)

    def test_max_attestation_uid(self, tracker):
        """Gate: Max uint256 attestation UID works correctly."""
        attestation = "0x" + "ff" * 32
        tx_id = self._generate_tx_id(1)

        result = tracker.record_usage_sync(attestation, tx_id)
        assert result is True
        assert tracker.is_valid_for_transaction(attestation, tx_id)

    def test_invalid_max_size(self):
        """Gate: Invalid max_size raises ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            InMemoryUsedAttestationTracker(max_size=0)

        with pytest.raises(ValueError, match="must be positive"):
            InMemoryUsedAttestationTracker(max_size=-1)

    @pytest.mark.asyncio
    async def test_get_all_usages(self, tracker):
        """Gate: get_all_usages returns complete mapping."""
        pairs = [
            (self._generate_attestation_uid(1), self._generate_tx_id(1)),
            (self._generate_attestation_uid(2), self._generate_tx_id(2)),
            (self._generate_attestation_uid(3), self._generate_tx_id(3)),
        ]

        for attestation, tx_id in pairs:
            await tracker.record_usage(attestation, tx_id)

        usages = tracker.get_all_usages()
        assert len(usages) == 3

    @pytest.mark.asyncio
    async def test_clear_all(self, tracker):
        """Gate: clear() removes all entries."""
        for i in range(5):
            attestation = self._generate_attestation_uid(i)
            tx_id = self._generate_tx_id(i)
            await tracker.record_usage(attestation, tx_id)

        assert tracker.get_count() == 5

        tracker.clear()

        assert tracker.get_count() == 0
        assert tracker.get_all_usages() == {}

    def test_lru_access_updates_order(self, tracker):
        """Gate: Accessing an entry updates its LRU position."""
        # Fill tracker to near capacity
        max_size = 100
        tracker = InMemoryUsedAttestationTracker(max_size=max_size)

        for i in range(max_size):
            attestation = self._generate_attestation_uid(i)
            tx_id = self._generate_tx_id(i)
            tracker.record_usage_sync(attestation, tx_id)

        # Access the first entry (should move it to end)
        first_attestation = self._generate_attestation_uid(0)
        tracker.get_usage_for_attestation(first_attestation)

        # Add new entry (should evict second entry, not first)
        new_attestation = self._generate_attestation_uid(999)
        new_tx_id = self._generate_tx_id(999)
        tracker.record_usage_sync(new_attestation, new_tx_id)

        # First entry should still exist (was moved to end)
        assert tracker.get_usage_for_attestation(first_attestation) is not None

        # Second entry should be evicted
        second_attestation = self._generate_attestation_uid(1)
        assert tracker.get_usage_for_attestation(second_attestation) is None
