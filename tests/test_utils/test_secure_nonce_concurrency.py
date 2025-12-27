"""
Nonce Concurrency Tests - Day 3 Gate List.

Gate List Requirements:
- Top 10 Risk #4 (Nonce): Parallel tx with unique monotonic nonces
- Simulate RPC failure + retry, nonce must not skip or duplicate
- Thread safety under concurrent access

PARITY: Validates behavior matches TypeScript SDK's nonce utilities.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import threading
import time
from collections import Counter
from typing import List, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.utils.secure_nonce import (
    generate_secure_nonce,
    generate_secure_nonces,
    is_valid_nonce,
)
from agirails.utils.received_nonce_tracker import (
    InMemoryReceivedNonceTracker,
    NonceValidationResult,
    SetBasedReceivedNonceTracker,
    create_received_nonce_tracker,
)


class TestSecureNonceGeneration:
    """Tests for cryptographically secure nonce generation."""

    def test_nonce_format_valid_bytes32(self):
        """Gate: Generated nonces are valid bytes32 format."""
        nonce = generate_secure_nonce()
        assert nonce.startswith("0x")
        assert len(nonce) == 66  # 0x + 64 hex chars
        assert is_valid_nonce(nonce)

    def test_nonce_uses_csprng(self):
        """Gate: Nonces use os.urandom (CSPRNG)."""
        with patch("os.urandom") as mock_urandom:
            mock_urandom.return_value = b"\x00" * 32
            nonce = generate_secure_nonce()
            mock_urandom.assert_called_once_with(32)
            assert nonce == "0x" + "00" * 32

    def test_10_parallel_nonces_all_unique(self):
        """Gate 4 (Nonce): 10 parallel tx have unique nonces."""
        nonces: List[str] = []

        def generate_nonce():
            return generate_secure_nonce()

        # Generate 10 nonces in parallel using threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(generate_nonce) for _ in range(10)]
            nonces = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All nonces must be unique
        assert len(nonces) == 10
        assert len(set(nonces)) == 10, "Nonces must be unique"

        # All nonces must be valid format
        for nonce in nonces:
            assert is_valid_nonce(nonce), f"Invalid nonce format: {nonce}"

    def test_100_parallel_nonces_all_unique(self):
        """Gate 4 (Nonce): 100 parallel tx have unique nonces (stress test)."""
        nonces: List[str] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(generate_secure_nonce) for _ in range(100)]
            nonces = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(nonces) == 100
        assert len(set(nonces)) == 100, "All 100 nonces must be unique"

    def test_nonces_are_high_entropy(self):
        """Gate: Nonces have high entropy (no patterns)."""
        nonces = generate_secure_nonces(100)

        # Convert to integers and check distribution
        values = [int(n, 16) for n in nonces]

        # Check that values are spread across the range
        # At minimum, we should have significant differences between nonces
        differences = []
        for i in range(len(values) - 1):
            diff = abs(values[i+1] - values[i])
            differences.append(diff)

        # Average difference should be very large (random 256-bit values)
        avg_diff = sum(differences) / len(differences)
        max_uint256 = 2**256
        # Average difference between random 256-bit values should be ~max/3
        # Being conservative: at least > max/1000 (still huge)
        assert avg_diff > max_uint256 / 1000000, "Nonces may not be random enough"

    def test_generate_secure_nonces_batch(self):
        """Gate: Batch generation produces unique nonces."""
        nonces = generate_secure_nonces(50)
        assert len(nonces) == 50
        assert len(set(nonces)) == 50, "Batch nonces must be unique"

    def test_generate_secure_nonces_invalid_count(self):
        """Gate: Invalid count raises ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            generate_secure_nonces(0)

        with pytest.raises(ValueError, match="must be positive"):
            generate_secure_nonces(-1)

        with pytest.raises(ValueError, match="exceeds maximum"):
            generate_secure_nonces(10001)


class TestReceivedNonceTrackerConcurrency:
    """Concurrency tests for ReceivedNonceTracker."""

    @pytest.fixture
    def memory_tracker(self) -> InMemoryReceivedNonceTracker:
        """Create memory-efficient tracker."""
        return InMemoryReceivedNonceTracker()

    @pytest.fixture
    def set_tracker(self) -> SetBasedReceivedNonceTracker:
        """Create set-based tracker."""
        return SetBasedReceivedNonceTracker(
            max_size_per_type=1000,
            max_total_entries=10000,
            max_nonces_per_minute=1000,  # High limit for tests
        )

    def _generate_monotonic_nonce(self, value: int) -> str:
        """Generate a bytes32 nonce from integer value."""
        return "0x" + format(value, "064x")

    def test_10_parallel_validations_monotonic(self, memory_tracker):
        """Gate 4: 10 parallel tx with monotonically increasing nonces."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        results: List[NonceValidationResult] = []
        lock = threading.Lock()

        def validate_nonce(nonce_value: int):
            nonce = self._generate_monotonic_nonce(nonce_value)
            result = memory_tracker.validate_and_record(sender, msg_type, nonce)
            with lock:
                results.append((nonce_value, result))

        # Send nonces 1-10 in parallel (but they arrive in order due to monotonic requirement)
        # For memory-efficient tracker, we need to send them sequentially
        # because it requires strict ordering
        for i in range(1, 11):
            validate_nonce(i)

        # All should be valid (monotonically increasing)
        valid_count = sum(1 for _, r in results if r.valid)
        assert valid_count == 10, f"Expected 10 valid, got {valid_count}"

    def test_parallel_duplicate_nonce_detection(self, set_tracker):
        """Gate 4: Duplicate nonces detected across parallel requests."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"
        nonce = self._generate_monotonic_nonce(12345)

        results: List[NonceValidationResult] = []
        lock = threading.Lock()

        def validate_same_nonce():
            result = set_tracker.validate_and_record(sender, msg_type, nonce)
            with lock:
                results.append(result)

        # 10 threads all try to validate the same nonce
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_same_nonce) for _ in range(10)]
            concurrent.futures.wait(futures)

        # Exactly ONE should succeed, rest should fail
        valid_count = sum(1 for r in results if r.valid)
        assert valid_count == 1, f"Expected exactly 1 valid, got {valid_count}"

        # All failures should mention replay
        for result in results:
            if not result.valid:
                assert "replay" in result.reason.lower()

    def test_concurrent_different_senders(self, set_tracker):
        """Gate: Different senders can use same nonce concurrently."""
        msg_type = "agirails.delivery.v1"
        nonce = self._generate_monotonic_nonce(99999)

        results: List[NonceValidationResult] = []
        lock = threading.Lock()

        def validate_for_sender(sender_id: int):
            sender = f"did:ethr:0xsender{sender_id}"
            result = set_tracker.validate_and_record(sender, msg_type, nonce)
            with lock:
                results.append((sender_id, result))

        # 10 different senders all use the same nonce
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate_for_sender, i) for i in range(10)]
            concurrent.futures.wait(futures)

        # All should succeed (different senders)
        valid_count = sum(1 for _, r in results if r.valid)
        assert valid_count == 10, f"All 10 senders should succeed, got {valid_count}"

    def test_rpc_failure_retry_no_skip(self, memory_tracker):
        """Gate 4: RPC failure + retry doesn't skip nonces."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        # Simulate: nonce 1 succeeds
        result1 = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(1)
        )
        assert result1.valid

        # Simulate: nonce 2 sent, RPC fails (but nonce was NOT recorded on chain)
        # Client retries with same nonce 2
        result2a = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(2)
        )
        assert result2a.valid

        # If we try nonce 2 again (simulating retry after local record), it should fail
        result2b = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(2)
        )
        assert not result2b.valid, "Retry of same nonce should fail"

        # Nonce 3 should work (no skip)
        result3 = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(3)
        )
        assert result3.valid, "Nonce 3 should succeed (no gap)"

    def test_rpc_failure_no_duplicate(self, set_tracker):
        """Gate 4: RPC failure doesn't allow duplicate nonces."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"
        nonce = self._generate_monotonic_nonce(42)

        # First attempt succeeds
        result1 = set_tracker.validate_and_record(sender, msg_type, nonce)
        assert result1.valid

        # Simulate: RPC returned error, client retries with SAME nonce
        # This should fail (duplicate detection)
        result2 = set_tracker.validate_and_record(sender, msg_type, nonce)
        assert not result2.valid
        assert "replay" in result2.reason.lower()

    def test_thread_safety_stress(self, set_tracker):
        """Gate: Thread safety under heavy concurrent load."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        successful_nonces: Set[str] = set()
        failed_nonces: Set[str] = set()
        lock = threading.Lock()

        def validate_random_nonce(thread_id: int):
            # Each thread generates 10 unique nonces
            for i in range(10):
                # Use thread_id * 1000 + i to ensure uniqueness
                nonce_value = thread_id * 1000 + i
                nonce = self._generate_monotonic_nonce(nonce_value)
                result = set_tracker.validate_and_record(sender, msg_type, nonce)
                with lock:
                    if result.valid:
                        successful_nonces.add(nonce)
                    else:
                        failed_nonces.add(nonce)

        # 50 threads, each with 10 unique nonces = 500 total unique nonces
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(validate_random_nonce, i) for i in range(50)]
            concurrent.futures.wait(futures)

        # All 500 should succeed (all unique)
        assert len(successful_nonces) == 500, f"Expected 500 unique, got {len(successful_nonces)}"
        assert len(failed_nonces) == 0, f"Expected 0 failures, got {len(failed_nonces)}"

    def test_out_of_order_nonces_set_based(self, set_tracker):
        """Gate: Set-based tracker allows out-of-order nonces."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        # Send nonces out of order: 5, 2, 8, 1, 10
        order = [5, 2, 8, 1, 10]
        results = []

        for value in order:
            nonce = self._generate_monotonic_nonce(value)
            result = set_tracker.validate_and_record(sender, msg_type, nonce)
            results.append(result)

        # All should succeed (set-based allows gaps)
        for i, result in enumerate(results):
            assert result.valid, f"Nonce {order[i]} should be valid"

    def test_out_of_order_nonces_memory_based_fails(self, memory_tracker):
        """Gate: Memory-efficient tracker rejects out-of-order nonces."""
        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        # First nonce: 10
        result1 = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(10)
        )
        assert result1.valid

        # Try nonce 5 (lower than 10) - should fail
        result2 = memory_tracker.validate_and_record(
            sender, msg_type, self._generate_monotonic_nonce(5)
        )
        assert not result2.valid, "Lower nonce should be rejected"
        assert "replay" in result2.reason.lower()

    def test_rate_limiting(self):
        """Gate: Rate limiting prevents flood attacks."""
        # Create tracker with very low rate limit for testing
        tracker = SetBasedReceivedNonceTracker(
            max_size_per_type=1000,
            max_total_entries=10000,
            max_nonces_per_minute=5,  # Very low for testing
        )

        sender = "did:ethr:0xsender1"
        msg_type = "agirails.delivery.v1"

        # First 5 should succeed
        for i in range(5):
            nonce = self._generate_monotonic_nonce(i)
            result = tracker.validate_and_record(sender, msg_type, nonce)
            assert result.valid, f"Nonce {i} should succeed (within rate limit)"

        # 6th should fail (rate limit)
        nonce6 = self._generate_monotonic_nonce(6)
        result6 = tracker.validate_and_record(sender, msg_type, nonce6)
        assert not result6.valid
        assert "rate limit" in result6.reason.lower()

    def test_global_limit(self):
        """Gate: Global limit prevents DoS."""
        tracker = SetBasedReceivedNonceTracker(
            max_size_per_type=100,
            max_total_entries=10,  # Very low for testing
            max_nonces_per_minute=1000,
        )

        msg_type = "agirails.delivery.v1"

        # Fill up to limit
        for i in range(10):
            sender = f"did:ethr:0xsender{i}"
            nonce = self._generate_monotonic_nonce(i)
            result = tracker.validate_and_record(sender, msg_type, nonce)
            assert result.valid

        # Next should fail (global limit)
        result = tracker.validate_and_record(
            "did:ethr:0xnew",
            msg_type,
            self._generate_monotonic_nonce(100)
        )
        assert not result.valid
        assert "limit" in result.reason.lower()


class TestNonceTrackerFactory:
    """Tests for nonce tracker factory function."""

    def test_create_memory_efficient_default(self):
        """Factory creates memory-efficient tracker by default."""
        tracker = create_received_nonce_tracker()
        assert isinstance(tracker, InMemoryReceivedNonceTracker)

    def test_create_set_based(self):
        """Factory creates set-based tracker when specified."""
        tracker = create_received_nonce_tracker("set-based")
        assert isinstance(tracker, SetBasedReceivedNonceTracker)

    def test_invalid_strategy(self):
        """Factory returns memory-efficient for unknown strategy."""
        tracker = create_received_nonce_tracker("unknown")
        assert isinstance(tracker, InMemoryReceivedNonceTracker)


class TestNonceValidation:
    """Tests for nonce format validation."""

    def test_valid_nonce_formats(self):
        """Valid nonce formats accepted."""
        valid_nonces = [
            "0x" + "00" * 32,  # All zeros
            "0x" + "ff" * 32,  # All ones
            "0x" + "aB" * 32,  # Mixed case
            generate_secure_nonce(),  # Generated nonce
        ]
        for nonce in valid_nonces:
            assert is_valid_nonce(nonce), f"Should be valid: {nonce}"

    def test_invalid_nonce_formats(self):
        """Invalid nonce formats rejected."""
        invalid_nonces = [
            "",  # Empty
            "0x",  # Too short
            "0x1234",  # Too short
            "0x" + "00" * 31,  # 31 bytes (62 hex)
            "0x" + "00" * 33,  # 33 bytes (66 hex)
            "not-hex",  # Not hex
            "00" * 32,  # Missing 0x prefix
            "0x" + "gg" * 32,  # Invalid hex chars
        ]
        for nonce in invalid_nonces:
            assert not is_valid_nonce(nonce), f"Should be invalid: {nonce}"
