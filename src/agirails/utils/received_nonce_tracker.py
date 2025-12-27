"""
ReceivedNonceTracker - Replay Attack Prevention for Message Receivers.

This utility tracks nonces of received messages to prevent replay attacks.
It works in conjunction with NonceManager (for senders) but serves the receiver side.

PARITY: Matches TypeScript SDK's utils/ReceivedNonceTracker.ts

Usage Pattern:
- Sender: Uses NonceManager to generate monotonically increasing nonces
- Receiver: Uses ReceivedNonceTracker to validate and track received nonces

Security Properties:
1. Nonces must be monotonically increasing per sender + message type
2. Duplicate nonces are rejected (replay attack prevention)
3. Nonces that are lower than the highest seen are rejected (old replay prevention)

WARNING: In-memory tracking only. For production:
- Use persistent storage (Redis, PostgreSQL, etc.)
- Implement nonce recovery from transaction history
- Consider nonce expiry for long-running processes
"""

from __future__ import annotations

import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class NonceValidationResult:
    """Nonce validation result."""

    valid: bool
    reason: Optional[str] = None
    expected_minimum: Optional[str] = None  # bytes32 format
    received_nonce: Optional[str] = None  # bytes32 format


class IReceivedNonceTracker(ABC):
    """Interface for tracking received nonces."""

    @abstractmethod
    def validate_and_record(
        self, sender: str, message_type: str, nonce: str
    ) -> NonceValidationResult:
        """
        Validate and record a received nonce.

        Args:
            sender: Sender DID (e.g., "did:ethr:0x...")
            message_type: Message type (e.g., "agirails.delivery.v1")
            nonce: Nonce value (bytes32 format: "0x...")

        Returns:
            Validation result
        """
        pass

    @abstractmethod
    def has_been_used(self, sender: str, message_type: str, nonce: str) -> bool:
        """
        Check if a nonce has been used (without recording).

        Args:
            sender: Sender DID
            message_type: Message type
            nonce: Nonce value (bytes32 format)

        Returns:
            True if nonce was already used
        """
        pass

    @abstractmethod
    def get_highest_nonce(self, sender: str, message_type: str) -> Optional[str]:
        """
        Get highest nonce seen for sender + message type.

        Args:
            sender: Sender DID
            message_type: Message type

        Returns:
            Highest nonce (bytes32 format) or None if none seen
        """
        pass

    @abstractmethod
    def reset(self, sender: str, message_type: str) -> None:
        """
        Reset tracking for a specific sender + message type.

        Args:
            sender: Sender DID
            message_type: Message type
        """
        pass

    @abstractmethod
    def clear_all(self) -> None:
        """Clear all tracked nonces."""
        pass


class InMemoryReceivedNonceTracker(IReceivedNonceTracker):
    """
    In-Memory Received Nonce Tracker.

    Strategy: Track highest nonce seen per sender + message type
    - Accept nonces that are strictly greater than the highest seen
    - Reject nonces that are <= highest seen (replay attack)

    Trade-off:
    - Memory efficient (one value per sender + type)
    - Requires ordered nonce sequences
    - Cannot skip nonces (nonce gaps are rejected)
    """

    def __init__(self) -> None:
        # Map: sender -> messageType -> highest nonce (as int)
        self._highest_nonces: Dict[str, Dict[str, int]] = {}
        self._lock = threading.RLock()

    def validate_and_record(
        self, sender: str, message_type: str, nonce: str
    ) -> NonceValidationResult:
        """Validate and record a received nonce."""
        # Validate nonce format (must be bytes32: 0x + 64 hex chars)
        if not re.match(r"^0x[a-fA-F0-9]{64}$", nonce):
            return NonceValidationResult(
                valid=False,
                reason="Invalid nonce format (must be bytes32)",
                received_nonce=nonce,
            )

        # Convert nonce to int for comparison
        nonce_value = int(nonce, 16)

        with self._lock:
            # Get sender's nonce map
            sender_nonces = self._highest_nonces.get(sender)
            if sender_nonces is None:
                sender_nonces = {}
                self._highest_nonces[sender] = sender_nonces

            # Get highest nonce for this message type
            highest_nonce = sender_nonces.get(message_type)

            if highest_nonce is None:
                # First message from this sender for this type
                sender_nonces[message_type] = nonce_value
                return NonceValidationResult(valid=True)

            # Nonce must be strictly greater than highest seen
            if nonce_value <= highest_nonce:
                expected_minimum = "0x" + format(highest_nonce + 1, "064x")
                return NonceValidationResult(
                    valid=False,
                    reason=f"Nonce replay detected: nonce must be > {self._int_to_bytes32(highest_nonce)}",
                    expected_minimum=expected_minimum,
                    received_nonce=nonce,
                )

            # Valid nonce - record it
            sender_nonces[message_type] = nonce_value
            return NonceValidationResult(valid=True)

    def has_been_used(self, sender: str, message_type: str, nonce: str) -> bool:
        """Check if a nonce has been used (non-mutating)."""
        nonce_value = int(nonce, 16)

        with self._lock:
            sender_nonces = self._highest_nonces.get(sender)
            if sender_nonces is None:
                return False  # No nonces seen from this sender

            highest_nonce = sender_nonces.get(message_type)
            if highest_nonce is None:
                return False  # No nonces seen for this message type

            # If the provided nonce is <= highest seen, it's been "used"
            return nonce_value <= highest_nonce

    def get_highest_nonce(self, sender: str, message_type: str) -> Optional[str]:
        """Get highest nonce seen."""
        with self._lock:
            sender_nonces = self._highest_nonces.get(sender)
            if sender_nonces is None:
                return None

            highest_nonce = sender_nonces.get(message_type)
            if highest_nonce is None:
                return None

            return self._int_to_bytes32(highest_nonce)

    def reset(self, sender: str, message_type: str) -> None:
        """Reset tracking for sender + message type."""
        with self._lock:
            sender_nonces = self._highest_nonces.get(sender)
            if sender_nonces:
                sender_nonces.pop(message_type, None)
                # Clean up sender map if empty
                if not sender_nonces:
                    del self._highest_nonces[sender]

    def clear_all(self) -> None:
        """Clear all tracked nonces."""
        with self._lock:
            self._highest_nonces.clear()

    def _int_to_bytes32(self, value: int) -> str:
        """Convert int to bytes32 hex string."""
        return "0x" + format(value, "064x")

    def get_all_nonces(self) -> Dict[str, Dict[str, str]]:
        """Get all nonces (for debugging/persistence)."""
        with self._lock:
            result: Dict[str, Dict[str, str]] = {}
            for sender, sender_nonces in self._highest_nonces.items():
                result[sender] = {
                    msg_type: self._int_to_bytes32(nonce)
                    for msg_type, nonce in sender_nonces.items()
                }
            return result


class SetBasedReceivedNonceTracker(IReceivedNonceTracker):
    """
    Set-Based Received Nonce Tracker.

    Strategy: Track exact set of used nonces per sender + message type
    - Accept nonces that haven't been seen before
    - Reject duplicate nonces (replay attack)
    - Allows non-sequential nonces (nonce gaps are OK)

    SECURITY FIX (NEW-H-2): Max size enforcement to prevent memory exhaustion
    SECURITY FIX (HIGH-2): Global total entries limit to prevent DoS
    SECURITY FIX (H-2): Rate limiting per sender to prevent flood attacks

    Trade-off:
    - Higher memory usage (stores every nonce)
    - More flexible (allows out-of-order delivery)
    - Requires periodic cleanup to prevent unbounded growth
    """

    def __init__(
        self,
        max_size_per_type: int = 10000,
        max_total_entries: int = 100000,
        max_nonces_per_minute: int = 100,
    ) -> None:
        """
        Create set-based tracker with optional max size.

        Args:
            max_size_per_type: Maximum nonces per sender+messageType (default: 10,000)
            max_total_entries: Maximum total nonces across all combinations (default: 100,000)
            max_nonces_per_minute: Maximum nonces per sender per minute (default: 100)
        """
        if max_size_per_type <= 0:
            raise ValueError("max_size_per_type must be positive")
        if max_total_entries <= 0:
            raise ValueError("max_total_entries must be positive")
        if max_nonces_per_minute <= 0:
            raise ValueError("max_nonces_per_minute must be positive")

        self._max_size_per_type = max_size_per_type
        self._max_total_entries = max_total_entries
        self._max_nonces_per_minute = max_nonces_per_minute
        self._rate_limit_window_ms = 60000  # 1 minute window

        # Map: sender -> messageType -> Set of used nonces
        self._used_nonces: Dict[str, Dict[str, Set[str]]] = {}
        self._total_entries = 0

        # Rate limiting: sender -> (count, window_start)
        self._rate_limit_state: Dict[str, tuple] = {}

        self._lock = threading.RLock()

    def _check_rate_limit(self, sender: str) -> bool:
        """Check rate limit for sender. Returns True if rate limit exceeded."""
        now = int(time.time() * 1000)
        state = self._rate_limit_state.get(sender)

        if state is None:
            # First nonce from this sender
            self._rate_limit_state[sender] = (1, now)
            return False

        count, window_start = state

        # Check if window expired (reset counter)
        if now - window_start >= self._rate_limit_window_ms:
            self._rate_limit_state[sender] = (1, now)
            return False

        # Increment counter
        new_count = count + 1
        self._rate_limit_state[sender] = (new_count, window_start)

        # Check if rate limit exceeded
        return new_count > self._max_nonces_per_minute

    def validate_and_record(
        self, sender: str, message_type: str, nonce: str
    ) -> NonceValidationResult:
        """
        Validate and record a received nonce.

        SECURITY FIX (NEW-H-2): Automatic cleanup when max size reached
        SECURITY FIX (HIGH-2): Global limit check to prevent DoS
        SECURITY FIX (H-2): Rate limiting per sender
        """
        # Validate nonce format
        if not re.match(r"^0x[a-fA-F0-9]{64}$", nonce):
            return NonceValidationResult(
                valid=False,
                reason="Invalid nonce format (must be bytes32)",
                received_nonce=nonce,
            )

        with self._lock:
            # Rate limit check
            if self._check_rate_limit(sender):
                return NonceValidationResult(
                    valid=False,
                    reason=f"Rate limit exceeded for sender {sender}: "
                    f"Maximum {self._max_nonces_per_minute} nonces per minute allowed.",
                    received_nonce=nonce,
                )

            # Global limit check
            if self._total_entries >= self._max_total_entries:
                return NonceValidationResult(
                    valid=False,
                    reason=f"Global nonce tracker limit reached ({self._max_total_entries} entries).",
                    received_nonce=nonce,
                )

            # Get sender's nonce map
            sender_nonces = self._used_nonces.get(sender)
            if sender_nonces is None:
                sender_nonces = {}
                self._used_nonces[sender] = sender_nonces

            # Get set of used nonces for this message type
            used_set = sender_nonces.get(message_type)
            if used_set is None:
                used_set = set()
                sender_nonces[message_type] = used_set

            # Check if nonce was already used
            if nonce in used_set:
                return NonceValidationResult(
                    valid=False,
                    reason="Nonce replay detected: this nonce has already been used",
                    received_nonce=nonce,
                )

            # Auto-cleanup if max size per type reached
            if len(used_set) >= self._max_size_per_type:
                # Keep only last 80% of entries (sorted by nonce value)
                keep_count = int(self._max_size_per_type * 0.8)
                sorted_nonces = sorted(used_set, key=lambda x: int(x, 16))
                removed_count = len(used_set) - keep_count
                used_set = set(sorted_nonces[-keep_count:])
                sender_nonces[message_type] = used_set
                self._total_entries -= removed_count

            # Valid nonce - record it
            used_set.add(nonce)
            self._total_entries += 1
            return NonceValidationResult(valid=True)

    def has_been_used(self, sender: str, message_type: str, nonce: str) -> bool:
        """Check if a nonce has been used."""
        with self._lock:
            sender_nonces = self._used_nonces.get(sender)
            if sender_nonces is None:
                return False

            used_set = sender_nonces.get(message_type)
            if used_set is None:
                return False

            return nonce in used_set

    def get_highest_nonce(self, sender: str, message_type: str) -> Optional[str]:
        """Get highest nonce seen (compute from set)."""
        with self._lock:
            sender_nonces = self._used_nonces.get(sender)
            if sender_nonces is None:
                return None

            used_set = sender_nonces.get(message_type)
            if used_set is None or not used_set:
                return None

            # Find maximum nonce in set
            max_nonce = max(int(n, 16) for n in used_set)
            return "0x" + format(max_nonce, "064x")

    def reset(self, sender: str, message_type: str) -> None:
        """Reset tracking for sender + message type."""
        with self._lock:
            sender_nonces = self._used_nonces.get(sender)
            if sender_nonces:
                used_set = sender_nonces.get(message_type)
                if used_set:
                    self._total_entries -= len(used_set)
                sender_nonces.pop(message_type, None)
                if not sender_nonces:
                    del self._used_nonces[sender]

    def clear_all(self) -> None:
        """Clear all tracked nonces."""
        with self._lock:
            self._used_nonces.clear()
            self._total_entries = 0

    def get_nonce_count(self, sender: str, message_type: str) -> int:
        """Get nonce count for sender + message type (for monitoring)."""
        with self._lock:
            sender_nonces = self._used_nonces.get(sender)
            if sender_nonces is None:
                return 0

            used_set = sender_nonces.get(message_type)
            return len(used_set) if used_set else 0

    def get_memory_usage(self) -> Dict[str, int]:
        """Get memory usage statistics."""
        with self._lock:
            combinations = sum(len(v) for v in self._used_nonces.values())
            return {
                "total_entries": self._total_entries,
                "combinations": combinations,
                "max_total_entries": self._max_total_entries,
            }


def create_received_nonce_tracker(
    strategy: str = "memory-efficient",
) -> IReceivedNonceTracker:
    """
    Factory function to create a nonce tracker.

    Args:
        strategy: 'memory-efficient' (highest nonce) or 'set-based' (all nonces)

    Returns:
        IReceivedNonceTracker instance
    """
    if strategy == "set-based":
        return SetBasedReceivedNonceTracker()
    return InMemoryReceivedNonceTracker()


__all__ = [
    "NonceValidationResult",
    "IReceivedNonceTracker",
    "InMemoryReceivedNonceTracker",
    "SetBasedReceivedNonceTracker",
    "create_received_nonce_tracker",
]
