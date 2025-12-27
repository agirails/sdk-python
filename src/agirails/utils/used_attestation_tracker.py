"""
UsedAttestationTracker - Prevents EAS Attestation Replay Attacks.

Tracks which attestation UIDs have been used for which transaction IDs.
This prevents a malicious provider from reusing an attestation from
Transaction A to settle Transaction B.

SECURITY: ACTPKernel V1 contract accepts any attestationUID without validation.
This tracker provides SDK-side protection until contract is upgraded.

PARITY: Matches TypeScript SDK's utils/UsedAttestationTracker.ts

Example:
    >>> tracker = InMemoryUsedAttestationTracker()
    >>> tracker.record_usage("0xattestation...", "0xtx...")
    True
    >>> tracker.is_valid_for_transaction("0xattestation...", "0xtx...")
    True
    >>> tracker.is_valid_for_transaction("0xattestation...", "0xother...")
    False
"""

from __future__ import annotations

import json
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional


class IUsedAttestationTracker(ABC):
    """Interface for tracking used attestations."""

    @abstractmethod
    async def record_usage(self, attestation_uid: str, tx_id: str) -> bool:
        """
        Record that an attestation was used for a transaction.

        Args:
            attestation_uid: EAS attestation UID (bytes32)
            tx_id: Transaction ID (bytes32)

        Returns:
            True if recorded, False if already used for different transaction
        """
        pass

    @abstractmethod
    def get_usage_for_attestation(self, attestation_uid: str) -> Optional[str]:
        """
        Check if attestation has been used.

        Args:
            attestation_uid: EAS attestation UID (bytes32)

        Returns:
            Transaction ID if used, None if not used
        """
        pass

    @abstractmethod
    def is_valid_for_transaction(self, attestation_uid: str, tx_id: str) -> bool:
        """
        Check if attestation is valid for transaction.

        Args:
            attestation_uid: EAS attestation UID
            tx_id: Transaction ID

        Returns:
            True if attestation is unused or already used for this txId
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all tracked attestations."""
        pass


class InMemoryUsedAttestationTracker(IUsedAttestationTracker):
    """
    In-Memory Used Attestation Tracker.

    SECURITY FIX (C-1): Prevents attestation replay attacks by tracking
    which attestation UIDs have been used for which transactions.

    SECURITY FIX (NEW-H-2): LRU-style cache with max size to prevent DoS

    WARNING: In-memory only. For production:
    - Use persistent storage (Redis, PostgreSQL, etc.)
    - Implement recovery from blockchain events
    """

    def __init__(self, max_size: int = 100000) -> None:
        """
        Create in-memory tracker with optional max size.

        Args:
            max_size: Maximum entries to store (default: 100,000)
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self._max_size = max_size
        self._used_attestations: Dict[str, str] = {}
        self._lock = threading.RLock()

    async def record_usage(self, attestation_uid: str, tx_id: str) -> bool:
        """Record attestation usage (async for interface consistency)."""
        return self.record_usage_sync(attestation_uid, tx_id)

    def record_usage_sync(self, attestation_uid: str, tx_id: str) -> bool:
        """
        Synchronous version of record_usage.

        SECURITY FIX (NEW-H-2): LRU eviction when max size reached
        """
        normalized_uid = attestation_uid.lower()
        normalized_tx_id = tx_id.lower()

        with self._lock:
            existing_tx_id = self._used_attestations.get(normalized_uid)

            # If attestation was already used for a different transaction, reject
            if existing_tx_id and existing_tx_id != normalized_tx_id:
                return False

            # SECURITY FIX (NEW-H-2): Enforce max size limit with LRU behavior
            if len(self._used_attestations) >= self._max_size and not existing_tx_id:
                # Remove oldest entry (first entry in dict - Python 3.7+ preserves order)
                first_key = next(iter(self._used_attestations))
                del self._used_attestations[first_key]
            elif existing_tx_id:
                # True LRU - delete and re-add to move to end
                del self._used_attestations[normalized_uid]

            # Record the usage (at end for LRU)
            self._used_attestations[normalized_uid] = normalized_tx_id
            return True

    def get_usage_for_attestation(self, attestation_uid: str) -> Optional[str]:
        """
        Check if attestation has been used.

        SECURITY FIX (MEDIUM-4): Updates access order for true LRU behavior
        """
        normalized_uid = attestation_uid.lower()

        with self._lock:
            tx_id = self._used_attestations.get(normalized_uid)

            # True LRU - move accessed item to end
            if tx_id is not None:
                del self._used_attestations[normalized_uid]
                self._used_attestations[normalized_uid] = tx_id

            return tx_id

    def is_valid_for_transaction(self, attestation_uid: str, tx_id: str) -> bool:
        """
        Check if attestation is valid for transaction.

        SECURITY FIX (MEDIUM-4): Updates access order for true LRU behavior
        """
        normalized_uid = attestation_uid.lower()
        normalized_tx_id = tx_id.lower()

        with self._lock:
            existing_tx_id = self._used_attestations.get(normalized_uid)

            # True LRU - move accessed item to end
            if existing_tx_id is not None:
                del self._used_attestations[normalized_uid]
                self._used_attestations[normalized_uid] = existing_tx_id

            # Valid if: not used OR used for same transaction
            return not existing_tx_id or existing_tx_id == normalized_tx_id

    def clear(self) -> None:
        """Clear all tracked attestations."""
        with self._lock:
            self._used_attestations.clear()

    def get_all_usages(self) -> Dict[str, str]:
        """Get all tracked attestations (for debugging/persistence)."""
        with self._lock:
            return dict(self._used_attestations)

    def get_count(self) -> int:
        """Get count of tracked attestations."""
        return len(self._used_attestations)


class FileBasedUsedAttestationTracker(IUsedAttestationTracker):
    """
    File-based Used Attestation Tracker for persistence.

    SECURITY FIX (C-1): Persistent storage for attestation tracking
    SECURITY FIX (NEW-H-4): File locking to prevent concurrent write corruption

    Survives process restarts.
    """

    # Maximum file size to prevent DoS (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(self, state_directory: str) -> None:
        """
        Create file-based tracker.

        Args:
            state_directory: Directory for persistent storage
        """
        self._in_memory = InMemoryUsedAttestationTracker()
        self._lock = threading.RLock()

        # Ensure directory exists
        actp_dir = Path(state_directory) / ".actp"
        actp_dir.mkdir(parents=True, exist_ok=True)

        self._file_path = actp_dir / "used-attestations.json"

        # Load existing data
        self._load_from_file()

    def _load_from_file(self) -> None:
        """Load tracked attestations from file."""
        if not self._file_path.exists():
            return

        # Security: Check file size
        file_size = self._file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"used-attestations.json exceeds {self.MAX_FILE_SIZE // 1024 // 1024}MB limit: {self._file_path}"
            )

        try:
            with open(self._file_path, "r") as f:
                data = json.load(f)
            for uid, tx_id in data.items():
                self._in_memory.record_usage_sync(uid, tx_id)
        except (json.JSONDecodeError, IOError) as e:
            # Fail closed: losing replay-protection state is a security issue
            raise ValueError(
                f"Failed to parse used-attestations.json (replay protection would be disabled). "
                f"Fix/delete the file: {self._file_path}. Error: {e}"
            )

    def _save_to_file(self) -> None:
        """Save data to file atomically."""
        data = self._in_memory.get_all_usages()
        temp_path = Path(str(self._file_path) + ".tmp")

        try:
            # Atomic write: temp file + rename
            with open(temp_path, "w") as f:
                json.dump(data, f, indent=2)
            temp_path.replace(self._file_path)
        except Exception:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

    async def record_usage(self, attestation_uid: str, tx_id: str) -> bool:
        """Record attestation usage with guaranteed persistence."""
        with self._lock:
            result = self._in_memory.record_usage_sync(attestation_uid, tx_id)
            if result:
                self._save_to_file()
            return result

    def record_usage_sync(self, attestation_uid: str, tx_id: str) -> bool:
        """Synchronous version (fire-and-forget persistence)."""
        with self._lock:
            result = self._in_memory.record_usage_sync(attestation_uid, tx_id)
            if result:
                try:
                    self._save_to_file()
                except Exception as e:
                    print(f"Failed to save attestation tracker state: {e}")
            return result

    def get_usage_for_attestation(self, attestation_uid: str) -> Optional[str]:
        """Check if attestation has been used."""
        return self._in_memory.get_usage_for_attestation(attestation_uid)

    def is_valid_for_transaction(self, attestation_uid: str, tx_id: str) -> bool:
        """Check if attestation is valid for transaction."""
        return self._in_memory.is_valid_for_transaction(attestation_uid, tx_id)

    def clear(self) -> None:
        """Clear all tracked attestations."""
        with self._lock:
            self._in_memory.clear()
            if self._file_path.exists():
                self._file_path.unlink()


def create_used_attestation_tracker(
    state_directory: Optional[str] = None,
) -> IUsedAttestationTracker:
    """
    Factory to create attestation tracker.

    Args:
        state_directory: Optional directory for persistent storage

    Returns:
        IUsedAttestationTracker instance
    """
    if state_directory:
        return FileBasedUsedAttestationTracker(state_directory)
    return InMemoryUsedAttestationTracker()


__all__ = [
    "IUsedAttestationTracker",
    "InMemoryUsedAttestationTracker",
    "FileBasedUsedAttestationTracker",
    "create_used_attestation_tracker",
]
