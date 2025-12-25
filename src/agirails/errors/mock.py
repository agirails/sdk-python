"""
Mock runtime-related exceptions for ACTP protocol.

These exceptions are raised during mock runtime operations,
particularly around state persistence and file locking.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agirails.errors.base import ACTPError


class MockStateCorruptedError(ACTPError):
    """
    Raised when the mock state file is corrupted or invalid.

    Example:
        >>> raise MockStateCorruptedError(".actp/mock-state.json")
    """

    def __init__(
        self,
        state_file: str,
        *,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["state_file"] = state_file
        if reason:
            details["reason"] = reason

        message = f"Mock state corrupted: {state_file}"
        if reason:
            message += f" ({reason})"

        super().__init__(
            message,
            code="MOCK_STATE_CORRUPTED",
            details=details,
        )
        self.state_file = state_file
        self.reason = reason


class MockStateVersionError(ACTPError):
    """
    Raised when the mock state file version is incompatible.

    Example:
        >>> raise MockStateVersionError("1.0.0", "2.0.0")
    """

    def __init__(
        self,
        found_version: str,
        expected_version: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["found_version"] = found_version
        details["expected_version"] = expected_version

        super().__init__(
            f"Mock state version mismatch: found {found_version}, expected {expected_version}",
            code="MOCK_STATE_VERSION_ERROR",
            details=details,
        )
        self.found_version = found_version
        self.expected_version = expected_version


class MockStateLockError(ACTPError):
    """
    Raised when unable to acquire a lock on the mock state file.

    Example:
        >>> raise MockStateLockError(".actp/mock-state.json", timeout_ms=5000)
    """

    def __init__(
        self,
        state_file: str,
        *,
        timeout_ms: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["state_file"] = state_file
        if timeout_ms is not None:
            details["timeout_ms"] = timeout_ms

        message = f"Failed to acquire lock on mock state: {state_file}"
        if timeout_ms:
            message += f" (timeout: {timeout_ms}ms)"

        super().__init__(
            message,
            code="MOCK_STATE_LOCK_ERROR",
            details=details,
        )
        self.state_file = state_file
        self.timeout_ms = timeout_ms
