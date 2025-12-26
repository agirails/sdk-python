"""
Base exception class for AGIRAILS SDK.

All ACTP-specific exceptions inherit from ACTPError, which provides
structured error information including error codes, transaction hashes,
and additional context details.

Security Note (L-1): Error verbosity is controlled by DEBUG_MODE.
When disabled, sensitive details like internal paths, IP addresses,
and field values are hidden from error messages.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

# Security Note (L-1): Control error verbosity
# Set AGIRAILS_DEBUG=1 to enable verbose error messages
DEBUG_MODE: bool = os.environ.get("AGIRAILS_DEBUG", "").lower() in ("1", "true", "yes")


def set_debug_mode(enabled: bool) -> None:
    """
    Enable or disable debug mode for error messages.

    Security Note (L-1): In production, keep debug mode disabled
    to prevent information disclosure through error messages.

    Args:
        enabled: True to enable verbose errors, False to hide details
    """
    global DEBUG_MODE
    DEBUG_MODE = enabled


def is_debug_mode() -> bool:
    """Check if debug mode is enabled."""
    return DEBUG_MODE


# Keys that should be redacted in production error messages
SENSITIVE_KEYS = frozenset({
    "ip", "resolved_ip", "hostname", "path", "file_path", "directory",
    "private_key", "secret", "password", "token", "api_key",
})


def _redact_sensitive_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact sensitive information from error details.

    Args:
        details: Original details dictionary

    Returns:
        Redacted details dictionary (safe for production)
    """
    if not details:
        return {}

    redacted = {}
    for key, value in details.items():
        if key.lower() in SENSITIVE_KEYS:
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = _redact_sensitive_details(value)
        else:
            redacted[key] = value
    return redacted


class ACTPError(Exception):
    """
    Base exception for all ACTP protocol errors.

    Provides structured error information that can be serialized and logged.

    Attributes:
        message: Human-readable error description.
        code: Machine-readable error code (e.g., "TRANSACTION_NOT_FOUND").
        tx_hash: Optional transaction hash related to the error.
        details: Optional dictionary with additional error context.

    Example:
        >>> raise ACTPError(
        ...     "Transaction failed",
        ...     code="TX_FAILED",
        ...     tx_hash="0x123...",
        ...     details={"gas_used": 21000}
        ... )
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "ACTP_ERROR",
        tx_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize ACTPError.

        Args:
            message: Human-readable error description.
            code: Machine-readable error code.
            tx_hash: Optional transaction hash related to the error.
            details: Optional dictionary with additional error context.
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.tx_hash = tx_hash
        self.details = details or {}

    def __str__(self) -> str:
        """Return formatted error message."""
        parts = [f"[{self.code}] {self.message}"]
        if self.tx_hash:
            parts.append(f"(tx: {self.tx_hash[:10]}...)")
        return " ".join(parts)

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        # Security Note (L-1): Redact sensitive details in production
        details = self.details if DEBUG_MODE else _redact_sensitive_details(self.details)
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code!r}, "
            f"tx_hash={self.tx_hash!r}, "
            f"details={details!r})"
        )

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert exception to a dictionary for JSON serialization.

        Security Note (L-1): By default, sensitive details are redacted
        unless include_sensitive=True or DEBUG_MODE is enabled.

        Args:
            include_sensitive: If True, include all details without redaction

        Returns:
            Dictionary representation of the error.
        """
        # Include full details only if explicitly requested or in debug mode
        if include_sensitive or DEBUG_MODE:
            details = self.details
        else:
            details = _redact_sensitive_details(self.details)

        return {
            "error": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
            "tx_hash": self.tx_hash,
            "details": details,
        }
