"""
Base exception class for AGIRAILS SDK.

All ACTP-specific exceptions inherit from ACTPError, which provides
structured error information including error codes, transaction hashes,
and additional context details.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


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
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code!r}, "
            f"tx_hash={self.tx_hash!r}, "
            f"details={self.details!r})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to a dictionary for JSON serialization.

        Returns:
            Dictionary representation of the error.
        """
        return {
            "error": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
            "tx_hash": self.tx_hash,
            "details": self.details,
        }
