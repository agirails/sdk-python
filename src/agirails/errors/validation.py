"""
Validation-related exceptions for ACTP protocol.

These exceptions are raised when input validation fails,
including address format, amount validation, and general
parameter validation.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from agirails.errors.base import ACTPError


class ValidationError(ACTPError):
    """
    Base exception for input validation failures.

    Example:
        >>> raise ValidationError("Invalid parameter value", field="amount")
    """

    def __init__(
        self,
        message: str,
        *,
        field: Optional[str] = None,
        value: Any = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)

        super().__init__(
            message,
            code="VALIDATION_ERROR",
            details=details,
        )
        self.field = field
        self.value = value


class InvalidAddressError(ValidationError):
    """
    Raised when an Ethereum address is invalid.

    Valid addresses must:
    - Start with '0x'
    - Have exactly 40 hexadecimal characters after '0x'

    Example:
        >>> raise InvalidAddressError("0xinvalid", field="provider")
    """

    def __init__(
        self,
        address: str,
        *,
        field: str = "address",
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["address"] = address
        if reason:
            details["reason"] = reason

        message = f"Invalid address: {address}"
        if reason:
            message += f" ({reason})"

        super().__init__(
            message,
            field=field,
            value=address,
            details=details,
        )
        self.code = "INVALID_ADDRESS"  # Override parent code
        self.address = address
        self.reason = reason


class InvalidAmountError(ValidationError):
    """
    Raised when a transaction amount is invalid.

    Amounts must be:
    - Positive (> 0)
    - At or above minimum ($0.05 USDC = 50000 wei)
    - Valid numeric format

    Example:
        >>> raise InvalidAmountError("-100", reason="Amount must be positive")
    """

    def __init__(
        self,
        amount: Union[str, int],
        *,
        field: str = "amount",
        reason: Optional[str] = None,
        min_amount: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["amount"] = str(amount)
        if reason:
            details["reason"] = reason
        if min_amount is not None:
            details["min_amount_wei"] = str(min_amount)

        message = f"Invalid amount: {amount}"
        if reason:
            message += f" ({reason})"

        super().__init__(
            message,
            field=field,
            value=amount,
            details=details,
        )
        self.code = "INVALID_AMOUNT"  # Override parent code
        self.amount = amount
        self.reason = reason
        self.min_amount = min_amount
