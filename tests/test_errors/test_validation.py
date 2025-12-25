"""Tests for validation error classes."""

from __future__ import annotations

import pytest

from agirails.errors.validation import (
    ValidationError,
    InvalidAddressError,
    InvalidAmountError,
)


class TestValidationError:
    """Tests for ValidationError base class."""

    def test_basic_creation(self) -> None:
        """Test creating validation error with message."""
        error = ValidationError("Invalid input")

        assert error.message == "Invalid input"
        assert error.code == "VALIDATION_ERROR"
        assert error.field is None
        assert error.value is None

    def test_with_field(self) -> None:
        """Test validation error with field name."""
        error = ValidationError("Invalid value", field="amount")

        assert error.field == "amount"
        assert error.details["field"] == "amount"

    def test_with_value(self) -> None:
        """Test validation error with value."""
        error = ValidationError("Too large", field="count", value=1000)

        assert error.value == 1000
        assert error.details["value"] == "1000"

    def test_inherits_from_actp_error(self) -> None:
        """Test inheritance chain."""
        from agirails.errors.base import ACTPError

        error = ValidationError("Test")
        assert isinstance(error, ACTPError)


class TestInvalidAddressError:
    """Tests for InvalidAddressError."""

    def test_basic_creation(self) -> None:
        """Test creating with invalid address."""
        error = InvalidAddressError("0xinvalid")

        assert "0xinvalid" in error.message
        assert error.code == "INVALID_ADDRESS"
        assert error.address == "0xinvalid"
        assert error.field == "address"

    def test_with_custom_field(self) -> None:
        """Test with custom field name."""
        error = InvalidAddressError("0xbad", field="provider")

        assert error.field == "provider"
        assert error.details["field"] == "provider"

    def test_with_reason(self) -> None:
        """Test with reason for invalidity."""
        error = InvalidAddressError(
            "0xshort",
            reason="Address must be 42 characters",
        )

        assert error.reason == "Address must be 42 characters"
        assert "Address must be 42 characters" in error.message
        assert error.details["reason"] == "Address must be 42 characters"

    def test_address_in_details(self) -> None:
        """Test address is included in details."""
        error = InvalidAddressError("0xtest123")

        assert error.details["address"] == "0xtest123"

    def test_inherits_from_validation_error(self) -> None:
        """Test inheritance chain."""
        error = InvalidAddressError("0x")
        assert isinstance(error, ValidationError)


class TestInvalidAmountError:
    """Tests for InvalidAmountError."""

    def test_basic_creation_string(self) -> None:
        """Test creating with string amount."""
        error = InvalidAmountError("-100")

        assert "-100" in error.message
        assert error.code == "INVALID_AMOUNT"
        assert error.amount == "-100"

    def test_basic_creation_int(self) -> None:
        """Test creating with integer amount."""
        error = InvalidAmountError(0)

        assert error.amount == 0
        assert error.details["amount"] == "0"

    def test_with_reason(self) -> None:
        """Test with reason for invalidity."""
        error = InvalidAmountError(
            -50,
            reason="Amount must be positive",
        )

        assert error.reason == "Amount must be positive"
        assert "Amount must be positive" in error.message

    def test_with_min_amount(self) -> None:
        """Test with minimum amount specified."""
        error = InvalidAmountError(
            10000,
            reason="Below minimum",
            min_amount=50000,
        )

        assert error.min_amount == 50000
        assert error.details["min_amount_wei"] == "50000"

    def test_custom_field(self) -> None:
        """Test with custom field name."""
        error = InvalidAmountError("bad", field="escrow_amount")

        assert error.field == "escrow_amount"

    def test_inherits_from_validation_error(self) -> None:
        """Test inheritance chain."""
        error = InvalidAmountError("x")
        assert isinstance(error, ValidationError)
