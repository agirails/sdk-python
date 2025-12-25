"""Tests for base ACTP error class."""

from __future__ import annotations

import pytest

from agirails.errors.base import ACTPError


class TestACTPError:
    """Tests for ACTPError base class."""

    def test_basic_creation(self) -> None:
        """Test creating error with just a message."""
        error = ACTPError("Something went wrong")

        assert error.message == "Something went wrong"
        assert error.code == "ACTP_ERROR"
        assert error.tx_hash is None
        assert error.details == {}

    def test_creation_with_all_params(self) -> None:
        """Test creating error with all parameters."""
        error = ACTPError(
            "Transaction failed",
            code="TX_FAILED",
            tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            details={"gas_used": 21000, "reason": "out of gas"},
        )

        assert error.message == "Transaction failed"
        assert error.code == "TX_FAILED"
        assert error.tx_hash == "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        assert error.details == {"gas_used": 21000, "reason": "out of gas"}

    def test_str_representation(self) -> None:
        """Test __str__ method."""
        error = ACTPError("Test error", code="TEST_CODE")
        assert str(error) == "[TEST_CODE] Test error"

    def test_str_with_tx_hash(self) -> None:
        """Test __str__ includes truncated tx hash."""
        error = ACTPError(
            "Failed",
            code="FAIL",
            tx_hash="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        assert "(tx: 0x12345678...)" in str(error)

    def test_repr_representation(self) -> None:
        """Test __repr__ method."""
        error = ACTPError("Test", code="CODE")
        repr_str = repr(error)

        assert "ACTPError" in repr_str
        assert "message='Test'" in repr_str
        assert "code='CODE'" in repr_str

    def test_to_dict_serialization(self) -> None:
        """Test to_dict() method for JSON serialization."""
        error = ACTPError(
            "Serializable error",
            code="SERIALIZE",
            tx_hash="0xabcd",
            details={"key": "value"},
        )

        result = error.to_dict()

        assert result["error"] == "ACTPError"
        assert result["code"] == "SERIALIZE"
        assert result["message"] == "Serializable error"
        assert result["tx_hash"] == "0xabcd"
        assert result["details"] == {"key": "value"}

    def test_to_dict_with_none_values(self) -> None:
        """Test to_dict() handles None values."""
        error = ACTPError("Simple error")
        result = error.to_dict()

        assert result["tx_hash"] is None
        assert result["details"] == {}

    def test_exception_inheritance(self) -> None:
        """Test that ACTPError inherits from Exception."""
        error = ACTPError("Test")

        assert isinstance(error, Exception)

        # Can be raised and caught
        with pytest.raises(ACTPError):
            raise error

    def test_exception_args(self) -> None:
        """Test that message is passed to Exception base."""
        error = ACTPError("Error message")

        # Exception.args should contain the message
        assert error.args == ("Error message",)

    def test_details_default_empty_dict(self) -> None:
        """Test that details defaults to empty dict, not None."""
        error = ACTPError("Test", details=None)

        assert error.details == {}
        assert error.details is not None

    def test_mutable_details(self) -> None:
        """Test that details can be modified after creation."""
        error = ACTPError("Test")
        error.details["added"] = "later"

        assert error.details["added"] == "later"

    def test_code_is_accessible(self) -> None:
        """Test error code is accessible for programmatic handling."""
        error = ACTPError("Test", code="SPECIFIC_CODE")

        # Can switch on error code
        if error.code == "SPECIFIC_CODE":
            handled = True
        else:
            handled = False

        assert handled is True
