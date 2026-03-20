"""Tests for receipt rendering utility."""

from __future__ import annotations

import json

import pytest

from agirails.cli.commands.receipt import (
    ReceiptData,
    ReceiptTiming,
    compute_display_fee,
    format_usdc,
    format_tx_id,
    render_receipt,
)
from agirails.cli.utils.output import OutputFormat


class TestComputeDisplayFee:
    """Tests for compute_display_fee."""

    def test_one_percent_of_ten_dollars(self) -> None:
        """1% of $10 = $0.10."""
        assert compute_display_fee(10_000_000) == 100_000

    def test_minimum_fee_on_small_amount(self) -> None:
        """$0.05 minimum on $1."""
        assert compute_display_fee(1_000_000) == 50_000

    def test_minimum_fee_on_tiny_amount(self) -> None:
        """$0.05 minimum on $0.10."""
        assert compute_display_fee(100_000) == 50_000

    def test_one_percent_on_hundred_dollars(self) -> None:
        """1% of $100 = $1.00."""
        assert compute_display_fee(100_000_000) == 1_000_000

    def test_zero_amount(self) -> None:
        """Zero amount should return minimum fee."""
        assert compute_display_fee(0) == 50_000


class TestFormatUsdc:
    """Tests for format_usdc."""

    def test_ten_dollars(self) -> None:
        assert format_usdc(10_000_000) == "$10.00 USDC"

    def test_one_cent(self) -> None:
        assert format_usdc(10_000) == "$0.01 USDC"

    def test_zero(self) -> None:
        assert format_usdc(0) == "$0.00 USDC"

    def test_large_amount(self) -> None:
        assert format_usdc(1_000_000_000) == "$1000.00 USDC"

    def test_fractional(self) -> None:
        assert format_usdc(5_500_000) == "$5.50 USDC"


class TestFormatTxId:
    """Tests for format_tx_id."""

    def test_short_id_unchanged(self) -> None:
        assert format_tx_id("0x1234") == "0x1234"

    def test_long_id_truncated(self) -> None:
        long_id = "0x" + "ab" * 32
        result = format_tx_id(long_id)
        assert len(result) < len(long_id)
        assert result.startswith("0xababab")
        assert "..." in result


class TestRenderReceipt:
    """Tests for render_receipt."""

    def _make_data(self) -> ReceiptData:
        return ReceiptData(
            agent="test-agent",
            service="content-generation",
            amount_wei=10_000_000,
            network="mock",
            tx_id="0x" + "ab" * 32,
            timing=ReceiptTiming(total_ms=42, escrow_lock_ms=10, settlement_ms=5),
        )

    def test_json_output(self) -> None:
        data = self._make_data()
        result = render_receipt(data, OutputFormat.JSON)
        parsed = json.loads(result)
        assert parsed["agent"] == "test-agent"
        assert parsed["service"] == "content-generation"
        assert parsed["amount"] == "$10.00 USDC"
        assert parsed["fee"] == "$0.10 USDC"
        assert parsed["net"] == "$9.90 USDC"
        assert parsed["network"] == "mock"
        assert parsed["timing"]["totalMs"] == 42

    def test_quiet_output(self) -> None:
        data = self._make_data()
        result = render_receipt(data, OutputFormat.QUIET)
        assert result == data.tx_id

    def test_pretty_output_contains_key_info(self) -> None:
        data = self._make_data()
        result = render_receipt(data, OutputFormat.PRETTY)
        assert "test-agent" in result
        assert "content-generation" in result
        assert "$10.00 USDC" in result
        assert "ACTP Transaction Complete" in result
