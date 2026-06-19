"""Tests for render_receipt_v3 — the FIX-5 framed ceremonial receipt.

Python port of sdk-js/src/cli/commands/test.framedReceipt.test.ts behaviours,
adapted to the Python string-returning renderer (ANSI colour omitted by SDK
convention; the structural content — frame, fields, perspective, reflection +
receipt-URL blocks, network variants, injectable clock — is what we assert).
"""

from __future__ import annotations

import datetime

from agirails.receipts.push import (
    ReceiptDataV3,
    ReceiptTimingV3,
    render_receipt_v3,
)

REFLECTION = "Stillness is its own answer."


def _fixed_clock(y=2026, mo=6, d=9, h=12, mi=34, s=56):
    dt = datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)
    return lambda: dt


def _base(**kw) -> ReceiptDataV3:
    args = dict(
        agent="demo-agent",
        counterparty="Sentinel",
        service="onboarding",
        amount_wei=10_000_000,
        network="base-sepolia",
        tx_id="0x" + "ab" * 32,
        timing=ReceiptTimingV3(total_ms=47321),
        now_fn=_fixed_clock(),
    )
    args.update(kw)
    return ReceiptDataV3(**args)


# ---------------------------------------------------------------------------
# Frame + header
# ---------------------------------------------------------------------------


def test_outer_and_inner_frame_present() -> None:
    out = render_receipt_v3(_base())
    assert any(ln.startswith("╔") and ln.endswith("╗") for ln in out.splitlines())
    assert any(ln.startswith("╚") and ln.endswith("╝") for ln in out.splitlines())
    assert "┌" in out and "┐" in out and "└" in out and "┘" in out


def test_header_and_tagline_testnet() -> None:
    out = render_receipt_v3(_base())
    assert "FIRST TRANSACTION RECEIPT" in out
    assert "Autonomously. Trustlessly" in out


def test_fee_breakdown_for_ten_dollars() -> None:
    out = render_receipt_v3(_base())
    assert "$10.00 USDC" in out  # amount
    assert "$0.10 USDC" in out  # fee (1% of $10)
    assert "$9.90 USDC" in out  # net


def test_duration_row() -> None:
    out = render_receipt_v3(_base())
    import re

    assert re.search(r"Duration\s+47321ms", out)


# ---------------------------------------------------------------------------
# Perspective
# ---------------------------------------------------------------------------


def test_provider_perspective_from_to() -> None:
    import re

    out = render_receipt_v3(_base(perspective="provider"))
    assert re.search(r"From\s+Sentinel", out)
    assert re.search(r"To\s+demo-agent", out)
    assert "demo-agent earned $9.90 USDC" in out


def test_buyer_perspective_from_to_and_hero() -> None:
    import re

    out = render_receipt_v3(_base(perspective="buyer"))
    assert re.search(r"From\s+demo-agent", out)
    assert re.search(r"To\s+Sentinel", out)
    # Buyer hero line shows GROSS outflow, not net.
    assert "demo-agent paid $10.00 USDC" in out
    assert "Your agent just made its first payment." in out


# ---------------------------------------------------------------------------
# Reflection block
# ---------------------------------------------------------------------------


def test_reflection_block_present_provider() -> None:
    out = render_receipt_v3(_base(perspective="provider", reflection=REFLECTION))
    assert "Reflection" in out
    assert REFLECTION in out


def test_reflection_block_buyer_labels_service_delivered() -> None:
    out = render_receipt_v3(_base(perspective="buyer", reflection=REFLECTION))
    assert "Service delivered" in out
    assert "(from Sentinel)" in out
    assert REFLECTION in out


def test_no_reflection_block_when_absent() -> None:
    import re

    out = render_receipt_v3(_base())
    assert not re.search(r"\bReflection\b", out)


def test_no_reflection_block_when_empty_string() -> None:
    import re

    out = render_receipt_v3(_base(reflection=""))
    assert not re.search(r"\bReflection\b", out)


# ---------------------------------------------------------------------------
# Receipt URL block
# ---------------------------------------------------------------------------


def test_receipt_url_block_present() -> None:
    out = render_receipt_v3(_base(receipt_url="https://agirails.app/r/r_abcdef1234567890"))
    assert "r_abcdef1234567890" in out
    assert "Receipt URL" in out


def test_no_receipt_label_https_on_one_line_when_absent() -> None:
    import re

    out = render_receipt_v3(_base())
    assert not re.search(r"Receipt\s+https", out)


# ---------------------------------------------------------------------------
# Network variants
# ---------------------------------------------------------------------------


def test_mainnet_variant_copy() -> None:
    out = render_receipt_v3(_base(network="base-mainnet"))
    assert "FIRST MAINNET SETTLEMENT" in out
    assert "This is real money" in out
    assert "Autonomously. Trustlessly" not in out


def test_on_chain_proof_rows_testnet() -> None:
    out = render_receipt_v3(
        _base(eth_tx_hash="0x" + "cd" * 32)
    )
    assert "sepolia.basescan.org" in out
    assert "Eth Tx" in out


def test_on_chain_proof_rows_mainnet() -> None:
    out = render_receipt_v3(
        _base(network="base-mainnet", eth_tx_hash="0x" + "cd" * 32)
    )
    assert "basescan.org" in out


# ---------------------------------------------------------------------------
# Injectable clock + no ANSI
# ---------------------------------------------------------------------------


def test_injectable_clock_is_byte_stable() -> None:
    out = render_receipt_v3(_base(now_fn=_fixed_clock(2026, 6, 9, 12, 34, 56)))
    assert "2026-06-09 12:34:56 UTC" in out


def test_no_ansi_escape_codes() -> None:
    out = render_receipt_v3(_base())
    assert "\x1b[" not in out


# ---------------------------------------------------------------------------
# Geometry — all human-mode frame lines share one display width
# ---------------------------------------------------------------------------


def test_frame_lines_uniform_width() -> None:
    out = render_receipt_v3(_base(reflection=REFLECTION, receipt_url="https://agirails.app/r/r_x"))
    lines = out.splitlines()
    # Lines that are part of the outer frame all start with ║ or ╔/╚.
    frame_lines = [ln for ln in lines if ln and ln[0] in "║╔╚"]
    widths = {len(ln) for ln in frame_lines}
    assert len(widths) == 1, f"frame widths not uniform: {sorted(widths)}"


def test_counterparty_fallback_to_requester_short_addr() -> None:
    out = render_receipt_v3(
        _base(counterparty=None, requester="0x" + "11" * 20, perspective="provider")
    )
    # short_addr(0x1111...1111) → 0x111111...1111
    assert "0x111111" in out


def test_zero_amount_no_negative_net() -> None:
    out = render_receipt_v3(_base(amount_wei=0))
    # Fee clamped to 0 → net is $0.00, never negative.
    assert "$0.00 USDC" in out
    assert "-$" not in out
