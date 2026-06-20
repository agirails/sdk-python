"""Tests for render_request_receipt — the V3 framed receipt wiring in run_request.

P1 parity (TS request.ts:198-237): a settled non-mock request renders the
buyer-perspective ceremonial V3 receipt. Mock / unsettled outcomes suppress
the frame (return None) so the caller falls back to the legacy success line.
"""

from __future__ import annotations

import datetime

from agirails.cli.lib.run_request import RunRequestResult, render_request_receipt


def _result(settled: bool = True, receipt_url=None, tx_id="0x" + "ab" * 32):
    return RunRequestResult(
        tx_id=tx_id,
        final_state="SETTLED" if settled else "DELIVERED",
        elapsed_ms=1234,
        settled=settled,
        payload={"reflection": "be still"},
        receipt_url=receipt_url,
    )


def _clock():
    dt = datetime.datetime(2026, 6, 18, 9, 0, 0, tzinfo=datetime.timezone.utc)
    return lambda: dt


def test_settled_testnet_renders_buyer_frame() -> None:
    out = render_request_receipt(
        result=_result(),
        network="testnet",
        amount="10",
        service="onboarding",
        provider="0x" + "cd" * 20,
        counterparty="Sentinel",
        reflection="Stillness.",
        now_fn=_clock(),
    )
    assert out is not None
    assert "FIRST TRANSACTION RECEIPT" in out
    # Buyer perspective: gross outflow on the hero line.
    assert "your-agent paid $10.00 USDC" in out
    assert "Sentinel" in out
    assert "Stillness." in out
    assert "base-sepolia" in out


def test_settled_mainnet_uses_mainnet_label() -> None:
    out = render_request_receipt(
        result=_result(),
        network="mainnet",
        amount="5",
        service="audit",
        provider="0x" + "cd" * 20,
        now_fn=_clock(),
    )
    assert out is not None
    assert "FIRST MAINNET SETTLEMENT" in out
    assert "$5.00 USDC" in out


def test_receipt_url_block_threaded() -> None:
    out = render_request_receipt(
        result=_result(receipt_url="https://agirails.app/r/r_xyz"),
        network="testnet",
        amount="10",
        service="onboarding",
        provider="0x" + "cd" * 20,
        now_fn=_clock(),
    )
    assert out is not None
    assert "Receipt URL" in out
    assert "r_xyz" in out


def test_mock_network_suppresses_frame() -> None:
    out = render_request_receipt(
        result=_result(),
        network="mock",
        amount="10",
        service="onboarding",
        provider="0x" + "cd" * 20,
    )
    assert out is None


def test_unsettled_suppresses_frame() -> None:
    out = render_request_receipt(
        result=_result(settled=False),
        network="testnet",
        amount="10",
        service="onboarding",
        provider="0x" + "cd" * 20,
    )
    assert out is None


def test_dollar_prefixed_amount_parsed() -> None:
    out = render_request_receipt(
        result=_result(),
        network="testnet",
        amount="$10",
        service="onboarding",
        provider="0x" + "cd" * 20,
        now_fn=_clock(),
    )
    assert out is not None
    assert "$10.00 USDC" in out


def test_counterparty_none_falls_back_to_provider_short_addr() -> None:
    out = render_request_receipt(
        result=_result(),
        network="testnet",
        amount="1",
        service="onboarding",
        provider="0x" + "ce" * 20,
        counterparty=None,
        now_fn=_clock(),
    )
    assert out is not None
    # short_addr of the provider address appears on the To line (buyer view).
    assert "0xcecece" in out
