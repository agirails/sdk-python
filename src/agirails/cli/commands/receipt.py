"""
Receipt rendering utility for ACTP CLI.

Provides formatted receipt output for test and transaction commands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from agirails.cli.utils.output import OutputFormat


@dataclass
class ReceiptTiming:
    """Timing breakdown for a transaction."""

    total_ms: int
    escrow_lock_ms: int
    settlement_ms: int


@dataclass
class ReceiptData:
    """Data for rendering a transaction receipt."""

    agent: str
    service: str
    amount_wei: int
    network: str
    tx_id: str
    timing: ReceiptTiming


def compute_display_fee(amount_wei: int) -> int:
    """Compute platform fee: max(1% of amount, $0.05 minimum).

    Args:
        amount_wei: Amount in USDC wei (6 decimals)

    Returns:
        Fee in USDC wei
    """
    one_percent = amount_wei * 100 // 10000
    return max(one_percent, 50000)


def format_usdc(wei: int) -> str:
    """Format wei amount as USDC display string.

    Args:
        wei: Amount in USDC wei (6 decimals)

    Returns:
        Formatted string like "$10.00 USDC"
    """
    usdc = wei / 1_000_000
    return f"${usdc:.2f} USDC"


def format_tx_id(tx_id: str) -> str:
    """Truncate transaction ID for display.

    Args:
        tx_id: Full transaction ID (hex)

    Returns:
        Truncated ID if longer than 14 chars
    """
    if len(tx_id) <= 14:
        return tx_id
    return f"{tx_id[:8]}...{tx_id[-4:]}"


def render_receipt(data: ReceiptData, output_format: OutputFormat) -> str:
    """Render a transaction receipt in the specified format.

    Args:
        data: Receipt data
        output_format: PRETTY, JSON, or QUIET

    Returns:
        Formatted receipt string
    """
    fee = compute_display_fee(data.amount_wei)
    net = data.amount_wei - fee

    if output_format == OutputFormat.JSON:
        return json.dumps(
            {
                "agent": data.agent,
                "service": data.service,
                "amount": format_usdc(data.amount_wei),
                "fee": format_usdc(fee),
                "net": format_usdc(net),
                "network": data.network,
                "txId": data.tx_id,
                "timing": {
                    "totalMs": data.timing.total_ms,
                    "escrowLockMs": data.timing.escrow_lock_ms,
                    "settlementMs": data.timing.settlement_ms,
                },
            },
            indent=2,
        )

    if output_format == OutputFormat.QUIET:
        return data.tx_id

    # Pretty box-drawing receipt
    lines = [
        "",
        "\u2713 ACTP Transaction Complete",
        "",
        "\u250c" + "\u2500" * 44 + "\u2510",
        f"\u2502  Agent:    {data.agent:<32}\u2502",
        f"\u2502  Service:  {data.service:<32}\u2502",
        f"\u2502  Amount:   {format_usdc(data.amount_wei):<32}\u2502",
        f"\u2502  Fee:      {format_usdc(fee):<32}\u2502",
        f"\u2502  Net:      {format_usdc(net):<32}\u2502",
        f"\u2502  Network:  {data.network:<32}\u2502",
        f"\u2502  TX:       {format_tx_id(data.tx_id):<32}\u2502",
        "\u251c" + "\u2500" * 44 + "\u2524",
        f"\u2502  Total:    {data.timing.total_ms}ms" + " " * max(0, 31 - len(f"{data.timing.total_ms}ms")) + "\u2502",
        f"\u2502  Escrow:   {data.timing.escrow_lock_ms}ms" + " " * max(0, 31 - len(f"{data.timing.escrow_lock_ms}ms")) + "\u2502",
        f"\u2502  Settle:   {data.timing.settlement_ms}ms" + " " * max(0, 31 - len(f"{data.timing.settlement_ms}ms")) + "\u2502",
        "\u2514" + "\u2500" * 44 + "\u2518",
    ]
    return "\n".join(lines)
