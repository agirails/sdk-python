"""
Pay Command - Create a payment transaction.

Usage:
    $ actp pay 0xProvider... 10.00
    $ actp pay 0xProvider... 10.00 --deadline 24h
    $ actp pay 0xProvider... 10.00 --description "Service payment"
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import get_client, ensure_initialized
from agirails.cli.utils.output import (
    print_success,
    print_error,
    print_json,
    format_usdc,
    format_address,
    OutputFormat,
)
from agirails.adapters.types import UnifiedPayParams
from agirails.cli.utils.validation import validate_amount


def pay(
    provider: str = typer.Argument(..., help="Provider address (0x...), HTTP endpoint, or agent ID"),
    amount: str = typer.Argument(..., help="Amount in USDC (e.g., 10.00)"),
    deadline: Optional[str] = typer.Option(
        None,
        "--deadline",
        help="Deadline (e.g., '24h', '7d', or Unix timestamp)"
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        help="Payment description"
    ),
) -> None:
    """Create a payment transaction to a provider."""
    opts = get_global_options()

    # Validate amount (provider can be address, URL, or agent ID — router decides)
    try:
        amount = validate_amount(amount)
    except typer.BadParameter as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Invalid input", str(e))
        raise typer.Exit(1)

    # Check initialization
    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized. Run 'actp init' first."})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    async def _pay() -> None:
        try:
            # Get client
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            # Create unified payment params (router selects adapter)
            # Deadline is passed as-is: the adapter's parse_deadline()
            # handles both relative formats ("24h", "7d") and unix timestamps.
            params = UnifiedPayParams(
                to=provider,
                amount=amount,
                deadline=deadline,
                description=description,
            )

            # Execute payment through router
            raw = await client.pay(params)

            # Normalize result (adapters may return dataclass or dict)
            if isinstance(raw, dict):
                r_tx_id = raw.get("tx_id", "")
                r_escrow_id = raw.get("escrow_id", "")
                r_state = raw.get("state", "")
                r_amount = raw.get("amount", "")
                r_deadline = raw.get("deadline", 0)
            else:
                r_tx_id = getattr(raw, "tx_id", "")
                r_escrow_id = getattr(raw, "escrow_id", "")
                r_state = getattr(raw, "state", "")
                r_amount = getattr(raw, "amount", "")
                r_deadline = getattr(raw, "deadline", 0)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "txId": r_tx_id,
                    "escrowId": r_escrow_id,
                    "state": r_state,
                    "amount": r_amount,
                    "deadline": r_deadline,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(r_tx_id)
            else:
                print_success("Payment created", {
                    "Transaction ID": r_tx_id,
                    "Escrow ID": r_escrow_id,
                    "State": r_state,
                    "Amount": format_usdc(r_amount),
                    "Provider": format_address(provider),
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Payment failed", str(e))
            raise typer.Exit(1)

    asyncio.run(_pay())
