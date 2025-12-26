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
from agirails.cli.utils.validation import validate_address, validate_amount
from agirails.adapters.basic import BasicPayParams


def pay(
    provider: str = typer.Argument(..., help="Provider address (0x...)"),
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

    # Validate inputs
    try:
        provider = validate_address(provider, "provider")
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

            # Create payment params
            params = BasicPayParams(
                to=provider,
                amount=amount,
                deadline=deadline,
                description=description,
            )

            # Execute payment
            result = await client.basic.pay(params)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "txId": result.tx_id,
                    "escrowId": result.escrow_id,
                    "state": result.state,
                    "amount": result.amount,
                    "deadline": result.deadline,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(result.tx_id)
            else:
                print_success("Payment created", {
                    "Transaction ID": result.tx_id,
                    "Escrow ID": result.escrow_id,
                    "State": result.state,
                    "Amount": format_usdc(result.amount),
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
