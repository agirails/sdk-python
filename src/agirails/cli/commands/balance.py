"""
Balance Command - Check USDC balance.

Usage:
    $ actp balance
    $ actp balance 0x...
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
from agirails.cli.utils.validation import validate_address


def balance(
    address: Optional[str] = typer.Argument(
        None,
        help="Address to check (defaults to configured address)"
    ),
) -> None:
    """Check USDC balance for an address."""
    opts = get_global_options()

    # Validate address if provided
    if address:
        try:
            address = validate_address(address)
        except typer.BadParameter as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Invalid input", str(e))
            raise typer.Exit(1)

    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized"})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    async def _balance() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            # Use configured address if not provided
            check_address = address or client.get_address()

            # Get balance
            balance_wei = await client.runtime.get_balance(check_address)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "address": check_address,
                    "balance": balance_wei,
                    "formatted": format_usdc(balance_wei),
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(balance_wei)
            else:
                print_success("Balance", {
                    "Address": format_address(check_address),
                    "Balance": format_usdc(balance_wei),
                    "Raw (wei)": balance_wei,
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to get balance", str(e))
            raise typer.Exit(1)

    asyncio.run(_balance())
