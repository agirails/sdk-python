"""
Mint Command - Mint test USDC tokens (mock mode only).

Usage:
    $ actp mint 0x... 1000
    $ actp mint 0x... 1000.50
"""

from __future__ import annotations

import asyncio

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
from agirails.runtime.base import is_mock_runtime


def mint(
    address: str = typer.Argument(..., help="Address to mint tokens to (0x...)"),
    amount: str = typer.Argument(..., help="Amount in USDC (e.g., 1000.00)"),
) -> None:
    """Mint test USDC tokens (mock mode only)."""
    opts = get_global_options()

    # Validate inputs
    try:
        address = validate_address(address)
        amount = validate_amount(amount)
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

    async def _mint() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            # Check if mock mode
            if not is_mock_runtime(client.runtime):
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": "Mint is only available in mock mode"})
                else:
                    print_error("Not available", "Mint is only available in mock mode")
                raise typer.Exit(1)

            # Mint tokens
            await client.mint_tokens(address, amount)

            # Get new balance
            new_balance = await client.runtime.get_balance(address)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "address": address,
                    "minted": amount,
                    "newBalance": new_balance,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(new_balance)
            else:
                print_success("Minted tokens", {
                    "Address": format_address(address),
                    "Minted": f"{amount} USDC",
                    "New Balance": format_usdc(new_balance),
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to mint", str(e))
            raise typer.Exit(1)

    asyncio.run(_mint())
