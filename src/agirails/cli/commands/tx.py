"""
Transaction Commands - View and manage transactions.

Usage:
    $ actp tx status <tx_id>
    $ actp tx list
    $ actp tx transition <tx_id> <state>
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
    print_info,
    print_json,
    print_table,
    print_transaction,
    format_usdc,
    format_address,
    OutputFormat,
)
from agirails.cli.utils.validation import validate_tx_id, validate_state


# Create tx subcommand group
tx_app = typer.Typer(
    name="tx",
    help="Transaction commands",
    no_args_is_help=True,
)


@tx_app.command("status")
def status(
    tx_id: str = typer.Argument(..., help="Transaction ID (0x...)"),
) -> None:
    """Get transaction status and details."""
    opts = get_global_options()

    # Validate tx_id
    try:
        tx_id = validate_tx_id(tx_id)
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

    async def _status() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            tx = await client.runtime.get_transaction(tx_id)

            if tx is None:
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": "Transaction not found", "txId": tx_id})
                else:
                    print_error("Transaction not found", tx_id)
                raise typer.Exit(1)

            # Convert to dict
            tx_dict = {
                "id": tx.id,
                "state": tx.state,
                "requester": tx.requester,
                "provider": tx.provider,
                "amount": tx.amount,
                "deadline": tx.deadline,
                "createdAt": tx.created_at,
                "updatedAt": tx.updated_at,
            }

            if opts.output_format == OutputFormat.JSON:
                print_json(tx_dict)
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(tx.state)
            else:
                print_transaction(tx_dict)

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to get transaction", str(e))
            raise typer.Exit(1)

    asyncio.run(_status())


@tx_app.command("list")
def list_transactions(
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum transactions to show"),
    state: Optional[str] = typer.Option(None, "--state", "-s", help="Filter by state"),
) -> None:
    """List all transactions."""
    opts = get_global_options()

    # Validate state if provided
    if state:
        try:
            state = validate_state(state)
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

    async def _list() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            txs = await client.runtime.get_all_transactions()

            # Filter by state if specified
            if state:
                txs = [tx for tx in txs if tx.state.upper() == state.upper()]

            # Limit results
            txs = txs[:limit]

            if opts.output_format == OutputFormat.JSON:
                tx_list = [
                    {
                        "id": tx.id,
                        "state": tx.state,
                        "requester": tx.requester,
                        "provider": tx.provider,
                        "amount": tx.amount,
                    }
                    for tx in txs
                ]
                print_json({"transactions": tx_list, "count": len(tx_list)})
            elif opts.output_format == OutputFormat.QUIET:
                for tx in txs:
                    typer.echo(tx.id)
            else:
                if not txs:
                    print_info("No transactions found")
                    return

                rows = [
                    [
                        format_address(tx.id, 8),
                        tx.state,
                        format_address(tx.provider),
                        format_usdc(tx.amount),
                    ]
                    for tx in txs
                ]
                print_table(
                    headers=["ID", "State", "Provider", "Amount"],
                    rows=rows,
                    title=f"Transactions ({len(txs)})",
                )

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to list transactions", str(e))
            raise typer.Exit(1)

    asyncio.run(_list())


@tx_app.command("transition")
def transition(
    tx_id: str = typer.Argument(..., help="Transaction ID (0x...)"),
    new_state: str = typer.Argument(..., help="New state (e.g., DELIVERED, SETTLED)"),
    proof: Optional[str] = typer.Option(None, "--proof", "-p", help="Proof hash (bytes32)"),
) -> None:
    """Transition a transaction to a new state."""
    opts = get_global_options()

    # Validate inputs
    try:
        tx_id = validate_tx_id(tx_id)
        new_state = validate_state(new_state)
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

    async def _transition() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            # Transition state
            await client.standard.transition_state(
                tx_id=tx_id,
                new_state=new_state,
            )

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "txId": tx_id,
                    "newState": new_state,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(new_state)
            else:
                print_success(f"Transitioned to {new_state}", {
                    "Transaction ID": tx_id,
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to transition", str(e))
            raise typer.Exit(1)

    asyncio.run(_transition())
