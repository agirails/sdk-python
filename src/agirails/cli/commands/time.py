"""
Time Commands - View and manipulate mock time.

Usage:
    $ actp time
    $ actp time advance 3600
    $ actp time set 1735200000
"""

from __future__ import annotations

import asyncio
from datetime import datetime

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import get_client, ensure_initialized
from agirails.cli.utils.output import (
    print_success,
    print_error,
    print_info,
    print_json,
    OutputFormat,
)
from agirails.cli.utils.validation import validate_seconds, validate_timestamp
from agirails.runtime.base import is_mock_runtime


# Create time subcommand group
time_app = typer.Typer(
    name="time",
    help="Time commands (mock mode only)",
    invoke_without_command=True,
)


@time_app.callback()
def time_callback(ctx: typer.Context) -> None:
    """Show current mock time if no subcommand."""
    if ctx.invoked_subcommand is None:
        show()


@time_app.command("show")
def show() -> None:
    """Show current mock time."""
    opts = get_global_options()

    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized"})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    async def _show() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            if not is_mock_runtime(client.runtime):
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": "Time commands only available in mock mode"})
                else:
                    print_error("Not available", "Time commands only available in mock mode")
                raise typer.Exit(1)

            timestamp = client.runtime.time.now()
            dt = datetime.fromtimestamp(timestamp)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "timestamp": timestamp,
                    "datetime": dt.isoformat(),
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(timestamp)
            else:
                print_info(f"Mock Time: {dt.strftime('%Y-%m-%d %H:%M:%S')} ({timestamp})")

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to get time", str(e))
            raise typer.Exit(1)

    asyncio.run(_show())


@time_app.command("advance")
def advance(
    seconds: int = typer.Argument(..., help="Seconds to advance"),
) -> None:
    """Advance mock time by seconds."""
    opts = get_global_options()

    # Validate seconds
    try:
        seconds = validate_seconds(seconds)
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

    async def _advance() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            if not is_mock_runtime(client.runtime):
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": "Time commands only available in mock mode"})
                else:
                    print_error("Not available", "Time commands only available in mock mode")
                raise typer.Exit(1)

            old_time = client.runtime.time.now()
            await client.runtime.time.advance_time(seconds)
            new_time = client.runtime.time.now()

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "advanced": seconds,
                    "oldTime": old_time,
                    "newTime": new_time,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(new_time)
            else:
                old_dt = datetime.fromtimestamp(old_time)
                new_dt = datetime.fromtimestamp(new_time)
                print_success(f"Advanced time by {seconds}s", {
                    "From": old_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    "To": new_dt.strftime('%Y-%m-%d %H:%M:%S'),
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to advance time", str(e))
            raise typer.Exit(1)

    asyncio.run(_advance())


@time_app.command("set")
def set_time(
    timestamp: int = typer.Argument(..., help="Unix timestamp to set"),
) -> None:
    """Set mock time to specific timestamp."""
    opts = get_global_options()

    # Validate timestamp
    try:
        timestamp = validate_timestamp(timestamp)
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

    async def _set() -> None:
        try:
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            if not is_mock_runtime(client.runtime):
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": "Time commands only available in mock mode"})
                else:
                    print_error("Not available", "Time commands only available in mock mode")
                raise typer.Exit(1)

            old_time = client.runtime.time.now()
            await client.runtime.time.set_time(timestamp)
            new_time = client.runtime.time.now()

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "oldTime": old_time,
                    "newTime": new_time,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(new_time)
            else:
                new_dt = datetime.fromtimestamp(new_time)
                print_success("Set time", {
                    "Timestamp": new_time,
                    "DateTime": new_dt.strftime('%Y-%m-%d %H:%M:%S'),
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Failed to set time", str(e))
            raise typer.Exit(1)

    asyncio.run(_set())
