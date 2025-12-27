"""
Watch Command - Stream transaction state changes.

Agent-first feature: Real-time monitoring of transaction state.
Outputs state changes as they happen, perfect for scripts
that need to react to transaction lifecycle events.

PARITY: Matches TypeScript SDK's cli/commands/watch.ts
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import get_client
from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_success,
    print_warning,
    print_json,
    format_state,
)
from agirails.runtime.types import State, TERMINAL_STATES

# Valid transaction states
VALID_STATES = frozenset([
    "INITIATED", "QUOTED", "COMMITTED", "IN_PROGRESS",
    "DELIVERED", "SETTLED", "DISPUTED", "CANCELLED",
])

# Terminal states where watching should stop
TERMINAL_STATE_NAMES = frozenset(["SETTLED", "CANCELLED"])


def is_valid_tx_id(tx_id: str) -> bool:
    """Validate transaction ID format (0x + 64 hex chars)."""
    if not tx_id.startswith("0x"):
        return False
    if len(tx_id) != 66:
        return False
    try:
        int(tx_id, 16)
        return True
    except ValueError:
        return False


async def run_watch(
    tx_id: str,
    timeout: int,
    interval: int,
    until: Optional[str],
    output_json: bool,
    quiet: bool,
    directory: Optional[Path],
    mode: Optional[str],
) -> int:
    """
    Run the watch command.

    Args:
        tx_id: Transaction ID to watch
        timeout: Timeout in seconds (0 = indefinite)
        interval: Polling interval in milliseconds
        until: Exit when reaching this state
        output_json: Output as JSON lines
        quiet: Minimal output (state names only)
        directory: Working directory
        mode: Client mode

    Returns:
        Exit code
    """
    # Validate tx_id format
    if not is_valid_tx_id(tx_id):
        if output_json:
            print_json({"error": {"code": "INVALID_INPUT", "message": f"Invalid transaction ID format: {tx_id}"}})
        else:
            print_error(f"Invalid transaction ID format: {tx_id}")
        return 1

    # Validate until state if provided
    until_state = until.upper() if until else None
    if until_state and until_state not in VALID_STATES:
        if output_json:
            print_json({"error": {"code": "INVALID_INPUT", "message": f"Invalid state: {until}. Valid: {', '.join(sorted(VALID_STATES))}"}})
        else:
            print_error(f"Invalid state: {until}. Valid states: {', '.join(sorted(VALID_STATES))}")
        return 1

    # Get client
    client = await get_client(mode=mode, directory=directory)

    # Get initial transaction
    tx = await client.standard.get_transaction(tx_id)
    if tx is None:
        if output_json:
            print_json({"error": {"code": "NOT_FOUND", "message": f"Transaction not found: {tx_id}"}})
        else:
            print_error(f"Transaction not found: {tx_id}")
        return 1

    # Get current state
    current_state = tx.state.value if hasattr(tx.state, "value") else str(tx.state)
    start_time = time.time()

    # Emit initial state
    _emit_state_change(tx_id, None, current_state, tx.updated_at, output_json, quiet)

    # Check if already at target state
    if until_state and current_state == until_state:
        if not quiet and not output_json:
            print_info("Transaction already at target state.")
        return 0

    # Check if terminal state
    if current_state in TERMINAL_STATE_NAMES:
        if not quiet and not output_json:
            print_info("Transaction is in terminal state.")
        return 0

    if not quiet and not output_json:
        print_info("Watching for state changes... (Ctrl+C to stop)")

    # Polling loop
    interval_seconds = interval / 1000.0

    while True:
        # Check timeout
        if timeout > 0:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                if not quiet and not output_json:
                    print_warning(f"Timeout reached ({timeout}s)")
                return 2  # Timeout exit code

        # Wait for interval
        await asyncio.sleep(interval_seconds)

        try:
            # Poll for updates
            updated_tx = await client.standard.get_transaction(tx_id)
            if updated_tx is None:
                if not quiet and not output_json:
                    print_warning("Transaction no longer exists")
                return 1

            new_state = updated_tx.state.value if hasattr(updated_tx.state, "value") else str(updated_tx.state)

            # Check for state change
            if new_state != current_state:
                previous_state = current_state
                current_state = new_state
                _emit_state_change(tx_id, previous_state, current_state, updated_tx.updated_at, output_json, quiet)

                # Check if reached target state
                if until_state and current_state == until_state:
                    if not quiet and not output_json:
                        print_success(f"Reached target state: {until_state}")
                    return 0

                # Check if terminal
                if current_state in TERMINAL_STATE_NAMES:
                    if not quiet and not output_json:
                        print_info(f"Transaction reached terminal state: {current_state}")
                    return 0

        except Exception as e:
            # Non-fatal: log warning and continue
            if not quiet and not output_json:
                print_warning(f"Poll error: {str(e)}")


def _emit_state_change(
    tx_id: str,
    from_state: Optional[str],
    to_state: str,
    timestamp: int,
    output_json: bool,
    quiet: bool,
) -> None:
    """Emit a state change event in the appropriate format."""
    iso_time = datetime.fromtimestamp(timestamp).isoformat()

    if output_json:
        # NDJSON format for easy parsing
        event = {
            "event": "state_change",
            "txId": tx_id,
            "fromState": from_state,
            "toState": to_state,
            "timestamp": iso_time,
            "unix": timestamp,
        }
        print(json.dumps(event), flush=True)
    elif quiet:
        print(to_state, flush=True)
    else:
        # Human-readable format
        if from_state:
            print(f"{iso_time}  {format_state(from_state)} -> {format_state(to_state)}", flush=True)
        else:
            print(f"{iso_time}  Current: {format_state(to_state)}", flush=True)


def watch(
    tx_id: str = typer.Argument(..., help="Transaction ID to watch"),
    timeout: int = typer.Option(0, "--timeout", "-t", help="Exit after timeout seconds (0 = indefinite)"),
    interval: int = typer.Option(1000, "--interval", "-i", help="Polling interval in milliseconds"),
    until: Optional[str] = typer.Option(None, "--until", help="Exit when transaction reaches this state"),
) -> None:
    """
    Watch a transaction for state changes (agent-first feature).

    Streams state changes as they happen, perfect for scripts
    that need to react to transaction lifecycle events.

    Examples:

        $ actp watch 0x123...abc

        $ actp watch 0x123...abc --until DELIVERED

        $ actp watch 0x123...abc --timeout 60 --json
    """
    global_opts = get_global_options()

    try:
        exit_code = asyncio.run(
            run_watch(
                tx_id=tx_id,
                timeout=timeout,
                interval=interval,
                until=until,
                output_json=global_opts.json_output,
                quiet=global_opts.quiet,
                directory=global_opts.directory,
                mode=global_opts.mode,
            )
        )
        raise typer.Exit(code=exit_code)
    except KeyboardInterrupt:
        if not global_opts.quiet:
            print_info("\nWatch stopped by user.")
        raise typer.Exit(code=0)
    except Exception as e:
        if global_opts.json_output:
            print_json({"error": {"code": "ERROR", "message": str(e)}})
        else:
            print_error(str(e))
        raise typer.Exit(code=1)


__all__ = ["watch", "run_watch"]
