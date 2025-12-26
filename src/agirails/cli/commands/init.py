"""
Init Command - Initialize ACTP in current directory.

Usage:
    $ actp init
    $ actp init --mode testnet
    $ actp init --address 0x...
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import (
    get_state_directory,
    init_directory,
    ensure_initialized,
    get_default_address,
    VALID_MODES,
)
from agirails.cli.utils.output import (
    print_success,
    print_error,
    print_warning,
    print_json,
    OutputFormat,
)


def init(
    mode: str = typer.Option(
        "mock",
        "--mode", "-m",
        help="Default mode: mock, testnet, mainnet"
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address", "-a",
        help="Default requester address"
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing configuration"
    ),
) -> None:
    """Initialize ACTP in the current directory."""
    opts = get_global_options()
    directory = opts.directory

    # Validate mode
    if mode not in VALID_MODES:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(VALID_MODES))}"})
        else:
            print_error("Invalid mode", f"Must be one of: {', '.join(sorted(VALID_MODES))}")
        raise typer.Exit(1)

    # Check if already initialized
    if ensure_initialized(directory) and not force:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Already initialized", "path": str(get_state_directory(directory))})
        else:
            print_warning(f"Already initialized at {get_state_directory(directory)}")
            print_warning("Use --force to overwrite")
        raise typer.Exit(1)

    # Use default address if not provided
    final_address = address or get_default_address()

    # Initialize
    try:
        state_dir = init_directory(
            directory=directory,
            mode=mode,
            address=final_address,
        )

        if opts.output_format == OutputFormat.JSON:
            print_json({
                "success": True,
                "path": str(state_dir),
                "mode": mode,
                "address": final_address,
            })
        elif opts.output_format == OutputFormat.QUIET:
            typer.echo(str(state_dir))
        else:
            print_success("Initialized ACTP", {
                "Directory": str(state_dir),
                "Mode": mode,
                "Address": final_address,
            })

    except Exception as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Failed to initialize", str(e))
        raise typer.Exit(1)
