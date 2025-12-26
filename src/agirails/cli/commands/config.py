"""
Config Commands - View and modify configuration.

Usage:
    $ actp config show
    $ actp config set mode testnet
    $ actp config set address 0x...
"""

from __future__ import annotations

from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import (
    load_config,
    save_config,
    get_config_path,
    ensure_initialized,
)
from agirails.cli.utils.output import (
    print_success,
    print_error,
    print_info,
    print_warning,
    print_json,
    OutputFormat,
)
from agirails.cli.utils.validation import validate_address


# Create config subcommand group
config_app = typer.Typer(
    name="config",
    help="Configuration commands",
    no_args_is_help=True,
)


@config_app.command("show")
def show() -> None:
    """Show current configuration."""
    opts = get_global_options()

    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized"})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    config = load_config(opts.directory)
    config_path = get_config_path(opts.directory)

    if opts.output_format == OutputFormat.JSON:
        print_json({
            "path": str(config_path),
            "config": config,
        })
    elif opts.output_format == OutputFormat.QUIET:
        for key, value in config.items():
            typer.echo(f"{key}={value}")
    else:
        print_info(f"Config: {config_path}")
        if config:
            for key, value in config.items():
                typer.echo(f"  {key}: {value}")
        else:
            typer.echo("  (empty)")


@config_app.command("set")
def set_config(
    key: str = typer.Argument(..., help="Configuration key"),
    value: str = typer.Argument(..., help="Configuration value"),
) -> None:
    """Set a configuration value."""
    opts = get_global_options()

    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized"})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    # Validate known keys - private_key NOT allowed in config (security risk)
    known_keys = {"mode", "address", "rpc_url"}
    if key == "private_key":
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "private_key cannot be stored in config (security risk). Use ACTP_PRIVATE_KEY environment variable instead."})
        else:
            print_error("Security Risk", "private_key cannot be stored in config file.")
            print_warning("Use ACTP_PRIVATE_KEY environment variable instead.")
        raise typer.Exit(1)
    if key not in known_keys:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Unknown key: {key}", "valid_keys": list(known_keys)})
        else:
            print_error(f"Unknown key: {key}", f"Valid keys: {', '.join(known_keys)}")
        raise typer.Exit(1)

    # Validate mode values
    if key == "mode" and value not in ("mock", "testnet", "mainnet"):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Invalid mode: {value}"})
        else:
            print_error(f"Invalid mode: {value}", "Must be: mock, testnet, or mainnet")
        raise typer.Exit(1)

    # Security Note (L-3): Validate and normalize addresses with checksum
    if key == "address":
        try:
            value = validate_address(value, param_name="address", require_checksum=True)
        except typer.BadParameter as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Invalid address", str(e))
            raise typer.Exit(1)

    # Load, update, save
    config = load_config(opts.directory)
    old_value = config.get(key)
    config[key] = value
    save_config(config, opts.directory)

    if opts.output_format == OutputFormat.JSON:
        print_json({
            "success": True,
            "key": key,
            "value": value,
            "oldValue": old_value,
        })
    elif opts.output_format == OutputFormat.QUIET:
        typer.echo(value)
    else:
        print_success(f"Set {key}", {
            "Value": value,
            "Previous": old_value or "(not set)",
        })


@config_app.command("get")
def get_config(
    key: str = typer.Argument(..., help="Configuration key"),
) -> None:
    """Get a configuration value."""
    opts = get_global_options()

    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized"})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    config = load_config(opts.directory)
    value = config.get(key)

    if value is None:
        if opts.output_format == OutputFormat.JSON:
            print_json({"key": key, "value": None, "exists": False})
        else:
            print_info(f"{key}: (not set)")
    else:
        if opts.output_format == OutputFormat.JSON:
            print_json({"key": key, "value": value, "exists": True})
        elif opts.output_format == OutputFormat.QUIET:
            typer.echo(value)
        else:
            typer.echo(f"{key}: {value}")
