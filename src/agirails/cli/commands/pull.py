"""Pull Command - Download on-chain config to local AGIRAILS.md.

Usage:
    $ actp pull
    $ actp pull --force
    $ actp pull --network base-sepolia --address 0x...
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
)
from agirails.config.on_chain_state import OnChainConfigState, OnChainStateError, ZERO_HASH, get_on_chain_config_state
from agirails.config.sync_operations import pull_config


def pull(
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite local file without confirmation"
    ),
    network: str = typer.Option(
        "base-mainnet",
        "--network",
        "-n",
        help="Network to pull from (base-sepolia, base-mainnet)",
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address",
        "-a",
        help="Agent address (default: from keystore)",
    ),
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        "-p",
        help="Path to AGIRAILS.md (default: ./AGIRAILS.md)",
    ),
    rpc_url: Optional[str] = typer.Option(
        None,
        "--rpc-url",
        help="Custom RPC URL",
    ),
) -> None:
    """Pull on-chain config to local AGIRAILS.md."""
    opts = get_global_options()
    md_path = str(path or Path(opts.directory or Path.cwd()) / "AGIRAILS.md")

    # Resolve agent address
    agent_address = address
    if not agent_address:
        agent_address = os.environ.get("ACTP_ADDRESS")
    if not agent_address:
        try:
            import asyncio
            from agirails.wallet.keystore import resolve_private_key, ResolvePrivateKeyOptions

            result = asyncio.run(
                resolve_private_key(options=ResolvePrivateKeyOptions(network=network))
            )
            if result:
                from eth_account import Account

                agent_address = Account.from_key(result).address
        except Exception:
            pass

    if not agent_address:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "No agent address. Use --address or set ACTP_ADDRESS."})
        else:
            print_error(
                "No agent address",
                "Use --address, set ACTP_ADDRESS, or configure a keystore.",
            )
        raise typer.Exit(1)

    # Read on-chain state
    try:
        on_chain = get_on_chain_config_state(agent_address, network, rpc_url)
    except OnChainStateError as e:
        print_error("On-chain read failed", str(e))
        raise typer.Exit(1)

    # Confirm overwrite if not forcing and local file exists
    if not force and Path(md_path).exists() and on_chain.has_config:
        if opts.output_format != OutputFormat.JSON:
            confirm = typer.confirm(
                "This will overwrite your local AGIRAILS.md. Continue?"
            )
            if not confirm:
                print_info("Aborted.")
                raise typer.Exit(0)

    # Pull
    try:
        result = pull_config(md_path, on_chain, force=force)
    except RuntimeError as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Pull failed", str(e))
        raise typer.Exit(1)

    # Output
    if opts.output_format == OutputFormat.JSON:
        print_json(
            {
                "written": result.written,
                "cid": result.cid,
                "status": result.status,
                "path": md_path,
                "network": network,
                "address": agent_address,
            }
        )
    elif opts.output_format == OutputFormat.QUIET:
        typer.echo("written" if result.written else "skipped")
    else:
        if result.written:
            print_success(
                "Config pulled successfully",
                {
                    "CID": result.cid,
                    "Path": md_path,
                },
            )
        else:
            print_info(result.status)
