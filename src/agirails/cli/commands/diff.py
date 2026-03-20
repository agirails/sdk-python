"""Diff Command - Compare local AGIRAILS.md with on-chain state.

Usage:
    $ actp diff
    $ actp diff --network base-sepolia
    $ actp diff --address 0x...
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
from agirails.config.sync_operations import (
    DiffStatus,
    diff_config,
)


_STATUS_LABELS = {
    DiffStatus.IN_SYNC: "In sync",
    DiffStatus.LOCAL_AHEAD: "Local ahead (unpublished changes)",
    DiffStatus.REMOTE_AHEAD: "Remote ahead (on-chain is newer)",
    DiffStatus.DIVERGED: "Diverged (both sides have changes)",
    DiffStatus.NO_LOCAL: "No local file, no on-chain config",
    DiffStatus.NO_REMOTE: "Local only (not yet published on-chain)",
}


def diff(
    network: str = typer.Option(
        "base-mainnet",
        "--network",
        "-n",
        help="Network to check (base-sepolia, base-mainnet)",
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address",
        "-a",
        help="Agent address to check on-chain (default: from keystore)",
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
    """Compare local AGIRAILS.md with on-chain config state."""
    opts = get_global_options()
    md_path = str(path or Path(opts.directory or Path.cwd()) / "AGIRAILS.md")

    # Resolve agent address
    agent_address = address
    if not agent_address:
        agent_address = os.environ.get("ACTP_ADDRESS")
    if not agent_address:
        # Try to resolve from keystore
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

    # Run diff
    result = diff_config(md_path, on_chain)

    # Output
    if opts.output_format == OutputFormat.JSON:
        print_json(
            {
                "status": result.status.value,
                "inSync": result.in_sync,
                "localHash": result.local_hash,
                "onChainHash": result.on_chain_hash,
                "onChainCID": result.on_chain_cid,
                "hasLocalFile": result.has_local_file,
                "hasOnChainConfig": result.has_on_chain_config,
                "network": network,
                "address": agent_address,
            }
        )
    elif opts.output_format == OutputFormat.QUIET:
        typer.echo(result.status.value)
    else:
        label = _STATUS_LABELS.get(result.status, result.status.value)
        if result.in_sync:
            print_success(f"Status: {label}")
        else:
            print_warning(f"Status: {label}")

        print_info(f"Network:       {network}")
        print_info(f"Agent:         {agent_address}")
        if result.local_hash:
            print_info(f"Local hash:    {result.local_hash}")
        if result.on_chain_hash != ZERO_HASH:
            print_info(f"On-chain hash: {result.on_chain_hash}")
        if result.on_chain_cid:
            print_info(f"On-chain CID:  {result.on_chain_cid}")
