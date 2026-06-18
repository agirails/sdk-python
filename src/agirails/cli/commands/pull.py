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
from agirails.cli.utils.client import load_config
from agirails.cli.utils.identity import resolve_identity_path
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


def _emit_buyer_local(output_format: OutputFormat) -> None:
    """Emit the honest local-sovereign buyer-local result. Mirrors TS pull.ts:92-107."""
    if output_format == OutputFormat.JSON:
        print_json(
            {
                "written": False,
                "status": "buyer-local",
                "intent": "pay",
                "note": (
                    "Buyer config is local-authored; nothing to pull "
                    "(budget stays private)."
                ),
            }
        )
        return
    if output_format == OutputFormat.QUIET:
        typer.echo("buyer-local")
        return
    print_success("Status: buyer-local")
    print_info(
        "Buyer (intent: pay): config is local-authored and budget is private — "
        "nothing to pull."
    )
    print_info(
        "Edit your {slug}.md locally, then run: actp publish to push the public fields."
    )


def pull(
    path_arg: Optional[str] = typer.Argument(
        None,
        metavar="[PATH]",
        help="Path to write config (default: ./AGIRAILS.md)",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite local file without confirmation"
    ),
    network: str = typer.Option(
        "base-sepolia",
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
        help="Path to AGIRAILS.md (overrides positional PATH; back-compat)",
    ),
    rpc_url: Optional[str] = typer.Option(
        None,
        "--rpc-url",
        help="Custom RPC URL",
    ),
) -> None:
    """Pull on-chain config to local AGIRAILS.md."""
    opts = get_global_options()
    # TS takes the path as a positional [path] argument (default ./AGIRAILS.md).
    # We accept both the positional PATH and the legacy `--path` option for
    # backward compatibility; `--path` wins when supplied.
    chosen_path = path or path_arg
    md_path = str(chosen_path or Path(opts.directory or Path.cwd()) / "AGIRAILS.md")

    # AIP-18 DEC-3: a pure buyer (intent: pay) is local-authored and never
    # anchored on-chain — there is nothing on-chain to pull, and its budget is
    # private (never synced). Report that honestly instead of "No config
    # published on-chain". Mirrors TS pull.ts:77-112.
    try:
        identity_path: Optional[str] = str(chosen_path) if chosen_path else None
        if identity_path is None:
            resolved = resolve_identity_path(
                str(opts.directory) if opts.directory else None
            )
            if resolved:
                identity_path = resolved
        if identity_path and Path(identity_path).exists():
            from agirails.config.agirailsmd import parse_agirails_md_v4

            with open(identity_path, "r", encoding="utf-8") as f:
                v4 = parse_agirails_md_v4(f.read())
            if v4.intent == "pay":
                _emit_buyer_local(opts.output_format)
                return
    except Exception:
        # Not a parseable v4 buyer file — fall through to the normal on-chain pull.
        pass

    # Resolve agent address.
    #
    # Resolution order: --address > ACTP_ADDRESS > config.address (Smart Wallet
    # for wallet:auto) > keystore EOA. Mirrors TS pull.ts:114-152.
    agent_address = address
    if not agent_address:
        agent_address = os.environ.get("ACTP_ADDRESS")
    if not agent_address:
        # config.address (Smart Wallet for wallet:auto) before EOA fallback.
        try:
            cfg = load_config(opts.directory)
            if cfg.get("address"):
                agent_address = cfg["address"]
        except Exception:
            pass
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
