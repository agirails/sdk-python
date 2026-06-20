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


def _emit_buyer_local(output_format: OutputFormat) -> None:
    """Emit the honest local-sovereign buyer-local result. Mirrors TS diff.ts:86-103."""
    if output_format == OutputFormat.JSON:
        print_json(
            {
                "status": "buyer-local",
                "intent": "pay",
                "inSync": True,
                "hasLocalFile": True,
                "hasOnChainConfig": False,
                "note": (
                    "Buyer config is local-authored; not anchored on-chain "
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
        "nothing to diff on-chain."
    )
    print_info(
        "Edit your {slug}.md locally, then run: actp publish (re-links to agirails.app)."
    )


def diff(
    path_arg: Optional[str] = typer.Argument(
        None,
        metavar="[PATH]",
        help="Path to AGIRAILS.md (default: ./AGIRAILS.md)",
    ),
    network: str = typer.Option(
        "base-sepolia",
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
        help="Path to AGIRAILS.md (overrides positional PATH; back-compat)",
    ),
    rpc_url: Optional[str] = typer.Option(
        None,
        "--rpc-url",
        help="Custom RPC URL",
    ),
) -> None:
    """Compare local AGIRAILS.md with on-chain config state."""
    opts = get_global_options()
    # TS takes the path as a positional [path] argument (default ./AGIRAILS.md).
    # We accept both the positional PATH and the legacy `--path` option for
    # backward compatibility; `--path` wins when supplied.
    chosen_path = path or path_arg

    # When the user gave no explicit path (Commander default './AGIRAILS.md'),
    # check the identity pointer first so a {slug}.md buyer/provider file is
    # found instead of defaulting to AGIRAILS.md. Mirrors TS diff.ts:65-74.
    if chosen_path is None:
        identity_path = resolve_identity_path(
            str(opts.directory) if opts.directory else None
        )
        if identity_path:
            md_path = identity_path
        else:
            md_path = str(Path(opts.directory or Path.cwd()) / "AGIRAILS.md")
    else:
        md_path = str(chosen_path)

    # AIP-18 DEC-3: a pure buyer (intent: pay) is never anchored on-chain — its
    # config is local-authored and its budget is private (never synced). An
    # on-chain diff doesn't apply, so report that honestly instead of the
    # misleading "no-remote / run publish". Mirrors TS diff.ts:76-108.
    try:
        if Path(md_path).exists():
            from agirails.config.agirailsmd import parse_agirails_md_v4

            with open(md_path, "r", encoding="utf-8") as f:
                v4 = parse_agirails_md_v4(f.read())
            if v4.intent == "pay":
                _emit_buyer_local(opts.output_format)
                return
    except Exception:
        # Not a parseable v4 buyer file — fall through to the normal on-chain diff.
        pass

    # Resolve agent address.
    #
    # Resolution order (matches `actp pull`):
    #   1. --address flag (explicit override)
    #   2. ACTP_ADDRESS env var
    #   3. config.address from .actp/config.json — for `wallet: 'auto'` this is
    #      the Smart Wallet address, which is the identity AgentRegistry has
    #      indexed (publish runs through Paymaster as msg.sender = Smart Wallet).
    #      Reading the on-chain hash for the EOA signer in that flow returns 0x0
    #      and surfaces a false "Pending chain sync" alarm. Mirrors TS
    #      diff.ts:122-131.
    #   4. EOA derived from the resolved private key (legacy single-wallet flow).
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
        # Try to resolve from keystore (EOA)
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
