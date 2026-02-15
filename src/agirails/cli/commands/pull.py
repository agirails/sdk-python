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
from agirails.config.sync_operations import (
    OnChainConfigReader,
    ZERO_HASH,
    pull_config,
)


def _get_on_chain_reader(
    address: str,
    network: str,
    rpc_url: Optional[str] = None,
) -> OnChainConfigReader:
    """Read on-chain config hash and CID for an agent."""
    try:
        from agirails.config.networks import get_network

        net_config = get_network(network)
        if not net_config.contracts.agent_registry:
            return OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")

        try:
            from web3 import Web3

            rpc = rpc_url or net_config.rpc_url
            w3 = Web3(Web3.HTTPProvider(rpc))

            abi = [
                {
                    "type": "function",
                    "name": "getConfigHash",
                    "inputs": [{"name": "agentAddress", "type": "address"}],
                    "outputs": [{"name": "", "type": "bytes32"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "getConfigCID",
                    "inputs": [{"name": "agentAddress", "type": "address"}],
                    "outputs": [{"name": "", "type": "string"}],
                    "stateMutability": "view",
                },
            ]

            contract = w3.eth.contract(
                address=w3.to_checksum_address(net_config.contracts.agent_registry),
                abi=abi,
            )

            config_hash_bytes = contract.functions.getConfigHash(
                w3.to_checksum_address(address)
            ).call()
            config_hash = "0x" + config_hash_bytes.hex()

            config_cid = contract.functions.getConfigCID(
                w3.to_checksum_address(address)
            ).call()

            return OnChainConfigReader(config_hash=config_hash, config_cid=config_cid)

        except ImportError:
            return OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")
        except Exception:
            return OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")

    except Exception:
        return OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")


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
    on_chain = _get_on_chain_reader(agent_address, network, rpc_url)

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
