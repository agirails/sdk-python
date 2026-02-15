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
from agirails.config.sync_operations import (
    DiffStatus,
    OnChainConfigReader,
    ZERO_HASH,
    diff_config,
)


def _get_on_chain_reader(
    address: str,
    network: str,
    rpc_url: Optional[str] = None,
) -> OnChainConfigReader:
    """Read on-chain config hash and CID for an agent.

    Args:
        address: Agent Ethereum address.
        network: Network name.
        rpc_url: Optional custom RPC URL.

    Returns:
        OnChainConfigReader with hash and CID.
    """
    try:
        from agirails.config.networks import get_network

        net_config = get_network(network)
        if not net_config.contracts.agent_registry:
            return OnChainConfigReader(config_hash=ZERO_HASH, config_cid="")

        # Use a simple web3 call to read configHash and configCID
        # For now, return zero if web3 isn't available
        try:
            from web3 import Web3

            rpc = rpc_url or net_config.rpc_url
            w3 = Web3(Web3.HTTPProvider(rpc))

            # Minimal ABI for reading config
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
    on_chain = _get_on_chain_reader(agent_address, network, rpc_url)

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
