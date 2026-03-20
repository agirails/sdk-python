"""
ACTP Register Command (DEPRECATED).

Use `actp publish` instead. This command is kept for backward compatibility
and requires --force-legacy to execute.

Usage:
    $ actp register                        # Shows deprecation warning, exits 0
    $ actp register --force-legacy         # Actually registers (legacy flow)
    $ actp register --force-legacy --json  # JSON output
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_warning,
    print_json,
    print_success,
)


def register(
    endpoint: Optional[str] = typer.Option(
        None, "--endpoint", help="Service endpoint URL"
    ),
    force_legacy: bool = typer.Option(
        False, "--force-legacy", help="Force legacy registration flow"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Minimal output"),
    network: str = typer.Option(
        "base-sepolia", "--network", "-n", help="Network to register on"
    ),
) -> None:
    """Register agent on-chain (DEPRECATED - use `actp publish` instead)."""
    global_opts = get_global_options()
    if json_output or global_opts.json_output:
        output_format = OutputFormat.JSON
    elif quiet or global_opts.quiet:
        output_format = OutputFormat.QUIET
    else:
        output_format = OutputFormat.PRETTY

    # Show deprecation warning (skip for JSON to keep stdout parseable)
    if output_format != OutputFormat.JSON:
        print_warning(
            "actp register is deprecated. Use `actp publish` instead."
        )

    if not force_legacy:
        if output_format == OutputFormat.JSON:
            typer.echo(
                '{"deprecated": true, "message": "Use actp publish instead"}'
            )
        raise typer.Exit(0)

    # Force-legacy flow
    try:
        asyncio.run(_register_legacy(endpoint, output_format, network))
    except Exception as e:
        print_error(f"Registration failed: {e}")
        raise typer.Exit(1)


async def _register_legacy(
    endpoint: Optional[str],
    output_format: OutputFormat,
    network: str,
) -> None:
    """Execute legacy registration flow."""
    from pathlib import Path

    from agirails.wallet.keystore import (
        resolve_private_key,
        ResolvePrivateKeyOptions,
    )
    from agirails.config.agirailsmd import parse_agirails_md
    from agirails.config.publish_pipeline import extract_registration_params
    from agirails.config.networks import get_network

    # Resolve private key
    private_key = await resolve_private_key(
        options=ResolvePrivateKeyOptions(network=network)
    )
    if not private_key:
        print_error("No private key found. Set ACTP_PRIVATE_KEY or use a keystore.")
        raise typer.Exit(1)

    # Parse AGIRAILS.md if available
    agirails_md_path = Path.cwd() / "AGIRAILS.md"
    registration_endpoint = endpoint
    service_descriptors = []

    if agirails_md_path.exists():
        content = agirails_md_path.read_text()
        config = parse_agirails_md(content)
        fm = config.frontmatter

        if not registration_endpoint:
            registration_endpoint = fm.get("endpoint", "")

        ep, descriptors = extract_registration_params(fm)
        if not registration_endpoint:
            registration_endpoint = ep
        service_descriptors = descriptors

    if not registration_endpoint:
        registration_endpoint = ""

    # Get network config
    net_config = get_network(network)
    if not net_config.aa:
        print_error(f"Network {network} does not support Account Abstraction")
        raise typer.Exit(1)

    agent_registry = net_config.contracts.agent_registry
    if not agent_registry:
        print_error(f"Network {network} has no AgentRegistry deployed")
        raise typer.Exit(1)

    # Build and submit registration
    from web3 import Web3
    from agirails.wallet.auto_wallet_provider import (
        AutoWalletProvider,
        AutoWalletConfig,
    )
    from agirails.wallet.aa.transaction_batcher import (
        build_register_agent_batch,
        build_testnet_mint_batch,
        ServiceDescriptor,
    )

    rpc_url = net_config.rpc_url
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    wallet_config = AutoWalletConfig(
        private_key=private_key,
        w3=w3,
        chain_id=net_config.chain_id,
        actp_kernel_address=net_config.contracts.actp_kernel,
        bundler_primary_url=net_config.aa.bundler_urls.get("primary", ""),
        bundler_backup_url=net_config.aa.bundler_urls.get("backup"),
        paymaster_primary_url=net_config.aa.paymaster_urls.get("primary", ""),
        paymaster_backup_url=net_config.aa.paymaster_urls.get("backup"),
    )

    wallet = await AutoWalletProvider.create(wallet_config)
    smart_wallet_address = wallet.get_address()

    # Build batch calls
    descriptors_for_batch = [
        ServiceDescriptor(
            service_type_hash=d.service_type_hash,
            service_type=d.service_type,
            schema_uri=d.schema_uri,
            min_price=d.min_price,
            max_price=d.max_price,
            avg_completion_time=d.avg_completion_time,
            metadata_cid=d.metadata_cid,
        )
        for d in service_descriptors
    ]

    batch_calls = build_register_agent_batch(
        agent_registry_address=agent_registry,
        endpoint=registration_endpoint,
        service_descriptors=descriptors_for_batch,
    )

    # On testnet, also mint test USDC
    minted_usdc = False
    if "sepolia" in network:
        mint_calls = build_testnet_mint_batch(
            mock_usdc_address=net_config.contracts.usdc,
            recipient=smart_wallet_address,
            amount=100_000_000,  # $100 USDC
        )
        batch_calls = batch_calls + mint_calls
        minted_usdc = True

    # Submit
    receipt = await wallet.send_batch_transaction(
        [
            type("TX", (), {"to": c.target, "data": c.call_data, "value": "0"})()
            for c in batch_calls
        ]
    )

    result = {
        "registered": receipt.success,
        "smartWallet": smart_wallet_address,
        "services": len(service_descriptors),
        "txHash": receipt.hash,
        "mintedUSDC": minted_usdc,
    }

    if output_format == OutputFormat.JSON:
        print_json(result)
    elif output_format == OutputFormat.QUIET:
        typer.echo(receipt.hash)
    else:
        print_success(
            "Agent registered on-chain",
            {
                "Smart Wallet": smart_wallet_address,
                "Services": str(len(service_descriptors)),
                "TX Hash": receipt.hash,
                "Minted USDC": str(minted_usdc),
            },
        )
