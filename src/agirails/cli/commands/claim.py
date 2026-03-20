"""Claim Command - Claim ownership of an agent on agirails.app.

Usage:
    $ actp claim <agent_id>
    $ actp claim <agent_id> --json
    $ actp claim <agent_id> -q
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_json,
    print_success,
)


def claim(
    agent_id: Optional[str] = typer.Argument(
        None,
        help="Agent ID to claim (uint256 from AgentRegistry)",
    ),
    all_agents: bool = typer.Option(
        False, "--all", help="Claim all agents owned by this wallet (not yet implemented)"
    ),
    network: str = typer.Option(
        "base-mainnet",
        "--network",
        "-n",
        help="Network (base-sepolia, base-mainnet)",
    ),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Minimal output"),
) -> None:
    """Claim ownership of an agent registered on-chain."""
    opts = get_global_options()
    if json_output:
        opts.json_output = True
    if quiet:
        opts.quiet = True

    # Guard: --all not yet implemented
    if all_agents:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "--all flag is not yet implemented"})
        else:
            print_error("--all flag is not yet implemented", "Specify an agent_id instead.")
        raise typer.Exit(1)

    # Guard: no agent_id
    if not agent_id:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "agent_id is required"})
        else:
            print_error(
                "agent_id is required",
                "Usage: actp claim <agent_id>\n"
                "  Your agent_id = uint256(uint160(walletAddress))\n"
                "  Find it in your AGIRAILS.md frontmatter or on-chain.",
            )
        raise typer.Exit(1)

    # Resolve private key
    try:
        from agirails.wallet.keystore import ResolvePrivateKeyOptions, resolve_private_key

        private_key = asyncio.run(
            resolve_private_key(options=ResolvePrivateKeyOptions(network=network))
        )
    except Exception as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Failed to resolve private key: {e}"})
        else:
            print_error("Failed to resolve private key", str(e))
        raise typer.Exit(1)

    if not private_key:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "No private key found"})
        else:
            print_error(
                "No private key found",
                "Set ACTP_PRIVATE_KEY, ACTP_KEYSTORE_BASE64, or create .actp/keystore.json",
            )
        raise typer.Exit(1)

    # Derive wallet address
    from eth_account import Account
    from eth_account.messages import encode_defunct

    acct = Account.from_key(private_key)
    wallet_address = acct.address

    # Get challenge
    try:
        from agirails.api.agirails_app import ClaimAgentParams, claim_agent, get_claim_challenge

        challenge_resp = asyncio.run(get_claim_challenge(wallet_address))
        challenge = challenge_resp.get("challenge")
        if not challenge:
            raise ValueError("No challenge returned from server")
    except Exception as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Failed to get challenge: {e}"})
        else:
            print_error("Failed to get challenge", str(e))
        raise typer.Exit(1)

    # Sign challenge (EIP-191)
    sig = acct.sign_message(encode_defunct(text=challenge))
    signature = sig.signature.hex()
    if not signature.startswith("0x"):
        signature = f"0x{signature}"

    # Claim
    try:
        result = asyncio.run(
            claim_agent(
                ClaimAgentParams(
                    agent_id=agent_id,
                    wallet=wallet_address,
                    challenge=challenge,
                    signature=signature,
                )
            )
        )
    except Exception as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"Claim failed: {e}"})
        else:
            print_error("Claim failed", str(e))
        raise typer.Exit(1)

    # Output
    slug = result.get("slug", "")
    profile_url = f"https://agirails.app/a/{slug}" if slug else ""

    if opts.output_format == OutputFormat.JSON:
        print_json({
            "status": "claimed",
            "agentId": agent_id,
            "wallet": wallet_address,
            "profileUrl": profile_url,
        })
    elif opts.output_format == OutputFormat.QUIET:
        typer.echo(agent_id)
    else:
        print_success(
            "Agent claimed",
            {
                "Agent ID": agent_id,
                "Wallet": wallet_address,
                **({"Profile": profile_url} if profile_url else {}),
            },
        )
