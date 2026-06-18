"""``actp agent`` — public-RPC warning surface for the provider daemon.

The full channel-driven provider daemon (ProviderOrchestrator + RelayChannel +
on-chain INITIATED-tx watch loop) lives in the negotiation subsystem and is
ported separately. This module owns the AIP / 3.5.0 **public-RPC warning** that
TS emits before starting that 24/7 on-chain listener (cli/commands/agent.ts:
149-159):

A 24/7 on-chain listener needs a real RPC. Public endpoints serve one-shot
transactions fine but cap ``eth_getLogs`` (~2000 blocks) and drop long-lived
filters, so the watch loop may silently miss jobs. We warn once, clearly.

``emit_public_rpc_warning`` is the reusable seam: ``actp agent`` (and any future
on-chain watcher such as ``actp serve`` if it gains one) calls it after the
listener banner so the operator gets a single, actionable diagnostic.

@module cli/commands/agent
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from agirails.cli.utils.output import print_info, print_success, print_warning
from agirails.config.networks import using_public_rpc


def emit_public_rpc_warning(
    network: str,
    *,
    mock: bool = False,
    rpc_override: Optional[str] = None,
) -> bool:
    """Warn once when a 24/7 on-chain listener runs on a public RPC.

    Mirrors TS agent.ts:152-159. No-op for mock mode, an explicit ``--rpc``
    override, or when a ``BASE_SEPOLIA_RPC`` / ``BASE_MAINNET_RPC`` env var is
    set (``using_public_rpc`` returns False).

    Args:
        network: Network name (base-sepolia | base-mainnet | mock).
        mock: True if running against MockRuntime (never warns).
        rpc_override: Explicit ``--rpc`` URL override (suppresses the warning).

    Returns:
        True if the warning was emitted, False otherwise.
    """
    if mock or rpc_override or not using_public_rpc(network):
        return False

    rpc_env = "BASE_MAINNET_RPC" if "mainnet" in network else "BASE_SEPOLIA_RPC"
    print_warning(f"⚠ Public RPC in use — no {rpc_env} (or --rpc) set.")
    print_warning("  One-shot transactions work, but this 24/7 listener may MISS jobs:")
    print_warning("  public RPCs cap eth_getLogs (~2000 blocks) and drop long-lived filters.")
    print_warning(f"  Fix: set {rpc_env}=<your endpoint> (Alchemy/Infura/QuickNode free tier).")
    return True


def agent(
    policy: Path = typer.Option(
        ...,
        "--policy",
        help="Path to ProviderPolicy JSON file.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    network: str = typer.Option(
        "base-sepolia",
        "--network",
        help="Network — base-sepolia | base-mainnet | mock.",
    ),
    rpc: Optional[str] = typer.Option(
        None,
        "--rpc",
        help="Custom RPC URL override (testnet/mainnet only).",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        help="Run with MockRuntime instead of BlockchainRuntime.",
    ),
) -> None:
    """Run a long-running provider daemon (channel-driven, no HTTP).

    The orchestrator/channel watch loop is ported in the negotiation subsystem;
    this entrypoint establishes the network context and emits the public-RPC
    diagnostic that TS prints before the 24/7 on-chain listener starts.
    """
    is_mock = mock or network == "mock"
    print_success(f"actp agent — network: {network}{' (mock)' if is_mock else ''}")
    print_info(f"  Policy: {policy}")

    # Warn before the listener would start, exactly where TS does.
    emit_public_rpc_warning(network, mock=is_mock, rpc_override=rpc)

    print_info(
        "Channel-driven provider daemon (ProviderOrchestrator + RelayChannel) "
        "is provided by the negotiation subsystem."
    )
