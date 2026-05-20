"""``actp repair`` — reshape an on-chain agent without redeploying.

Common uses:

  - Drop a phantom service registered by an earlier misshape (e.g. a
    pay-only agent registered as a ``code-review`` provider before the
    intent-aware publish flow existed).
  - Update the on-chain endpoint to a real HTTPS URL after wiring a
    webhook for x402 / off-protocol intake.
  - Toggle ``isActive`` / ``listed`` flags to hide from public
    discovery without forfeiting reputation.

Wraps existing ``AgentRegistry`` SDK methods. This CLI is the user-
facing surface that explains what's about to change and asks for
confirmation before sending the on-chain transactions.

Destructive ops that forfeit reputation (``deregisterAgent``) are
intentionally NOT exposed here — they live behind a separate command
with bigger guards.

Python port of ``sdk-js/src/cli/commands/repair.ts``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List, Optional, Tuple

import typer

from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_json,
    print_success,
)
from agirails.config.networks import get_network
from agirails.protocol.agent_registry import AgentRegistry
from agirails.wallet.keystore import ResolvePrivateKeyOptions, resolve_private_key


# ============================================================================
# Helpers
# ============================================================================


def _parse_bool(value: str, flag: str) -> bool:
    v = value.lower().strip()
    if v in ("true", "1", "yes", "y"):
        return True
    if v in ("false", "0", "no", "n"):
        return False
    raise typer.BadParameter(f"{flag} must be true|false (got: {value})")


def _network_to_tier(network: str) -> str:
    if "mainnet" in network:
        return "mainnet"
    if "sepolia" in network:
        return "testnet"
    return "mock"


def _confirm(yes: bool, json_output: bool) -> bool:
    if yes:
        return True
    # Non-interactive contexts must use --yes explicitly. We hard-fail
    # in JSON / non-TTY mode rather than block on stdin.
    if json_output or not sys.stdin.isatty():
        raise typer.Exit(_die_non_tty())
    answer = input("? Send these on-chain transactions? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def _die_non_tty() -> int:
    print_error(
        "Non-TTY environment requires explicit confirmation. Re-run with "
        "--yes to acknowledge."
    )
    return 2


# ============================================================================
# Command
# ============================================================================


def repair(
    remove_service: Optional[str] = typer.Option(
        None,
        "--remove-service",
        help="Remove a service type from your on-chain provider role.",
    ),
    endpoint: Optional[str] = typer.Option(
        None,
        "--endpoint",
        help="Update on-chain endpoint URL (must be HTTPS).",
    ),
    active: Optional[str] = typer.Option(
        None, "--active", help="Set on-chain isActive (true|false)."
    ),
    listed: Optional[str] = typer.Option(
        None,
        "--listed",
        help="Set on-chain listed flag (true|false).",
    ),
    network: str = typer.Option(
        "base-sepolia",
        "--network",
        help="Network to repair on (base-sepolia | base-mainnet | mock).",
    ),
    yes: bool = typer.Option(
        False,
        "-y",
        "--yes",
        help="Skip confirmation prompts (required for non-TTY).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
) -> None:
    """Reshape on-chain agent (drop phantom services, update endpoint, toggle flags)."""
    try:
        asyncio.run(
            _run(
                remove_service=remove_service,
                endpoint=endpoint,
                active=active,
                listed=listed,
                network=network,
                yes=yes,
                json_output=json_output,
            )
        )
    except typer.Exit:
        raise
    except Exception as exc:
        if json_output:
            print_json({"ok": False, "error": str(exc)})
        else:
            print_error(f"repair failed: {exc}")
        raise typer.Exit(code=1)


async def _run(
    *,
    remove_service: Optional[str],
    endpoint: Optional[str],
    active: Optional[str],
    listed: Optional[str],
    network: str,
    yes: bool,
    json_output: bool,
) -> None:
    # 1. At least one repair action must be specified.
    actions: List[str] = []
    if remove_service:
        actions.append(f"remove-service {remove_service}")
    if endpoint is not None:
        actions.append(f"endpoint → {endpoint}")
    if active is not None:
        actions.append(f"active → {active}")
    if listed is not None:
        actions.append(f"listed → {listed}")

    if not actions:
        raise typer.BadParameter(
            "No repair action specified. Use one of: --remove-service, "
            "--endpoint, --active, --listed"
        )

    # 2. Validate inputs BEFORE touching the network.
    if endpoint is not None and not endpoint.startswith("https://"):
        raise typer.BadParameter(
            f"--endpoint must be HTTPS (got: {endpoint})"
        )
    active_bool = _parse_bool(active, "--active") if active is not None else None
    listed_bool = _parse_bool(listed, "--listed") if listed is not None else None

    # 3. Resolve signer.
    tier = _network_to_tier(network)
    private_key = await resolve_private_key(
        options=ResolvePrivateKeyOptions(network=tier)
    )
    if not private_key:
        raise RuntimeError(
            "No wallet found. Set ACTP_KEYSTORE_BASE64 / ACTP_PRIVATE_KEY "
            "or run `actp init` first."
        )

    cfg = get_network(network)
    if not cfg.contracts.agent_registry:
        raise RuntimeError(
            f"AgentRegistry not configured for network: {network}"
        )

    registry = await AgentRegistry.create(
        private_key=private_key, network=cfg
    )
    signer_address = registry._account.address  # noqa: SLF001 — narrow OK

    # 4. Confirm.
    if not json_output:
        print_info(f"About to repair on-chain agent for wallet: {signer_address}")
        print_info(f"  Network: {network}")
        print_info("  Actions:")
        for a in actions:
            print_info(f"    - {a}")

    if not _confirm(yes, json_output=json_output):
        if json_output:
            print_json({"ok": False, "error": "cancelled"})
        else:
            print_info("Cancelled — no on-chain transactions sent.")
        raise typer.Exit(code=0)

    # 5. Sequential execution. If one fails, the earlier txs already
    # landed; user can retry the rest by re-running with only the
    # remaining flags.
    tx_hashes: List[Tuple[str, str]] = []  # (action, tx_hash)

    if remove_service:
        if not json_output:
            print_info("")
            print_info(f'Removing service "{remove_service}"')
        receipt = await registry.remove_service_type(remove_service)
        tx_hashes.append((f"remove-service:{remove_service}", receipt.transaction_hash))
        if not json_output:
            print_success(f"Removed. tx: {receipt.transaction_hash}")

    if endpoint is not None:
        if not json_output:
            print_info("")
            print_info(f"Updating endpoint → {endpoint}")
        receipt = await registry.update_endpoint(endpoint)
        tx_hashes.append(("update-endpoint", receipt.transaction_hash))
        if not json_output:
            print_success(f"Updated. tx: {receipt.transaction_hash}")

    if active_bool is not None:
        if not json_output:
            print_info("")
            print_info(f"Setting active → {active_bool}")
        receipt = await registry.set_active_status(active_bool)
        tx_hashes.append((f"set-active:{active_bool}", receipt.transaction_hash))
        if not json_output:
            print_success(f"Set. tx: {receipt.transaction_hash}")

    if listed_bool is not None:
        if not json_output:
            print_info("")
            print_info(f"Setting listed → {listed_bool}")
        receipt = await registry.set_listed(listed_bool)
        tx_hashes.append((f"set-listed:{listed_bool}", receipt.transaction_hash))
        if not json_output:
            print_success(f"Set. tx: {receipt.transaction_hash}")

    # 6. Summary.
    if json_output:
        print_json(
            {
                "ok": True,
                "wallet": signer_address,
                "network": network,
                "txHashes": [
                    {"action": a, "txHash": h} for (a, h) in tx_hashes
                ],
            }
        )
    else:
        print_info("")
        print_success(f"Repair complete ({len(tx_hashes)} tx).")
