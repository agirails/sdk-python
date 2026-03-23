"""
Negotiate Command — Autonomous buyer-side negotiation.

Discovers agents, scores them, validates against buyer policy,
and optionally executes the full negotiation flow.

1:1 parity with TypeScript SDK's `actp negotiate` command.

Usage:
    $ actp negotiate --policy buyer-policy.json
    $ actp negotiate --policy buyer-policy.json --dry-run
    $ actp negotiate --policy buyer-policy.json --poll-interval 5000
    $ actp negotiate --policy buyer-policy.json --json
    $ actp negotiate --policy buyer-policy.json -q
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_info,
    print_json,
    print_success,
)


# ============================================================================
# Helpers
# ============================================================================


def _error(fmt: OutputFormat, message: str) -> None:
    """Print error in the appropriate format."""
    if fmt == OutputFormat.JSON:
        print_json({"error": message})
    else:
        print_error(message)


def _parse_ttl(ttl: str) -> int:
    """Parse a TTL string. Delegates to PolicyEngine.parse_ttl for single source of truth."""
    from agirails.negotiation.policy_engine import PolicyEngine
    return PolicyEngine.parse_ttl(ttl)


# ============================================================================
# Command
# ============================================================================


def negotiate(
    policy_path: str = typer.Option(
        ...,
        "--policy",
        help="Path to buyer policy JSON file",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Score candidates without creating transactions",
    ),
    poll_interval: str = typer.Option(
        "3000",
        "--poll-interval",
        help="Poll interval for quote state (ms)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
    quiet: bool = typer.Option(
        False,
        "-q",
        "--quiet",
        help="Minimal output",
    ),
) -> None:
    """Run autonomous buyer-side negotiation."""
    opts = get_global_options()

    # Determine output format (command-level flags override global)
    if json_output:
        fmt = OutputFormat.JSON
    elif quiet:
        fmt = OutputFormat.QUIET
    else:
        fmt = opts.output_format

    # --- Load policy ---
    try:
        raw = Path(policy_path).read_text(encoding="utf-8")
        policy_dict: Dict[str, Any] = json.loads(raw)
    except (OSError, json.JSONDecodeError) as err:
        _error(fmt, f"Failed to load policy: {err}")
        raise typer.Exit(1)

    # --- Validate required policy fields (structure + types + ranges) ---
    errors: list[str] = []

    if not policy_dict.get("task") or not isinstance(policy_dict.get("task"), str):
        errors.append("task must be a non-empty string")

    # constraints.max_unit_price.amount
    constraints = policy_dict.get("constraints") or {}
    max_unit_price = constraints.get("max_unit_price") or {}
    mup_amount = max_unit_price.get("amount")
    if (
        not isinstance(mup_amount, (int, float))
        or not math.isfinite(mup_amount)
        or mup_amount <= 0
    ):
        errors.append(
            "constraints.max_unit_price.amount must be a finite positive number"
        )

    # constraints.max_daily_spend.amount
    max_daily_spend = constraints.get("max_daily_spend") or {}
    mds_amount = max_daily_spend.get("amount")
    if (
        not isinstance(mds_amount, (int, float))
        or not math.isfinite(mds_amount)
        or mds_amount <= 0
    ):
        errors.append(
            "constraints.max_daily_spend.amount must be a finite positive number"
        )

    # negotiation.rounds_max
    negotiation = policy_dict.get("negotiation") or {}
    rounds_max = negotiation.get("rounds_max")
    if (
        isinstance(rounds_max, bool)
        or not isinstance(rounds_max, int)
        or rounds_max < 1
    ):
        errors.append("negotiation.rounds_max must be a positive integer")

    # negotiation.quote_ttl
    quote_ttl = negotiation.get("quote_ttl")
    if not quote_ttl or not isinstance(quote_ttl, str):
        errors.append('negotiation.quote_ttl must be a string (e.g. "15m", "2h")')
    else:
        try:
            _parse_ttl(quote_ttl)
        except ValueError:
            errors.append(
                f'negotiation.quote_ttl has invalid format: "{quote_ttl}" '
                '(expected e.g. "15m", "2h", "30s")'
            )

    # selection.prioritize
    selection = policy_dict.get("selection") or {}
    prioritize = selection.get("prioritize")
    if not isinstance(prioritize, list) or len(prioritize) == 0:
        errors.append("selection.prioritize must be a non-empty array")

    if errors:
        _error(fmt, f"Invalid policy: {'; '.join(errors)}")
        raise typer.Exit(1)

    # --- Validate poll interval ---
    if not re.match(r"^\d+$", poll_interval):
        _error(
            fmt,
            f'--poll-interval must be a whole number >= 100ms, got: "{poll_interval}"',
        )
        raise typer.Exit(1)

    poll_interval_ms = int(poll_interval)
    if poll_interval_ms < 100:
        _error(
            fmt,
            f'--poll-interval must be a whole number >= 100ms, got: "{poll_interval}"',
        )
        raise typer.Exit(1)

    # --- Run negotiation ---
    async def _negotiate() -> None:
        from agirails.cli.utils.client import get_client
        from agirails.negotiation.buyer_orchestrator import (
            BuyerOrchestrator,
            OrchestratorConfig,
            ProgressEvent,
        )
        from agirails.negotiation.policy_engine import (
            BuyerPolicy,
            Constraints,
            MaxDailySpend,
            MaxUnitPrice,
            Negotiation,
            Selection,
        )

        client = await get_client(
            mode=opts.mode,
            directory=opts.directory,
        )

        # Build BuyerPolicy dataclass from validated dict
        sel = policy_dict.get("selection") or {}
        weights_raw = sel.get("weights")

        buyer_policy = BuyerPolicy(
            task=policy_dict["task"],
            constraints=Constraints(
                max_unit_price=MaxUnitPrice(
                    amount=constraints["max_unit_price"]["amount"],
                    currency=constraints["max_unit_price"].get("currency", "USDC"),
                    unit=constraints["max_unit_price"].get("unit", "request"),
                ),
                max_daily_spend=MaxDailySpend(
                    amount=constraints["max_daily_spend"]["amount"],
                    currency=constraints["max_daily_spend"].get("currency", "USDC"),
                ),
            ),
            negotiation=Negotiation(
                rounds_max=negotiation["rounds_max"],
                quote_ttl=negotiation["quote_ttl"],
            ),
            selection=Selection(
                prioritize=sel["prioritize"],
                min_reputation=sel.get("min_reputation"),
                weights=weights_raw,
            ),
        )

        orchestrator = BuyerOrchestrator(
            policy=buyer_policy,
            runtime=client.runtime,
            requester_address=client.address,
        )

        # Progress callback for human mode
        def on_progress(event: ProgressEvent) -> None:
            if fmt in (OutputFormat.JSON, OutputFormat.QUIET):
                return

            event_type = getattr(event, "type", None)

            if event_type == "discovery":
                print_info(f"Found {getattr(event, 'candidates', 0)} candidates")
            elif event_type == "scoring":
                print_info(f"Ranked {getattr(event, 'ranked', 0)} candidates")
            elif event_type == "round_start":
                typer.echo(
                    f"  Round {getattr(event, 'round', '')}: trying {getattr(event, 'provider', '')}..."
                )
            elif event_type == "waiting_quote":
                typer.echo(
                    f"    Waiting for quote ({getattr(event, 'ttl_seconds', '')}s TTL)..."
                )
            elif event_type == "quote_received":
                typer.echo("    Quote received, validating...")
            elif event_type == "round_end":
                action = getattr(event, "action", "")
                reason = getattr(event, "reason", "")
                rnd = getattr(event, "round", "")
                if action == "accepted":
                    print_success(f"Round {rnd}: accepted - {reason}")
                else:
                    typer.echo(f"    Round {rnd}: {action} - {reason}")

        config = OrchestratorConfig(
            dry_run=dry_run,
            poll_interval_ms=poll_interval_ms,
            on_progress=on_progress,
        )

        try:
            result = await orchestrator.negotiate(config=config)

            # Build output data from NegotiationResult dataclass
            result_data = {
                "success": result.success,
                "commerce_session_id": result.commerce_session_id,
                "actp_tx_id": result.actp_tx_id,
                "selected_provider": result.selected_provider,
                "rounds_used": result.rounds_used,
                "reason": result.reason,
                "rounds": [
                    {
                        "round": r.round,
                        "provider_slug": r.provider_slug,
                        "provider_address": r.provider_address,
                        "action": r.action,
                        "reason": r.reason,
                        "tx_id": r.tx_id,
                    }
                    for r in result.rounds
                ],
            }

            # JSON output
            if fmt == OutputFormat.JSON:
                print_json(result_data)
                if not result.success:
                    raise typer.Exit(1)
                return

            # Quiet output
            if fmt == OutputFormat.QUIET:
                if result.success:
                    typer.echo(result.actp_tx_id or "")
                else:
                    typer.echo(result.reason or "")
                if not result.success:
                    raise typer.Exit(1)
                return

            # Human output
            if result.success:
                print_success("Negotiation complete", {
                    "Session": result.commerce_session_id,
                    "Transaction": result.actp_tx_id or "-",
                    "Provider": result.selected_provider or "-",
                    "Rounds": str(result.rounds_used),
                    "Reason": result.reason,
                })
            else:
                print_error(
                    f"Negotiation failed: {result.reason}",
                    f"Rounds used: {result.rounds_used}",
                )
                raise typer.Exit(1)

        except typer.Exit:
            raise
        except Exception as e:
            _error(fmt, str(e))
            raise typer.Exit(1)

    asyncio.run(_negotiate())
