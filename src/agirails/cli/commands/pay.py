"""
Pay Command - Create a payment transaction.

Usage:
    $ actp pay 0xProvider... 10.00
    $ actp pay 0xProvider... 10.00 --deadline 24h
    $ actp pay agirails.app/a/<slug> 10.00

`actp pay` is a Level 0 primitive — no handler routing, no quote/accept
negotiation. Callers who want hashed service routing belong on
`actp request --service <name>` (mirrors TS `src/cli/commands/pay.ts`).
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import get_client, ensure_initialized
from agirails.cli.utils.output import (
    print_success,
    print_error,
    print_json,
    print_info,
    format_usdc,
    format_address,
    OutputFormat,
)
from agirails.adapters.types import UnifiedPayParams
from agirails.cli.utils.validation import validate_amount


# ============================================================================
# --service rejection (PRD §5.9)
# ============================================================================

#: Canonical directive emitted when a caller passes `--service` to `actp pay`.
#: Exported so tests + future doc tooling can assert/inspect the exact wording.
#: Byte-identical to TS `PAY_SERVICE_REJECTION_MESSAGE`
#: (`src/cli/commands/pay.ts:69-73`).
PAY_SERVICE_REJECTION_MESSAGE = (
    "Error: 'actp pay' is a Level 0 primitive and does not accept --service.\n"
    "For negotiated Level 1 job flow (where a provider's handler runs after quote/accept),\n"
    "use 'actp request <provider> <amount> --service <name>' instead.\n"
    "See https://agirails.io/docs/sdk/level-0-vs-level-1"
)

#: Exit code for `actp pay --service` rejection. 64 = `EX_USAGE` from
#: sysexits.h — the standard signal for "command-line usage error" so scripts
#: can distinguish a misuse from a generic ACTP failure. Mirrors TS
#: `EX_USAGE` (`src/cli/commands/pay.ts:80`).
EX_USAGE = 64

#: agirails.app/a/<slug> URL matcher (case-insensitive). Mirrors the TS regex
#: in `src/cli/commands/pay.ts:103`.
_SLUG_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?agirails\.app/a/([a-z0-9_-]+)$",
    re.IGNORECASE,
)


def pay(
    provider: str = typer.Argument(..., help="Provider address (0x...), HTTP endpoint, agent ID, or agirails.app/a/<slug>"),
    amount: str = typer.Argument(..., help="Amount in USDC (e.g., 10.00)"),
    deadline: Optional[str] = typer.Option(
        None,
        "--deadline",
        "-d",
        help="Deadline (e.g., '24h', '7d', or Unix timestamp)"
    ),
    dispute_window: str = typer.Option(
        "172800",
        "--dispute-window",
        "-w",
        help="Dispute window in seconds",
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        help="Payment description"
    ),
    service: Optional[str] = typer.Option(
        None,
        "--service",
        help="(rejected — see actp request for Level 1 flow)",
    ),
) -> None:
    """Create a payment transaction to a provider."""
    opts = get_global_options()

    # PRD §5.9: --service belongs on `actp request`, not `actp pay`. The flag
    # is parsed only so we can intercept and route the user. `errorResult`
    # semantics (JSON-visible) are mirrored so the directive is visible in
    # --json and --quiet modes too; a silent exit-64 would leave scripts
    # guessing at the cause. Mirrors TS `src/cli/commands/pay.ts:93-100`.
    if service is not None:
        if opts.output_format == OutputFormat.JSON:
            print_json({
                "error": {
                    "code": "PAY_SERVICE_REJECTED",
                    "message": PAY_SERVICE_REJECTION_MESSAGE,
                    "details": {"use": "actp request <provider> <amount> --service <name>"},
                }
            })
        else:
            print_error("Invalid usage", PAY_SERVICE_REJECTION_MESSAGE)
        raise typer.Exit(EX_USAGE)

    # Validate amount (provider can be address, URL, or agent ID — router decides)
    try:
        amount = validate_amount(amount)
    except typer.BadParameter as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Invalid input", str(e))
        raise typer.Exit(1)

    # Check initialization
    if not ensure_initialized(opts.directory):
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": "Not initialized. Run 'actp init' first."})
        else:
            print_error("Not initialized", "Run 'actp init' first")
        raise typer.Exit(1)

    async def _pay() -> None:
        # Resolve slug URLs (e.g. agirails.app/a/arha) to wallet addresses.
        # Mirrors TS `src/cli/commands/pay.ts:102-122`.
        to = provider
        slug_match = _SLUG_URL_RE.match(to)
        if slug_match:
            slug = slug_match.group(1).lower()
            try:
                from agirails.api.discover import discover_agents, DiscoverParams

                result = await discover_agents(DiscoverParams(search=slug, limit=10))
                agent = next(
                    (a for a in result.agents if a.slug.lower() == slug),
                    None,
                )
                if agent is None or not agent.wallet_address:
                    if opts.output_format == OutputFormat.JSON:
                        print_json({"error": f'Agent "{slug}" not found or has no wallet address.'})
                    else:
                        print_error(
                            "Resolution failed",
                            f'Agent "{slug}" not found or has no wallet address.',
                        )
                    raise typer.Exit(1)
                to = agent.wallet_address
                if opts.output_format == OutputFormat.PRETTY:
                    print_info(f"Resolved {slug} → {to}")
            except typer.Exit:
                raise
            except Exception as e:
                if opts.output_format == OutputFormat.JSON:
                    print_json({"error": str(e)})
                else:
                    print_error("Resolution failed", str(e))
                raise typer.Exit(1)

        try:
            # Get client
            client = await get_client(
                mode=opts.mode,
                directory=opts.directory,
            )

            # Parse dispute window (seconds). Mirrors TS parseInt
            # (`src/cli/commands/pay.ts:137`).
            try:
                parsed_dispute_window = int(dispute_window, 10)
            except (TypeError, ValueError):
                parsed_dispute_window = 172800

            # Create unified payment params (router selects adapter)
            # Deadline is passed as-is: the adapter's parse_deadline() handles
            # both relative formats ("24h", "7d") and unix timestamps.
            params = UnifiedPayParams(
                to=to,
                amount=amount,
                deadline=deadline,
                description=description,
            )
            # Thread the dispute window through where supported. UnifiedPayParams
            # does not carry a dedicated field (adapters subsystem), so attach it
            # best-effort so downstream adapters that read it pick it up while
            # older adapters ignore it. Keeps the CLI surface at parity with TS
            # `basic.pay({ disputeWindow })` without touching the adapters layer.
            try:
                setattr(params, "dispute_window", parsed_dispute_window)
            except Exception:
                pass

            # Execute payment through router
            raw = await client.pay(params)

            # Normalize result (adapters may return dataclass or dict)
            if isinstance(raw, dict):
                r_tx_id = raw.get("tx_id", "")
                r_escrow_id = raw.get("escrow_id", "")
                r_state = raw.get("state", "")
                r_amount = raw.get("amount", "")
                r_deadline = raw.get("deadline", 0)
            else:
                r_tx_id = getattr(raw, "tx_id", "")
                r_escrow_id = getattr(raw, "escrow_id", "")
                r_state = getattr(raw, "state", "")
                r_amount = getattr(raw, "amount", "")
                r_deadline = getattr(raw, "deadline", 0)

            if opts.output_format == OutputFormat.JSON:
                print_json({
                    "success": True,
                    "txId": r_tx_id,
                    "escrowId": r_escrow_id,
                    "state": r_state,
                    "amount": r_amount,
                    "deadline": r_deadline,
                })
            elif opts.output_format == OutputFormat.QUIET:
                typer.echo(r_tx_id)
            else:
                print_success("Payment created", {
                    "Transaction ID": r_tx_id,
                    "Escrow ID": r_escrow_id,
                    "State": r_state,
                    "Amount": format_usdc(r_amount),
                    "Provider": format_address(to),
                })

        except typer.Exit:
            raise
        except Exception as e:
            if opts.output_format == OutputFormat.JSON:
                print_json({"error": str(e)})
            else:
                print_error("Payment failed", str(e))
            raise typer.Exit(1)

    asyncio.run(_pay())
