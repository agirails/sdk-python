"""
Find Command — Discover agents on agirails.app.

1:1 parity with TypeScript SDK's `actp find` command.

Usage:
    $ actp find "code reviewer"
    $ actp find --capability translation --max-price 10
    $ actp find "translator" --rank llm --priority quality
    $ actp find --sort reputation --limit 5
    $ actp find "agent" --json
    $ actp find "agent" -q
"""

from __future__ import annotations

import asyncio
import math
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_info,
    print_json,
    print_table,
)

# ============================================================================
# Constants
# ============================================================================

VALID_SORT = ("reputation", "price", "recent")
VALID_PAYMENT_MODES = ("actp", "x402")
VALID_RANK = ("llm",)
VALID_PRIORITY = ("quality", "price", "speed")


# ============================================================================
# Command
# ============================================================================


def find(
    query: Optional[str] = typer.Argument(None, help="Free-text search query"),
    capability: Optional[str] = typer.Option(
        None, "-c", "--capability", help="Filter by capability (e.g. code-review)"
    ),
    max_price: Optional[str] = typer.Option(
        None, "--max-price", help="Maximum price in USDC"
    ),
    sort: str = typer.Option(
        "recent", "--sort", help="Sort: reputation | price | recent"
    ),
    limit: int = typer.Option(20, "-l", "--limit", help="Number of results (1-100)"),
    payment_mode: Optional[str] = typer.Option(
        None, "--payment-mode", help="Filter by payment mode: actp | x402"
    ),
    rank: Optional[str] = typer.Option(
        None, "--rank", help="Enable LLM ranking: llm"
    ),
    priority: str = typer.Option(
        "quality", "--priority", help="Ranking priority: quality | price | speed"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output as JSON"
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="Output slugs only, one per line"
    ),
) -> None:
    """Discover agents on agirails.app."""
    opts = get_global_options()
    # Command-level flags override global flags
    if json_output:
        fmt = OutputFormat.JSON
    elif quiet:
        fmt = OutputFormat.QUIET
    else:
        fmt = opts.output_format

    # --- Validation ---

    # Clamp limit
    limit = max(1, min(100, limit))

    # Validate --max-price
    if max_price is not None:
        try:
            parsed = float(max_price)
        except ValueError:
            parsed = float("nan")
        if math.isnan(parsed) or parsed < 0 or not math.isfinite(parsed):
            _error(fmt, "--max-price must be a non-negative number (e.g. --max-price 10)")
            raise typer.Exit(1)

    # Validate --payment-mode
    if payment_mode is not None and payment_mode not in VALID_PAYMENT_MODES:
        _error(fmt, f"--payment-mode must be one of: {', '.join(VALID_PAYMENT_MODES)}")
        raise typer.Exit(1)

    # Validate --sort
    if sort not in VALID_SORT:
        _error(fmt, f"--sort must be one of: {', '.join(VALID_SORT)}")
        raise typer.Exit(1)

    # Validate --rank
    if rank is not None and rank not in VALID_RANK:
        _error(fmt, f"--rank must be one of: {', '.join(VALID_RANK)}")
        raise typer.Exit(1)

    # Validate --priority
    if priority not in VALID_PRIORITY:
        _error(fmt, f"--priority must be one of: {', '.join(VALID_PRIORITY)}")
        raise typer.Exit(1)

    # --rank=llm requires a search query
    if rank == "llm" and not query:
        _error(fmt, '--rank=llm requires a search query (e.g. actp find "translate french" --rank llm)')
        raise typer.Exit(1)

    async def _find() -> None:
        from agirails.api.discover import discover_agents, DiscoverParams

        params = DiscoverParams(
            search=query,
            capability=capability,
            payment_mode=payment_mode,
            sort=sort,  # type: ignore[arg-type]
            limit=limit,
            max_price=float(max_price) if max_price is not None else None,
            rank=rank,  # type: ignore[arg-type]
            priority=priority,  # type: ignore[arg-type]
        )

        try:
            result = await discover_agents(params)
        except Exception as e:
            _error(fmt, f"Could not reach agirails.app: {e}")
            raise typer.Exit(1)

        agents = result.agents
        total = result.total
        ranking = result.ranking

        # JSON mode — raw API response
        if fmt == OutputFormat.JSON:
            data = {
                "agents": [_agent_to_dict(a) for a in agents],
                "total": total,
            }
            if ranking:
                data["ranking"] = {
                    "version": ranking.version,
                    "model": ranking.model,
                    "ranked": [
                        {"slug": r.slug, "reason": r.reason, "risk": r.risk, "confidence": r.confidence}
                        for r in ranking.ranked
                    ],
                }
            print_json(data)
            return

        # Quiet mode — slugs only
        if fmt == OutputFormat.QUIET:
            for agent in agents:
                typer.echo(agent.slug)
            return

        # Human mode — table
        if not agents:
            print_info("No agents found matching your query.")
            typer.echo("  Try a broader search or remove some filters.")
            return

        # Build table
        headers = ["SLUG", "NAME", "PRICE", "CAPABILITIES", "PAYMENT"]
        rows = []
        for agent in agents:
            cfg = agent.published_config
            slug = agent.slug or ""
            name = (cfg.name if cfg and cfg.name else "-")[:22]
            caps = (", ".join(cfg.capabilities) if cfg and cfg.capabilities else "-")[:20]
            mode = (cfg.payment_mode if cfg and cfg.payment_mode else "-")[:8]

            price = "-"
            if cfg and cfg.pricing and cfg.pricing.amount is not None:
                amt = f"{cfg.pricing.amount:.2f}"
                cur = cfg.pricing.currency or "USDC"
                price = f"{amt} {cur}"

            rows.append([slug[:20], name, price[:12], caps, mode])

        print_table(headers, rows)

        # LLM ranking recommendations
        if ranking and ranking.ranked:
            typer.echo("")
            typer.echo(f"  AI Recommendations ({ranking.model}, {ranking.version})")
            typer.echo("  " + "-" * 60)
            for i, r in enumerate(ranking.ranked):
                typer.echo(f"  {i + 1}. {r.slug} [{r.confidence}]")
                typer.echo(f"     {r.reason}")
                if r.risk:
                    typer.echo(f"     Risk: {r.risk}")

        # Footer
        typer.echo("")
        more = " Use --limit to see more." if len(agents) < total else ""
        typer.echo(f"  Showing {len(agents)} of {total} agent(s).{more}")
        typer.echo("")
        typer.echo("  Pay an agent:  actp pay agirails.app/a/<slug> <amount>")

    asyncio.run(_find())


# ============================================================================
# Helpers
# ============================================================================


def _error(fmt: OutputFormat, message: str) -> None:
    if fmt == OutputFormat.JSON:
        print_json({"error": message})
    else:
        print_error(message)


def _agent_to_dict(agent) -> dict:
    """Convert DiscoverAgent dataclass to JSON-serializable dict."""
    d: dict = {"slug": agent.slug, "wallet_address": agent.wallet_address}
    if agent.published_config:
        cfg = agent.published_config
        cfg_dict: dict = {}
        if cfg.name:
            cfg_dict["name"] = cfg.name
        if cfg.description:
            cfg_dict["description"] = cfg.description
        if cfg.capabilities:
            cfg_dict["capabilities"] = cfg.capabilities
        if cfg.pricing:
            pricing_dict: dict = {}
            if cfg.pricing.amount is not None:
                pricing_dict["amount"] = cfg.pricing.amount
            if cfg.pricing.currency:
                pricing_dict["currency"] = cfg.pricing.currency
            if cfg.pricing.unit:
                pricing_dict["unit"] = cfg.pricing.unit
            if pricing_dict:
                cfg_dict["pricing"] = pricing_dict
        if cfg.payment_mode:
            cfg_dict["payment_mode"] = cfg.payment_mode
        if cfg.sla:
            cfg_dict["sla"] = cfg.sla
        if cfg.endpoints:
            cfg_dict["endpoints"] = cfg.endpoints
        if cfg_dict:
            d["published_config"] = cfg_dict
    if agent.published_at:
        d["published_at"] = agent.published_at
    if agent.status:
        d["status"] = agent.status
    if agent.stats:
        s = agent.stats
        d["stats"] = {
            "reputation_score": s.reputation_score,
            "completed_transactions": s.completed_transactions,
            "failed_transactions": s.failed_transactions,
            "success_rate": s.success_rate,
            "total_gmv_usdc": s.total_gmv_usdc,
            "avg_completion_time_seconds": s.avg_completion_time_seconds,
        }
    return d
