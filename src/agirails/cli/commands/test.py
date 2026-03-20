"""
ACTP Test Command - Mock earning loop proving ACTP lifecycle works.

Usage:
    $ actp test
    $ actp test --json
    $ actp test -q
    $ actp test --network base-sepolia
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import OutputFormat, print_error
from agirails.cli.commands.receipt import (
    ReceiptData,
    ReceiptTiming,
    render_receipt,
)


# Test job templates keyed by service type
_TEST_JOBS = {
    "content-generation": {
        "service": "content-generation",
        "description": "Generate a test blog post about AI agents",
    },
    "data-analysis": {
        "service": "data-analysis",
        "description": "Analyze sample dataset for patterns",
    },
    "code-review": {
        "service": "code-review",
        "description": "Review sample code for quality issues",
    },
}

_DEFAULT_JOB = {
    "service": "generic-task",
    "description": "Execute a generic test task",
}


def parse_duration(duration_str: str) -> int:
    """Parse a duration string like '48h' into seconds.

    Supports: s (seconds), m (minutes), h (hours), d (days).
    Default: 48h (172800 seconds).

    Args:
        duration_str: Duration string (e.g., '48h', '7d', '30m')

    Returns:
        Duration in seconds
    """
    if not duration_str:
        return 172800  # 48h default

    match = re.match(r"^(\d+)(s|m|h|d)$", duration_str.strip())
    if not match:
        return 172800  # fallback to 48h

    value = int(match.group(1))
    unit = match.group(2)

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def test(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Minimal output"),
    network: str = typer.Option(
        "mock", "--network", "-n", help="Network (default: mock)"
    ),
    directory: Optional[Path] = typer.Option(
        None, "--directory", "-d", help="Directory containing AGIRAILS.md"
    ),
) -> None:
    """Run a mock ACTP earning loop to verify lifecycle works."""
    # Determine output format
    global_opts = get_global_options()
    if json_output or global_opts.json_output:
        output_format = OutputFormat.JSON
    elif quiet or global_opts.quiet:
        output_format = OutputFormat.QUIET
    else:
        output_format = OutputFormat.PRETTY

    # Find AGIRAILS.md
    search_dir = directory or global_opts.directory or Path.cwd()
    agirails_md_path = Path(search_dir) / "AGIRAILS.md"

    if not agirails_md_path.exists():
        print_error("No AGIRAILS.md found in current directory")
        print_error("Run `actp init` first or use --directory")
        raise typer.Exit(1)

    try:
        asyncio.run(_run_test(agirails_md_path, output_format, network))
    except Exception as e:
        print_error(f"Test failed: {e}")
        raise typer.Exit(1)


async def _run_test(
    agirails_md_path: Path,
    output_format: OutputFormat,
    network: str,
) -> None:
    """Run the mock ACTP lifecycle test."""
    from agirails.config.agirailsmd import parse_agirails_md
    from agirails.runtime.mock_runtime import MockRuntime
    from agirails.runtime.base import CreateTransactionParams

    # Parse AGIRAILS.md
    content = agirails_md_path.read_text()
    config = parse_agirails_md(content)
    fm = config.frontmatter

    # Extract agent info
    agent_slug = fm.get("slug", fm.get("name", "test-agent"))

    # Match service to test job template
    services = fm.get("services", [])
    first_service = services[0] if services else {}
    service_type = first_service.get("type", "") if isinstance(first_service, dict) else str(first_service)
    job = _TEST_JOBS.get(service_type, _DEFAULT_JOB)

    # Get pricing
    pricing = fm.get("pricing", {})
    base_price = pricing.get("base", 10_000_000)  # default $10 USDC
    if isinstance(base_price, str):
        # Handle string amounts like "10.00"
        base_price = int(float(base_price) * 1_000_000)

    # Get dispute window
    sla = fm.get("sla", {})
    dispute_window_str = sla.get("dispute_window", "48h")
    dispute_window = parse_duration(str(dispute_window_str))

    # Provider address from frontmatter or random
    provider_address = fm.get("wallet", None)

    # Create ephemeral runtime
    runtime = MockRuntime()

    # Generate random requester
    try:
        from eth_account import Account
        requester_account = Account.create()
        requester = requester_account.address
    except ImportError:
        # Fallback: deterministic test address
        requester = "0x" + "11" * 20

    if not provider_address:
        try:
            from eth_account import Account
            provider_account = Account.create()
            provider_address = provider_account.address
        except ImportError:
            provider_address = "0x" + "22" * 20

    # Mint tokens to requester
    await runtime.mint_tokens(requester, str(base_price * 2))

    # Run lifecycle with timing
    total_start = time.monotonic()

    # Create transaction
    escrow_start = time.monotonic()
    tx_id = await runtime.create_transaction(
        CreateTransactionParams(
            provider=provider_address,
            requester=requester,
            amount=str(base_price),
            deadline=runtime.time.now() + 3600,
            dispute_window=dispute_window,
            service_description=job["description"],
        )
    )

    # Link escrow
    escrow_id = await runtime.link_escrow(tx_id, str(base_price))
    escrow_ms = int((time.monotonic() - escrow_start) * 1000)

    # Progress through states
    await runtime.transition_state(tx_id, "IN_PROGRESS")
    await runtime.transition_state(tx_id, "DELIVERED", proof="test-delivery-proof")

    # Advance time past dispute window and settle
    settle_start = time.monotonic()
    await runtime.time.advance_time(dispute_window + 1)
    await runtime.release_escrow(escrow_id)
    settle_ms = int((time.monotonic() - settle_start) * 1000)

    total_ms = int((time.monotonic() - total_start) * 1000)

    # Render receipt
    receipt = render_receipt(
        ReceiptData(
            agent=agent_slug,
            service=job["service"],
            amount_wei=base_price,
            network=network,
            tx_id=tx_id,
            timing=ReceiptTiming(
                total_ms=total_ms,
                escrow_lock_ms=escrow_ms,
                settlement_ms=settle_ms,
            ),
        ),
        output_format,
    )

    typer.echo(receipt)
