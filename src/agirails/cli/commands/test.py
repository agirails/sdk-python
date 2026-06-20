"""
ACTP Test Command.

Pre-4.0.0 this command ran ONLY a mock simulation of the earning loop.
From 4.0.0 (parity with sdk-js/src/cli/commands/test.ts) a real onboarding
request can be run against the deployed Sentinel agent on Base Sepolia:
it walks the full state machine via ``run_request``, settles the escrow as
the requester, wires the AIP-16 delivery channel (setup envelope + response
envelope subscription), renders the receipt, and prints the public receipt
URL on SETTLED.

The mock path (``--network mock``, the default) is preserved verbatim for
backward compatibility and offline / CI use.

Usage:
    $ actp test                       # mock earning loop (offline)
    $ actp test --network base-sepolia  # live Sentinel onboarding request
    $ actp test --json
    $ actp test -q
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

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


# ============================================================================
# resolveAgent — slug → on-chain identity (mirror sdk-js cli/lib/resolveAgent.ts)
# ============================================================================
#
# Built-in slug → address table. Add entries only for SDK-shipped reference
# agents that callers should reach without external discovery. Source of truth
# for Sentinel: Public Agents/seed-sentinel/sentinel.md (wallet field). If
# Sentinel rotates, set ACTP_SENTINEL_ADDRESS or republish the SDK.
_KNOWN_AGENTS = {
    "sentinel": {
        "base-sepolia": "0x3813A642C57CF3c20ff1170C0646c309B4bf6d64",
    },
}

# Slug → env var name (rotation escape hatch, no SDK republish needed).
_ENV_OVERRIDES = {
    "sentinel": "ACTP_SENTINEL_ADDRESS",
}


class AgentNotFoundError(RuntimeError):
    def __init__(self, slug: str, network: str) -> None:
        known = ", ".join(
            s for s, nets in _KNOWN_AGENTS.items() if network in nets
        )
        super().__init__(
            f"Agent '{slug}' is not registered for network '{network}'. "
            f"Known agents on this network: {known or '(none)'}."
        )
        self.slug = slug
        self.network = network


class InvalidAgentAddressError(RuntimeError):
    def __init__(self, env_var: str, value: str) -> None:
        super().__init__(
            f"Env var {env_var} contains an invalid Ethereum address: "
            f'"{value}". Expected a 0x-prefixed 40-character hex string.'
        )
        self.env_var = env_var
        self.value = value


def _is_evm_address(s: str) -> bool:
    return (
        isinstance(s, str)
        and len(s) == 42
        and s.startswith("0x")
        and all(c in "0123456789abcdefABCDEF" for c in s[2:])
    )


def resolve_agent(slug: str, network: str) -> dict:
    """Resolve a known agent slug on a network (mirror resolveAgent.ts:104).

    Resolution order: env-var override → constant table → AgentNotFoundError.
    Returns ``{slug, address, network, source}``.
    """
    normalized = slug.strip().lower()

    # 1. Env-var override path (rotation escape hatch).
    env_var = _ENV_OVERRIDES.get(normalized)
    if env_var:
        raw = (os.environ.get(env_var) or "").strip()
        if raw:
            if not _is_evm_address(raw):
                raise InvalidAgentAddressError(env_var, raw)
            return {
                "slug": normalized,
                "address": raw,
                "network": network,
                "source": "env",
            }

    # 2. Constant table.
    addr = _KNOWN_AGENTS.get(normalized, {}).get(network)
    if not addr:
        raise AgentNotFoundError(normalized, network)
    return {
        "slug": normalized,
        "address": addr,
        "network": network,
        "source": "table",
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

    # Live path: a real network → run the onboarding request against Sentinel.
    if network in ("testnet", "mainnet", "base-sepolia", "base-mainnet"):
        from agirails.cli.lib.run_request import QuoteTimeoutError

        try:
            asyncio.run(_run_live_test(output_format, network))
        except QuoteTimeoutError as e:
            # Quote-timeout gets its own exit code (2) so scripts can tell
            # "Sentinel offline" from generic failures (TS test.ts:65-72).
            print_error(str(e))
            raise typer.Exit(2)
        except Exception as e:
            print_error(f"Test failed: {e}")
            raise typer.Exit(1)
        return

    # Mock path (default, offline): the legacy mock earning loop.
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


# ============================================================================
# Live path — real onboarding request against Sentinel (TS test.ts:136-315)
# ============================================================================


async def _run_live_test(output_format: OutputFormat, network: str) -> None:
    """Run a real onboarding request against the deployed Sentinel.

    Mirrors TS ``runTest`` (test.ts:136-315): resolve Sentinel, wire the
    AIP-16 RelayDeliveryChannel (privacy='public'), walk the state machine,
    settle escrow, render the receipt + reflection, and print the public
    receipt URL.
    """
    from agirails.cli.lib.run_request import run_request
    from agirails.config.networks import get_network
    from agirails.delivery import (
        RelayDeliveryChannel,
        RelayDeliveryChannelOptions,
    )

    # Sentinel only resolves on Base Sepolia today (TS test.ts:138).
    sentinel_net = "base-sepolia" if network in ("testnet", "base-sepolia") else network
    request_network = "testnet" if sentinel_net == "base-sepolia" else "mainnet"
    sentinel = resolve_agent("sentinel", sentinel_net)

    pretty = output_format == OutputFormat.PRETTY
    if pretty:
        typer.echo("")
        typer.echo("→ Requesting onboarding service from Sentinel")
        typer.echo(f"  address: {sentinel['address']}")
        typer.echo(f"  network: {sentinel_net} (source: {sentinel['source']})")
        typer.echo("")

    # AIP-16: wire the delivery channel so the buyer posts a setup envelope
    # and subscribes for Sentinel's response envelope. Without the three opts
    # (delivery_channel / expected_kernel_address / expected_chain_id) the
    # whole AIP-16 path is skipped (TS test.ts:163-169). Sentinel's channel
    # privacy is 'public', so no buyer ephemeral keypair is needed.
    network_config = get_network(sentinel_net)
    delivery_channel = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url=os.environ.get("AGIRAILS_RELAY_URL")
            or "https://www.agirails.app",
        )
    )

    def _on_transition(state: str, tx_id: str, elapsed: float) -> None:
        if pretty:
            typer.echo(f"  [{elapsed:7.2f}s] {state:<12} {tx_id}")

    result = await run_request(
        provider=sentinel["address"],
        amount="10",  # Sentinel covenant: $10 USDC ($10–$100 band).
        service="onboarding",
        network=request_network,
        auto_accept=True,
        delivery_channel=delivery_channel,
        expected_kernel_address=network_config.contracts.actp_kernel,
        expected_chain_id=network_config.chain_id,
        delivery_privacy="public",
        on_transition=_on_transition,
    )

    # Reflection is the canonical Sentinel payload (TS test.ts:189).
    reflection = _extract_reflection(result.payload)

    if output_format == OutputFormat.JSON:
        from agirails.cli.utils.output import print_json

        print_json(
            {
                "txId": result.tx_id,
                "finalState": result.final_state,
                "elapsedMs": result.elapsed_ms,
                "settled": result.settled,
                "reflection": reflection,
                "payload": result.payload,
                "receiptUrl": result.receipt_url,
                "deliveryError": result.delivery_error,
            }
        )
        return

    if output_format == OutputFormat.QUIET:
        typer.echo(reflection or result.tx_id)
        return

    # Pretty mode: receipt + reflection + receipt URL.
    typer.echo("")
    receipt = render_receipt(
        ReceiptData(
            agent="your-agent",
            service="onboarding",
            amount_wei=10_000_000,
            network=sentinel_net,
            tx_id=result.tx_id,
            timing=ReceiptTiming(
                total_ms=result.elapsed_ms,
                escrow_lock_ms=0,
                settlement_ms=0,
            ),
        ),
        output_format,
    )
    typer.echo(receipt)

    if not result.settled:
        typer.echo("")
        print_error(
            f"Escrow settlement did NOT complete after delivery "
            f"(finalState={result.final_state}). Verify with "
            f"`actp tx status {result.tx_id}` and retry settlement manually."
        )
        return

    if reflection:
        typer.echo("")
        typer.echo(f"Reflection: {reflection}")
    else:
        typer.echo("")
        typer.echo(f"Settled in {result.elapsed_ms} ms")

    # Receipt URL — the wow artifact. Present only when the buyer-side V2 push
    # succeeded (real on-chain network + signer). The standalone "Receipt:"
    # line is the copy-paste-friendly anchor scripts/tests grep for
    # (TS test.ts:299-302).
    if result.receipt_url:
        typer.echo("")
        typer.echo(f"Receipt: {result.receipt_url}")


def _extract_reflection(payload: Any) -> Optional[str]:
    """Pull the reflection string out of a Sentinel payload (TS test.ts:317)."""
    if not isinstance(payload, dict):
        return None
    refl = payload.get("reflection")
    if isinstance(refl, str):
        return refl
    # Provider-side wraps handler output as {type:'delivery.proof', result:{...}}.
    if payload.get("type") == "delivery.proof":
        inner = payload.get("result")
        if isinstance(inner, dict) and isinstance(inner.get("reflection"), str):
            return inner["reflection"]
    return None


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
