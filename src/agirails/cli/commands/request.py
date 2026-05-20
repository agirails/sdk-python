"""``actp request`` — Level 1 negotiated job request.

Creates an on-chain INITIATED transaction whose routing key is
``keccak256(toUtf8Bytes(service_name.strip()))``. A registered
provider listening for that hash will quote, accept, run its handler,
and deliver. The CLI waits for delivery and prints each state
transition.

Distinct from ``actp pay`` (Level 0): pay commits funds directly
without a handler. ``actp request`` routes through the provider's
handler with separate quote / delivery timeouts and a final
requester-immediate settle.

Python port of ``sdk-js/src/cli/commands/request.ts``.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import typer

from agirails.cli.lib.run_request import (
    DeliveryTimeoutError,
    QuoteTimeoutError,
    run_request,
)
from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_json,
    print_success,
)


_VALID_NETWORKS = {"mock", "testnet", "mainnet"}


def request(
    provider: str = typer.Argument(
        ..., help="Provider EVM address (0x…) or agirails.app slug URL."
    ),
    amount: str = typer.Argument(
        ..., help='Amount to escrow, USDC (e.g. "0.05").'
    ),
    service: str = typer.Option(
        ...,
        "--service",
        help="Service name; on-chain key is keccak256(toUtf8Bytes(name)).",
    ),
    deadline: Optional[str] = typer.Option(
        None,
        "--deadline",
        help="Job deadline (ISO 8601, unix seconds, or duration like '1h').",
    ),
    network: str = typer.Option(
        "testnet",
        "--network",
        help="Target network: mock | testnet | mainnet.",
    ),
    quote_timeout: int = typer.Option(
        30_000,
        "--quote-timeout",
        min=1,
        help="Max wait for the quote phase, ms (default 30000).",
    ),
    delivery_timeout: int = typer.Option(
        300_000,
        "--delivery-timeout",
        min=1,
        help="Max wait for delivery, ms (default 300000).",
    ),
    auto_accept: bool = typer.Option(
        True,
        "--auto-accept/--no-auto-accept",
        help="Auto-accept the first quote (default: auto-accept).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="Emit only the transaction id."
    ),
) -> None:
    """Request a Level 1 negotiated service (quote → accept → deliver → settle)."""
    if network not in _VALID_NETWORKS:
        raise typer.BadParameter(
            f'Invalid --network: "{network}". Expected mock | testnet | mainnet.'
        )

    try:
        result = asyncio.run(
            _run(
                provider=provider,
                amount=amount,
                service=service,
                deadline=deadline,
                network=network,
                quote_timeout=quote_timeout,
                delivery_timeout=delivery_timeout,
                auto_accept=auto_accept,
                json_output=json_output,
                quiet=quiet,
            )
        )
    except QuoteTimeoutError as exc:
        # PRD §5.6: exit code 2 is the canonical no-quote signal so
        # scripts can distinguish "provider offline" from other failures.
        _emit_error(
            json_output=json_output,
            code="QUOTE_TIMEOUT",
            message=str(exc),
            details={"txId": exc.tx_id, "timeoutMs": exc.timeout_ms},
        )
        raise typer.Exit(code=2)
    except DeliveryTimeoutError as exc:
        _emit_error(
            json_output=json_output,
            code="DELIVERY_TIMEOUT",
            message=str(exc),
            details={
                "txId": exc.tx_id,
                "timeoutMs": exc.timeout_ms,
                "lastState": exc.last_state,
            },
        )
        raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        _emit_error(
            json_output=json_output,
            code="REQUEST_FAILED",
            message=str(exc),
        )
        raise typer.Exit(code=1)

    if quiet:
        # Pipe-friendly: only the tx id.
        typer.echo(result.tx_id)
        return
    if json_output:
        print_json(
            {
                "ok": True,
                "txId": result.tx_id,
                "finalState": result.final_state,
                "elapsedMs": result.elapsed_ms,
                "settled": result.settled,
                "payload": result.payload,
            }
        )
        return

    print_info("")
    print_success(f"Settled in {result.elapsed_ms} ms (state: {result.final_state})")
    if isinstance(result.payload, dict) and "reflection" in result.payload:
        print_success(f"Reflection: {result.payload['reflection']}")


async def _run(
    *,
    provider: str,
    amount: str,
    service: str,
    deadline: Optional[str],
    network: str,
    quote_timeout: int,
    delivery_timeout: int,
    auto_accept: bool,
    json_output: bool,
    quiet: bool,
):
    if not (quiet or json_output):
        print_info(f"→ Requesting {service} from {provider}")
        print_info(
            f"  amount: {amount}, network: {network}, "
            f"quote-timeout: {quote_timeout}ms"
        )
        print_info("")

    def _on_transition(state: str, tx_id: str, elapsed_s: float) -> None:
        if quiet or json_output:
            return
        # Live progress log line.
        print_info(
            f"  [t+{elapsed_s:6.2f}s] {state:<12} {tx_id}"
        )

    return await run_request(
        provider=provider,
        amount=amount,
        service=service,
        deadline=deadline,
        network=network,  # type: ignore[arg-type]
        quote_timeout_ms=quote_timeout,
        delivery_timeout_ms=delivery_timeout,
        auto_accept=auto_accept,
        on_transition=_on_transition,
    )


def _emit_error(
    *,
    json_output: bool,
    code: str,
    message: str,
    details: Optional[dict] = None,
) -> None:
    if json_output:
        print_json(
            {
                "ok": False,
                "code": code,
                "error": message,
                "details": details or {},
            }
        )
    else:
        print_error(message)
