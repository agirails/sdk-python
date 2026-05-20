"""``actp serve`` — run the AIP-2.1 quote-channel daemon.

Loads a ProviderPolicy JSON file, builds a FastAPI app via
:func:`agirails.server.app.create_app`, and serves it with uvicorn.

Scope:
  - accept + verify incoming counter-offers via :class:`QuoteChannelHandler`
  - log the policy verdict (ACCEPT / COUNTER / REJECT) per round
  - one-line health response on ``GET /``

Not in scope here (matches TS daemon v1):
  - On-chain INITIATED-tx detection (handled by ``actp agent`` /
    long-running `Agent` instances).
  - Sending CounterAcceptMessage back to buyer (no reverse-endpoint
    discovery in v1 — operator handles delivery).

Usage::

    actp serve --policy ./provider-policy.json --port 8787 --network base-sepolia
    actp serve --policy ./provider-policy.json --mock        # local testing

Example policy JSON (saved as ``provider-policy.json``)::

    {
      "services": ["text-generation"],
      "pricing": {
        "min_acceptable": {"amount": 500000, "currency": "USDC", "unit": "base"},
        "ideal_price":    {"amount": 1000000, "currency": "USDC", "unit": "base"}
      },
      "quote_ttl": "15m",
      "counter_strategy": "concede",
      "concede_pct": 30,
      "max_requotes": 2
    }
"""

from pathlib import Path
from typing import Optional

import typer

from agirails.cli.utils.output import print_error, print_info, print_success


def serve(
    policy: Path = typer.Option(
        ...,
        "--policy",
        help="Path to ProviderPolicy JSON file.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    port: int = typer.Option(
        8787, "--port", min=1, max=65535, help="HTTP port to listen on."
    ),
    host: str = typer.Option(
        "0.0.0.0", "--host", help="Bind address (default: 0.0.0.0)."
    ),
    network: str = typer.Option(
        "base-sepolia",
        "--network",
        help="Network — base-sepolia | base-mainnet | mock.",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        help="Use a mock provider address / zero kernel for local testing.",
    ),
    provider_address: Optional[str] = typer.Option(
        None,
        "--provider-address",
        help=(
            "Provider EOA / Smart Wallet address shown on /health. "
            "Defaults to env ACTP_PROVIDER_ADDRESS or a placeholder."
        ),
    ),
) -> None:
    """Run a long-running provider daemon (AIP-2.1 quote channel)."""
    try:
        # Lazy imports — server stack is an optional dependency.
        try:
            import uvicorn  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "uvicorn is not installed. Install the server extras:\n"
                "  pip install agirails[server]"
            ) from exc

        from agirails.config.networks import get_network
        from agirails.server.app import create_app
        from agirails.server.policy import load_policy_from_file
        from agirails.server.quote_channel import build_channel_path

        # 1. Load + validate policy.
        loaded_policy = load_policy_from_file(policy)

        # 2. Resolve kernel address + chainId from network config.
        if mock:
            kernel_address = "0x" + "0" * 40
            chain_id = 84532
        else:
            network_cfg = get_network(network)
            kernel_address = network_cfg.contracts.actp_kernel
            chain_id = network_cfg.chain_id

        # 3. Provider address for /health.
        import os
        signer_address = (
            provider_address
            or os.environ.get("ACTP_PROVIDER_ADDRESS")
            or "0x" + "0" * 40
        )

        # 4. Build app.
        app = create_app(
            policy=loaded_policy,
            kernel_address_by_chain_id={chain_id: kernel_address},
            signer_address=signer_address,
            service_label="actp-serve",
        )

        # 5. Banner + serve.
        print_success(f"actp serve listening on http://{host}:{port}")
        print_info(f"  Network:       {network}{'  (mock)' if mock else ''}")
        print_info(f"  Provider:      {signer_address}")
        print_info(f"  Channel base:  {build_channel_path(chain_id, '<txId>')}")
        print_info(f"  Health:        GET /")
        print_info("")
        print_info(
            "Counter-offers POSTed to /quote-channel/{chainId}/{txId} are verified +"
        )
        print_info(
            "evaluated against the policy. Verdicts are logged here; v1 does NOT"
        )
        print_info(
            "auto-deliver CounterAccept back to the buyer (AIP-2.1 §5.3)."
        )

        import uvicorn as _uvicorn

        _uvicorn.run(app, host=host, port=port, log_level="info")
    except Exception as exc:
        print_error(f"actp serve failed: {exc}")
        raise typer.Exit(code=1)
