"""Health Command - Check agent endpoint and config health.

Usage:
    $ actp health
    $ actp health --json
    $ actp health --timeout 10000
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
)

CheckStatus = Literal["pass", "warn", "fail", "info"]

SLA_THRESHOLD_MS = 2000
PENDING_ENDPOINT = "https://pending.agirails.io"


def _probe_endpoint(url: str, timeout_s: float) -> Dict[str, Any]:
    """Probe endpoint with HEAD → GET fallback.

    Returns dict with: reachable (bool), method, status_code, response_time_ms, error.
    """
    for method in ("HEAD", "GET"):
        try:
            # Try httpx first, then urllib
            try:
                import httpx

                with httpx.Client(timeout=timeout_s) as client:
                    start = time.monotonic()
                    resp = client.request(method, url, follow_redirects=True)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    return {
                        "reachable": True,
                        "method": method,
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed_ms,
                    }
            except ImportError:
                from urllib.request import Request, urlopen

                req = Request(url, method=method)
                start = time.monotonic()
                with urlopen(req, timeout=int(timeout_s)) as resp:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    return {
                        "reachable": True,
                        "method": method,
                        "status_code": resp.status,
                        "response_time_ms": elapsed_ms,
                    }
        except Exception as e:
            if method == "GET":
                # Both HEAD and GET failed
                return {
                    "reachable": False,
                    "method": method,
                    "response_time_ms": 0,
                    "error": str(e),
                }
            # HEAD failed, try GET
            continue

    return {"reachable": False, "method": "GET", "response_time_ms": 0, "error": "All probes failed"}


def health(
    path: Optional[str] = typer.Argument(None, help="Path to AGIRAILS.md"),
    network: str = typer.Option(
        "base-sepolia", "--network", "-n", help="Network to check"
    ),
    address: Optional[str] = typer.Option(
        None, "--address", "-a", help="Agent address"
    ),
    timeout: int = typer.Option(5000, "--timeout", help="Probe timeout in ms"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Minimal output"),
) -> None:
    """Check agent endpoint and config health."""
    # Command-level flags override global
    opts = get_global_options()
    if json_output:
        fmt = OutputFormat.JSON
    elif quiet:
        fmt = OutputFormat.QUIET
    else:
        fmt = opts.output_format

    md_path = path or str(Path(opts.directory or Path.cwd()) / "AGIRAILS.md")
    timeout_s = timeout / 1000.0
    checks: List[Dict[str, str]] = []
    fatal = False

    # ── Check 1: AGIRAILS.md exists and parses ────────────────────────
    frontmatter: Dict[str, Any] = {}
    try:
        p = Path(md_path)
        if not p.exists():
            checks.append({"name": "AGIRAILS.md", "status": "fail", "detail": f"Not found: {md_path}"})
            fatal = True
        else:
            content = p.read_text(encoding="utf-8")
            from agirails.config.agirailsmd import parse_agirails_md

            parsed = parse_agirails_md(content)
            frontmatter = parsed.frontmatter
            name = frontmatter.get("name") or frontmatter.get("slug") or "unknown"
            checks.append({"name": "AGIRAILS.md", "status": "pass", "detail": f"Parsed ({name})"})
    except Exception as e:
        checks.append({"name": "AGIRAILS.md", "status": "fail", "detail": f"Parse error: {e}"})
        fatal = True

    # ── Check 2: Endpoint set and not placeholder ─────────────────────
    if not fatal:
        endpoint = frontmatter.get("endpoint", "")
        if not endpoint or endpoint == PENDING_ENDPOINT:
            checks.append({"name": "Endpoint", "status": "fail", "detail": "No endpoint set (placeholder or missing)"})
            fatal = True
        else:
            checks.append({"name": "Endpoint", "status": "pass", "detail": endpoint})

    # ── Check 3 & 4: Endpoint reachable + health ──────────────────────
    if not fatal:
        endpoint = frontmatter["endpoint"]
        probe = _probe_endpoint(endpoint, timeout_s)

        if probe["reachable"]:
            checks.append({
                "name": "Endpoint reachable",
                "status": "pass",
                "detail": f"{probe['response_time_ms']}ms ({probe['method']} {probe.get('status_code', '?')})",
            })

            status_code = probe.get("status_code", 200)
            if status_code and status_code >= 500:
                checks.append({
                    "name": "Endpoint health",
                    "status": "warn",
                    "detail": f"Endpoint returned {status_code} — server error",
                })
            elif probe["response_time_ms"] > SLA_THRESHOLD_MS:
                checks.append({
                    "name": "Response time",
                    "status": "warn",
                    "detail": f"{probe['response_time_ms']}ms exceeds {SLA_THRESHOLD_MS}ms SLA",
                })
            else:
                checks.append({
                    "name": "Response time",
                    "status": "pass",
                    "detail": f"{probe['response_time_ms']}ms (< {SLA_THRESHOLD_MS}ms)",
                })
        else:
            checks.append({
                "name": "Endpoint reachable",
                "status": "fail",
                "detail": probe.get("error", "Endpoint unreachable"),
            })
            fatal = True

    # ── Check 5: Pending publish status ───────────────────────────────
    if not fatal:
        try:
            from agirails.config.pending_publish import load_pending_publish

            pending = load_pending_publish(network=network)
            if pending:
                checks.append({
                    "name": "Pending publish",
                    "status": "info",
                    "detail": f"Mainnet activation on first payment (hash: {pending.config_hash[:10]}...)",
                })
            else:
                checks.append({"name": "Pending publish", "status": "pass", "detail": "No pending publish"})
        except Exception:
            checks.append({"name": "Pending publish", "status": "pass", "detail": "No pending publish file"})

    # ── Check 6: Config hash matches on-chain ─────────────────────────
    if not fatal:
        try:
            from agirails.config.networks import get_network

            net_config = get_network(network)

            if not net_config.contracts.agent_registry:
                checks.append({"name": "On-chain config", "status": "info", "detail": f"No AgentRegistry on {network}"})
            else:
                agent_address = address or os.environ.get("ACTP_ADDRESS")
                if not agent_address:
                    try:
                        import asyncio
                        from agirails.wallet.keystore import resolve_private_key, ResolvePrivateKeyOptions

                        result = asyncio.run(
                            resolve_private_key(options=ResolvePrivateKeyOptions(network=network))
                        )
                        if result:
                            from eth_account import Account

                            agent_address = Account.from_key(result).address
                    except Exception:
                        pass

                if not agent_address:
                    checks.append({"name": "On-chain config", "status": "info", "detail": "No agent address (use --address or set ACTP_ADDRESS)"})
                else:
                    content = Path(md_path).read_text(encoding="utf-8")
                    from agirails.config.agirailsmd import compute_config_hash
                    from agirails.config.on_chain_state import get_on_chain_agent_state

                    local_hash = compute_config_hash(content).config_hash
                    on_chain = get_on_chain_agent_state(agent_address, network)

                    if not on_chain.is_registered:
                        checks.append({"name": "On-chain config", "status": "info", "detail": "Agent not yet registered on-chain"})
                    elif on_chain.config_hash == local_hash:
                        checks.append({"name": "On-chain config", "status": "pass", "detail": f"Hash matches ({network})"})
                    else:
                        checks.append({
                            "name": "On-chain config",
                            "status": "warn",
                            "detail": f"Hash mismatch — local {local_hash[:10]}... vs on-chain {on_chain.config_hash[:10]}...",
                        })
        except Exception as e:
            checks.append({"name": "On-chain config", "status": "warn", "detail": f"Could not check: {e}"})

    # ── Output ────────────────────────────────────────────────────────
    warnings = sum(1 for c in checks if c["status"] == "warn")
    healthy = not fatal

    if fmt == OutputFormat.JSON:
        print_json({"checks": checks, "healthy": healthy, "warnings": warnings})
    elif fmt == OutputFormat.QUIET:
        typer.echo("PASS" if healthy else "FAIL")
    else:
        typer.echo("")
        for check in checks:
            icon = {"pass": "\u2713", "warn": "\u26A0", "info": "\u2139", "fail": "\u2717"}.get(check["status"], "?")
            typer.echo(f"  {icon} {check['name']}: {check['detail']}")
        typer.echo("")
        if healthy:
            suffix = f" ({warnings} warning{'s' if warnings > 1 else ''})" if warnings > 0 else ""
            print_success(f"Health: PASS{suffix}")
        else:
            print_error("Health: FAIL")
