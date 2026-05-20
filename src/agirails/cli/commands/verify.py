"""``actp verify`` — trustless verification of agent identity files.

Accepts input from file path, URL, or stdin (pipe). Walks the
verification chain:

  1. Parse AGIRAILS.md (frontmatter + body)
  2. Compute config hash (canonical-JSON + keccak256)
  3. Match against on-chain config hash via AgentRegistry
  4. Optionally fetch IPFS content at the registered CID and confirm
     it hashes to the same value
  5. Optionally fetch reputation snapshot from agirails.app

The Purple Cow moment::

    curl -s https://agirails.app/a/some-agent/agent.md | actp verify

Python port of ``sdk-js/src/cli/commands/verify.ts``.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import typer

from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
)
from agirails.config.agirailsmd import compute_config_hash, parse_agirails_md
from agirails.config.networks import get_network
from agirails.config.on_chain_state import (
    OnChainStateError,
    get_on_chain_config_state,
    ZERO_HASH,
)


_IPFS_GATEWAYS = (
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
)
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


# ============================================================================
# Result shape
# ============================================================================


@dataclass
class OnChainResult:
    checked: bool = False
    match: bool = False
    network: Optional[str] = None
    address: Optional[str] = None
    registry_hash: Optional[str] = None
    registry_cid: Optional[str] = None


@dataclass
class IpfsResult:
    checked: bool = False
    match: bool = False
    cid: Optional[str] = None


@dataclass
class ReputationResult:
    score: float = 0.0
    completed: int = 0
    success_rate: float = 0.0
    volume: str = "0"


@dataclass
class VerifyResult:
    valid: bool = True
    name: str = ""
    slug: str = ""
    config_hash: str = ""
    on_chain: OnChainResult = field(default_factory=OnChainResult)
    ipfs: IpfsResult = field(default_factory=IpfsResult)
    trust_tier: str = "unverified"  # chain-verified | published | unverified
    reputation: Optional[ReputationResult] = None

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        # match TS camelCase wire shape so SDKs and dashboards can share parsers
        return {
            "valid": out["valid"],
            "name": out["name"],
            "slug": out["slug"],
            "configHash": out["config_hash"],
            "onChain": {
                "checked": out["on_chain"]["checked"],
                "match": out["on_chain"]["match"],
                "network": out["on_chain"]["network"],
                "address": out["on_chain"]["address"],
                "registryHash": out["on_chain"]["registry_hash"],
                "registryCID": out["on_chain"]["registry_cid"],
            },
            "ipfs": {
                "checked": out["ipfs"]["checked"],
                "match": out["ipfs"]["match"],
                "cid": out["ipfs"]["cid"],
            },
            "trustTier": out["trust_tier"],
            **(
                {"reputation": out["reputation"]}
                if out["reputation"] is not None
                else {}
            ),
        }


# ============================================================================
# Command
# ============================================================================


def verify(
    source: Optional[str] = typer.Argument(
        None, help="File path, URL, or '-' for stdin."
    ),
    network: str = typer.Option(
        "base-sepolia",
        "-n",
        "--network",
        help="Network for on-chain verification (base-sepolia | base-mainnet).",
    ),
    address: Optional[str] = typer.Option(
        None,
        "-a",
        "--address",
        help="Agent address override (defaults to frontmatter wallet).",
    ),
    reputation: bool = typer.Option(
        False, "--reputation", help="Also fetch + display reputation data."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="Minimal output; exit code only."
    ),
) -> None:
    """Verify an agent identity file against on-chain state."""
    try:
        exit_code = asyncio.run(
            _run(
                source=source,
                network=network,
                address=address,
                reputation=reputation,
                json_output=json_output,
                quiet=quiet,
            )
        )
        raise typer.Exit(code=exit_code)
    except typer.Exit:
        raise
    except Exception as exc:
        if json_output:
            print_json({"ok": False, "error": str(exc)})
        else:
            print_error(f"verify failed: {exc}")
        raise typer.Exit(code=1)


async def _run(
    *,
    source: Optional[str],
    network: str,
    address: Optional[str],
    reputation: bool,
    json_output: bool,
    quiet: bool,
) -> int:
    # 1. Read input.
    content = await _read_content(source)
    if not content:
        print_error(
            "No input provided. Usage: actp verify <file> or pipe from stdin."
        )
        return 2

    # 2. Parse frontmatter.
    try:
        parsed = parse_agirails_md(content)
    except Exception as exc:
        print_error(f"Invalid identity file: {exc}")
        return 2
    fm = parsed.frontmatter or {}
    if not quiet and not json_output:
        print_success("Valid identity file")

    # 3. Compute hash.
    hash_result = compute_config_hash(content)
    config_hash = hash_result.config_hash
    if not quiet and not json_output:
        print_success(f"Config hash: {config_hash}")

    name = str(fm.get("name", ""))
    slug = str(fm.get("slug", ""))
    wallet_field = fm.get("wallet")
    effective_address = _resolve_address(wallet_field, address)

    result = VerifyResult(name=name, slug=slug, config_hash=config_hash)

    # 4. On-chain verification.
    if effective_address:
        try:
            net_cfg = get_network(network)
            if not net_cfg.contracts.agent_registry:
                if not quiet and not json_output:
                    print_warning(
                        "AgentRegistry not deployed on this network"
                    )
            else:
                on_chain_state = get_on_chain_config_state(
                    address=effective_address, network=network
                )
                result.on_chain = OnChainResult(
                    checked=True,
                    match=on_chain_state.config_hash == config_hash,
                    network=net_cfg.name,
                    address=effective_address,
                    registry_hash=on_chain_state.config_hash,
                    registry_cid=on_chain_state.config_cid or None,
                )
                if result.on_chain.match:
                    if not quiet and not json_output:
                        print_success(f"On-chain match: {net_cfg.name}")
                    result.trust_tier = "chain-verified"
                elif on_chain_state.config_hash == ZERO_HASH:
                    if not quiet and not json_output:
                        print_warning("No config published on-chain yet")
                    result.trust_tier = "published"
                else:
                    if not quiet and not json_output:
                        print_error(
                            f"On-chain mismatch: chain={on_chain_state.config_hash[:10]}… "
                            f"local={config_hash[:10]}…"
                        )
                    result.valid = False

                # 5. IPFS verification (if CID known).
                if on_chain_state.config_cid:
                    result.ipfs.cid = on_chain_state.config_cid
                    result.ipfs.checked = True
                    ipfs_content = await _fetch_ipfs(on_chain_state.config_cid)
                    if ipfs_content:
                        ipfs_hash = compute_config_hash(ipfs_content).config_hash
                        result.ipfs.match = ipfs_hash == config_hash
                        if not quiet and not json_output:
                            if result.ipfs.match:
                                print_success(
                                    f"IPFS CID: {on_chain_state.config_cid[:16]}… "
                                    "(content matches)"
                                )
                            else:
                                print_warning(
                                    "IPFS content hash differs from local"
                                )
                    elif not quiet and not json_output:
                        print_warning("IPFS fetch failed (gateways unavailable)")
        except OnChainStateError as exc:
            if not quiet and not json_output:
                print_warning(f"On-chain check failed: {exc}")
        except Exception as exc:
            if not quiet and not json_output:
                print_warning(f"On-chain check failed: {exc}")
    else:
        if not quiet and not json_output:
            print_info("No on-chain identity (mock/unpublished agent)")
        result.trust_tier = "published" if wallet_field else "unverified"

    # 6. Optional reputation fetch.
    if reputation and slug:
        rep_url = _reputation_url(content, slug)
        rep_data = await _fetch_reputation(rep_url)
        if rep_data is not None:
            result.reputation = ReputationResult(
                score=float(rep_data.get("reputation_score", 0)),
                completed=int(rep_data.get("completed_transactions", 0)),
                success_rate=float(rep_data.get("success_rate", 0)),
                volume=str(rep_data.get("total_volume_usdc", "0")),
            )
            if not quiet and not json_output:
                print_success(
                    f"Reputation: {result.reputation.score:g}/100 "
                    f"({result.reputation.completed} txs, "
                    f"{result.reputation.success_rate:g}% success)"
                )
        elif not quiet and not json_output:
            print_warning("Reputation fetch failed")

    # 7. Summary.
    if json_output:
        print_json(result.to_dict())
    elif not quiet:
        print_info("")
        print_info(
            f"  Agent: {name} ({slug}) | Trust: {result.trust_tier}"
        )

    return 0 if result.valid else 1


# ============================================================================
# Helpers
# ============================================================================


async def _read_content(source: Optional[str]) -> Optional[str]:
    """Read identity file content from file, URL, or stdin."""
    if not source or source == "-":
        # stdin
        if sys.stdin.isatty():
            return None
        return sys.stdin.read()

    if source.startswith("http://") or source.startswith("https://"):
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            res = await client.get(source)
            res.raise_for_status()
            return res.text

    path = Path(source)
    if path.exists():
        return path.read_text(encoding="utf-8")

    raise FileNotFoundError(f"File not found: {source}")


def _resolve_address(
    wallet_field: Any, override: Optional[str]
) -> Optional[str]:
    """Pick the agent address: --address override > frontmatter wallet > None."""
    if override:
        if not _HEX_ADDRESS.match(override):
            raise ValueError(f"Invalid --address: {override}")
        return override
    if isinstance(wallet_field, str) and _HEX_ADDRESS.match(wallet_field):
        return wallet_field
    return None


async def _fetch_ipfs(cid: str) -> Optional[str]:
    """Try IPFS gateways in order, return first success (or None)."""
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        for gw in _IPFS_GATEWAYS:
            try:
                res = await client.get(f"{gw}{cid}")
                if res.is_success:
                    return res.text
            except httpx.HTTPError:
                continue
    return None


def _reputation_url(content: str, slug: str) -> str:
    """Extract check_reputation URL from frontmatter or fall back to default."""
    match = re.search(
        r"check_reputation:\s*[\"']?([^\s\"']+)", content
    )
    if match:
        return match.group(1)
    return f"https://agirails.app/a/{slug}/{slug}.reputation.json"


async def _fetch_reputation(url: str) -> Optional[Dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            res = await client.get(url)
            if res.is_success:
                data = res.json()
                if isinstance(data, dict):
                    return data
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return None
    return None
