"""Sync Operations - Pull + Diff for AGIRAILS.md.

Terraform-style sync: compare local AGIRAILS.md with on-chain state.
Never auto-overwrites -- shows diff and requires explicit confirmation.

Diff Status:
  - ``in-sync``: local hash matches on-chain hash.
  - ``local-ahead``: local file has changes not yet published.
  - ``remote-ahead``: on-chain config is newer than local.
  - ``diverged``: both sides have changes (manual merge needed).
  - ``no-local``: no local file, no on-chain config.
  - ``no-remote``: local file exists, but nothing on-chain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx

from agirails.config.agirailsmd import (
    compute_config_hash,
    parse_agirails_md,
    serialize_agirails_md,
)

logger = logging.getLogger("agirails.config.sync")

# ============================================================================
# Constants
# ============================================================================

ZERO_HASH = "0x" + "0" * 64

IPFS_GATEWAYS = [
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
]

IPFS_FETCH_TIMEOUT = 15.0  # seconds


# ============================================================================
# Types
# ============================================================================


class DiffStatus(str, Enum):
    """Sync status between local file and on-chain state."""

    IN_SYNC = "in-sync"
    LOCAL_AHEAD = "local-ahead"
    REMOTE_AHEAD = "remote-ahead"
    DIVERGED = "diverged"
    NO_LOCAL = "no-local"
    NO_REMOTE = "no-remote"


@dataclass
class DiffResult:
    """Result of comparing local AGIRAILS.md with on-chain state."""

    in_sync: bool
    local_hash: Optional[str]
    on_chain_hash: str
    on_chain_cid: str
    has_on_chain_config: bool
    has_local_file: bool
    status: DiffStatus


@dataclass
class PullResult:
    """Result of pulling on-chain config to local file."""

    written: bool
    content: Optional[str] = None
    cid: Optional[str] = None
    status: str = ""


# ============================================================================
# On-chain reader interface (protocol-agnostic)
# ============================================================================


class OnChainConfigReader:
    """Interface for reading on-chain agent config state.

    This is a thin abstraction so sync_operations doesn't depend
    directly on web3 or AgentRegistry internals.
    """

    def __init__(self, config_hash: str, config_cid: str) -> None:
        self.config_hash = config_hash
        self.config_cid = config_cid

    @property
    def has_config(self) -> bool:
        return self.config_hash != ZERO_HASH and self.config_cid != ""


# ============================================================================
# Diff
# ============================================================================


def diff_config(
    local_path: str,
    on_chain: OnChainConfigReader,
) -> DiffResult:
    """Compare local AGIRAILS.md with on-chain config state.

    Args:
        local_path: Path to local AGIRAILS.md file.
        on_chain: On-chain config reader with hash and CID.

    Returns:
        DiffResult showing sync status and hashes.
    """
    has_on_chain = on_chain.has_config
    on_chain_hash = on_chain.config_hash
    on_chain_cid = on_chain.config_cid

    path = Path(local_path)
    has_local = path.exists()
    local_hash: Optional[str] = None

    if has_local:
        content = path.read_text(encoding="utf-8")
        result = compute_config_hash(content)
        local_hash = result.config_hash

    # Determine status
    if not has_local and not has_on_chain:
        status = DiffStatus.NO_LOCAL
        in_sync = True
    elif not has_local and has_on_chain:
        status = DiffStatus.REMOTE_AHEAD
        in_sync = False
    elif has_local and not has_on_chain:
        status = DiffStatus.NO_REMOTE
        in_sync = False
    elif local_hash == on_chain_hash:
        status = DiffStatus.IN_SYNC
        in_sync = True
    else:
        # Both exist, hashes differ. Check frontmatter config_hash for directionality.
        status = DiffStatus.DIVERGED
        in_sync = False

        if has_local:
            try:
                content = path.read_text(encoding="utf-8")
                parsed = parse_agirails_md(content)
                fm_hash = parsed.frontmatter.get("config_hash")
                if not fm_hash:
                    # Never published from this file -> local is the only source
                    status = DiffStatus.LOCAL_AHEAD
                elif fm_hash == on_chain_hash:
                    # Last publish matches on-chain, local edits are newer
                    status = DiffStatus.LOCAL_AHEAD
                # else: fm config_hash != on-chain hash -> remote updated -> diverged
            except (ValueError, KeyError):
                pass  # Parse error -> keep as diverged

    return DiffResult(
        in_sync=in_sync,
        local_hash=local_hash,
        on_chain_hash=on_chain_hash,
        on_chain_cid=on_chain_cid,
        has_on_chain_config=has_on_chain,
        has_local_file=has_local,
        status=status,
    )


# ============================================================================
# IPFS Fetch
# ============================================================================


def fetch_from_ipfs(cid: str) -> str:
    """Fetch content from IPFS using public gateways.

    Tries multiple gateways with fallback. No Filebase credentials needed.

    Args:
        cid: IPFS CID to fetch.

    Returns:
        Raw content as string.

    Raises:
        RuntimeError: If all gateways fail.
    """
    errors: list[str] = []

    for gateway in IPFS_GATEWAYS:
        try:
            response = httpx.get(
                f"{gateway}{cid}",
                timeout=IPFS_FETCH_TIMEOUT,
                follow_redirects=True,
            )
            if response.status_code == 200:
                return response.text
            errors.append(f"{gateway}: HTTP {response.status_code}")
        except Exception as e:
            errors.append(f"{gateway}: {e}")

    error_list = "\n  - ".join(errors)
    raise RuntimeError(
        f"Failed to fetch CID {cid} from all IPFS gateways:\n  - {error_list}"
    )


# ============================================================================
# Pull
# ============================================================================


def pull_config(
    local_path: str,
    on_chain: OnChainConfigReader,
    force: bool = False,
) -> PullResult:
    """Pull on-chain config to local AGIRAILS.md.

    Downloads from IPFS via public gateways (no credentials needed),
    verifies integrity against on-chain configHash, then writes locally.

    Args:
        local_path: Path to local AGIRAILS.md file.
        on_chain: On-chain config reader with hash and CID.
        force: Overwrite local file without confirmation check.

    Returns:
        PullResult with written status and content.
    """
    diff_result = diff_config(local_path, on_chain)

    if not diff_result.has_on_chain_config:
        return PullResult(
            written=False,
            status="No config published on-chain for this agent.",
        )

    if diff_result.in_sync:
        return PullResult(
            written=False,
            status="Already in sync. No changes needed.",
        )

    # Fetch from IPFS
    content = fetch_from_ipfs(diff_result.on_chain_cid)

    # Integrity verification
    downloaded = compute_config_hash(content)
    if downloaded.config_hash != diff_result.on_chain_hash:
        return PullResult(
            written=False,
            cid=diff_result.on_chain_cid,
            status=(
                f"Integrity check failed! Downloaded content hash "
                f"({downloaded.config_hash}) does not match on-chain hash "
                f"({diff_result.on_chain_hash}). The IPFS content may have "
                f"been tampered with."
            ),
        )

    # Check if local file exists and we're not forcing
    if diff_result.has_local_file and not force:
        return PullResult(
            written=False,
            content=content,
            cid=diff_result.on_chain_cid,
            status=(
                f"Remote config differs from local. Use --force to overwrite. "
                f"CID: {diff_result.on_chain_cid}"
            ),
        )

    # Stamp on-chain metadata into frontmatter
    parsed = parse_agirails_md(content)
    stamped = serialize_agirails_md(
        {
            **parsed.frontmatter,
            "config_hash": diff_result.on_chain_hash,
            "config_cid": diff_result.on_chain_cid,
        },
        parsed.body,
    )

    Path(local_path).write_text(stamped, encoding="utf-8")

    return PullResult(
        written=True,
        content=stamped,
        cid=diff_result.on_chain_cid,
        status=f"Pulled and verified config from IPFS ({diff_result.on_chain_cid}) -> {local_path}",
    )


__all__ = [
    "DiffResult",
    "DiffStatus",
    "OnChainConfigReader",
    "PullResult",
    "diff_config",
    "fetch_from_ipfs",
    "pull_config",
    "ZERO_HASH",
]
