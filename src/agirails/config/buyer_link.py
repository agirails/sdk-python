"""Buyer Link Module — gasless gate marker for pure buyers (AIP-18).

A pure buyer (``intent: pay``) never registers on AgentRegistry and therefore
has no on-chain ``configHash`` and no ``pending-publish`` file (DEC-3/DEC-4).
Without a signal the SDK's auto-wallet gate (see ACTPClient) would fall back to
the EOA wallet and the buyer would have to fund ETH — contradicting DEC-8
("buyers are gasless, they need only USDC").

When ``actp publish`` LINKS a pay-only agent, it writes this marker. The gate
treats its presence the same way it treats a pending-publish: proof of a
legitimate AGIRAILS agent, so the sponsored auto wallet is used. Unlike
pending-publish it triggers NO lazy on-chain activation — a buyer never
registers.

The marker is intentionally network-agnostic (one ``buyer-link.json``): an
agent's buyer intent does not change between testnet and mainnet, and a buyer's
only costly on-chain action — ``pay()`` — locks USDC in escrow, which is itself
the anti-DOS backstop (see threat-model). So granting the sponsored wallet on
this marker does not open a free-gas vector.

Mirrors TS ``config/buyerLink.ts`` (BuyerLink, save_buyer_link, load_buyer_link,
has_buyer_link, delete_buyer_link, get_buyer_link_path). Writes are atomic
(write-to-tmp + os.rename, mode 0o600) and symlink-safe — reusing
``pending_publish``'s ``get_actp_dir`` for path resolution (ACTP_DIR env or
``cwd/.actp``).

@module config/buyer_link
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from agirails.config.pending_publish import SecurityError, get_actp_dir


# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class BuyerLink:
    """Buyer link state — saved to ``.actp/buyer-link.json``.

    Mirrors TS ``BuyerLink`` interface (config/buyerLink.ts:36-45).
    """

    # The agent's slug (for debuggability / dashboard linking)
    slug: str
    # The signer/EOA (or Smart Wallet) address that performed the link
    wallet: str
    # ISO 8601 timestamp of when the link was created
    linked_at: str
    # Schema version
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the on-disk JSON shape (camelCase, version first).

        Field order matches TS so the JSON is byte-comparable: version, slug,
        wallet, linkedAt.
        """
        return {
            "version": self.version,
            "slug": self.slug,
            "wallet": self.wallet,
            "linkedAt": self.linked_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BuyerLink":
        """Deserialize from the on-disk JSON shape."""
        return cls(
            version=int(data.get("version", 1)),
            slug=str(data.get("slug", "")),
            wallet=str(data.get("wallet", "")),
            linked_at=str(data.get("linkedAt", "")),
        )


# ============================================================================
# Helpers
# ============================================================================


def _now_iso() -> str:
    """ISO 8601 UTC timestamp with millisecond precision + 'Z' (match JS Date)."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ============================================================================
# Public API
# ============================================================================


def get_buyer_link_path(actp_dir: Optional[str] = None) -> str:
    """Path to the buyer-link marker. Network-agnostic by design.

    Mirrors TS ``getBuyerLinkPath`` (config/buyerLink.ts:59-61).

    Args:
        actp_dir: The ``.actp`` directory to use. Defaults to ``get_actp_dir()``
            (ACTP_DIR env or ``cwd/.actp``). ``actp publish`` passes the project
            root of the published ``{slug}.md`` so the marker lands beside that
            agent's config — not in whatever directory the command ran from.

    Returns:
        Absolute path to ``buyer-link.json``.
    """
    return os.path.join(get_actp_dir(actp_dir), "buyer-link.json")


def save_buyer_link(link: BuyerLink, actp_dir: Optional[str] = None) -> str:
    """Save the buyer-link marker to ``{actp_dir}/buyer-link.json``.

    Mirrors TS ``saveBuyerLink`` (config/buyerLink.ts:69-92): creates the dir if
    missing, refuses to write through a symlinked directory, and writes
    atomically with mode 0o600.

    Args:
        link: Buyer link state to save.
        actp_dir: Explicit ``.actp`` directory override.

    Returns:
        Path to the written file.

    Raises:
        SecurityError: If the ``.actp`` directory (or target file) is a symlink
            or is not a directory.
    """
    dir_path = get_actp_dir(actp_dir)

    # Verify the dir is real (symlink-attack prevention) — use os.lstat so a
    # symlinked or broken-symlink dir is rejected, not followed.
    dir_exists = False
    if os.path.lexists(dir_path):
        st = os.lstat(dir_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise SecurityError(
                f"Security: {dir_path} is not a real directory "
                f"(symlink attack prevention)"
            )
        dir_exists = True
    if not dir_exists:
        os.makedirs(dir_path, mode=0o700, exist_ok=True)

    file_path = get_buyer_link_path(dir_path)

    # Symlink check on target file itself.
    if os.path.lexists(file_path):
        st = os.lstat(file_path)
        if stat.S_ISLNK(st.st_mode):
            raise SecurityError(
                f"Security: {file_path} is a symbolic link "
                f"(symlink attack prevention)"
            )

    tmp_path = file_path + ".tmp"
    content = json.dumps(link.to_dict(), indent=2)

    # Atomic write: write to .tmp (mode 0o600), then rename.
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)

    os.rename(tmp_path, file_path)

    return file_path


def load_buyer_link(
    network: Optional[str] = None, actp_dir: Optional[str] = None
) -> Optional[BuyerLink]:
    """Load the buyer-link marker, or None if the agent is not a linked buyer.

    Mirrors TS ``loadBuyerLink`` (config/buyerLink.ts:103-112).

    Args:
        network: Accepted for call-site symmetry with ``load_pending_publish``;
            the marker is network-agnostic so the argument is ignored.
        actp_dir: The ``.actp`` directory to read from. Defaults to
            ``get_actp_dir()`` — at runtime ACTPClient runs from the project
            root, so the default matches where ``actp publish`` wrote it.

    Returns:
        The BuyerLink, or None if absent/corrupt.
    """
    file_path = get_buyer_link_path(actp_dir)
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return BuyerLink.from_dict(json.load(f))
    except Exception:
        # Corrupt marker → treat as absent rather than crash client creation.
        return None


def has_buyer_link(
    network: Optional[str] = None, actp_dir: Optional[str] = None
) -> bool:
    """Whether a buyer-link marker exists.

    Mirrors TS ``hasBuyerLink`` (config/buyerLink.ts:115-117).
    """
    return load_buyer_link(network, actp_dir) is not None


def delete_buyer_link(actp_dir: Optional[str] = None) -> None:
    """Delete the buyer-link marker. Best-effort — never raises.

    Mirrors TS ``deleteBuyerLink`` (config/buyerLink.ts:125-132). Called when an
    agent transitions away from pure-buyer (e.g. it now publishes a provider
    config and gains a real configHash), so the marker doesn't linger.
    """
    try:
        file_path = get_buyer_link_path(actp_dir)
        if os.path.exists(file_path):
            os.unlink(file_path)
    except Exception:
        # Best-effort cleanup.
        pass
