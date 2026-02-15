"""Pending Publish Module - Deferred on-chain activation for Lazy Publish.

When ``actp publish`` runs, it saves a ``pending-publish.{network}.json`` file
instead of making on-chain calls.  The first real payment triggers activation
(registerAgent, publishConfig, setListed) in a single UserOp alongside the
payment calls.

Files are chain-scoped: testnet and mainnet pending publishes coexist
independently.  Legacy ``pending-publish.json`` (unscoped) is supported for
migration.

The file is deleted after successful on-chain activation.

Security:
  - Atomic writes (write-to-tmp + os.rename) prevent partial reads.
  - File mode 0o600 (owner read/write only).
  - Symlink attack prevention via os.lstat before write.
  - ``ACTP_DIR`` env var override for custom locations.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================================
# Types
# ============================================================================


@dataclass
class ServiceDescriptorData:
    """Serializable service descriptor for pending publish state."""

    service_type_hash: str
    service_type: str
    schema_uri: str = ""
    min_price: str = "0"
    max_price: str = "0"
    avg_completion_time: int = 3600
    metadata_cid: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "serviceTypeHash": self.service_type_hash,
            "serviceType": self.service_type,
            "schemaURI": self.schema_uri,
            "minPrice": self.min_price,
            "maxPrice": self.max_price,
            "avgCompletionTime": self.avg_completion_time,
            "metadataCID": self.metadata_cid,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceDescriptorData":
        return cls(
            service_type_hash=data.get("serviceTypeHash", ""),
            service_type=data.get("serviceType", ""),
            schema_uri=data.get("schemaURI", ""),
            min_price=str(data.get("minPrice", "0")),
            max_price=str(data.get("maxPrice", "0")),
            avg_completion_time=int(data.get("avgCompletionTime", 3600)),
            metadata_cid=data.get("metadataCID", ""),
        )


@dataclass
class PendingPublishData:
    """Pending publish state - saved to ``.actp/pending-publish.{network}.json``."""

    version: int = 1
    config_hash: str = ""
    cid: str = ""
    endpoint: str = ""
    service_descriptors: List[ServiceDescriptorData] = field(default_factory=list)
    created_at: str = ""
    network: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "version": self.version,
            "configHash": self.config_hash,
            "cid": self.cid,
            "endpoint": self.endpoint,
            "serviceDescriptors": [sd.to_dict() for sd in self.service_descriptors],
            "createdAt": self.created_at or datetime.now(timezone.utc).isoformat(),
        }
        if self.network:
            result["network"] = self.network
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PendingPublishData":
        descriptors = [
            ServiceDescriptorData.from_dict(sd)
            for sd in data.get("serviceDescriptors", [])
        ]
        return cls(
            version=data.get("version", 1),
            config_hash=data.get("configHash", ""),
            cid=data.get("cid", ""),
            endpoint=data.get("endpoint", ""),
            service_descriptors=descriptors,
            created_at=data.get("createdAt", ""),
            network=data.get("network"),
        )


# ============================================================================
# Helpers
# ============================================================================


def get_actp_dir(actp_dir: Optional[str] = None) -> str:
    """Get the .actp directory path.

    Respects ``ACTP_DIR`` env var for custom locations.
    Defaults to ``{cwd}/.actp``.

    Args:
        actp_dir: Explicit override. Takes priority over env var.

    Returns:
        Absolute path to .actp directory.
    """
    if actp_dir:
        return os.path.abspath(actp_dir)
    env_dir = os.environ.get("ACTP_DIR")
    if env_dir:
        return os.path.abspath(env_dir)
    return os.path.join(os.getcwd(), ".actp")


def _get_pending_publish_path(network: Optional[str] = None, actp_dir: Optional[str] = None) -> str:
    """Get the path to a pending-publish file.

    Args:
        network: Optional network identifier (e.g. 'base-sepolia').
            If provided, returns ``pending-publish.{network}.json``.
            Otherwise returns legacy ``pending-publish.json``.
        actp_dir: Explicit .actp directory override.

    Returns:
        Absolute path to pending-publish JSON file.
    """
    base = get_actp_dir(actp_dir)
    if network:
        return os.path.join(base, f"pending-publish.{network}.json")
    return os.path.join(base, "pending-publish.json")


def _validate_directory(dir_path: str) -> None:
    """Validate that the directory is safe to write to.

    Checks for symlink attacks: the .actp directory must be a real
    directory, not a symbolic link.

    Args:
        dir_path: Path to validate.

    Raises:
        SecurityError: If the path is a symlink or not a directory.
    """
    if os.path.exists(dir_path):
        st = os.lstat(dir_path)
        if stat.S_ISLNK(st.st_mode):
            raise SecurityError(
                f"Security: {dir_path} is a symbolic link (symlink attack prevention)"
            )
        if not stat.S_ISDIR(st.st_mode):
            raise SecurityError(
                f"Security: {dir_path} is not a directory"
            )


class SecurityError(Exception):
    """Raised when a security check fails."""


# ============================================================================
# Public API
# ============================================================================


def save_pending_publish(
    data: PendingPublishData,
    network: Optional[str] = None,
    actp_dir: Optional[str] = None,
) -> str:
    """Save a pending publish to ``.actp/pending-publish.{network}.json``.

    Creates the .actp directory if it doesn't exist.
    File is written atomically (write-to-tmp + rename) with mode 0o600.

    Args:
        data: Pending publish data to save.
        network: Network identifier for chain-scoped file.
            Overrides ``data.network`` if provided.
        actp_dir: Explicit .actp directory override.

    Returns:
        Path to the written file.

    Raises:
        SecurityError: If .actp directory is a symlink.
    """
    effective_network = network or data.network
    dir_path = get_actp_dir(actp_dir)

    _validate_directory(dir_path)

    if not os.path.exists(dir_path):
        os.makedirs(dir_path, mode=0o700, exist_ok=True)

    file_path = _get_pending_publish_path(effective_network, actp_dir)
    tmp_path = file_path + ".tmp"

    # Symlink check on target file itself
    if os.path.exists(file_path):
        st = os.lstat(file_path)
        if stat.S_ISLNK(st.st_mode):
            raise SecurityError(
                f"Security: {file_path} is a symbolic link (symlink attack prevention)"
            )

    # Ensure network is recorded in the data
    serialized = data.to_dict()
    if effective_network and "network" not in serialized:
        serialized["network"] = effective_network

    content = json.dumps(serialized, indent=2)

    # Atomic write: write to .tmp, then rename
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)

    os.rename(tmp_path, file_path)

    return file_path


def load_pending_publish(
    network: Optional[str] = None,
    actp_dir: Optional[str] = None,
) -> Optional[PendingPublishData]:
    """Load a pending publish from ``.actp/pending-publish.{network}.json``.

    If ``network`` is provided:
      1. Try ``pending-publish.{network}.json``
      2. Fall back to legacy ``pending-publish.json`` (migration)

    If no ``network``: loads legacy ``pending-publish.json``.

    Args:
        network: Network identifier.
        actp_dir: Explicit .actp directory override.

    Returns:
        PendingPublishData or None if no file found.
    """
    # Try network-scoped file first
    if network:
        scoped_path = _get_pending_publish_path(network, actp_dir)
        if os.path.exists(scoped_path):
            with open(scoped_path, "r") as f:
                return PendingPublishData.from_dict(json.load(f))

    # Fall back to legacy file
    legacy_path = _get_pending_publish_path(None, actp_dir)
    if os.path.exists(legacy_path):
        with open(legacy_path, "r") as f:
            return PendingPublishData.from_dict(json.load(f))

    return None


def delete_pending_publish(
    network: Optional[str] = None,
    actp_dir: Optional[str] = None,
) -> None:
    """Delete the pending-publish file for a given network.

    Deletes both the network-scoped file and legacy file (cleanup).
    No-op if files don't exist. Best-effort -- never throws.

    Args:
        network: Network identifier.
        actp_dir: Explicit .actp directory override.
    """
    try:
        if network:
            scoped_path = _get_pending_publish_path(network, actp_dir)
            if os.path.exists(scoped_path):
                os.unlink(scoped_path)

        legacy_path = _get_pending_publish_path(None, actp_dir)
        if os.path.exists(legacy_path):
            os.unlink(legacy_path)
    except OSError:
        # Best-effort: file deletion should never crash post-payment UX
        pass


def has_pending_publish(
    network: Optional[str] = None,
    actp_dir: Optional[str] = None,
) -> bool:
    """Check if a pending-publish file exists.

    Args:
        network: Network identifier.
        actp_dir: Explicit .actp directory override.

    Returns:
        True if a pending-publish file exists for the given network.
    """
    if network:
        scoped_path = _get_pending_publish_path(network, actp_dir)
        if os.path.exists(scoped_path):
            return True

    legacy_path = _get_pending_publish_path(None, actp_dir)
    return os.path.exists(legacy_path)


__all__ = [
    "PendingPublishData",
    "ServiceDescriptorData",
    "SecurityError",
    "get_actp_dir",
    "save_pending_publish",
    "load_pending_publish",
    "delete_pending_publish",
    "has_pending_publish",
]
