"""Publish Pipeline - AGIRAILS.md -> IPFS -> On-Chain.

Orchestrates the publish flow:
  1. Read AGIRAILS.md -> parse -> compute configHash.
  2. Upload to Filebase (S3-compatible IPFS pinning) or publish proxy fallback.
  3. Save pending-publish for lazy mainnet activation.
  4. Update AGIRAILS.md frontmatter with config_hash and published_at.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from eth_utils import keccak

from agirails.config.agirailsmd import (
    compute_config_hash,
    parse_agirails_md,
    serialize_agirails_md,
)

logger = logging.getLogger("agirails.config.publish")

# ============================================================================
# Constants
# ============================================================================

PUBLISH_PROXY_URL = "https://publish.agirails.io"
PENDING_ENDPOINT = "https://pending.agirails.io"

# Service descriptor defaults
SERVICE_DEFAULTS = {
    "schema_uri": "",
    "min_price": 0,
    "max_price": 1_000_000_000,  # 1000 USDC
    "avg_completion_time": 3600,  # 1 hour
    "metadata_cid": "",
}


# ============================================================================
# Types
# ============================================================================


@dataclass
class PublishResult:
    """Result from the publish pipeline."""

    cid: str
    config_hash: str
    dry_run: bool = False


@dataclass
class FilebaseCredentials:
    """Filebase S3-compatible credentials."""

    access_key: str
    secret_key: str
    bucket: str
    endpoint: str = "https://s3.filebase.com"


@dataclass
class ServiceDescriptorInfo:
    """Extracted service descriptor from frontmatter."""

    service_type_hash: str
    service_type: str
    schema_uri: str = ""
    min_price: int = 0
    max_price: int = 1_000_000_000
    avg_completion_time: int = 3600
    metadata_cid: str = ""


# ============================================================================
# Registration Params Extraction
# ============================================================================


def _compute_type_hash(service_type: str) -> str:
    """Compute keccak256 hash of a service type string."""
    return "0x" + keccak(text=service_type).hex()


def extract_registration_params(
    frontmatter: Dict[str, Any],
) -> tuple[str, List[ServiceDescriptorInfo]]:
    """Extract registration params from AGIRAILS.md frontmatter.

    Supports two formats:
      - ``services``: full ServiceDescriptor objects with pricing.
      - ``capabilities``: simple string list, auto-converted with defaults.

    Args:
        frontmatter: Parsed YAML frontmatter dict.

    Returns:
        Tuple of (endpoint, list of ServiceDescriptorInfo).

    Raises:
        ValueError: If neither services nor capabilities are present.
    """
    endpoint = frontmatter.get("endpoint", PENDING_ENDPOINT)
    if not isinstance(endpoint, str) or not endpoint:
        endpoint = PENDING_ENDPOINT

    # Try explicit services first
    services = frontmatter.get("services")
    if isinstance(services, list) and services:
        descriptors = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            service_type = str(svc.get("type", svc.get("service_type", ""))).strip().lower()
            if not service_type:
                continue

            min_price = SERVICE_DEFAULTS["min_price"]
            max_price = SERVICE_DEFAULTS["max_price"]

            price = svc.get("price")
            if isinstance(price, str) and "-" in price:
                parts = price.split("-")
                min_price = int(float(parts[0]) * 1_000_000)
                max_price = int(float(parts[1]) * 1_000_000)
            else:
                if svc.get("min_price") is not None:
                    min_price = int(float(svc["min_price"]) * 1_000_000)
                if svc.get("max_price") is not None:
                    max_price = int(float(svc["max_price"]) * 1_000_000)

            descriptors.append(
                ServiceDescriptorInfo(
                    service_type_hash=_compute_type_hash(service_type),
                    service_type=service_type,
                    schema_uri=str(svc.get("schema_uri", svc.get("schemaURI", ""))),
                    min_price=min_price,
                    max_price=max_price,
                    avg_completion_time=int(
                        svc.get(
                            "avg_completion_time",
                            svc.get("avgCompletionTime", SERVICE_DEFAULTS["avg_completion_time"]),
                        )
                    ),
                    metadata_cid=str(svc.get("metadata_cid", svc.get("metadataCID", ""))),
                )
            )
        if descriptors:
            return endpoint, descriptors

    # Fallback: capabilities list
    capabilities = frontmatter.get("capabilities")
    if isinstance(capabilities, list) and capabilities:
        descriptors = []
        for cap in capabilities:
            service_type = str(cap).strip().lower()
            if not service_type:
                continue
            descriptors.append(
                ServiceDescriptorInfo(
                    service_type_hash=_compute_type_hash(service_type),
                    service_type=service_type,
                )
            )
        if descriptors:
            return endpoint, descriptors

    raise ValueError(
        'AGIRAILS.md must have "services" (with type field) or "capabilities" '
        "in frontmatter for agent registration."
    )


# ============================================================================
# IPFS Upload
# ============================================================================


def upload_to_filebase(
    content: str,
    credentials: FilebaseCredentials,
) -> str:
    """Upload content to Filebase (S3-compatible IPFS pinning).

    Args:
        content: Content to upload.
        credentials: Filebase S3 credentials.

    Returns:
        IPFS CID string.

    Raises:
        RuntimeError: If upload fails.
    """
    try:
        import boto3
    except ImportError:
        raise ImportError(
            "boto3 is required for Filebase upload. "
            "Install with: pip install boto3"
        )

    s3 = boto3.client(
        "s3",
        endpoint_url=credentials.endpoint,
        aws_access_key_id=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
    )

    key = f"agirails-config-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"

    s3.put_object(
        Bucket=credentials.bucket,
        Key=key,
        Body=content.encode("utf-8"),
        ContentType="text/markdown",
        Metadata={"type": "agirails-config", "version": "1.0"},
    )

    # Filebase returns CID in response headers
    head = s3.head_object(Bucket=credentials.bucket, Key=key)
    cid = head.get("Metadata", {}).get("cid")
    if not cid:
        # Fallback: check ResponseMetadata
        cid = head.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amz-meta-cid")
    if not cid:
        raise RuntimeError("Filebase did not return CID in response headers")

    return cid


def upload_via_proxy(
    content: str,
    config_hash: str,
    proxy_url: str = PUBLISH_PROXY_URL,
) -> str:
    """Upload content via the AGIRAILS publish proxy.

    The proxy handles IPFS pinning and returns a CID.

    Args:
        content: Content to upload.
        config_hash: Expected config hash for verification.
        proxy_url: Publish proxy URL.

    Returns:
        IPFS CID string.

    Raises:
        RuntimeError: If upload fails or hash mismatch.
    """
    response = httpx.post(
        f"{proxy_url}/api/publish",
        json={
            "content": content,
            "configHash": config_hash,
        },
        timeout=30.0,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Publish proxy returned HTTP {response.status_code}: {response.text}"
        )

    data = response.json()
    cid = data.get("cid")
    returned_hash = data.get("configHash")

    if not cid:
        raise RuntimeError("Publish proxy did not return a CID")

    if returned_hash and returned_hash != config_hash:
        raise RuntimeError(
            f"Hash mismatch! Local: {config_hash}, Proxy: {returned_hash}"
        )

    return cid


# ============================================================================
# Publish Pipeline
# ============================================================================


def publish_config(
    content: str,
    filebase_credentials: Optional[FilebaseCredentials] = None,
    proxy_url: str = PUBLISH_PROXY_URL,
    dry_run: bool = False,
) -> PublishResult:
    """Compute hash and upload AGIRAILS.md to IPFS.

    Uses Filebase if credentials are provided, otherwise falls back
    to the publish proxy.

    Args:
        content: Raw AGIRAILS.md file content.
        filebase_credentials: Optional Filebase S3 credentials.
        proxy_url: Publish proxy URL (fallback).
        dry_run: If True, compute hash but skip upload.

    Returns:
        PublishResult with CID and config hash.
    """
    hash_result = compute_config_hash(content)

    if dry_run:
        return PublishResult(
            cid="(dry-run)",
            config_hash=hash_result.config_hash,
            dry_run=True,
        )

    # Upload to IPFS
    if filebase_credentials:
        cid = upload_to_filebase(content, filebase_credentials)
    else:
        cid = upload_via_proxy(content, hash_result.config_hash, proxy_url)

    return PublishResult(
        cid=cid,
        config_hash=hash_result.config_hash,
        dry_run=False,
    )


def update_frontmatter_after_publish(
    content: str,
    config_hash: str,
    cid: str,
) -> str:
    """Update AGIRAILS.md frontmatter with publish metadata.

    Adds/updates config_hash, config_cid, and published_at fields.

    Args:
        content: Raw AGIRAILS.md content.
        config_hash: Computed config hash.
        cid: IPFS CID.

    Returns:
        Updated AGIRAILS.md content.
    """
    parsed = parse_agirails_md(content)
    updated_fm = {
        **parsed.frontmatter,
        "config_hash": config_hash,
        "config_cid": cid,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    return serialize_agirails_md(updated_fm, parsed.body)


__all__ = [
    "FilebaseCredentials",
    "PublishResult",
    "ServiceDescriptorInfo",
    "extract_registration_params",
    "publish_config",
    "update_frontmatter_after_publish",
    "upload_to_filebase",
    "upload_via_proxy",
    "PENDING_ENDPOINT",
    "PUBLISH_PROXY_URL",
]
