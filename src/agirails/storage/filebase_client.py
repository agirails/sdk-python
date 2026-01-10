"""
Filebase Client - IPFS Hot Storage (AIP-7 §4 Tier 1)

S3-compatible IPFS client using Filebase for hot storage.
Provides automatic pinning, content addressing, and gateway retrieval.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from agirails.errors.storage import (
    CircuitBreakerOpenError,
    FilebaseDownloadError,
    FilebaseError,
    FilebaseUploadError,
    FileSizeLimitError,
    InvalidCIDError,
    SSRFProtectionError,
)
from agirails.storage.types import (
    CircuitBreakerConfig,
    DownloadResult,
    FilebaseConfig,
    IPFSUploadResult,
)
from agirails.utils.circuit_breaker import CircuitBreaker
from agirails.utils.retry import RetryConfig, retry_async
from agirails.utils.validation import (
    ALLOWED_IPFS_GATEWAYS,
    is_gateway_allowed,
    sanitize_for_logging,
    validate_cid,
)


class FilebaseClient:
    """
    IPFS hot storage client using Filebase S3-compatible API.

    Features:
    - S3-compatible uploads to IPFS via Filebase
    - Circuit breaker for gateway health tracking
    - Retry with exponential backoff
    - SSRF protection (gateway whitelist)
    - DoS protection (size limits)

    Example:
        ```python
        from agirails.storage import FilebaseClient, FilebaseConfig

        client = FilebaseClient(FilebaseConfig(
            access_key=os.environ["FILEBASE_ACCESS_KEY"],
            secret_key=os.environ["FILEBASE_SECRET_KEY"],
        ))

        # Upload JSON
        result = await client.upload_json({"key": "value"})
        print(f"Uploaded to IPFS: {result.cid}")

        # Download
        data = await client.download(result.cid)
        ```
    """

    def __init__(self, config: FilebaseConfig) -> None:
        """
        Initialize Filebase client.

        Args:
            config: Filebase configuration
        """
        self._config = config
        self._circuit_breaker = CircuitBreaker(
            config.circuit_breaker or CircuitBreakerConfig()
        )
        self._retry_config = RetryConfig(
            max_attempts=3,
            base_delay_ms=1000,
            retryable_errors=(FilebaseError, httpx.TransportError),
        )

    @property
    def bucket(self) -> str:
        """Get configured bucket name."""
        return self._config.bucket

    @property
    def gateway_url(self) -> str:
        """Get configured gateway URL."""
        return self._config.gateway_url

    @property
    def circuit_breaker_state(self) -> str:
        """Get current circuit breaker state."""
        return self._circuit_breaker.state.value

    async def upload(
        self,
        content: bytes,
        filename: Optional[str] = None,
        content_type: str = "application/octet-stream",
    ) -> IPFSUploadResult:
        """
        Upload content to IPFS via Filebase.

        Args:
            content: Raw bytes to upload
            filename: Optional filename (defaults to content hash)
            content_type: MIME type of content

        Returns:
            IPFSUploadResult with CID and metadata

        Raises:
            FileSizeLimitError: If content exceeds max_file_size
            FilebaseUploadError: If upload fails
            CircuitBreakerOpenError: If circuit breaker is open
        """
        # Size check (P1-1: DoS protection)
        if len(content) > self._config.max_file_size:
            raise FileSizeLimitError(
                f"Content size {len(content)} exceeds limit {self._config.max_file_size}",
                file_size=len(content),
                max_size=self._config.max_file_size,
            )

        # Generate filename from content hash if not provided
        if not filename:
            content_hash = hashlib.sha256(content).hexdigest()[:16]
            filename = f"{content_hash}.bin"

        async def do_upload() -> IPFSUploadResult:
            # Use httpx with S3 signing
            # Note: For production, use aioboto3 for proper AWS S3 signing
            # This is a simplified implementation using httpx
            url = f"{self._config.endpoint}/{self._config.bucket}/{filename}"

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout / 1000)
            ) as client:
                # Filebase S3-compatible upload
                # In production, use proper AWS Signature V4
                response = await client.put(
                    url,
                    content=content,
                    headers={
                        "Content-Type": content_type,
                        "x-amz-acl": "public-read",
                    },
                    auth=(self._config.access_key, self._config.secret_key),
                )

                if response.status_code not in (200, 201):
                    raise FilebaseUploadError(
                        f"Upload failed: HTTP {response.status_code}",
                        bucket=self._config.bucket,
                        key=filename,
                    )

                # Get CID from response headers
                cid = response.headers.get("x-amz-meta-cid")
                if not cid:
                    # Fallback: Try HEAD request
                    head_response = await client.head(
                        url,
                        auth=(self._config.access_key, self._config.secret_key),
                    )
                    cid = head_response.headers.get("x-amz-meta-cid")

                if not cid:
                    raise FilebaseUploadError(
                        "Failed to get CID from Filebase response",
                        bucket=self._config.bucket,
                        key=filename,
                    )

                return IPFSUploadResult(
                    cid=cid,
                    size=len(content),
                    uploaded_at=datetime.now(timezone.utc),
                )

        try:
            return await self._circuit_breaker.execute(
                lambda: retry_async(do_upload, self._retry_config)
            )
        except CircuitBreakerOpenError:
            raise CircuitBreakerOpenError(
                "IPFS gateway circuit breaker is open",
                gateway=self._config.gateway_url,
            )

    async def upload_json(
        self,
        data: Dict[str, Any],
        filename: Optional[str] = None,
    ) -> IPFSUploadResult:
        """
        Upload JSON data to IPFS.

        Args:
            data: Dictionary to serialize as JSON
            filename: Optional filename

        Returns:
            IPFSUploadResult with CID
        """
        # Canonical JSON (sorted keys, minimal whitespace)
        content = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()

        if not filename:
            content_hash = hashlib.sha256(content).hexdigest()[:16]
            filename = f"{content_hash}.json"

        return await self.upload(
            content,
            filename=filename,
            content_type="application/json",
        )

    async def download(
        self,
        cid: str,
        gateway_url: Optional[str] = None,
    ) -> DownloadResult:
        """
        Download content from IPFS by CID.

        Args:
            cid: IPFS CID (CIDv0 or CIDv1)
            gateway_url: Optional custom gateway (must be whitelisted)

        Returns:
            DownloadResult with data and metadata

        Raises:
            InvalidCIDError: If CID format is invalid
            SSRFProtectionError: If gateway is not whitelisted
            FileSizeLimitError: If content exceeds max_download_size
            FilebaseDownloadError: If download fails
        """
        # Validate CID format
        if not validate_cid(cid):
            raise InvalidCIDError(
                cid,
                reason="Invalid CID format (must be CIDv0 or CIDv1)",
            )

        # SSRF protection: Validate gateway
        gateway = gateway_url or self._config.gateway_url
        if not is_gateway_allowed(gateway):
            raise SSRFProtectionError(
                sanitize_for_logging(gateway),
                reason="Gateway not in whitelist",
            )

        # Construct URL
        url = f"{gateway.rstrip('/')}/{cid}"

        async def do_download() -> DownloadResult:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout / 1000),
                follow_redirects=True,
            ) as client:
                # Stream response to check size before loading
                async with client.stream("GET", url) as response:
                    if response.status_code == 404:
                        raise FilebaseDownloadError(
                            f"Content not found: {cid}",
                            cid=cid,
                            gateway=gateway,
                        )

                    if response.status_code != 200:
                        raise FilebaseDownloadError(
                            f"Download failed: HTTP {response.status_code}",
                            cid=cid,
                            gateway=gateway,
                        )

                    # Check Content-Length header first (P1-1: DoS protection)
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        size = int(content_length)
                        if size > self._config.max_download_size:
                            raise FileSizeLimitError(
                                f"Content size {size} exceeds limit {self._config.max_download_size}",
                                file_size=size,
                                max_size=self._config.max_download_size,
                            )

                    # Stream download with size check
                    chunks = []
                    total_size = 0

                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        total_size += len(chunk)

                        # Check size limit during download
                        if total_size > self._config.max_download_size:
                            raise FileSizeLimitError(
                                f"Content size exceeds limit {self._config.max_download_size}",
                                file_size=total_size,
                                max_size=self._config.max_download_size,
                            )

                        chunks.append(chunk)

                    data = b"".join(chunks)

                    return DownloadResult(
                        data=data,
                        size=len(data),
                        downloaded_at=datetime.now(timezone.utc),
                    )

        try:
            return await self._circuit_breaker.execute(
                lambda: retry_async(do_download, self._retry_config)
            )
        except CircuitBreakerOpenError:
            raise CircuitBreakerOpenError(
                "IPFS gateway circuit breaker is open",
                gateway=gateway,
            )

    async def download_json(
        self,
        cid: str,
        gateway_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Download and parse JSON from IPFS.

        Args:
            cid: IPFS CID
            gateway_url: Optional custom gateway

        Returns:
            Parsed JSON as dictionary
        """
        result = await self.download(cid, gateway_url)
        return json.loads(result.data.decode("utf-8"))

    async def pin(self, cid: str) -> bool:
        """
        Pin content on Filebase (prevents garbage collection).

        Note: Filebase auto-pins uploaded content. This is for
        pinning content uploaded elsewhere.

        Args:
            cid: IPFS CID to pin

        Returns:
            True if successful

        Raises:
            NotImplementedError: External pinning not yet supported
        """
        # Filebase pins automatically on upload
        # For external CIDs, we'd need to use their pinning API
        raise NotImplementedError("External pinning not yet supported")

    async def unpin(self, cid: str) -> bool:
        """
        Unpin content from Filebase.

        Args:
            cid: IPFS CID to unpin

        Returns:
            True if successful

        Raises:
            NotImplementedError: Unpinning not yet supported
        """
        raise NotImplementedError("Unpinning not yet supported")

    def get_gateway_url(self, cid: str) -> str:
        """
        Get the full gateway URL for a CID.

        Args:
            cid: IPFS CID

        Returns:
            Full gateway URL
        """
        return f"{self._config.gateway_url.rstrip('/')}/{cid}"

    def get_stats(self) -> dict:
        """
        Get client statistics.

        Returns:
            Dictionary with client stats and circuit breaker state
        """
        return {
            "bucket": self._config.bucket,
            "gateway_url": self._config.gateway_url,
            "max_file_size": self._config.max_file_size,
            "max_download_size": self._config.max_download_size,
            "circuit_breaker": self._circuit_breaker.get_stats(),
        }
