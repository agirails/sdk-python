"""
Filebase Client - IPFS Hot Storage (AIP-7 §4 Tier 1)

S3-compatible IPFS client using Filebase for hot storage.
Provides automatic pinning, content addressing, and gateway retrieval.

Parity note (TS source of truth: sdk-js/src/storage/FilebaseClient.ts):
The TypeScript client uses ``@aws-sdk/client-s3`` which signs every PUT/HEAD with
AWS Signature Version 4. Filebase's S3-compatible endpoint REQUIRES SigV4 and
rejects HTTP Basic auth with HTTP 403. This module therefore implements SigV4
natively over ``httpx`` (no boto3/botocore dependency) so uploads actually
authenticate. The canonical-request / signing-key derivation is verified against
AWS's published "Signature Version 4 test suite" get-vanilla vector and the
"derive signing key" worked example in ``tests/test_storage``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import quote, urlsplit

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


# AWS region used by Filebase S3-compatible endpoint (mirrors TS DEFAULT_REGION).
DEFAULT_REGION = "us-east-1"
# S3 service name for the SigV4 credential scope.
S3_SERVICE = "s3"
# SHA256 of an empty payload (precomputed for HEAD/GET requests).
EMPTY_PAYLOAD_HASH = hashlib.sha256(b"").hexdigest()


# ============================================================================
# AWS Signature Version 4 (native, no boto3)
# ============================================================================
#
# This implements the subset of SigV4 needed for S3 path-style PutObject /
# HeadObject requests against Filebase. It is intentionally dependency-free.
#
# References (verified by unit tests):
#   - "Signature Version 4 test suite" / get-vanilla example
#   - AWS docs "Examples of how to derive a signing key for Signature Version 4"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _derive_signing_key(
    secret_key: str, datestamp: str, region: str, service: str
) -> bytes:
    """Derive the SigV4 signing key (kSigning).

    Matches the AWS "derive a signing key" worked example byte-for-byte.
    """
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    k_signing = _hmac_sha256(k_service, "aws4_request")
    return k_signing


def _uri_encode_path(path: str) -> str:
    """URI-encode an S3 object key path for the canonical request.

    S3 does NOT double-encode the path (unlike most other services), so each
    path segment is percent-encoded but the ``/`` separators are preserved.
    ``~`` is left unencoded per RFC 3986 (``quote`` already keeps it via safe).
    """
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    # safe="/~" -> keep slashes and tilde; encode everything else.
    return quote(path, safe="/~")


def sign_aws_v4(
    *,
    method: str,
    url: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    headers: Optional[Dict[str, str]] = None,
    payload: bytes = b"",
    now: Optional[datetime] = None,
    sign_content_sha256: bool = True,
) -> Dict[str, str]:
    """Compute AWS Signature Version 4 headers for an S3-style request.

    Args:
        method: HTTP method (GET/PUT/HEAD/...).
        url: Full request URL (scheme://host[:port]/path[?query]).
        region: AWS region for the credential scope.
        service: AWS service name (``s3``).
        access_key: AWS access key id.
        secret_key: AWS secret access key.
        headers: Caller-supplied headers to include in the signature.
        payload: Raw request body (empty for GET/HEAD).
        now: Optional fixed timestamp (UTC) — used by tests for determinism.
        sign_content_sha256: Include ``x-amz-content-sha256`` in the SIGNED
            header set (True for real S3 / Filebase, which require it). Set
            False to reproduce the AWS "Signature Version 4 test suite"
            get-vanilla vector, which predates that header and signs only
            ``host;x-amz-date``. The header is still RETURNED either way.

    Returns:
        A new dict of headers including ``Authorization``,
        ``x-amz-date`` and ``x-amz-content-sha256`` (plus any provided headers).
    """
    parts = urlsplit(url)
    host = parts.netloc
    canonical_uri = _uri_encode_path(parts.path or "/")

    # Canonical query string: split, percent-encode, and sort by key then value.
    if parts.query:
        pairs = []
        for segment in parts.query.split("&"):
            if "=" in segment:
                k, v = segment.split("=", 1)
            else:
                k, v = segment, ""
            pairs.append(
                (
                    quote(k, safe="~"),
                    quote(v, safe="~"),
                )
            )
        pairs.sort()
        canonical_querystring = "&".join(f"{k}={v}" for k, v in pairs)
    else:
        canonical_querystring = ""

    dt = now or datetime.now(timezone.utc)
    amzdate = dt.strftime("%Y%m%dT%H%M%SZ")
    datestamp = dt.strftime("%Y%m%d")

    payload_hash = _sha256_hex(payload) if payload else EMPTY_PAYLOAD_HASH

    # Build the set of headers to sign. Host and x-amz-date are always signed;
    # x-amz-content-sha256 is signed for S3 (required) but can be excluded to
    # match the AWS test-suite get-vanilla vector. Content-Type is signed when
    # present (S3 expects it).
    sign_headers: Dict[str, str] = {
        "host": host,
        "x-amz-date": amzdate,
    }
    if sign_content_sha256:
        sign_headers["x-amz-content-sha256"] = payload_hash
    if headers:
        for name, value in headers.items():
            lname = name.lower()
            # Always sign content-type and any x-amz-* headers.
            if lname == "content-type" or lname.startswith("x-amz-"):
                sign_headers[lname] = str(value).strip()

    sorted_names = sorted(sign_headers.keys())
    canonical_headers = "".join(
        f"{name}:{sign_headers[name]}\n" for name in sorted_names
    )
    signed_headers = ";".join(sorted_names)

    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            algorithm,
            amzdate,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )

    signing_key = _derive_signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{algorithm} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    result_headers: Dict[str, str] = dict(headers or {})
    result_headers["x-amz-date"] = amzdate
    result_headers["x-amz-content-sha256"] = payload_hash
    result_headers["Authorization"] = authorization
    return result_headers


class FilebaseClient:
    """
    IPFS hot storage client using Filebase S3-compatible API.

    Features:
    - S3-compatible uploads to IPFS via Filebase (AWS SigV4 signed)
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
        self._region = DEFAULT_REGION
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

    def _sign(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: bytes = b"",
    ) -> Dict[str, str]:
        """Sign a request to the Filebase S3 endpoint with AWS SigV4.

        Returns a new headers dict that includes the ``Authorization`` header.
        """
        return sign_aws_v4(
            method=method,
            url=url,
            region=self._region,
            service=S3_SERVICE,
            access_key=self._config.access_key,
            secret_key=self._config.secret_key,
            headers=headers,
            payload=payload,
        )

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
            # Path-style S3 URL: {endpoint}/{bucket}/{key}
            url = f"{self._config.endpoint}/{self._config.bucket}/{filename}"

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout / 1000)
            ) as client:
                # AWS SigV4-signed PUT (Filebase rejects HTTP Basic auth).
                put_headers = self._sign(
                    "PUT",
                    url,
                    {
                        "Content-Type": content_type,
                        "x-amz-acl": "public-read",
                    },
                    payload=content,
                )
                response = await client.put(
                    url,
                    content=content,
                    headers=put_headers,
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
                    # Fallback: Try HEAD request (also SigV4-signed)
                    head_headers = self._sign("HEAD", url, {})
                    head_response = await client.head(
                        url,
                        headers=head_headers,
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
