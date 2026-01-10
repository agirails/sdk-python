"""
Storage-related exceptions for ACTP protocol (AIP-7).

These exceptions are raised during interactions with
decentralized storage systems like IPFS or Irys.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agirails.errors.base import ACTPError


class StorageError(ACTPError):
    """
    Base exception for storage operations.

    Example:
        >>> raise StorageError("Failed to connect to IPFS gateway")
    """

    def __init__(
        self,
        message: str,
        *,
        cid: Optional[str] = None,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if cid:
            details["cid"] = cid
        if gateway:
            details["gateway"] = gateway

        super().__init__(
            message,
            code="STORAGE_ERROR",
            details=details,
        )
        self.cid = cid
        self.gateway = gateway


class InvalidCIDError(StorageError):
    """
    Raised when a Content Identifier (CID) is invalid.

    Example:
        >>> raise InvalidCIDError("not-a-valid-cid")
    """

    def __init__(
        self,
        cid: str,
        *,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if reason:
            details["reason"] = reason

        message = f"Invalid CID: {cid}"
        if reason:
            message += f" ({reason})"

        super().__init__(
            message,
            cid=cid,
            details=details,
        )
        self.code = "INVALID_CID"
        self.reason = reason


class UploadTimeoutError(StorageError):
    """
    Raised when a storage upload times out.

    Example:
        >>> raise UploadTimeoutError(30000, file_size=1048576)
    """

    def __init__(
        self,
        timeout_ms: int,
        *,
        file_size: Optional[int] = None,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["timeout_ms"] = timeout_ms
        if file_size is not None:
            details["file_size_bytes"] = file_size

        super().__init__(
            f"Upload timed out after {timeout_ms}ms",
            gateway=gateway,
            details=details,
        )
        self.code = "UPLOAD_TIMEOUT"
        self.timeout_ms = timeout_ms
        self.file_size = file_size


class DownloadTimeoutError(StorageError):
    """
    Raised when a storage download times out.

    Example:
        >>> raise DownloadTimeoutError("bafybeie5...", 30000)
    """

    def __init__(
        self,
        cid: str,
        timeout_ms: int,
        *,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["timeout_ms"] = timeout_ms

        super().__init__(
            f"Download timed out after {timeout_ms}ms for CID: {cid}",
            cid=cid,
            gateway=gateway,
            details=details,
        )
        self.code = "DOWNLOAD_TIMEOUT"
        self.timeout_ms = timeout_ms


class FileSizeLimitExceededError(StorageError):
    """
    Raised when a file exceeds the maximum allowed size.

    Example:
        >>> raise FileSizeLimitExceededError(10485760, 5242880)
    """

    def __init__(
        self,
        file_size: int,
        max_size: int,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["file_size_bytes"] = file_size
        details["max_size_bytes"] = max_size
        details["excess_bytes"] = file_size - max_size

        super().__init__(
            f"File size ({file_size} bytes) exceeds limit ({max_size} bytes)",
            details=details,
        )
        self.code = "FILE_SIZE_LIMIT_EXCEEDED"
        self.file_size = file_size
        self.max_size = max_size


class StorageAuthenticationError(StorageError):
    """
    Raised when storage authentication fails.

    Example:
        >>> raise StorageAuthenticationError("Invalid API key")
    """

    def __init__(
        self,
        message: str = "Storage authentication failed",
        *,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message,
            gateway=gateway,
            details=details,
        )
        self.code = "STORAGE_AUTH_ERROR"


class StorageRateLimitError(StorageError):
    """
    Raised when storage rate limit is exceeded.

    Example:
        >>> raise StorageRateLimitError(60000, gateway="https://gateway.ipfs.io")
    """

    def __init__(
        self,
        retry_after_ms: Optional[int] = None,
        *,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if retry_after_ms is not None:
            details["retry_after_ms"] = retry_after_ms

        message = "Storage rate limit exceeded"
        if retry_after_ms:
            message += f" (retry after {retry_after_ms}ms)"

        super().__init__(
            message,
            gateway=gateway,
            details=details,
        )
        self.code = "STORAGE_RATE_LIMIT"
        self.retry_after_ms = retry_after_ms


class ContentNotFoundError(StorageError):
    """
    Raised when content cannot be found in storage.

    Example:
        >>> raise ContentNotFoundError("bafybeie5...")
    """

    def __init__(
        self,
        cid: str,
        *,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            f"Content not found: {cid}",
            cid=cid,
            gateway=gateway,
            details=details,
        )
        self.code = "CONTENT_NOT_FOUND"


# ============================================================================
# Filebase-specific Errors
# ============================================================================


class FilebaseError(StorageError):
    """
    Base exception for Filebase operations.

    Example:
        >>> raise FilebaseError("Connection to Filebase failed")
    """

    def __init__(
        self,
        message: str,
        *,
        bucket: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if bucket:
            details["bucket"] = bucket

        super().__init__(message, details=details)
        self.code = "FILEBASE_ERROR"
        self.bucket = bucket


class FilebaseUploadError(FilebaseError):
    """
    Raised when uploading to Filebase fails.

    Example:
        >>> raise FilebaseUploadError("Upload failed: bucket not found")
    """

    def __init__(
        self,
        message: str = "Filebase upload failed",
        *,
        bucket: Optional[str] = None,
        key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if key:
            details["key"] = key

        super().__init__(message, bucket=bucket, details=details)
        self.code = "FILEBASE_UPLOAD_ERROR"
        self.key = key


class FilebaseDownloadError(FilebaseError):
    """
    Raised when downloading from Filebase fails.

    Example:
        >>> raise FilebaseDownloadError("Download failed: CID not found")
    """

    def __init__(
        self,
        message: str = "Filebase download failed",
        *,
        cid: Optional[str] = None,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details=details)
        self.code = "FILEBASE_DOWNLOAD_ERROR"
        self.cid = cid
        self.gateway = gateway


# ============================================================================
# Arweave-specific Errors
# ============================================================================


class ArweaveError(StorageError):
    """
    Base exception for Arweave/Irys operations.

    Example:
        >>> raise ArweaveError("Connection to Irys node failed")
    """

    def __init__(
        self,
        message: str,
        *,
        node_url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if node_url:
            details["node_url"] = node_url

        super().__init__(message, details=details)
        self.code = "ARWEAVE_ERROR"
        self.node_url = node_url


class ArweaveUploadError(ArweaveError):
    """
    Raised when uploading to Arweave fails.

    Example:
        >>> raise ArweaveUploadError("Upload failed: insufficient funds")
    """

    def __init__(
        self,
        message: str = "Arweave upload failed",
        *,
        node_url: Optional[str] = None,
        size_bytes: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if size_bytes is not None:
            details["size_bytes"] = size_bytes

        super().__init__(message, node_url=node_url, details=details)
        self.code = "ARWEAVE_UPLOAD_ERROR"
        self.size_bytes = size_bytes


class ArweaveDownloadError(ArweaveError):
    """
    Raised when downloading from Arweave fails.

    Example:
        >>> raise ArweaveDownloadError("Transaction not found")
    """

    def __init__(
        self,
        message: str = "Arweave download failed",
        *,
        tx_id: Optional[str] = None,
        gateway: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if tx_id:
            details["tx_id"] = tx_id
        if gateway:
            details["gateway"] = gateway

        super().__init__(message, details=details)
        self.code = "ARWEAVE_DOWNLOAD_ERROR"
        self.tx_id = tx_id
        self.gateway = gateway


class InsufficientFundsError(ArweaveError):
    """
    Raised when Irys balance is insufficient for upload.

    Example:
        >>> raise InsufficientFundsError(1000000, 5000000)
    """

    def __init__(
        self,
        balance: int,
        required: int,
        *,
        currency: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["balance"] = balance
        details["required"] = required
        details["deficit"] = required - balance
        if currency:
            details["currency"] = currency

        message = f"Insufficient Irys balance: {balance} < {required}"
        super().__init__(message, details=details)
        self.code = "INSUFFICIENT_FUNDS"
        self.balance = balance
        self.required = required
        self.currency = currency


# ============================================================================
# Security Errors
# ============================================================================


class SSRFProtectionError(StorageError):
    """
    Raised when a URL fails SSRF protection checks.

    Example:
        >>> raise SSRFProtectionError("https://evil.com/ipfs/Qm...")
    """

    def __init__(
        self,
        url: str,
        *,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["url"] = url
        if reason:
            details["reason"] = reason

        message = f"SSRF protection: URL not allowed: {url}"
        if reason:
            message += f" ({reason})"

        super().__init__(message, details=details)
        self.code = "SSRF_PROTECTION_ERROR"
        self.url = url
        self.reason = reason


class FileSizeLimitError(StorageError):
    """
    Raised when file size exceeds configured limits.

    Alias for FileSizeLimitExceededError for API compatibility.

    Example:
        >>> raise FileSizeLimitError("Content size 100MB exceeds limit 50MB")
    """

    def __init__(
        self,
        message: str,
        *,
        file_size: Optional[int] = None,
        max_size: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if file_size is not None:
            details["file_size_bytes"] = file_size
        if max_size is not None:
            details["max_size_bytes"] = max_size
        if file_size is not None and max_size is not None:
            details["excess_bytes"] = file_size - max_size

        super().__init__(message, details=details)
        self.code = "FILE_SIZE_LIMIT"
        self.file_size = file_size
        self.max_size = max_size


class CircuitBreakerOpenError(StorageError):
    """
    Raised when circuit breaker is open and blocking requests.

    Example:
        >>> raise CircuitBreakerOpenError("Gateway unhealthy")
    """

    def __init__(
        self,
        message: str = "Circuit breaker is open",
        *,
        gateway: Optional[str] = None,
        reset_at: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if reset_at is not None:
            details["reset_at"] = reset_at

        super().__init__(message, gateway=gateway, details=details)
        self.code = "CIRCUIT_BREAKER_OPEN"
        self.reset_at = reset_at


# ============================================================================
# Archive Bundle Errors
# ============================================================================


class ArchiveBundleValidationError(StorageError):
    """
    Raised when archive bundle validation fails.

    Example:
        >>> raise ArchiveBundleValidationError("Missing required field: tx_id")
    """

    def __init__(
        self,
        message: str,
        *,
        field: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field

        super().__init__(message, details=details)
        self.code = "ARCHIVE_BUNDLE_VALIDATION_ERROR"
        self.field = field
