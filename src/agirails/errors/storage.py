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
