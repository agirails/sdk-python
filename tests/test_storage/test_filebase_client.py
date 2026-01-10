"""
Tests for FilebaseClient IPFS operations.

Tests cover:
- Upload operations (JSON, binary)
- Download operations with SSRF protection
- Size limit enforcement
- Circuit breaker integration
- CID validation
- Gateway whitelist enforcement
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from agirails.storage.filebase_client import FilebaseClient
from agirails.storage.types import (
    FilebaseConfig,
    CircuitBreakerConfig,
    IPFSUploadResult,
)
from agirails.errors.storage import (
    FilebaseUploadError,
    FilebaseDownloadError,
    FileSizeLimitError,
    SSRFProtectionError,
    InvalidCIDError,
    CircuitBreakerOpenError,
)

from .conftest import (
    VALID_CID_V0,
    VALID_CID_V1,
)


# =============================================================================
# Helper Functions for Mocking httpx
# =============================================================================


def create_mock_response(
    status_code: int = 200,
    headers: Dict[str, str] = None,
    content: bytes = b"",
) -> MagicMock:
    """Create a mock httpx Response."""
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.content = content
    response.text = content.decode("utf-8") if content else ""
    return response


def create_mock_stream_response(
    status_code: int = 200,
    headers: Dict[str, str] = None,
    chunks: list = None,
) -> AsyncMock:
    """Create a mock streaming response for httpx."""
    response = AsyncMock()
    response.status_code = status_code
    response.headers = headers or {}

    async def aiter_bytes(chunk_size=8192):
        for chunk in (chunks or [b""]):
            yield chunk

    response.aiter_bytes = aiter_bytes
    return response


# =============================================================================
# FilebaseClient Initialization Tests
# =============================================================================


class TestFilebaseClientInit:
    """Tests for FilebaseClient initialization."""

    def test_init_with_config(self, filebase_config: FilebaseConfig) -> None:
        """Test FilebaseClient initialization with config."""
        client = FilebaseClient(filebase_config)
        assert client._config == filebase_config
        assert client._circuit_breaker is not None

    def test_init_without_circuit_breaker(self) -> None:
        """Test client init without circuit breaker config."""
        config = FilebaseConfig(
            access_key="key",
            secret_key="secret",
            circuit_breaker=None,
        )
        client = FilebaseClient(config)
        assert client._circuit_breaker is not None  # Default CB created

    def test_circuit_breaker_state_property(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test circuit breaker state property."""
        client = FilebaseClient(filebase_config)
        assert client.circuit_breaker_state == "closed"

    def test_bucket_property(self, filebase_config: FilebaseConfig) -> None:
        """Test bucket property returns config value."""
        client = FilebaseClient(filebase_config)
        assert client.bucket == filebase_config.bucket

    def test_gateway_url_property(self, filebase_config: FilebaseConfig) -> None:
        """Test gateway_url property returns config value."""
        client = FilebaseClient(filebase_config)
        assert client.gateway_url == filebase_config.gateway_url


# =============================================================================
# Upload Tests
# =============================================================================


class TestFilebaseUpload:
    """Tests for FilebaseClient upload operations."""

    @pytest.mark.asyncio
    async def test_upload_binary_success(
        self,
        filebase_config: FilebaseConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test successful binary upload."""
        client = FilebaseClient(filebase_config)

        # Create mock response with CID in header
        mock_put_response = create_mock_response(
            status_code=200,
            headers={"x-amz-meta-cid": VALID_CID_V0},
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.upload(sample_binary_data)

            assert result.cid == VALID_CID_V0
            assert result.size == len(sample_binary_data)
            mock_client.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_json_success(
        self,
        filebase_config: FilebaseConfig,
        sample_json_data: Dict[str, Any],
    ) -> None:
        """Test successful JSON upload."""
        client = FilebaseClient(filebase_config)

        mock_put_response = create_mock_response(
            status_code=200,
            headers={"x-amz-meta-cid": VALID_CID_V1},
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.upload_json(sample_json_data)

            assert result.cid == VALID_CID_V1
            # Verify content type in call
            call_args = mock_client.put.call_args
            assert call_args.kwargs.get("headers", {}).get("Content-Type") == "application/json"

    @pytest.mark.asyncio
    async def test_upload_with_custom_filename(
        self,
        filebase_config: FilebaseConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload with custom filename."""
        client = FilebaseClient(filebase_config)

        mock_put_response = create_mock_response(
            status_code=200,
            headers={"x-amz-meta-cid": VALID_CID_V0},
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.upload(sample_binary_data, filename="custom_file.bin")

            # Verify URL contains the custom filename
            call_args = mock_client.put.call_args
            assert "custom_file.bin" in call_args.args[0]

    @pytest.mark.asyncio
    async def test_upload_size_limit_exceeded(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test upload rejects oversized content."""
        client = FilebaseClient(filebase_config)
        large_data = b"X" * (filebase_config.max_file_size + 1)

        with pytest.raises(FileSizeLimitError) as exc_info:
            await client.upload(large_data)

        assert "exceeds limit" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_upload_cid_from_head_request(
        self,
        filebase_config: FilebaseConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test CID extraction from fallback HEAD request."""
        client = FilebaseClient(filebase_config)

        # PUT response has no CID, HEAD response has it
        mock_put_response = create_mock_response(status_code=200, headers={})
        mock_head_response = create_mock_response(
            status_code=200,
            headers={"x-amz-meta-cid": VALID_CID_V0},
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.head = AsyncMock(return_value=mock_head_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.upload(sample_binary_data)

            assert result.cid == VALID_CID_V0
            mock_client.head.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_no_cid_in_response(
        self,
        filebase_config: FilebaseConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload fails when no CID in response."""
        client = FilebaseClient(filebase_config)

        # Both PUT and HEAD have no CID
        mock_put_response = create_mock_response(status_code=200, headers={})
        mock_head_response = create_mock_response(status_code=200, headers={})

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.head = AsyncMock(return_value=mock_head_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(FilebaseUploadError) as exc_info:
                await client.upload(sample_binary_data)

            assert "cid" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_upload_http_error(
        self,
        filebase_config: FilebaseConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload handles HTTP error response."""
        client = FilebaseClient(filebase_config)

        mock_put_response = create_mock_response(status_code=500, headers={})

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(FilebaseUploadError) as exc_info:
                await client.upload(sample_binary_data)

            assert "500" in str(exc_info.value)


# =============================================================================
# Download Tests
# =============================================================================


class TestFilebaseDownload:
    """Tests for FilebaseClient download operations."""

    @pytest.mark.asyncio
    async def test_download_success(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test successful content download."""
        client = FilebaseClient(filebase_config)
        expected_data = b"Downloaded content from IPFS"

        mock_stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(len(expected_data))},
            chunks=[expected_data],
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()

            # Create stream context manager
            mock_stream_ctx = AsyncMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_response)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.download(VALID_CID_V0)

            assert result.data == expected_data
            assert result.size == len(expected_data)

    @pytest.mark.asyncio
    async def test_download_invalid_cid_rejected(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test download rejects invalid CID format."""
        client = FilebaseClient(filebase_config)

        with pytest.raises(InvalidCIDError):
            await client.download("invalid_cid_format")

    @pytest.mark.asyncio
    async def test_download_ssrf_protection(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test download rejects non-whitelisted gateways."""
        client = FilebaseClient(filebase_config)

        with pytest.raises(SSRFProtectionError) as exc_info:
            await client.download(VALID_CID_V0, gateway_url="https://evil.com/ipfs/")

        assert "whitelist" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_download_size_limit_via_header(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test download rejects oversized content based on Content-Length."""
        client = FilebaseClient(filebase_config)
        large_size = filebase_config.max_download_size + 1

        mock_stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(large_size)},
            chunks=[],
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()

            mock_stream_ctx = AsyncMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_response)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(FileSizeLimitError):
                await client.download(VALID_CID_V0)

    @pytest.mark.asyncio
    async def test_download_size_limit_during_streaming(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test download rejects oversized content during streaming."""
        client = FilebaseClient(filebase_config)
        # Create chunks that exceed limit
        chunk_size = filebase_config.max_download_size // 2 + 1
        chunks = [b"X" * chunk_size, b"X" * chunk_size]

        mock_stream_response = create_mock_stream_response(
            status_code=200,
            headers={},  # No Content-Length
            chunks=chunks,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()

            mock_stream_ctx = AsyncMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_response)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(FileSizeLimitError):
                await client.download(VALID_CID_V0)

    @pytest.mark.asyncio
    async def test_download_json_success(
        self,
        filebase_config: FilebaseConfig,
        sample_json_data: Dict[str, Any],
    ) -> None:
        """Test successful JSON download and parse."""
        client = FilebaseClient(filebase_config)
        json_bytes = json.dumps(sample_json_data).encode()

        mock_stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(len(json_bytes))},
            chunks=[json_bytes],
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()

            mock_stream_ctx = AsyncMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_response)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await client.download_json(VALID_CID_V0)

            assert result == sample_json_data

    @pytest.mark.asyncio
    async def test_download_404_error(
        self,
        filebase_config: FilebaseConfig,
    ) -> None:
        """Test download handles 404 response."""
        client = FilebaseClient(filebase_config)

        mock_stream_response = create_mock_stream_response(
            status_code=404,
            headers={},
            chunks=[],
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()

            mock_stream_ctx = AsyncMock()
            mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream_response)
            mock_stream_ctx.__aexit__ = AsyncMock(return_value=None)

            mock_client.stream = MagicMock(return_value=mock_stream_ctx)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(FilebaseDownloadError) as exc_info:
                await client.download(VALID_CID_V0)

            assert "not found" in str(exc_info.value).lower()


# =============================================================================
# CID Validation Tests
# =============================================================================


class TestCIDValidation:
    """Tests for CID format validation."""

    @pytest.mark.asyncio
    async def test_valid_cidv0(self, filebase_config: FilebaseConfig) -> None:
        """Test CIDv0 format is accepted."""
        client = FilebaseClient(filebase_config)
        # CIDv0 starts with Qm and is 46 chars
        valid_v0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        assert len(valid_v0) == 46

        # Should not raise InvalidCIDError (will fail for mocking reasons)
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(Exception) as exc_info:
                await client.download(valid_v0)
            # Should not be InvalidCIDError
            assert not isinstance(exc_info.value, InvalidCIDError)

    @pytest.mark.asyncio
    async def test_valid_cidv1(self, filebase_config: FilebaseConfig) -> None:
        """Test CIDv1 format is accepted."""
        client = FilebaseClient(filebase_config)
        # CIDv1 starts with 'b' and is 59+ chars
        valid_v1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        assert len(valid_v1) >= 50

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with pytest.raises(Exception) as exc_info:
                await client.download(valid_v1)
            assert not isinstance(exc_info.value, InvalidCIDError)

    @pytest.mark.asyncio
    async def test_invalid_cid_formats(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test various invalid CID formats are rejected."""
        client = FilebaseClient(filebase_config)
        invalid_cids = [
            "",
            "abc",
            "Qm" + "x" * 10,  # Too short
            "0x1234567890",  # Ethereum address format
            "https://example.com",  # URL
            "Qm" + "!" * 44,  # Invalid characters
        ]

        for invalid_cid in invalid_cids:
            with pytest.raises(InvalidCIDError):
                await client.download(invalid_cid)


# =============================================================================
# Gateway Whitelist Tests
# =============================================================================


class TestGatewayWhitelist:
    """Tests for SSRF protection via gateway whitelist."""

    @pytest.mark.asyncio
    async def test_allowed_gateways(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test allowed IPFS gateways."""
        client = FilebaseClient(filebase_config)
        allowed_gateways = [
            "https://ipfs.filebase.io/ipfs/",
            "https://gateway.pinata.cloud/ipfs/",
            "https://ipfs.io/ipfs/",
            "https://cloudflare-ipfs.com/ipfs/",
            "https://w3s.link/ipfs/",
            "https://dweb.link/ipfs/",
        ]

        for gateway in allowed_gateways:
            # Should not raise SSRFProtectionError
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_class.return_value = mock_client

                try:
                    await client.download(VALID_CID_V0, gateway_url=gateway)
                except SSRFProtectionError:
                    pytest.fail(f"Gateway {gateway} should be allowed")
                except Exception:
                    pass  # Other errors expected in mocked context

    @pytest.mark.asyncio
    async def test_blocked_gateways(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test blocked/malicious gateways."""
        client = FilebaseClient(filebase_config)
        blocked_gateways = [
            "https://evil.com/ipfs/",
            "https://localhost/ipfs/",
            "https://127.0.0.1/ipfs/",
            "http://internal-server/ipfs/",
            "file:///etc/passwd",
        ]

        for gateway in blocked_gateways:
            with pytest.raises(SSRFProtectionError):
                await client.download(VALID_CID_V0, gateway_url=gateway)


# =============================================================================
# Circuit Breaker Integration Tests
# =============================================================================


class TestCircuitBreakerIntegration:
    """Tests for circuit breaker integration."""

    @pytest.mark.asyncio
    async def test_circuit_opens_after_failures(self) -> None:
        """Test circuit breaker opens after threshold failures."""
        config = FilebaseConfig(
            access_key="key",
            secret_key="secret",
            circuit_breaker=CircuitBreakerConfig(
                enabled=True,
                failure_threshold=2,  # Open after 2 failures
                reset_timeout_ms=60000,
            ),
        )
        client = FilebaseClient(config)

        # Mock httpx to raise error
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=httpx.TransportError("Connection failed"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            # Trigger failures
            for _ in range(2):
                try:
                    await client.upload(b"test")
                except Exception:
                    pass

            # Circuit should be open now
            assert client.circuit_breaker_state in ["open", "half_open"]

    def test_circuit_breaker_disabled(self) -> None:
        """Test client works with circuit breaker disabled."""
        config = FilebaseConfig(
            access_key="key",
            secret_key="secret",
            circuit_breaker=CircuitBreakerConfig(enabled=False),
        )
        client = FilebaseClient(config)
        assert client._circuit_breaker is not None
        assert client._circuit_breaker.config.enabled is False


# =============================================================================
# Utility Method Tests
# =============================================================================


class TestUtilityMethods:
    """Tests for utility methods."""

    def test_get_gateway_url(self, filebase_config: FilebaseConfig) -> None:
        """Test get_gateway_url constructs correct URL."""
        client = FilebaseClient(filebase_config)
        url = client.get_gateway_url(VALID_CID_V0)
        expected = f"{filebase_config.gateway_url.rstrip('/')}/{VALID_CID_V0}"
        assert url == expected

    def test_get_stats(self, filebase_config: FilebaseConfig) -> None:
        """Test get_stats returns client information."""
        client = FilebaseClient(filebase_config)
        stats = client.get_stats()

        assert "bucket" in stats
        assert "gateway_url" in stats
        assert "max_file_size" in stats
        assert "max_download_size" in stats
        assert "circuit_breaker" in stats
        assert stats["bucket"] == filebase_config.bucket


# =============================================================================
# Pin/Unpin Tests (Not Implemented)
# =============================================================================


class TestPinOperations:
    """Tests for pin/unpin operations."""

    @pytest.mark.asyncio
    async def test_pin_not_implemented(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test pin raises NotImplementedError."""
        client = FilebaseClient(filebase_config)

        with pytest.raises(NotImplementedError):
            await client.pin(VALID_CID_V0)

    @pytest.mark.asyncio
    async def test_unpin_not_implemented(
        self, filebase_config: FilebaseConfig
    ) -> None:
        """Test unpin raises NotImplementedError."""
        client = FilebaseClient(filebase_config)

        with pytest.raises(NotImplementedError):
            await client.unpin(VALID_CID_V0)
