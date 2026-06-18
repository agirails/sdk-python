"""
Tests for ArweaveClient permanent storage operations.

Tests cover:
- Client initialization and factory method
- Balance and pricing queries
- Upload operations (binary, JSON, bundle)
- Download operations
- GraphQL tag queries
- Circuit breaker integration
- Error handling
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from agirails.storage.arweave_client import (
    ArweaveClient,
    IRYS_NODES,
    ARWEAVE_GATEWAYS,
)
from agirails.storage.types import (
    ArweaveConfig,
    CircuitBreakerConfig,
    ArchiveBundle,
    ArweaveUploadResult,
    ARCHIVE_BUNDLE_TYPE,
)
from agirails.errors.storage import (
    ArweaveError,
    ArweaveUploadError,
    ArweaveDownloadError,
    InsufficientFundsError,
    FileSizeLimitError,
    SSRFProtectionError,
)
from agirails.utils.circuit_breaker import CircuitBreakerOpenError

from .conftest import VALID_TX_ID


# Valid Arweave TX ID: 43-character base64url string (parity with
# TS ARWEAVE_TX_ID_PATTERN = /^[a-zA-Z0-9_-]{43}$/).
VALID_ARWEAVE_TX_ID = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM-_12"  # 43 chars
assert len(VALID_ARWEAVE_TX_ID) == 43

# Whitelisted Arweave gateway (default in ARWEAVE_GATEWAYS[0]).
ALLOWED_ARWEAVE_GATEWAY = "https://arweave.net"


# =============================================================================
# Helper Functions
# =============================================================================


def create_mock_response(
    status_code: int = 200,
    json_data: Any = None,
    text: str = "",
    content: bytes = b"",
) -> MagicMock:
    """Create a mock httpx Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.text = text
    response.content = content
    if json_data is not None:
        response.json.return_value = json_data
    return response


class MockAsyncContextManager:
    """Mock async context manager for httpx.AsyncClient."""

    def __init__(self, mock_client: AsyncMock):
        self.mock_client = mock_client

    async def __aenter__(self):
        return self.mock_client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None


def create_mock_httpx_client(response: MagicMock, method: str = "get") -> MagicMock:
    """Create a mock httpx.AsyncClient that properly handles async context manager."""
    mock_http = AsyncMock()

    if method == "get":
        mock_http.get = AsyncMock(return_value=response)
    elif method == "post":
        mock_http.post = AsyncMock(return_value=response)

    # Create a factory that returns the async context manager
    def factory(*args, **kwargs):
        return MockAsyncContextManager(mock_http)

    mock_client_class = MagicMock(side_effect=factory)
    return mock_client_class


def create_mock_stream_response(
    status_code: int = 200,
    headers: Dict[str, str] = None,
    chunks: list = None,
) -> AsyncMock:
    """Create a mock streaming httpx response (for ArweaveClient.download)."""
    response = AsyncMock()
    response.status_code = status_code
    response.headers = headers or {}

    async def aiter_bytes(chunk_size=8192):
        for chunk in (chunks if chunks is not None else [b""]):
            yield chunk

    response.aiter_bytes = aiter_bytes
    return response


def create_mock_stream_client(stream_response: AsyncMock) -> MagicMock:
    """Create a mock httpx.AsyncClient whose .stream() yields stream_response."""
    def factory(*args, **kwargs):
        mock_client = AsyncMock()

        stream_ctx = AsyncMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_response)
        stream_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_client.stream = MagicMock(return_value=stream_ctx)
        return MockAsyncContextManager(mock_client)

    return MagicMock(side_effect=factory)


# =============================================================================
# ArweaveClient Initialization Tests
# =============================================================================


class TestArweaveClientInit:
    """Tests for ArweaveClient initialization."""

    def test_init_with_config(self, arweave_config: ArweaveConfig) -> None:
        """Test ArweaveClient initialization with config."""
        client = ArweaveClient(arweave_config)
        assert client._config == arweave_config
        assert client._node_url == IRYS_NODES[arweave_config.network]
        assert client._account is not None

    def test_node_url_mainnet(self) -> None:
        """Test correct node URL for mainnet."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
            network="mainnet",
        )
        client = ArweaveClient(config)
        assert client.node_url == "https://node1.irys.xyz"

    def test_node_url_devnet(self) -> None:
        """Test correct node URL for devnet."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
            network="devnet",
        )
        client = ArweaveClient(config)
        assert client.node_url == "https://devnet.irys.xyz"

    def test_address_property(self, arweave_config: ArweaveConfig) -> None:
        """Test address property returns wallet address."""
        client = ArweaveClient(arweave_config)
        assert client.address.startswith("0x")
        assert len(client.address) == 42

    @pytest.mark.asyncio
    async def test_create_factory_method(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test async factory method."""
        with patch.object(ArweaveClient, "get_balance", return_value=1000000):
            client = await ArweaveClient.create(arweave_config)
            assert isinstance(client, ArweaveClient)

    def test_circuit_breaker_state_property(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test circuit breaker state property."""
        client = ArweaveClient(arweave_config)
        assert client.circuit_breaker_state == "closed"


# =============================================================================
# Balance and Pricing Tests
# =============================================================================


class TestBalanceAndPricing:
    """Tests for balance and pricing queries."""

    @pytest.mark.asyncio
    async def test_get_balance_success(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test successful balance query."""
        client = ArweaveClient(arweave_config)
        expected_balance = 1000000000  # 1 Gwei

        mock_response = create_mock_response(
            status_code=200,
            json_data={"balance": str(expected_balance)}
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            balance = await client.get_balance()
            assert balance == expected_balance

    @pytest.mark.asyncio
    async def test_get_balance_not_found_returns_zero(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test balance returns 0 when account not found."""
        client = ArweaveClient(arweave_config)

        mock_response = create_mock_response(status_code=404)

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            balance = await client.get_balance()
            assert balance == 0

    @pytest.mark.asyncio
    async def test_get_balance_error(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test balance query error handling."""
        # Use a config with disabled circuit breaker for predictable error behavior
        config = ArweaveConfig(
            private_key=arweave_config.private_key,
            rpc_url=arweave_config.rpc_url,
            network=arweave_config.network,
            timeout=arweave_config.timeout,
            circuit_breaker=CircuitBreakerConfig(enabled=False),
        )
        client = ArweaveClient(config)

        # Override retry config to single attempt for faster test
        from agirails.utils.retry import RetryConfig
        client._retry_config = RetryConfig(
            max_attempts=1,
            base_delay_ms=1,
            retryable_errors=(ArweaveError,),
        )

        mock_response = create_mock_response(status_code=500)

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            with pytest.raises(ArweaveError):
                await client.get_balance()

    @pytest.mark.asyncio
    async def test_get_upload_price(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test upload price query."""
        client = ArweaveClient(arweave_config)
        expected_price = 100000  # Price for upload

        mock_response = create_mock_response(
            status_code=200,
            text=str(expected_price)
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            price = await client.get_upload_price(1024)
            assert price == expected_price


# =============================================================================
# Upload Tests
# =============================================================================


class TestArweaveUpload:
    """Tests for ArweaveClient upload operations.

    PARITY DIVERGENCE (documented): the Python upload path FAILS CLOSED because
    a byte-exact ANS-104 DataItem signer is not yet implemented. The Irys node
    rejects non-ANS-104 payloads, so silently producing an invalid transaction
    would corrupt the Arweave-first write-order invariant. Upload therefore
    raises NotImplementedError after the balance check rather than POSTing an
    EIP-191 personal_sign that the node would reject. Reads stay functional.
    """

    @pytest.mark.asyncio
    async def test_upload_fails_closed(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Upload fails closed with an actionable ANS-104 error (no invalid POST)."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with pytest.raises(NotImplementedError) as exc_info:
                    await client.upload(sample_binary_data)

        msg = str(exc_info.value).lower()
        assert "ans-104" in msg
        assert "irys" in msg

    @pytest.mark.asyncio
    async def test_upload_with_tags_fails_closed(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Upload with tags also fails closed (tags do not bypass the gate)."""
        client = ArweaveClient(arweave_config)
        tags = [
            ("Content-Type", "application/octet-stream"),
            ("Custom-Tag", "custom-value"),
        ]

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with pytest.raises(NotImplementedError):
                    await client.upload(sample_binary_data, tags=tags)

    @pytest.mark.asyncio
    async def test_upload_insufficient_funds(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload fails with insufficient funds (checked BEFORE the ANS-104 gate)."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "get_upload_price", return_value=1000000):
            with patch.object(client, "get_balance", return_value=100):  # Too low
                with pytest.raises(InsufficientFundsError) as exc_info:
                    await client.upload(sample_binary_data)

                assert exc_info.value.balance == 100
                assert exc_info.value.required == 1000000

    @pytest.mark.asyncio
    async def test_upload_json_fails_closed(
        self,
        arweave_config: ArweaveConfig,
        sample_json_data: Dict[str, Any],
    ) -> None:
        """upload_json fails closed via the same gate."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with pytest.raises(NotImplementedError):
                    await client.upload_json(sample_json_data)

    @pytest.mark.asyncio
    async def test_upload_bundle_fails_closed(
        self,
        arweave_config: ArweaveConfig,
        valid_archive_bundle: ArchiveBundle,
    ) -> None:
        """upload_bundle fails closed via the same gate."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with pytest.raises(NotImplementedError):
                    await client.upload_bundle(valid_archive_bundle)


# =============================================================================
# Download Tests
# =============================================================================


class TestArweaveDownload:
    """Tests for ArweaveClient download operations."""

    @pytest.mark.asyncio
    async def test_download_success(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test successful content download."""
        client = ArweaveClient(arweave_config)
        expected_data = b"Downloaded from Arweave"

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(len(expected_data))},
            chunks=[expected_data],
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            result = await client.download(VALID_ARWEAVE_TX_ID)

            assert result.data == expected_data
            assert result.size == len(expected_data)

    @pytest.mark.asyncio
    async def test_download_not_found(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download with non-existent transaction."""
        # Use a config with disabled circuit breaker for predictable error behavior
        config = ArweaveConfig(
            private_key=arweave_config.private_key,
            rpc_url=arweave_config.rpc_url,
            network=arweave_config.network,
            timeout=arweave_config.timeout,
            circuit_breaker=CircuitBreakerConfig(enabled=False),
        )
        client = ArweaveClient(config)

        # Override retry config to single attempt for faster test
        from agirails.utils.retry import RetryConfig
        client._retry_config = RetryConfig(
            max_attempts=1,
            base_delay_ms=1,
            retryable_errors=(ArweaveError,),
        )

        stream_response = create_mock_stream_response(status_code=404)

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            with pytest.raises(ArweaveDownloadError) as exc_info:
                await client.download(VALID_ARWEAVE_TX_ID)

            assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_download_custom_gateway(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download with a whitelisted custom gateway URL."""
        client = ArweaveClient(arweave_config)
        custom_gateway = "https://gateway.irys.xyz"  # whitelisted

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": "4"},
            chunks=[b"test"],
        )

        captured = {}

        def factory(*args, **kwargs):
            mock_client = AsyncMock()
            stream_ctx = AsyncMock()
            stream_ctx.__aenter__ = AsyncMock(return_value=stream_response)
            stream_ctx.__aexit__ = AsyncMock(return_value=None)

            def stream(method, url, *a, **k):
                captured["url"] = url
                return stream_ctx

            mock_client.stream = MagicMock(side_effect=stream)
            return MockAsyncContextManager(mock_client)

        with patch("httpx.AsyncClient", MagicMock(side_effect=factory)):
            await client.download(VALID_ARWEAVE_TX_ID, gateway_url=custom_gateway)

            # Verify the request URL used the custom whitelisted gateway.
            assert custom_gateway in captured["url"]
            assert VALID_ARWEAVE_TX_ID in captured["url"]

    @pytest.mark.asyncio
    async def test_download_invalid_tx_id_rejected(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download rejects malformed TX IDs before any network call (P1-3)."""
        client = ArweaveClient(arweave_config)

        invalid_tx_ids = [
            "",
            "short",
            "tx123",
            "nonexistent_tx",
            "abc" * 20,  # too long
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM-_1",  # 42 chars
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM-_123",  # 44 chars
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM-_1!",  # invalid char
        ]

        for tx_id in invalid_tx_ids:
            with pytest.raises(ArweaveDownloadError) as exc_info:
                await client.download(tx_id)
            assert "invalid arweave tx id" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_download_blocked_gateway_rejected(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download rejects non-whitelisted gateways (P0-1 SSRF)."""
        client = ArweaveClient(arweave_config)

        blocked_gateways = [
            "https://evil.com",
            "https://169.254.169.254",
            "http://internal-server",
            "https://attacker.arweave.net.evil.com",
        ]

        for gateway in blocked_gateways:
            with pytest.raises(SSRFProtectionError):
                await client.download(VALID_ARWEAVE_TX_ID, gateway_url=gateway)

    @pytest.mark.asyncio
    async def test_download_size_limit_via_header(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download rejects oversized content based on Content-Length (P1-1)."""
        client = ArweaveClient(arweave_config)
        large_size = client._max_download_size + 1

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(large_size)},
            chunks=[],
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            with pytest.raises(FileSizeLimitError):
                await client.download(VALID_ARWEAVE_TX_ID)

    @pytest.mark.asyncio
    async def test_download_size_limit_during_streaming(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download rejects oversized content during streaming (P1-1)."""
        client = ArweaveClient(arweave_config)
        half = client._max_download_size // 2 + 1
        chunks = [b"X" * half, b"X" * half]

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={},  # No Content-Length
            chunks=chunks,
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            with pytest.raises(FileSizeLimitError):
                await client.download(VALID_ARWEAVE_TX_ID)

    @pytest.mark.asyncio
    async def test_download_bundle_success(
        self,
        arweave_config: ArweaveConfig,
        valid_archive_bundle: ArchiveBundle,
    ) -> None:
        """Test successful bundle download and parse."""
        client = ArweaveClient(arweave_config)
        bundle_json = valid_archive_bundle.model_dump_json(by_alias=True)
        bundle_bytes = bundle_json.encode()

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": str(len(bundle_bytes))},
            chunks=[bundle_bytes],
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            result = await client.download_bundle(VALID_ARWEAVE_TX_ID)

            assert isinstance(result, ArchiveBundle)
            assert result.tx_id == valid_archive_bundle.tx_id


# =============================================================================
# GraphQL Query Tests
# =============================================================================


class TestGraphQLQueries:
    """Tests for Arweave GraphQL tag queries."""

    @pytest.mark.asyncio
    async def test_query_by_tags_success(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test successful tag-based query."""
        client = ArweaveClient(arweave_config)
        expected_ids = ["tx1", "tx2", "tx3"]

        mock_response = create_mock_response(
            status_code=200,
            json_data={
                "data": {
                    "transactions": {
                        "edges": [
                            {"node": {"id": tx_id}} for tx_id in expected_ids
                        ]
                    }
                }
            }
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "post")
        ):
            result = await client.query_by_tags(
                {"Protocol": "AGIRAILS", "ChainId": "8453"}
            )

            assert result == expected_ids

    @pytest.mark.asyncio
    async def test_query_by_tags_empty(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test query with no matching results."""
        client = ArweaveClient(arweave_config)

        mock_response = create_mock_response(
            status_code=200,
            json_data={"data": {"transactions": {"edges": []}}}
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "post")
        ):
            result = await client.query_by_tags({"Protocol": "NONEXISTENT"})

            assert result == []

    @pytest.mark.asyncio
    async def test_find_archives_by_chain(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test finding archives by chain ID."""
        client = ArweaveClient(arweave_config)
        expected_ids = ["archive1", "archive2"]

        with patch.object(
            client, "query_by_tags", return_value=expected_ids
        ) as mock_query:
            result = await client.find_archives_by_chain(8453)

            mock_query.assert_called_once_with(
                {
                    "Protocol": "AGIRAILS",
                    "Type": ARCHIVE_BUNDLE_TYPE,
                    "ChainId": "8453",
                },
                100,
            )
            assert result == expected_ids

    @pytest.mark.asyncio
    async def test_find_archive_by_tx_found(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test finding archive by ACTP transaction ID."""
        client = ArweaveClient(arweave_config)
        expected_id = "archive_tx"

        with patch.object(
            client, "query_by_tags", return_value=[expected_id]
        ):
            result = await client.find_archive_by_tx(VALID_TX_ID)

            assert result == expected_id

    @pytest.mark.asyncio
    async def test_find_archive_by_tx_not_found(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test finding archive when none exists."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "query_by_tags", return_value=[]):
            result = await client.find_archive_by_tx("nonexistent_tx")

            assert result is None


# =============================================================================
# Fund Tests
# =============================================================================


class TestFunding:
    """Tests for Irys funding operations."""

    @pytest.mark.asyncio
    async def test_fund_not_implemented(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test fund raises NotImplementedError."""
        client = ArweaveClient(arweave_config)

        with pytest.raises(NotImplementedError) as exc_info:
            await client.fund(1000000)

        assert "web3" in str(exc_info.value).lower()


# =============================================================================
# Stats and Metadata Tests
# =============================================================================


class TestClientStats:
    """Tests for client statistics and metadata."""

    def test_get_stats(self, arweave_config: ArweaveConfig) -> None:
        """Test getting client statistics."""
        client = ArweaveClient(arweave_config)
        stats = client.get_stats()

        assert "address" in stats
        assert "node_url" in stats
        assert "currency" in stats
        assert "network" in stats
        assert "circuit_breaker" in stats
        assert stats["address"].startswith("0x")
        assert stats["currency"] == "base-eth"
        assert stats["network"] == "devnet"


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


class TestCircuitBreakerArweave:
    """Tests for circuit breaker integration with Arweave client."""

    @pytest.mark.asyncio
    async def test_circuit_opens_on_failures(self) -> None:
        """Test circuit breaker opens after repeated failures."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
            circuit_breaker=CircuitBreakerConfig(
                enabled=True,
                failure_threshold=2,
                reset_timeout_ms=60000,
            ),
        )
        client = ArweaveClient(config)

        # Override retry config to single attempt for faster test and predictable behavior
        from agirails.utils.retry import RetryConfig
        client._retry_config = RetryConfig(
            max_attempts=1,
            base_delay_ms=1,
            retryable_errors=(ArweaveError,),
        )

        stream_response = create_mock_stream_response(status_code=500)

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            # Trigger failures - the download method uses circuit breaker
            for _ in range(3):
                try:
                    # Use download which goes through circuit breaker
                    await client.download(VALID_ARWEAVE_TX_ID)
                except (ArweaveDownloadError, CircuitBreakerOpenError):
                    pass

            # Circuit should be open
            assert client.circuit_breaker_state in ["open", "half_open"]

    @pytest.mark.asyncio
    async def test_circuit_breaker_disabled(self) -> None:
        """Test operations work with circuit breaker disabled."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
            circuit_breaker=CircuitBreakerConfig(enabled=False),
        )
        client = ArweaveClient(config)

        stream_response = create_mock_stream_response(
            status_code=200,
            headers={"Content-Length": "9"},
            chunks=[b"test data"],
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            result = await client.download(VALID_ARWEAVE_TX_ID)
            assert result.data == b"test data"

    @pytest.mark.asyncio
    async def test_circuit_breaker_open_error(self) -> None:
        """Test CircuitBreakerOpenError is raised when circuit is open."""
        config = ArweaveConfig(
            private_key="0x" + "1" * 64,
            rpc_url="https://mainnet.base.org",
            circuit_breaker=CircuitBreakerConfig(
                enabled=True,
                failure_threshold=1,  # Open after 1 failure
                reset_timeout_ms=60000,
            ),
        )
        client = ArweaveClient(config)

        # Override retry config to single attempt
        from agirails.utils.retry import RetryConfig
        client._retry_config = RetryConfig(
            max_attempts=1,
            base_delay_ms=1,
            retryable_errors=(ArweaveError,),
        )

        stream_response = create_mock_stream_response(status_code=500)

        with patch(
            "httpx.AsyncClient",
            create_mock_stream_client(stream_response),
        ):
            # First call should fail and open circuit
            try:
                await client.download(VALID_ARWEAVE_TX_ID)
            except ArweaveDownloadError:
                pass

            # Second call should get circuit breaker error
            with pytest.raises(CircuitBreakerOpenError):
                await client.download(VALID_ARWEAVE_TX_ID)
