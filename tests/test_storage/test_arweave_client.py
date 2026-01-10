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
)
from agirails.utils.circuit_breaker import CircuitBreakerOpenError

from .conftest import VALID_TX_ID


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
    """Tests for ArweaveClient upload operations."""

    @pytest.mark.asyncio
    async def test_upload_success(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test successful content upload."""
        client = ArweaveClient(arweave_config)
        expected_tx_id = "arweave_tx_" + "a" * 32

        mock_response = create_mock_response(
            status_code=200,
            json_data={"id": expected_tx_id}
        )

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with patch(
                    "httpx.AsyncClient",
                    create_mock_httpx_client(mock_response, "post")
                ):
                    result = await client.upload(sample_binary_data)

                    assert result.tx_id == expected_tx_id
                    assert result.size == len(sample_binary_data)

    @pytest.mark.asyncio
    async def test_upload_with_tags(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload with custom tags."""
        client = ArweaveClient(arweave_config)
        tags = [
            ("Content-Type", "application/octet-stream"),
            ("Custom-Tag", "custom-value"),
        ]

        mock_response = create_mock_response(
            status_code=200,
            json_data={"id": "tx123"}
        )

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with patch(
                    "httpx.AsyncClient",
                    create_mock_httpx_client(mock_response, "post")
                ):
                    result = await client.upload(sample_binary_data, tags=tags)
                    assert result.tx_id == "tx123"

    @pytest.mark.asyncio
    async def test_upload_insufficient_funds(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload fails with insufficient funds."""
        client = ArweaveClient(arweave_config)

        with patch.object(client, "get_upload_price", return_value=1000000):
            with patch.object(client, "get_balance", return_value=100):  # Too low
                with pytest.raises(InsufficientFundsError) as exc_info:
                    await client.upload(sample_binary_data)

                assert exc_info.value.balance == 100
                assert exc_info.value.required == 1000000

    @pytest.mark.asyncio
    async def test_upload_json_success(
        self,
        arweave_config: ArweaveConfig,
        sample_json_data: Dict[str, Any],
    ) -> None:
        """Test successful JSON upload."""
        client = ArweaveClient(arweave_config)

        mock_response = create_mock_response(
            status_code=200,
            json_data={"id": "json_tx"}
        )

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with patch(
                    "httpx.AsyncClient",
                    create_mock_httpx_client(mock_response, "post")
                ):
                    result = await client.upload_json(sample_json_data)
                    assert result.tx_id == "json_tx"

    @pytest.mark.asyncio
    async def test_upload_bundle_success(
        self,
        arweave_config: ArweaveConfig,
        valid_archive_bundle: ArchiveBundle,
    ) -> None:
        """Test successful archive bundle upload."""
        client = ArweaveClient(arweave_config)

        mock_response = create_mock_response(
            status_code=200,
            json_data={"id": "bundle_tx"}
        )

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with patch(
                    "httpx.AsyncClient",
                    create_mock_httpx_client(mock_response, "post")
                ):
                    result = await client.upload_bundle(valid_archive_bundle)

                    assert result.tx_id == "bundle_tx"

    @pytest.mark.asyncio
    async def test_upload_error(
        self,
        arweave_config: ArweaveConfig,
        sample_binary_data: bytes,
    ) -> None:
        """Test upload error handling."""
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

        mock_response = create_mock_response(
            status_code=500,
            text="Internal Server Error"
        )

        with patch.object(client, "get_upload_price", return_value=100):
            with patch.object(client, "get_balance", return_value=1000000):
                with patch(
                    "httpx.AsyncClient",
                    create_mock_httpx_client(mock_response, "post")
                ):
                    with pytest.raises(ArweaveUploadError):
                        await client.upload(sample_binary_data)


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
        tx_id = "arweave_tx_123"

        mock_response = create_mock_response(
            status_code=200,
            content=expected_data
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            result = await client.download(tx_id)

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

        mock_response = create_mock_response(status_code=404)

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            with pytest.raises(ArweaveDownloadError) as exc_info:
                await client.download("nonexistent_tx")

            assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_download_custom_gateway(
        self, arweave_config: ArweaveConfig
    ) -> None:
        """Test download with custom gateway URL."""
        client = ArweaveClient(arweave_config)
        custom_gateway = "https://gateway.irys.xyz"

        mock_response = create_mock_response(
            status_code=200,
            content=b"test"
        )

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_response)

        def factory(*args, **kwargs):
            return MockAsyncContextManager(mock_http)

        with patch("httpx.AsyncClient", MagicMock(side_effect=factory)):
            await client.download("tx123", gateway_url=custom_gateway)

            # Verify the get was called with custom gateway URL
            call_args = mock_http.get.call_args
            assert custom_gateway in str(call_args)

    @pytest.mark.asyncio
    async def test_download_bundle_success(
        self,
        arweave_config: ArweaveConfig,
        valid_archive_bundle: ArchiveBundle,
    ) -> None:
        """Test successful bundle download and parse."""
        client = ArweaveClient(arweave_config)
        bundle_json = valid_archive_bundle.model_dump_json(by_alias=True)

        mock_response = create_mock_response(
            status_code=200,
            content=bundle_json.encode()
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            result = await client.download_bundle("bundle_tx")

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

        mock_response = create_mock_response(status_code=500)

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            # Trigger failures - the download method uses circuit breaker
            for _ in range(3):
                try:
                    # Use download which goes through circuit breaker
                    await client.download("fake_tx")
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

        mock_response = create_mock_response(
            status_code=200,
            content=b"test data"
        )

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            result = await client.download("tx123")
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

        mock_response = create_mock_response(status_code=500)

        with patch(
            "httpx.AsyncClient",
            create_mock_httpx_client(mock_response, "get")
        ):
            # First call should fail and open circuit
            try:
                await client.download("fake_tx")
            except ArweaveDownloadError:
                pass

            # Second call should get circuit breaker error
            with pytest.raises(CircuitBreakerOpenError):
                await client.download("another_fake_tx")
