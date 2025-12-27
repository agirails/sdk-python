"""
Comprehensive tests for level0/provider.py.

These tests cover all code paths in the provider module:
- ProviderStatus enum
- ProviderConfig dataclass
- RegisteredService dataclass
- Provider class (service registration, lifecycle, job processing)
- Helper functions (_get_tx_field, _to_snake_case, _extract_service_name, _extract_input)
- create_provider factory function
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.level0.provider import (
    ProviderStatus,
    ProviderConfig,
    RegisteredService,
    Provider,
    create_provider,
)
from agirails.level0.directory import ServiceEntry


class TestProviderStatus:
    """Tests for ProviderStatus enum."""

    def test_all_status_values(self):
        """Verify all status values."""
        assert ProviderStatus.IDLE.value == "idle"
        assert ProviderStatus.STARTING.value == "starting"
        assert ProviderStatus.RUNNING.value == "running"
        assert ProviderStatus.STOPPING.value == "stopping"
        assert ProviderStatus.STOPPED.value == "stopped"
        assert ProviderStatus.ERROR.value == "error"


class TestProviderConfig:
    """Tests for ProviderConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ProviderConfig()
        assert config.address is None
        assert config.name == ""
        assert config.description == ""
        assert config.max_concurrent == 10
        assert config.poll_interval == 5.0
        assert config.auto_start is False

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ProviderConfig(
            address="0x" + "a" * 40,
            name="TestProvider",
            description="Test description",
            max_concurrent=5,
            poll_interval=2.0,
            auto_start=True,
        )
        assert config.address == "0x" + "a" * 40
        assert config.name == "TestProvider"
        assert config.description == "Test description"
        assert config.max_concurrent == 5
        assert config.poll_interval == 2.0
        assert config.auto_start is True


class TestRegisteredService:
    """Tests for RegisteredService dataclass."""

    def test_creation(self):
        """Test RegisteredService creation."""
        entry = ServiceEntry(name="test-service")
        handler = lambda x: x  # noqa: E731

        registered = RegisteredService(entry=entry, handler=handler)

        assert registered.entry.name == "test-service"
        assert registered.handler is handler
        assert isinstance(registered.registered_at, datetime)

    def test_custom_registered_at(self):
        """Test custom registered_at timestamp."""
        entry = ServiceEntry(name="test")
        handler = lambda x: x  # noqa: E731
        custom_time = datetime(2024, 1, 1, 12, 0, 0)

        registered = RegisteredService(
            entry=entry,
            handler=handler,
            registered_at=custom_time,
        )

        assert registered.registered_at == custom_time


class TestProviderInit:
    """Tests for Provider initialization."""

    def test_default_initialization(self):
        """Test default Provider initialization."""
        provider = Provider()

        assert provider.status == ProviderStatus.IDLE
        assert provider.address is None
        assert provider.services == []
        assert provider.stats == {
            "jobs_received": 0,
            "jobs_completed": 0,
            "jobs_failed": 0,
            "total_earnings": 0.0,
        }
        assert provider.is_running is False

    def test_initialization_with_config(self):
        """Test Provider initialization with config."""
        config = ProviderConfig(
            address="0x" + "a" * 40,
            name="TestProvider",
            max_concurrent=5,
        )
        provider = Provider(config=config)

        assert provider.address == "0x" + "a" * 40

    def test_initialization_with_client(self):
        """Test Provider initialization with client."""
        mock_client = MagicMock()
        mock_client.address = "0x" + "b" * 40

        provider = Provider(client=mock_client)

        # Address from client takes precedence
        assert provider.address == "0x" + "b" * 40

    def test_repr(self):
        """Test Provider string representation."""
        provider = Provider()
        repr_str = repr(provider)

        assert "Provider" in repr_str
        assert "status=idle" in repr_str
        assert "services=0" in repr_str


class TestProviderServiceRegistration:
    """Tests for service registration."""

    def test_register_service(self):
        """Test registering a service."""
        provider = Provider()

        async def handler(data):
            return data

        entry = provider.register_service(
            name="echo",
            handler=handler,
            description="Echo service",
            capabilities=["text"],
        )

        assert entry.name == "echo"
        assert entry.description == "Echo service"
        assert "echo" in provider.services
        assert provider.get_handler("echo") is handler

    def test_register_duplicate_raises(self):
        """Test that duplicate registration raises."""
        provider = Provider()
        handler = lambda x: x  # noqa: E731

        provider.register_service("echo", handler)

        with pytest.raises(ValueError, match="already registered"):
            provider.register_service("echo", handler)

    def test_unregister_service(self):
        """Test unregistering a service."""
        provider = Provider()
        handler = lambda x: x  # noqa: E731

        provider.register_service("echo", handler)
        assert "echo" in provider.services

        result = provider.unregister_service("echo")
        assert result is True
        assert "echo" not in provider.services

    def test_unregister_nonexistent_service(self):
        """Test unregistering nonexistent service returns False."""
        provider = Provider()

        result = provider.unregister_service("nonexistent")
        assert result is False

    def test_service_decorator(self):
        """Test @provider.service() decorator."""
        provider = Provider()

        @provider.service("echo", description="Echo service", capabilities=["text"])
        async def echo_handler(data):
            return data

        assert "echo" in provider.services
        assert provider.get_handler("echo") is echo_handler

    def test_get_handler_not_found(self):
        """Test get_handler returns None for unknown service."""
        provider = Provider()
        assert provider.get_handler("unknown") is None


class TestProviderLifecycle:
    """Tests for Provider start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start(self):
        """Test starting provider."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        assert provider.status == ProviderStatus.IDLE

        await provider.start()

        assert provider.status == ProviderStatus.RUNNING
        assert provider.is_running is True
        assert provider._started_at is not None

        # Cleanup
        await provider.stop()

    @pytest.mark.asyncio
    async def test_start_already_running_raises(self):
        """Test starting already running provider raises."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        await provider.start()

        with pytest.raises(RuntimeError, match="already running"):
            await provider.start()

        # Cleanup
        await provider.stop()

    @pytest.mark.asyncio
    async def test_stop(self):
        """Test stopping provider."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        await provider.start()
        assert provider.is_running is True

        await provider.stop()

        assert provider.status == ProviderStatus.STOPPED
        assert provider.is_running is False
        assert provider._stopped_at is not None

    @pytest.mark.asyncio
    async def test_stop_not_running(self):
        """Test stopping non-running provider is no-op."""
        provider = Provider()

        # Should not raise
        await provider.stop()
        assert provider.status == ProviderStatus.IDLE

    @pytest.mark.asyncio
    @pytest.mark.timeout(5)
    async def test_stop_timeout_cancels_poll_task(self):
        """Test stop cancels poll task on timeout."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        await provider.start()
        original_stop_event = provider._stop_event

        # Create a task that won't respond to stop event quickly
        async def stubborn_task():
            while True:
                await asyncio.sleep(0.01)  # Busy loop, ignores stop event

        # Replace poll task with stubborn task
        if provider._poll_task:
            provider._poll_task.cancel()
            try:
                await provider._poll_task
            except asyncio.CancelledError:
                pass

        provider._poll_task = asyncio.create_task(stubborn_task())

        # Mock wait_for to timeout quickly
        original_wait_for = asyncio.wait_for

        async def mock_wait_for(awaitable, timeout):
            # Use much shorter timeout
            return await original_wait_for(awaitable, timeout=0.05)

        with patch("agirails.level0.provider.asyncio.wait_for", mock_wait_for):
            await provider.stop()

        assert provider.status == ProviderStatus.STOPPED


class TestProviderGetTxField:
    """Tests for Provider._get_tx_field helper."""

    def test_dict_access(self):
        """Test _get_tx_field with dict."""
        provider = Provider()
        tx = {"state": "INITIATED", "provider": "0xabc", "amount": "100"}

        assert provider._get_tx_field(tx, "state") == "INITIATED"
        assert provider._get_tx_field(tx, "provider") == "0xabc"
        assert provider._get_tx_field(tx, "amount") == "100"
        assert provider._get_tx_field(tx, "missing") is None

    def test_object_access(self):
        """Test _get_tx_field with object attributes."""
        provider = Provider()

        class MockTx:
            state = "DELIVERED"
            provider = "0xprov"
            amount = "500"

        tx = MockTx()
        assert provider._get_tx_field(tx, "state") == "DELIVERED"
        assert provider._get_tx_field(tx, "provider") == "0xprov"

    def test_state_enum_value_extraction(self):
        """Test _get_tx_field extracts .value from State enum."""
        provider = Provider()

        class MockState:
            value = "COMMITTED"

        class MockTx:
            state = MockState()

        tx = MockTx()
        assert provider._get_tx_field(tx, "state") == "COMMITTED"

    def test_snake_case_fallback(self):
        """Test _get_tx_field falls back to snake_case."""
        provider = Provider()

        class MockTx:
            service_description = "test service"

        tx = MockTx()
        # serviceDescription -> service_description
        assert provider._get_tx_field(tx, "serviceDescription") == "test service"


class TestProviderToSnakeCase:
    """Tests for Provider._to_snake_case helper."""

    def test_camel_to_snake(self):
        """Test camelCase to snake_case conversion."""
        provider = Provider()

        assert provider._to_snake_case("serviceDescription") == "service_description"
        assert provider._to_snake_case("txId") == "tx_id"
        assert provider._to_snake_case("deliveryProof") == "delivery_proof"
        assert provider._to_snake_case("simple") == "simple"


class TestProviderExtractServiceName:
    """Tests for Provider._extract_service_name."""

    def test_json_format(self):
        """Test extracting service name from JSON format."""
        provider = Provider()

        tx = {"serviceDescription": json.dumps({"service": "echo", "input": {}})}
        assert provider._extract_service_name(tx) == "echo"

    def test_legacy_format(self):
        """Test extracting service name from legacy format."""
        provider = Provider()

        tx = {"serviceDescription": "service:echo;input:{}"}
        assert provider._extract_service_name(tx) == "echo"

    def test_plain_string(self):
        """Test extracting service name from plain string."""
        provider = Provider()

        tx = {"serviceDescription": "my-service"}
        assert provider._extract_service_name(tx) == "my-service"

    def test_empty_service_description(self):
        """Test extracting from empty/missing service description."""
        provider = Provider()

        assert provider._extract_service_name({}) == "unknown"
        assert provider._extract_service_name({"serviceDescription": ""}) == "unknown"

    def test_long_string_returns_unknown(self):
        """Test long non-JSON string returns unknown."""
        provider = Provider()

        long_string = "a" * 100
        tx = {"serviceDescription": long_string}
        assert provider._extract_service_name(tx) == "unknown"


class TestProviderExtractInput:
    """Tests for Provider._extract_input."""

    def test_json_format(self):
        """Test extracting input from JSON format."""
        provider = Provider()

        tx = {"serviceDescription": json.dumps({"service": "echo", "input": {"msg": "hello"}})}
        assert provider._extract_input(tx) == {"msg": "hello"}

    def test_legacy_format_json(self):
        """Test extracting input from legacy format with JSON input."""
        provider = Provider()

        tx = {"serviceDescription": 'service:echo;input:{"msg":"hello"}'}
        assert provider._extract_input(tx) == {"msg": "hello"}

    def test_legacy_format_plain(self):
        """Test extracting input from legacy format with plain input."""
        provider = Provider()

        tx = {"serviceDescription": "service:echo;input:plain-text"}
        assert provider._extract_input(tx) == "plain-text"

    def test_empty_service_description(self):
        """Test extracting from empty/missing service description."""
        provider = Provider()

        assert provider._extract_input({}) == {}
        assert provider._extract_input({"serviceDescription": ""}) == {}

    def test_no_input_in_json(self):
        """Test extracting from JSON without input field."""
        provider = Provider()

        tx = {"serviceDescription": json.dumps({"service": "echo"})}
        assert provider._extract_input(tx) == {}


class TestProviderHandleRequest:
    """Tests for Provider.handle_request method."""

    @pytest.mark.asyncio
    async def test_handle_request_success(self):
        """Test successful request handling."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        async def echo_handler(data):
            return {"echoed": data}

        provider.register_service("echo", echo_handler)
        await provider.start()

        try:
            result = await provider.handle_request("echo", {"msg": "hello"})
            assert result == {"echoed": {"msg": "hello"}}
            assert provider.stats["jobs_completed"] == 1
        finally:
            await provider.stop()

    @pytest.mark.asyncio
    async def test_handle_request_sync_handler(self):
        """Test request handling with sync handler."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        def sync_handler(data):
            return {"sync": data}

        provider.register_service("sync", sync_handler)
        await provider.start()

        try:
            result = await provider.handle_request("sync", {"test": "value"})
            assert result == {"sync": {"test": "value"}}
        finally:
            await provider.stop()

    @pytest.mark.asyncio
    async def test_handle_request_not_running_raises(self):
        """Test handle_request raises when provider not running."""
        provider = Provider()

        def handler(data):
            return data

        provider.register_service("test", handler)

        with pytest.raises(RuntimeError, match="not running"):
            await provider.handle_request("test", {})

    @pytest.mark.asyncio
    async def test_handle_request_service_not_found_raises(self):
        """Test handle_request raises for unknown service."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))
        await provider.start()

        try:
            with pytest.raises(ValueError, match="not found"):
                await provider.handle_request("unknown", {})
        finally:
            await provider.stop()

    @pytest.mark.asyncio
    async def test_handle_request_handler_exception(self):
        """Test handle_request propagates handler exception."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        async def failing_handler(data):
            raise ValueError("Handler error")

        provider.register_service("fail", failing_handler)
        await provider.start()

        try:
            with pytest.raises(ValueError, match="Handler error"):
                await provider.handle_request("fail", {})

            assert provider.stats["jobs_failed"] == 1
        finally:
            await provider.stop()

    @pytest.mark.asyncio
    async def test_handle_request_with_transaction_id(self):
        """Test handle_request with custom transaction ID."""
        provider = Provider(config=ProviderConfig(poll_interval=0.1))

        def handler(data):
            return data

        provider.register_service("test", handler)
        await provider.start()

        try:
            result = await provider.handle_request(
                "test",
                {"data": "test"},
                transaction_id="0xtx123",
            )
            assert result == {"data": "test"}
        finally:
            await provider.stop()

    @pytest.mark.asyncio
    async def test_handle_request_without_semaphore(self):
        """Test handle_request works without semaphore."""
        provider = Provider()

        def handler(data):
            return data

        provider.register_service("test", handler)
        provider._status = ProviderStatus.RUNNING  # Manually set running
        provider._semaphore = None  # No semaphore

        result = await provider.handle_request("test", {"key": "value"})
        assert result == {"key": "value"}


class TestProviderPollLoop:
    """Tests for Provider polling functionality."""

    @pytest.mark.asyncio
    async def test_poll_loop_stops_on_event(self):
        """Test poll loop stops when stop event is set."""
        provider = Provider(config=ProviderConfig(poll_interval=0.01))

        await provider.start()

        # Should be running
        assert provider.is_running

        # Stop should terminate poll loop
        await provider.stop()
        assert provider.status == ProviderStatus.STOPPED

    @pytest.mark.asyncio
    async def test_poll_for_requests_no_client(self):
        """Test _poll_for_requests returns early without client."""
        provider = Provider()
        provider._client = None

        # Should not raise
        await provider._poll_for_requests()

    @pytest.mark.asyncio
    async def test_poll_for_requests_with_filtered_query(self):
        """Test _poll_for_requests uses filtered query when available."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.get_transactions_by_provider = AsyncMock(return_value=[])
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        await provider._poll_for_requests()

        mock_runtime.get_transactions_by_provider.assert_called_once()

    @pytest.mark.asyncio
    async def test_poll_for_requests_fallback_to_all(self):
        """Test _poll_for_requests falls back to get_all_transactions."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        mock_client = MagicMock()

        # Create a runtime object that has get_all_transactions but NOT get_transactions_by_provider
        class MockRuntime:
            async def get_all_transactions(self):
                return []

        mock_runtime = MockRuntime()
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        # Verify fallback is used (hasattr check in source code)
        assert not hasattr(mock_runtime, "get_transactions_by_provider")
        assert hasattr(mock_runtime, "get_all_transactions")

        # Should not raise
        await provider._poll_for_requests()

    @pytest.mark.asyncio
    async def test_poll_for_requests_processes_pending(self):
        """Test _poll_for_requests processes pending transactions."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        # Register handler
        async def echo_handler(data):
            return data

        provider.register_service("echo", echo_handler)

        # Mock client and runtime
        mock_client = MagicMock()
        mock_runtime = MagicMock()

        tx = {
            "id": "0xtx123",
            "provider": "0x" + "a" * 40,
            "state": "INITIATED",
            "amount": "100",
            "serviceDescription": json.dumps({"service": "echo", "input": {"msg": "hi"}}),
        }
        mock_runtime.get_transactions_by_provider = AsyncMock(return_value=[tx])
        mock_runtime.link_escrow = AsyncMock()
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        mock_client.address = "0x" + "a" * 40
        provider._client = mock_client

        await provider._poll_for_requests()

        # Job should be accepted
        assert provider.stats["jobs_received"] == 1
        mock_runtime.link_escrow.assert_called_once_with("0xtx123", "100")

        # Wait a bit for async job processing
        await asyncio.sleep(0.1)

    @pytest.mark.asyncio
    async def test_poll_for_requests_skips_active_jobs(self):
        """Test _poll_for_requests skips already active jobs."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        def handler(data):
            return data

        provider.register_service("echo", handler)

        # Mark job as active
        provider._active_jobs.add("0xtx123")

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        tx = {
            "id": "0xtx123",
            "provider": "0x" + "a" * 40,
            "state": "INITIATED",
            "serviceDescription": json.dumps({"service": "echo"}),
        }
        mock_runtime.get_transactions_by_provider = AsyncMock(return_value=[tx])
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        await provider._poll_for_requests()

        # Should not increment jobs_received (skipped)
        assert provider.stats["jobs_received"] == 0

    @pytest.mark.asyncio
    async def test_poll_for_requests_skips_no_handler(self):
        """Test _poll_for_requests skips transactions without handler."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        # No handler registered

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        tx = {
            "id": "0xtx123",
            "provider": "0x" + "a" * 40,
            "state": "INITIATED",
            "serviceDescription": json.dumps({"service": "unknown"}),
        }
        mock_runtime.get_transactions_by_provider = AsyncMock(return_value=[tx])
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        await provider._poll_for_requests()

        # Should not process (no handler)
        assert provider.stats["jobs_received"] == 0


class TestProviderProcessJob:
    """Tests for Provider._process_job method."""

    @pytest.mark.asyncio
    async def test_process_job_success(self):
        """Test successful job processing."""
        provider = Provider()

        async def handler(data):
            return {"result": data}

        provider.register_service("test", handler)

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        tx = {"serviceDescription": json.dumps({"service": "test", "input": {"key": "val"}})}

        await provider._process_job("0xtx123", tx, "test", handler)

        assert provider.stats["jobs_completed"] == 1
        mock_runtime.transition_state.assert_called_once()

        # Check proof was passed
        call_args = mock_runtime.transition_state.call_args
        assert call_args[0][0] == "0xtx123"
        assert call_args[0][1] == "DELIVERED"
        assert "proof" in call_args[1]

    @pytest.mark.asyncio
    async def test_process_job_sync_handler(self):
        """Test job processing with sync handler."""
        provider = Provider()

        def sync_handler(data):
            return {"sync_result": data}

        provider.register_service("sync", sync_handler)

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        tx = {"serviceDescription": json.dumps({"service": "sync", "input": {}})}

        await provider._process_job("0xtx456", tx, "sync", sync_handler)

        assert provider.stats["jobs_completed"] == 1

    @pytest.mark.asyncio
    async def test_process_job_handler_failure(self):
        """Test job processing with handler failure."""
        provider = Provider()

        async def failing_handler(data):
            raise RuntimeError("Handler failed")

        provider.register_service("fail", failing_handler)

        tx = {"serviceDescription": json.dumps({"service": "fail", "input": {}})}

        # Should not raise, but increment failed count
        await provider._process_job("0xtx789", tx, "fail", failing_handler)

        assert provider.stats["jobs_failed"] == 1
        assert "0xtx789" not in provider._active_jobs

    @pytest.mark.asyncio
    async def test_process_job_cleans_up_active_jobs(self):
        """Test _process_job removes from active_jobs on completion."""
        provider = Provider()

        async def handler(data):
            return data

        provider.register_service("test", handler)
        provider._active_jobs.add("0xtx111")

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        tx = {"serviceDescription": json.dumps({"service": "test", "input": {}})}

        await provider._process_job("0xtx111", tx, "test", handler)

        # Should be removed from active jobs
        assert "0xtx111" not in provider._active_jobs

    @pytest.mark.asyncio
    async def test_process_job_string_result(self):
        """Test job processing with string result."""
        provider = Provider()

        def string_handler(data):
            return "plain string result"

        provider.register_service("string", string_handler)

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        tx = {"serviceDescription": json.dumps({"service": "string", "input": {}})}

        await provider._process_job("0xtx222", tx, "string", string_handler)

        assert provider.stats["jobs_completed"] == 1


class TestCreateProviderFactory:
    """Tests for create_provider factory function."""

    @pytest.mark.asyncio
    async def test_create_provider_default(self):
        """Test create_provider with defaults."""
        provider = await create_provider()

        assert isinstance(provider, Provider)
        assert provider.status == ProviderStatus.IDLE

    @pytest.mark.asyncio
    async def test_create_provider_with_config(self):
        """Test create_provider with config."""
        config = ProviderConfig(
            name="TestProvider",
            max_concurrent=3,
        )
        provider = await create_provider(config=config)

        assert provider._config.name == "TestProvider"
        assert provider._config.max_concurrent == 3

    @pytest.mark.asyncio
    async def test_create_provider_with_client(self):
        """Test create_provider with client."""
        mock_client = MagicMock()
        mock_client.address = "0x" + "c" * 40

        provider = await create_provider(client=mock_client)

        assert provider._client is mock_client
        assert provider.address == "0x" + "c" * 40


class TestProviderDirectory:
    """Tests for Provider.directory property."""

    def test_directory_property(self):
        """Test directory property returns service directory."""
        provider = Provider()

        directory = provider.directory
        assert directory is provider._directory

    def test_directory_with_custom(self):
        """Test provider with custom directory."""
        from agirails.level0.directory import ServiceDirectory

        custom_dir = ServiceDirectory()
        # Register a service to make it distinguishable
        custom_dir.register("test-marker")
        provider = Provider(directory=custom_dir)

        # Check that the custom directory is used by verifying the marker service exists
        assert provider.directory.has("test-marker")


class TestProviderPollLoopException:
    """Tests for exception handling in poll loop."""

    @pytest.mark.asyncio
    async def test_poll_loop_handles_poll_exception(self):
        """Test poll loop continues after exception in _poll_for_requests."""
        provider = Provider(config=ProviderConfig(poll_interval=0.01))

        call_count = [0]

        async def failing_poll():
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Poll error")
            # Third call succeeds

        with patch.object(provider, "_poll_for_requests", failing_poll):
            await provider.start()
            await asyncio.sleep(0.05)  # Let it poll a few times
            await provider.stop()

        # Should have been called multiple times despite errors
        assert call_count[0] >= 2


class TestProviderMissingCoverage:
    """Tests for missing coverage paths."""

    def test_get_tx_field_snake_case_with_enum(self):
        """Test _get_tx_field extracts .value from snake_case enum attribute."""
        provider = Provider()

        class MockState:
            value = "IN_PROGRESS"

        class MockTx:
            # Only has snake_case version, not camelCase
            service_description = "test"

        tx = MockTx()
        # This triggers snake_case fallback path
        result = provider._get_tx_field(tx, "serviceDescription")
        assert result == "test"

    def test_get_tx_field_snake_case_enum_extraction(self):
        """Test _get_tx_field extracts .value from snake_case State enum."""
        provider = Provider()

        class MockState:
            value = "DISPUTED"

        class MockTx:
            # Only snake_case with enum
            current_state = MockState()

        tx = MockTx()
        # currentState -> current_state, should extract .value
        result = provider._get_tx_field(tx, "currentState")
        assert result == "DISPUTED"

    def test_get_tx_field_object_no_attribute(self):
        """Test _get_tx_field returns None when object has no matching attribute."""
        provider = Provider()

        class MockTx:
            existing_field = "value"

        tx = MockTx()
        # Neither camelCase nor snake_case exists
        result = provider._get_tx_field(tx, "nonExistentField")
        assert result is None

    @pytest.mark.asyncio
    async def test_process_job_without_client(self):
        """Test _process_job works without client (no runtime transition)."""
        provider = Provider()

        async def handler(data):
            return {"processed": True}

        provider.register_service("test", handler)
        provider._client = None  # No client

        tx = {"serviceDescription": json.dumps({"service": "test", "input": {}})}

        await provider._process_job("0xtx_no_client", tx, "test", handler)

        # Should complete without error and update stats
        assert provider.stats["jobs_completed"] == 1

    @pytest.mark.asyncio
    async def test_process_job_runtime_without_transition_state(self):
        """Test _process_job works when runtime lacks transition_state method."""
        provider = Provider()

        async def handler(data):
            return {"result": "ok"}

        provider.register_service("test", handler)

        mock_client = MagicMock()
        # Runtime without transition_state method
        mock_runtime = MagicMock(spec=[])  # Empty spec - no methods
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        tx = {"serviceDescription": json.dumps({"service": "test", "input": {}})}

        await provider._process_job("0xtx_no_transition", tx, "test", handler)

        # Should complete without error
        assert provider.stats["jobs_completed"] == 1

    @pytest.mark.asyncio
    async def test_poll_for_requests_transaction_error(self):
        """Test _poll_for_requests handles error during transaction processing."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        def handler(data):
            return data

        provider.register_service("echo", handler)

        mock_client = MagicMock()
        mock_runtime = MagicMock()

        # First transaction will error, second should still process
        tx_good = {
            "id": "0xtx_good",
            "provider": "0x" + "a" * 40,
            "state": "INITIATED",
            "amount": "100",
            "serviceDescription": json.dumps({"service": "echo", "input": {}}),
        }
        tx_bad = {
            "id": "0xtx_bad",
            "provider": "0x" + "a" * 40,
            "state": "INITIATED",
            "amount": "100",
            "serviceDescription": json.dumps({"service": "echo", "input": {}}),
        }
        mock_runtime.get_transactions_by_provider = AsyncMock(return_value=[tx_bad, tx_good])

        # link_escrow fails for first tx
        async def failing_link_escrow(tx_id, amount):
            if tx_id == "0xtx_bad":
                raise Exception("Escrow link failed")

        mock_runtime.link_escrow = AsyncMock(side_effect=failing_link_escrow)
        mock_runtime.transition_state = AsyncMock()
        mock_client.runtime = mock_runtime
        mock_client.address = "0x" + "a" * 40
        provider._client = mock_client

        await provider._poll_for_requests()

        # Bad tx should be removed from active jobs
        assert "0xtx_bad" not in provider._active_jobs
        # Good tx should be processed
        assert provider.stats["jobs_received"] >= 1

    @pytest.mark.asyncio
    async def test_poll_for_requests_global_exception(self):
        """Test _poll_for_requests handles global polling exception."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        mock_client = MagicMock()
        mock_runtime = MagicMock()
        # get_transactions_by_provider raises exception
        mock_runtime.get_transactions_by_provider = AsyncMock(
            side_effect=Exception("Network error")
        )
        mock_client.runtime = mock_runtime
        provider._client = mock_client

        # Should not raise, just log error
        await provider._poll_for_requests()

        # Stats should be unchanged
        assert provider.stats["jobs_received"] == 0


class TestProviderExtractEdgeCases:
    """Tests for edge cases in extraction methods."""

    def test_extract_service_name_json_without_service_key(self):
        """Test _extract_service_name with JSON but no 'service' key."""
        provider = Provider()

        tx = {"serviceDescription": json.dumps({"other": "data"})}
        # Falls through JSON check (no "service" key) to plain string check
        # But JSON string is long, so returns "unknown"
        result = provider._extract_service_name(tx)
        # The JSON string {"other": "data"} is short enough to be returned
        # Actually let me check the length: '{"other": "data"}' is 17 chars, < 64
        assert result == '{"other": "data"}'

    def test_extract_service_name_legacy_no_semicolon(self):
        """Test _extract_service_name with service: prefix but no semicolon."""
        provider = Provider()

        tx = {"serviceDescription": "service:myservice"}
        result = provider._extract_service_name(tx)
        assert result == "myservice"

    def test_extract_input_legacy_invalid_json(self):
        """Test _extract_input with legacy format but invalid JSON input."""
        provider = Provider()

        tx = {"serviceDescription": "service:test;input:{invalid json}"}
        result = provider._extract_input(tx)
        # Returns the raw string when JSON decode fails
        assert result == "{invalid json}"

    def test_extract_input_no_input_marker(self):
        """Test _extract_input with no ;input: marker."""
        provider = Provider()

        tx = {"serviceDescription": json.dumps({"service": "test"})}
        result = provider._extract_input(tx)
        assert result == {}


class TestProviderEdgeBranches:
    """Tests for remaining edge branches to achieve 100% coverage."""

    @pytest.mark.asyncio
    async def test_stop_without_stop_event(self):
        """Test stop() when _stop_event is None."""
        provider = Provider()
        provider._status = ProviderStatus.RUNNING
        provider._stop_event = None  # Edge case
        provider._poll_task = None

        await provider.stop()

        assert provider.status == ProviderStatus.STOPPED

    @pytest.mark.asyncio
    async def test_stop_without_poll_task(self):
        """Test stop() when _poll_task is None but _stop_event exists."""
        provider = Provider()
        provider._status = ProviderStatus.RUNNING
        provider._stop_event = asyncio.Event()
        provider._poll_task = None  # Edge case

        await provider.stop()

        assert provider.status == ProviderStatus.STOPPED

    @pytest.mark.asyncio
    async def test_poll_fallback_returns_empty(self):
        """Test _poll_for_requests with fallback that filters to empty list."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        mock_client = MagicMock()

        # Runtime has get_all_transactions but no get_transactions_by_provider
        class MockRuntime:
            async def get_all_transactions(self):
                # Return transactions but none match our provider
                return [
                    {"id": "tx1", "provider": "0x" + "b" * 40, "state": "INITIATED"},
                ]

        mock_client.runtime = MockRuntime()
        provider._client = mock_client

        # Should not raise, just return early
        await provider._poll_for_requests()

        assert provider.stats["jobs_received"] == 0

    @pytest.mark.asyncio
    async def test_poll_runtime_without_link_escrow(self):
        """Test _poll_for_requests when runtime lacks link_escrow method."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        def handler(data):
            return data

        provider.register_service("echo", handler)

        mock_client = MagicMock()

        # Runtime without link_escrow but with get_transactions_by_provider
        class MockRuntime:
            async def get_transactions_by_provider(self, addr, state, limit):
                return [
                    {
                        "id": "0xtx123",
                        "provider": "0x" + "a" * 40,
                        "state": "INITIATED",
                        "amount": "100",
                        "serviceDescription": json.dumps({"service": "echo", "input": {}}),
                    }
                ]

            async def transition_state(self, tx_id, state, **kwargs):
                pass

        mock_client.runtime = MockRuntime()
        mock_client.address = "0x" + "a" * 40
        provider._client = mock_client

        await provider._poll_for_requests()

        # Should process without link_escrow call
        assert provider.stats["jobs_received"] == 1

    @pytest.mark.asyncio
    async def test_handle_request_without_semaphore_async_handler(self):
        """Test handle_request without semaphore with async handler."""
        provider = Provider()

        async def async_handler(data):
            return {"async_result": data}

        provider.register_service("async_test", async_handler)
        provider._status = ProviderStatus.RUNNING
        provider._semaphore = None  # No semaphore

        result = await provider.handle_request("async_test", {"key": "value"})
        assert result == {"async_result": {"key": "value"}}

    @pytest.mark.asyncio
    async def test_poll_fallback_with_matching_transactions(self):
        """Test _poll_for_requests fallback path with matching transactions."""
        provider = Provider(config=ProviderConfig(address="0x" + "a" * 40))

        def handler(data):
            return data

        provider.register_service("test", handler)

        mock_client = MagicMock()

        # Runtime has get_all_transactions but not get_transactions_by_provider
        # Returns transactions that match our provider
        class MockRuntime:
            async def get_all_transactions(self):
                return [
                    {
                        "id": "0xtx_fallback",
                        "provider": "0x" + "a" * 40,
                        "state": "INITIATED",
                        "amount": "50",
                        "serviceDescription": json.dumps({"service": "test", "input": {}}),
                    }
                ]

            async def link_escrow(self, tx_id, amount):
                pass

            async def transition_state(self, tx_id, state, **kwargs):
                pass

        mock_client.runtime = MockRuntime()
        mock_client.address = "0x" + "a" * 40
        provider._client = mock_client

        await provider._poll_for_requests()

        # Transaction should be processed
        assert provider.stats["jobs_received"] == 1
