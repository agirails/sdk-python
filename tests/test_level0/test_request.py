"""
Comprehensive tests for level0/request.py.

These tests cover all code paths in the request module:
- RequestStatus enum
- ProgressInfo dataclass
- RequestOptions with deadline parsing
- TransactionInfo and RequestResult dataclasses
- LegacyRequestResult factory methods
- RequestHandle class (status checking, waiting, cancellation)
- Global client management
- Provider discovery
- Main request() function
- Helper functions (_get_requester_address, _get_private_key)
- Batch requests
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.level0.request import (
    RequestStatus,
    ProgressInfo,
    RequestOptions,
    TransactionInfo,
    RequestResult,
    LegacyRequestResult,
    RequestHandle,
    set_request_client,
    get_request_client,
    _find_provider,
    _get_requester_address,
    _get_private_key,
    request,
    request_batch,
)


class TestRequestStatus:
    """Tests for RequestStatus enum."""

    def test_all_status_values(self):
        """Verify all status values."""
        assert RequestStatus.PENDING.value == "pending"
        assert RequestStatus.INITIATED.value == "initiated"
        assert RequestStatus.COMMITTED.value == "committed"
        assert RequestStatus.IN_PROGRESS.value == "in_progress"
        assert RequestStatus.DELIVERED.value == "delivered"
        assert RequestStatus.SETTLED.value == "settled"
        assert RequestStatus.COMPLETED.value == "completed"
        assert RequestStatus.FAILED.value == "failed"
        assert RequestStatus.CANCELLED.value == "cancelled"
        assert RequestStatus.DISPUTED.value == "disputed"
        assert RequestStatus.TIMEOUT.value == "timeout"


class TestProgressInfo:
    """Tests for ProgressInfo dataclass."""

    def test_creation(self):
        """Test ProgressInfo creation."""
        info = ProgressInfo(state="initiated", progress=50, message="Processing...")
        assert info.state == "initiated"
        assert info.progress == 50
        assert info.message == "Processing..."


class TestRequestOptions:
    """Tests for RequestOptions and deadline parsing."""

    def test_default_values(self):
        """Test default option values."""
        opts = RequestOptions()
        assert opts.budget == 1.0
        assert opts.deadline is None
        assert opts.timeout == 300_000
        assert opts.provider is None
        assert opts.metadata == {}
        assert opts.wait is True
        assert opts.poll_interval == 2000
        assert opts.dispute_window == 172800
        assert opts.network == "mock"
        assert opts.wallet is None
        assert opts.rpc_url is None
        assert opts.state_directory is None
        assert opts.on_progress is None

    def test_deadline_none_uses_timeout(self):
        """Deadline=None defaults to now + timeout."""
        opts = RequestOptions(timeout=60_000)  # 60 seconds
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - (now + 60)) <= 1

    def test_deadline_datetime(self):
        """Deadline as datetime object."""
        future = datetime.now() + timedelta(hours=1)
        opts = RequestOptions(deadline=future)
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - int(future.timestamp())) <= 1

    def test_deadline_unix_timestamp(self):
        """Deadline as large Unix timestamp."""
        ts = 2000000000  # Year 2033
        opts = RequestOptions(deadline=ts)
        assert opts.get_deadline_timestamp() == ts

    def test_deadline_small_int_as_seconds_from_now(self):
        """Small int deadline treated as seconds from now."""
        opts = RequestOptions(deadline=3600)  # 1 hour
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - (now + 3600)) <= 1

    def test_deadline_string_hours(self):
        """Deadline string format +Xh."""
        opts = RequestOptions(deadline="+2h")
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - (now + 7200)) <= 1

    def test_deadline_string_days(self):
        """Deadline string format +Xd."""
        opts = RequestOptions(deadline="+1d")
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - (now + 86400)) <= 1

    def test_deadline_string_minutes(self):
        """Deadline string format +Xm."""
        opts = RequestOptions(deadline="+30m")
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        assert abs(deadline - (now + 1800)) <= 1

    def test_deadline_invalid_string_falls_back(self):
        """Invalid deadline string falls back to timeout."""
        opts = RequestOptions(deadline="+abc", timeout=60_000)
        now = int(time.time())
        deadline = opts.get_deadline_timestamp()
        # Falls back to now + timeout/1000
        assert abs(deadline - (now + 60)) <= 1

    def test_deadline_iso_date_string(self):
        """Deadline as ISO date string (if dateutil available)."""
        try:
            from dateutil import parser  # noqa
            future_iso = (datetime.now() + timedelta(hours=2)).isoformat()
            opts = RequestOptions(deadline=future_iso)
            now = int(time.time())
            deadline = opts.get_deadline_timestamp()
            # Should be approximately 2 hours from now
            assert abs(deadline - (now + 7200)) <= 5
        except ImportError:
            pytest.skip("dateutil not installed")


class TestTransactionInfo:
    """Tests for TransactionInfo dataclass."""

    def test_creation(self):
        """Test TransactionInfo creation."""
        info = TransactionInfo(
            id="0x123",
            provider="0xprovider",
            amount=100.0,
            fee=1.0,
            duration=5000,
            proof="0xproof",
        )
        assert info.id == "0x123"
        assert info.provider == "0xprovider"
        assert info.amount == 100.0
        assert info.fee == 1.0
        assert info.duration == 5000
        assert info.proof == "0xproof"


class TestRequestResult:
    """Tests for RequestResult dataclass."""

    def test_from_delivery(self):
        """Test creating result from delivery."""
        result = RequestResult.from_delivery(
            output={"text": "Hello"},
            tx_id="0xtx123",
            provider="0xprovider",
            budget=10.0,
            duration=3000,
            proof="0xproof",
        )
        assert result.result == {"text": "Hello"}
        assert result.transaction.id == "0xtx123"
        assert result.transaction.provider == "0xprovider"
        assert result.transaction.amount == 10.0
        assert result.transaction.fee == 0.1  # 1% of 10.0
        assert result.transaction.duration == 3000
        assert result.transaction.proof == "0xproof"


class TestLegacyRequestResult:
    """Tests for LegacyRequestResult dataclass."""

    def test_ok_factory(self):
        """Test ok() factory method."""
        result = LegacyRequestResult.ok(
            output={"data": "test"},
            transaction_id="0x123",
            provider="0xprovider",
            cost=5.0,
        )
        assert result.success is True
        assert result.output == {"data": "test"}
        assert result.error is None
        assert result.transaction_id == "0x123"
        assert result.status == RequestStatus.COMPLETED
        assert result.provider == "0xprovider"
        assert result.cost == 5.0
        assert result.completed_at is not None

    def test_fail_factory(self):
        """Test fail() factory method."""
        result = LegacyRequestResult.fail(
            error="Service unavailable",
            transaction_id="0x456",
        )
        assert result.success is False
        assert result.output is None
        assert result.error == "Service unavailable"
        assert result.transaction_id == "0x456"
        assert result.status == RequestStatus.FAILED
        assert result.completed_at is not None

    def test_timeout_factory(self):
        """Test timeout() factory method."""
        result = LegacyRequestResult.timeout(transaction_id="0x789")
        assert result.success is False
        assert result.error == "Request timed out"
        assert result.status == RequestStatus.TIMEOUT
        assert result.transaction_id == "0x789"
        assert result.completed_at is not None


class TestRequestHandle:
    """Tests for RequestHandle class."""

    def test_properties(self):
        """Test handle properties."""
        opts = RequestOptions(budget=5.0)
        handle = RequestHandle(
            transaction_id="0xtx123",
            service="echo",
            options=opts,
            client=None,
            start_time=1000000,
        )

        assert handle.transaction_id == "0xtx123"
        assert handle.service == "echo"
        assert handle.status == RequestStatus.INITIATED

    def test_is_complete_terminal_states(self):
        """Test is_complete for terminal states."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        # Initial state - not complete
        assert handle.is_complete is False

        # Terminal states
        for status in [
            RequestStatus.COMPLETED,
            RequestStatus.SETTLED,
            RequestStatus.DELIVERED,
            RequestStatus.FAILED,
            RequestStatus.CANCELLED,
            RequestStatus.TIMEOUT,
        ]:
            handle._status = status
            assert handle.is_complete is True

        # Non-terminal states
        for status in [
            RequestStatus.PENDING,
            RequestStatus.INITIATED,
            RequestStatus.COMMITTED,
            RequestStatus.IN_PROGRESS,
        ]:
            handle._status = status
            assert handle.is_complete is False

    def test_get_tx_field_dict(self):
        """Test _get_tx_field with dict."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        tx = {"state": "DELIVERED", "provider": "0xprov"}
        assert handle._get_tx_field(tx, "state") == "DELIVERED"
        assert handle._get_tx_field(tx, "provider") == "0xprov"
        assert handle._get_tx_field(tx, "missing") is None

    def test_get_tx_field_object(self):
        """Test _get_tx_field with object attributes."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        # Mock object with attributes
        class MockTx:
            state = "DELIVERED"
            provider = "0xprov"

        tx = MockTx()
        assert handle._get_tx_field(tx, "state") == "DELIVERED"
        assert handle._get_tx_field(tx, "provider") == "0xprov"

    def test_get_tx_field_state_enum(self):
        """Test _get_tx_field extracts value from State enum."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        # Mock State enum
        class MockState:
            value = "DELIVERED"

        class MockTx:
            state = MockState()

        tx = MockTx()
        assert handle._get_tx_field(tx, "state") == "DELIVERED"

    def test_get_tx_field_snake_case_mapping(self):
        """Test _get_tx_field with camelCase to snake_case."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        class MockTx:
            delivery_proof = "0xproof"

        tx = MockTx()
        # deliveryProof -> delivery_proof
        assert handle._get_tx_field(tx, "deliveryProof") == "0xproof"

    def test_get_tx_field_none(self):
        """Test _get_tx_field with None transaction."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)
        assert handle._get_tx_field(None, "state") is None

    @pytest.mark.asyncio
    async def test_check_status_no_client(self):
        """check_status returns current status when no client."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts, client=None)
        handle._status = RequestStatus.COMMITTED

        status = await handle.check_status()
        assert status == RequestStatus.COMMITTED

    @pytest.mark.asyncio
    async def test_check_status_with_client(self):
        """check_status fetches from client."""
        opts = RequestOptions()
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        # Mock transaction
        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        handle = RequestHandle("0x1", "test", opts, client=mock_client)
        status = await handle.check_status()

        assert status == RequestStatus.DELIVERED
        mock_client.runtime.get_transaction.assert_called_once_with("0x1")

    @pytest.mark.asyncio
    async def test_check_status_exception_handling(self):
        """check_status handles exceptions gracefully."""
        opts = RequestOptions()
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.get_transaction = AsyncMock(side_effect=Exception("Network error"))

        handle = RequestHandle("0x1", "test", opts, client=mock_client)
        handle._status = RequestStatus.COMMITTED

        status = await handle.check_status()
        # Should return existing status on error
        assert status == RequestStatus.COMMITTED

    @pytest.mark.asyncio
    async def test_cancel_already_complete(self):
        """cancel() returns False when already complete."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)
        handle._status = RequestStatus.SETTLED

        result = await handle.cancel()
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_no_client(self):
        """cancel() succeeds without client."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts, client=None)

        result = await handle.cancel()
        assert result is True
        assert handle.status == RequestStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_with_client(self):
        """cancel() transitions state via client."""
        opts = RequestOptions()
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.transition_state = AsyncMock()

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        result = await handle.cancel()
        assert result is True
        assert handle.status == RequestStatus.CANCELLED
        mock_client.runtime.transition_state.assert_called_once_with("0x1", "CANCELLED")

    @pytest.mark.asyncio
    async def test_cancel_exception_handling(self):
        """cancel() returns False on exception."""
        opts = RequestOptions()
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.transition_state = AsyncMock(side_effect=Exception("Error"))

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        result = await handle.cancel()
        assert result is False

    def test_extract_result_empty_tx(self):
        """_extract_result returns {} for empty transaction."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        assert handle._extract_result(None) == {}
        assert handle._extract_result({}) == {}

    def test_extract_result_no_proof(self):
        """_extract_result returns {} when no delivery proof."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        tx = {"state": "DELIVERED", "deliveryProof": ""}
        assert handle._extract_result(tx) == {}

    def test_extract_result_with_delivery_proof(self):
        """_extract_result parses delivery proof JSON."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        proof = json.dumps({
            "type": "delivery.proof",
            "result": {"text": "Hello world"},
            "timestamp": 12345,
        })
        tx = {"deliveryProof": proof}

        result = handle._extract_result(tx)
        assert result == {"text": "Hello world"}

    def test_extract_result_invalid_json(self):
        """_extract_result handles invalid JSON."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        tx = {"deliveryProof": "not-json"}
        result = handle._extract_result(tx)
        # Returns raw data wrapped
        assert result == {"data": "not-json"}

    def test_extract_result_no_type_marker(self):
        """_extract_result returns parsed data if no type marker."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        proof = json.dumps({"data": "test", "metadata": {}})
        tx = {"deliveryProof": proof}

        result = handle._extract_result(tx)
        # Returns parsed dict as-is (no result extraction)
        assert result == {"data": "test", "metadata": {}}

    @pytest.mark.asyncio
    async def test_wait_returns_cached_result(self):
        """wait() returns cached result if available."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts)

        cached = RequestResult(
            result={"cached": True},
            transaction=TransactionInfo("0x1", "0xp", 1.0, 0.01, 100, ""),
        )
        handle._result = cached

        result = await handle.wait()
        assert result is cached

    @pytest.mark.asyncio
    async def test_try_cancel_no_client(self):
        """_try_cancel does nothing without client."""
        opts = RequestOptions()
        handle = RequestHandle("0x1", "test", opts, client=None)
        # Should not raise
        await handle._try_cancel()

    @pytest.mark.asyncio
    async def test_try_cancel_with_cancellable_state(self):
        """_try_cancel cancels transaction in INITIATED/COMMITTED state."""
        opts = RequestOptions()
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        mock_tx = MagicMock()
        mock_tx.state = "INITIATED"
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)
        mock_client.runtime.transition_state = AsyncMock()

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        with patch.object(handle, '_get_tx_field', return_value="INITIATED"):
            await handle._try_cancel()

        mock_client.runtime.transition_state.assert_called_once_with("0x1", "CANCELLED")


class TestGlobalClient:
    """Tests for global client management."""

    def test_set_and_get_client(self):
        """Test setting and getting global client."""
        # Clear first
        set_request_client(None)
        assert get_request_client() is None

        mock_client = MagicMock()
        set_request_client(mock_client)
        assert get_request_client() is mock_client

        # Clean up
        set_request_client(None)


class TestFindProvider:
    """Tests for _find_provider function."""

    def test_specific_address(self):
        """Returns specific address if provided."""
        result = _find_provider("test", "0x1234567890123456789012345678901234567890")
        assert result == "0x1234567890123456789012345678901234567890"

    def test_strategy_any(self):
        """Returns mock provider for 'any' strategy."""
        result = _find_provider("test", "any")
        assert result is not None
        assert result.startswith("0x")
        assert len(result) == 42

    def test_strategy_none(self):
        """Returns mock provider when no strategy specified."""
        result = _find_provider("test", None)
        assert result is not None
        assert result.startswith("0x")

    def test_strategy_best_cheapest(self):
        """'best' and 'cheapest' try directory first."""
        # These strategies attempt directory lookup
        # Without directory, should return None
        result = _find_provider("test", "best")
        assert result is None

        result = _find_provider("test", "cheapest")
        assert result is None


class TestGetRequesterAddress:
    """Tests for _get_requester_address function."""

    def test_no_wallet_returns_mock(self):
        """Returns mock address when no wallet."""
        result = _get_requester_address(None)
        assert result.startswith("0x")
        assert len(result) == 42

    def test_wallet_is_address(self):
        """Returns lowercase address when wallet is address."""
        addr = "0x1234567890123456789012345678901234567890"
        result = _get_requester_address(addr)
        assert result == addr.lower()

    def test_wallet_is_private_key(self):
        """Derives address from private key."""
        try:
            from eth_account import Account
            # Real private key
            pk = "0x" + "a" * 64
            result = _get_requester_address(pk)
            expected = Account.from_key(pk).address.lower()
            assert result == expected
        except ImportError:
            pytest.skip("eth_account not installed")

    def test_wallet_dict_with_private_key(self):
        """Extracts address from wallet dict with privateKey."""
        try:
            from eth_account import Account
            pk = "0x" + "b" * 64
            result = _get_requester_address({"privateKey": pk})
            expected = Account.from_key(pk).address.lower()
            assert result == expected
        except ImportError:
            pytest.skip("eth_account not installed")

    def test_wallet_string_unknown_format(self):
        """Returns string as-is for unknown format."""
        result = _get_requester_address("some-wallet-id")
        assert result == "some-wallet-id"

    def test_wallet_dict_no_private_key(self):
        """Returns mock address for dict without privateKey."""
        result = _get_requester_address({"address": "0x123"})
        assert result.startswith("0x")


class TestGetPrivateKey:
    """Tests for _get_private_key function."""

    def test_no_wallet_returns_none(self):
        """Returns None when no wallet."""
        assert _get_private_key(None) is None

    def test_wallet_is_private_key(self):
        """Returns private key when wallet is private key."""
        pk = "0x" + "a" * 64
        assert _get_private_key(pk) == pk

    def test_wallet_is_address(self):
        """Returns None when wallet is address (not private key)."""
        addr = "0x1234567890123456789012345678901234567890"
        assert _get_private_key(addr) is None

    def test_wallet_dict_with_private_key(self):
        """Extracts private key from wallet dict."""
        pk = "0x" + "c" * 64
        result = _get_private_key({"privateKey": pk})
        assert result == pk

    def test_wallet_dict_no_private_key(self):
        """Returns None when dict has no privateKey."""
        assert _get_private_key({"address": "0x123"}) is None


class TestRequest:
    """Tests for main request() function."""

    @pytest.mark.asyncio
    async def test_request_basic_mock_mode(self):
        """Test basic request in mock mode."""
        # Clean up global client
        set_request_client(None)

        with patch("agirails.client.ACTPClient") as MockClient:
            # Setup mock client
            mock_client_instance = MagicMock()
            mock_client_instance.runtime = MagicMock()
            mock_client_instance.runtime.create_transaction = AsyncMock(return_value="0xtx123")

            # Mock get_transaction to return delivered state
            mock_tx = MagicMock()
            mock_tx.state = "DELIVERED"
            mock_tx.provider = "0xprovider"
            mock_tx.deliveryProof = json.dumps({
                "type": "delivery.proof",
                "result": {"output": "test"},
            })
            mock_client_instance.runtime.get_transaction = AsyncMock(return_value=mock_tx)

            MockClient.create = AsyncMock(return_value=mock_client_instance)

            result = await request(
                "echo",
                input={"msg": "hello"},
                budget=1.0,
                network="mock",
                timeout=1000,
            )

            assert isinstance(result, RequestResult)
            assert result.transaction.id == "0xtx123"

    @pytest.mark.asyncio
    async def test_request_no_wait(self):
        """Test request with wait=False returns handle."""
        set_request_client(None)

        with patch("agirails.client.ACTPClient") as MockClient:
            mock_client_instance = MagicMock()
            mock_client_instance.runtime = MagicMock()
            mock_client_instance.runtime.create_transaction = AsyncMock(return_value="0xtx456")
            MockClient.create = AsyncMock(return_value=mock_client_instance)

            result = await request(
                "echo",
                input={"msg": "hello"},
                budget=1.0,
                network="mock",
                wait=False,
            )

            assert isinstance(result, RequestHandle)
            assert result.transaction_id == "0xtx456"
            assert result.service == "echo"

    @pytest.mark.asyncio
    async def test_request_with_global_client(self):
        """Test request uses global client."""
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.create_transaction = AsyncMock(return_value="0xtx789")

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xprov"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": "done",
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        set_request_client(mock_client)

        try:
            result = await request(
                "test-service",
                input={"data": "test"},
                budget=5.0,
                timeout=1000,
            )

            assert isinstance(result, RequestResult)
            mock_client.runtime.create_transaction.assert_called_once()
        finally:
            set_request_client(None)

    @pytest.mark.asyncio
    async def test_request_with_progress_callback(self):
        """Test request calls progress callback."""
        progress_calls = []

        def on_progress(info):
            progress_calls.append(info)

        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.create_transaction = AsyncMock(return_value="0xprog")

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xp"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": "ok",
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        set_request_client(mock_client)

        try:
            await request(
                "progress-test",
                input={},
                budget=1.0,
                timeout=1000,
                on_progress=on_progress,
            )

            # Should have at least one progress call
            assert len(progress_calls) >= 1
            assert progress_calls[0].state == "initiated"
            assert progress_calls[0].progress == 10
        finally:
            set_request_client(None)

    @pytest.mark.asyncio
    async def test_request_no_provider_found(self):
        """Test request raises when no provider found."""
        set_request_client(None)

        # When provider="best" or "cheapest", _find_provider returns None
        # if no directory entries found, which raises ValueError
        with pytest.raises(ValueError, match="No provider found"):
            await request(
                "unknown-service-xyz",
                input={},
                budget=1.0,
                provider="best",  # Best strategy with no directory returns None
            )

    @pytest.mark.asyncio
    async def test_request_with_explicit_client(self):
        """Test request uses explicitly passed client."""
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()
        mock_client.runtime.create_transaction = AsyncMock(return_value="0xexplicit")

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xp"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": "explicit",
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        # Don't set global client
        set_request_client(None)

        result = await request(
            "explicit-test",
            input={},
            budget=1.0,
            timeout=1000,
            client=mock_client,
        )

        assert result.transaction.id == "0xexplicit"


class TestRequestBatch:
    """Tests for request_batch() function."""

    @pytest.mark.asyncio
    async def test_batch_all_success(self):
        """Test batch request with all successful."""
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        call_count = [0]

        async def mock_create_tx(*args, **kwargs):
            call_count[0] += 1
            return f"0xtx{call_count[0]}"

        mock_client.runtime.create_transaction = mock_create_tx

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xp"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": {"batch": True},
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        set_request_client(mock_client)

        try:
            results = await request_batch([
                {"service": "echo", "input": {"msg": "a"}, "budget": 0.1},
                {"service": "echo", "input": {"msg": "b"}, "budget": 0.2},
            ])

            assert len(results) == 2
            assert all(isinstance(r, RequestResult) for r in results)
        finally:
            set_request_client(None)

    @pytest.mark.asyncio
    async def test_batch_with_exceptions(self):
        """Test batch handles exceptions gracefully."""
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        call_count = [0]

        async def mock_create_tx(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("Second request failed")
            return f"0xtx{call_count[0]}"

        mock_client.runtime.create_transaction = mock_create_tx

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xp"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": "ok",
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        set_request_client(mock_client)

        try:
            results = await request_batch([
                {"service": "echo", "input": {"msg": "a"}, "budget": 0.1},
                {"service": "echo", "input": {"msg": "b"}, "budget": 0.2},
                {"service": "echo", "input": {"msg": "c"}, "budget": 0.3},
            ])

            assert len(results) == 3
            # First and third should succeed, second should be error result
            assert results[1].result is None
            assert results[1].transaction.id == ""
        finally:
            set_request_client(None)


class TestRequestHandleWait:
    """Tests for RequestHandle.wait() method."""

    @pytest.mark.asyncio
    async def test_wait_timeout(self):
        """wait() raises TimeoutError when timeout exceeded."""
        opts = RequestOptions(timeout=100, poll_interval=50)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        # Always return IN_PROGRESS
        mock_tx = MagicMock()
        mock_tx.state = "IN_PROGRESS"
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)
        mock_client.runtime.transition_state = AsyncMock()

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        with pytest.raises(TimeoutError, match="timed out"):
            await handle.wait(timeout=100)

        assert handle.status == RequestStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_wait_cancelled_raises(self):
        """wait() raises when transaction cancelled."""
        opts = RequestOptions(timeout=5000, poll_interval=50)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        mock_tx = MagicMock()
        mock_tx.state = "CANCELLED"
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        with pytest.raises(Exception, match="cancelled"):
            await handle.wait(timeout=1000)

    @pytest.mark.asyncio
    async def test_wait_disputed_raises(self):
        """wait() raises when transaction disputed."""
        opts = RequestOptions(timeout=5000, poll_interval=50)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        mock_tx = MagicMock()
        mock_tx.state = "DISPUTED"
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        with pytest.raises(Exception, match="disputed"):
            await handle.wait(timeout=1000)

    @pytest.mark.asyncio
    async def test_wait_success_delivered(self):
        """wait() extracts result on DELIVERED state."""
        opts = RequestOptions(timeout=5000, poll_interval=50)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        mock_tx = MagicMock()
        mock_tx.state = "DELIVERED"
        mock_tx.provider = "0xprovider"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": {"success": True},
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        result = await handle.wait(timeout=1000)
        assert result.result == {"success": True}
        assert result.transaction.provider == "0xprovider"

    @pytest.mark.asyncio
    async def test_wait_success_settled(self):
        """wait() extracts result on SETTLED state."""
        opts = RequestOptions(timeout=5000, poll_interval=50)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        mock_tx = MagicMock()
        mock_tx.state = "SETTLED"
        mock_tx.provider = "0xprov"
        mock_tx.deliveryProof = json.dumps({
            "type": "delivery.proof",
            "result": "settled",
        })
        mock_client.runtime.get_transaction = AsyncMock(return_value=mock_tx)

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        result = await handle.wait(timeout=1000)
        assert result.result == "settled"

    @pytest.mark.asyncio
    async def test_wait_with_progress_callback(self):
        """wait() calls progress callback during polling."""
        progress_calls = []

        def on_progress(info):
            progress_calls.append(info)

        opts = RequestOptions(timeout=5000, poll_interval=50, on_progress=on_progress)
        mock_client = MagicMock()
        mock_client.runtime = MagicMock()

        call_count = [0]

        async def mock_get_tx(_):
            call_count[0] += 1
            mock_tx = MagicMock()
            # Return IN_PROGRESS first, then DELIVERED
            if call_count[0] < 3:
                mock_tx.state = "IN_PROGRESS"
            else:
                mock_tx.state = "DELIVERED"
                mock_tx.provider = "0xp"
                mock_tx.deliveryProof = json.dumps({
                    "type": "delivery.proof",
                    "result": "done",
                })
            return mock_tx

        mock_client.runtime.get_transaction = mock_get_tx

        handle = RequestHandle("0x1", "test", opts, client=mock_client)

        await handle.wait(timeout=5000)

        # Should have progress calls during polling
        assert len(progress_calls) >= 1
