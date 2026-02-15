"""
Tests for BundlerClient -- ERC-4337 bundler JSON-RPC client.

Covers:
- Primary success
- Failover to backup
- Retry with backoff
- Non-transient error stops retry
- Receipt polling
- Gas estimation parsing
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from agirails.wallet.aa.bundler_client import (
    BundlerClient,
    BundlerConfig,
    BundlerHTTPError,
    BundlerRPCError,
    UserOpReceipt,
    _is_non_transient,
)
from agirails.wallet.aa.constants import UserOperationV06


# ============================================================================
# Fixtures
# ============================================================================

SAMPLE_USER_OP = UserOperationV06(
    sender="0x1111111111111111111111111111111111111111",
    nonce=0,
    init_code="0x",
    call_data="0xdeadbeef",
    call_gas_limit=100000,
    verification_gas_limit=200000,
    pre_verification_gas=50000,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=1000000000,
    paymaster_and_data="0x",
    signature="0xaabb",
)


def _mock_json_response(result=None, error=None, status_code=200):
    """Create a mock httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.reason_phrase = "OK" if status_code == 200 else "Error"
    body = {"jsonrpc": "2.0", "id": 1}
    if error:
        body["error"] = error
    else:
        body["result"] = result
    response.json.return_value = body
    return response


# ============================================================================
# Tests
# ============================================================================


class TestBundlerClient:
    """Tests for BundlerClient."""

    @pytest.mark.asyncio
    async def test_estimate_gas_success(self) -> None:
        """Successful gas estimation parses hex values."""
        config = BundlerConfig(primary_url="https://bundler.example.com")
        client = BundlerClient(config)

        mock_response = _mock_json_response(result={
            "callGasLimit": "0x186a0",
            "verificationGasLimit": "0x30d40",
            "preVerificationGas": "0xc350",
        })

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            result = await client.estimate_user_operation_gas(SAMPLE_USER_OP)

        assert result.call_gas_limit == 0x186a0
        assert result.verification_gas_limit == 0x30d40
        assert result.pre_verification_gas == 0xc350

    @pytest.mark.asyncio
    async def test_send_user_operation_success(self) -> None:
        """Successful send returns UserOp hash."""
        config = BundlerConfig(primary_url="https://bundler.example.com")
        client = BundlerClient(config)

        expected_hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        mock_response = _mock_json_response(result=expected_hash)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            result = await client.send_user_operation(SAMPLE_USER_OP)

        assert result == expected_hash

    @pytest.mark.asyncio
    async def test_failover_to_backup(self) -> None:
        """Falls back to backup URL when primary fails."""
        config = BundlerConfig(
            primary_url="https://primary.example.com",
            backup_url="https://backup.example.com",
            max_retries=0,  # No retries, immediate failover
        )
        client = BundlerClient(config)

        fail_response = _mock_json_response(status_code=500)
        success_response = _mock_json_response(result="0xhash123")

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "primary" in url:
                return fail_response
            return success_response

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=mock_post)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            result = await client.send_user_operation(SAMPLE_USER_OP)

        assert result == "0xhash123"
        assert call_count == 2  # primary + backup

    @pytest.mark.asyncio
    async def test_retry_with_backoff(self) -> None:
        """Retries on transient errors with exponential backoff."""
        config = BundlerConfig(
            primary_url="https://bundler.example.com",
            max_retries=2,
            base_delay_s=0.01,  # Fast for testing
        )
        client = BundlerClient(config)

        call_count = 0
        success_response = _mock_json_response(result="0xhash123")
        fail_response = _mock_json_response(status_code=503)

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return fail_response
            return success_response

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=mock_post)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            result = await client.send_user_operation(SAMPLE_USER_OP)

        assert result == "0xhash123"
        assert call_count == 3  # 2 failures + 1 success

    @pytest.mark.asyncio
    async def test_non_transient_error_stops_retry(self) -> None:
        """Non-transient AA errors stop retrying immediately."""
        config = BundlerConfig(
            primary_url="https://bundler.example.com",
            max_retries=2,
            base_delay_s=0.01,
        )
        client = BundlerClient(config)

        error_response = _mock_json_response(
            error={"code": -32602, "message": "AA invalid signature"}
        )

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=error_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            with pytest.raises(BundlerRPCError, match="AA invalid signature"):
                await client.send_user_operation(SAMPLE_USER_OP)

        # Should only be called once (no retries for non-transient)
        assert mock_instance.post.call_count == 1

    @pytest.mark.asyncio
    async def test_receipt_polling(self) -> None:
        """wait_for_receipt polls until receipt is available."""
        config = BundlerConfig(primary_url="https://bundler.example.com")
        client = BundlerClient(config)

        call_count = 0
        null_response = _mock_json_response(result=None)
        receipt_response = _mock_json_response(result={
            "userOpHash": "0xhash",
            "receipt": {
                "transactionHash": "0xtxhash",
                "blockNumber": "0xa",
                "status": "0x1",
            },
            "success": True,
        })

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return null_response
            return receipt_response

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=mock_post)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            receipt = await client.wait_for_receipt(
                "0xhash", timeout_s=5.0, poll_interval_s=0.01
            )

        assert receipt.transaction_hash == "0xtxhash"
        assert receipt.block_number == 10
        assert receipt.success is True

    @pytest.mark.asyncio
    async def test_receipt_timeout(self) -> None:
        """wait_for_receipt raises TimeoutError after timeout."""
        config = BundlerConfig(primary_url="https://bundler.example.com")
        client = BundlerClient(config)

        null_response = _mock_json_response(result=None)

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=null_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            with pytest.raises(TimeoutError, match="not mined"):
                await client.wait_for_receipt(
                    "0xhash", timeout_s=0.05, poll_interval_s=0.01
                )


# ============================================================================
# Tests: _is_non_transient
# ============================================================================


class TestIsNonTransient:
    """Tests for non-transient error detection."""

    def test_json_rpc_parse_error(self) -> None:
        """JSON-RPC parse error is non-transient."""
        err = BundlerRPCError(code=-32700, message="Parse error")
        assert _is_non_transient(err) is True

    def test_json_rpc_invalid_request(self) -> None:
        """JSON-RPC invalid request is non-transient."""
        err = BundlerRPCError(code=-32600, message="Invalid request")
        assert _is_non_transient(err) is True

    def test_aa_invalid_signature(self) -> None:
        """AA invalid signature is non-transient."""
        err = BundlerRPCError(code=-32000, message="AA invalid signature rejected")
        assert _is_non_transient(err) is True

    def test_generic_error_is_transient(self) -> None:
        """Generic errors are transient (should retry)."""
        err = Exception("Connection timeout")
        assert _is_non_transient(err) is False

    def test_http_error_is_transient(self) -> None:
        """HTTP errors are transient."""
        err = BundlerHTTPError("HTTP 503")
        assert _is_non_transient(err) is False
