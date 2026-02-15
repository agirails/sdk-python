"""
Tests for X402Adapter.

Tests the X402 atomic payment protocol adapter:
- can_handle() - HTTPS URL detection
- validate() - Security validations
- pay() - Atomic payment flow (direct + relay)
- Lifecycle methods raise (atomic = no lifecycle)
- Fee calculations (minimum $0.05 enforcement)

@module tests/test_adapters/test_x402_adapter
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock

import httpx
import pytest

from agirails.adapters import UnifiedPayParams
from agirails.adapters.x402_adapter import (
    X402Adapter,
    X402AdapterConfig,
    X402PayParams,
    X402PayResult,
)
from agirails.types.x402 import (
    X402_HEADERS,
    X402_PROOF_HEADERS,
    X402Error,
    X402ErrorCode,
)


# ============================================================================
# Mock Helpers
# ============================================================================

REQUESTER = "0x" + "1" * 40
PROVIDER = "0x" + "2" * 40
RELAY_ADDRESS = "0x" + "3" * 40
MOCK_TX_HASH = "0x" + "a" * 64
RELAY_TX_HASH = "0x" + "c" * 64


def _mock_response(
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
    text: str = "",
) -> httpx.Response:
    """Create a mock httpx.Response."""
    resp = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        text=text,
        request=httpx.Request("GET", "https://mock.test"),
    )
    return resp


def _mock_402_response(
    payment_address: str = PROVIDER,
    amount: str = "10000000",
    network: str = "base-sepolia",
    deadline: Optional[int] = None,
    service_id: Optional[str] = None,
) -> httpx.Response:
    """Create a mock 402 Payment Required response with X-Payment-* headers."""
    if deadline is None:
        deadline = int(time.time()) + 86400

    headers = {
        X402_HEADERS["REQUIRED"]: "true",
        X402_HEADERS["ADDRESS"]: payment_address,
        X402_HEADERS["AMOUNT"]: amount,
        X402_HEADERS["NETWORK"]: network,
        X402_HEADERS["TOKEN"]: "USDC",
        X402_HEADERS["DEADLINE"]: str(deadline),
    }
    if service_id is not None:
        headers[X402_HEADERS["SERVICE_ID"]] = service_id

    return _mock_response(402, headers)


def _create_mock_fetch(responses: list[httpx.Response]) -> AsyncMock:
    """Create a mock fetch function that returns responses in sequence."""
    call_index = 0

    async def mock_fetch(url: str = "", **kwargs: Any) -> httpx.Response:
        nonlocal call_index
        resp = responses[min(call_index, len(responses) - 1)]
        call_index += 1
        return resp

    # Wrap in AsyncMock to track calls
    mock = AsyncMock(side_effect=mock_fetch)
    return mock


async def _mock_transfer_fn(to: str, amount: str) -> str:
    """Mock transfer function returning a fixed tx hash."""
    return MOCK_TX_HASH


def _default_config(**overrides: Any) -> X402AdapterConfig:
    """Create default test config with optional overrides."""
    config = {
        "expected_network": "base-sepolia",
        "transfer_fn": _mock_transfer_fn,
        "request_timeout": 5.0,
    }
    config.update(overrides)
    return X402AdapterConfig(**config)


# ============================================================================
# Tests: Metadata
# ============================================================================


class TestMetadata:
    """Tests for adapter metadata."""

    def test_adapter_id(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.metadata.id == "x402"

    def test_no_escrow(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.metadata.uses_escrow is False

    def test_no_disputes(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.metadata.supports_disputes is False

    def test_no_release_required(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.metadata.release_required is False

    def test_priority_70(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.metadata.priority == 70


# ============================================================================
# Tests: can_handle
# ============================================================================


class TestCanHandle:
    """Tests for can_handle() method."""

    def test_https_url_returns_true(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.can_handle(UnifiedPayParams(to="https://api.example.com/service", amount="10")) is True

    def test_https_localhost_returns_true(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.can_handle(UnifiedPayParams(to="https://localhost:3000/pay", amount="10")) is True

    def test_http_url_returns_false(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.can_handle(UnifiedPayParams(to="http://api.example.com/service", amount="10")) is False

    def test_ethereum_address_returns_false(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.can_handle(UnifiedPayParams(to="0x1234567890123456789012345678901234567890", amount="10")) is False

    def test_invalid_url_returns_false(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        assert adapter.can_handle(UnifiedPayParams(to="not-a-url", amount="10")) is False


# ============================================================================
# Tests: validate
# ============================================================================


class TestValidate:
    """Tests for validate() method."""

    def test_valid_https_url_passes(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        # Should not raise
        adapter.validate(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

    def test_http_url_raises(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(X402Error) as exc_info:
            adapter.validate(UnifiedPayParams(to="http://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.INSECURE_PROTOCOL

    def test_embedded_credentials_raises(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(X402Error, match="embedded credentials"):
            adapter.validate(UnifiedPayParams(to="https://user:pass@api.example.com/service", amount="10"))


# ============================================================================
# Tests: pay - Happy Path
# ============================================================================


class TestPayHappyPath:
    """Tests for pay() happy path."""

    @pytest.mark.asyncio
    async def test_full_flow_402_to_200(self):
        """402 -> atomic payment -> 200 retry."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(200, text='{"data": "success"}'),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert result.success is True
        assert result.tx_id == MOCK_TX_HASH
        assert result.adapter == "x402"

    @pytest.mark.asyncio
    async def test_escrow_id_is_none(self):
        """x402 has no escrow."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert result.escrow_id is None

    @pytest.mark.asyncio
    async def test_release_required_is_false(self):
        """Atomic = instant settlement, no release needed."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert result.release_required is False

    @pytest.mark.asyncio
    async def test_response_in_result(self):
        """Result includes the HTTP response from retry."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert result.response is not None
        assert result.response.status_code == 200

    @pytest.mark.asyncio
    async def test_transfer_fn_called_with_correct_params(self):
        """transfer_fn receives provider address and amount from 402 headers."""
        captured: Dict[str, str] = {}

        async def tracking_transfer(to: str, amount: str) -> str:
            captured["to"] = to
            captured["amount"] = amount
            return "0x" + "b" * 64

        fetch_mock = _create_mock_fetch([
            _mock_402_response(payment_address=PROVIDER, amount="10000000"),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(
            transfer_fn=tracking_transfer,
            fetch_fn=fetch_mock,
        ))

        await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert captured["to"] == PROVIDER.lower()
        assert captured["amount"] == "10000000"


# ============================================================================
# Tests: pay - Free Service (200 on initial request)
# ============================================================================


class TestPayFreeService:
    """Tests for free service (200 on initial request)."""

    @pytest.mark.asyncio
    async def test_free_service_returns_success(self):
        fetch_mock = _create_mock_fetch([
            _mock_response(200, text='{"free": true}'),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/free", amount="10"))

        assert result.success is True
        assert result.amount == "0.00 USDC"
        assert result.release_required is False
        assert result.tx_id == "0x" + "0" * 64


# ============================================================================
# Tests: pay - Error Cases
# ============================================================================


class TestPayErrors:
    """Tests for pay() error handling."""

    @pytest.mark.asyncio
    async def test_network_mismatch(self):
        """Expected base-sepolia but server says base-mainnet."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(network="base-mainnet"),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.NETWORK_MISMATCH

    @pytest.mark.asyncio
    async def test_deadline_passed(self):
        """Payment deadline already in the past."""
        past_deadline = int(time.time()) - 3600
        fetch_mock = _create_mock_fetch([
            _mock_402_response(deadline=past_deadline),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.DEADLINE_PASSED

    @pytest.mark.asyncio
    async def test_retry_failure(self):
        """Retry after payment returns non-2xx."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(500),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.RETRY_FAILED

    @pytest.mark.asyncio
    async def test_payment_failure(self):
        """transfer_fn raises an exception."""
        async def failing_transfer(to: str, amount: str) -> str:
            raise RuntimeError("Insufficient balance")

        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(
            transfer_fn=failing_transfer,
            fetch_fn=fetch_mock,
        ))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.PAYMENT_FAILED

    @pytest.mark.asyncio
    async def test_not_402_response(self):
        """Server returns 403 instead of 402."""
        fetch_mock = _create_mock_fetch([
            _mock_response(403),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.NOT_402_RESPONSE


# ============================================================================
# Tests: pay - Missing/Invalid Headers
# ============================================================================


class TestPayHeaderValidation:
    """Tests for payment header parsing and validation."""

    @pytest.mark.asyncio
    async def test_missing_required_header(self):
        """402 without X-Payment-Required header."""
        resp = _mock_response(402, headers={
            X402_HEADERS["ADDRESS"]: PROVIDER,
            X402_HEADERS["AMOUNT"]: "10000000",
            X402_HEADERS["NETWORK"]: "base-sepolia",
            X402_HEADERS["TOKEN"]: "USDC",
            X402_HEADERS["DEADLINE"]: str(int(time.time()) + 86400),
        })
        fetch_mock = _create_mock_fetch([resp])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.MISSING_HEADERS

    @pytest.mark.asyncio
    async def test_invalid_address(self):
        """402 with invalid payment address."""
        resp = _mock_response(402, headers={
            X402_HEADERS["REQUIRED"]: "true",
            X402_HEADERS["ADDRESS"]: "invalid",
            X402_HEADERS["AMOUNT"]: "10000000",
            X402_HEADERS["NETWORK"]: "base-sepolia",
            X402_HEADERS["TOKEN"]: "USDC",
            X402_HEADERS["DEADLINE"]: str(int(time.time()) + 86400),
        })
        fetch_mock = _create_mock_fetch([resp])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_invalid_network(self):
        """402 with unsupported network."""
        resp = _mock_response(402, headers={
            X402_HEADERS["REQUIRED"]: "true",
            X402_HEADERS["ADDRESS"]: PROVIDER,
            X402_HEADERS["AMOUNT"]: "10000000",
            X402_HEADERS["NETWORK"]: "ethereum-mainnet",
            X402_HEADERS["TOKEN"]: "USDC",
            X402_HEADERS["DEADLINE"]: str(int(time.time()) + 86400),
        })
        fetch_mock = _create_mock_fetch([resp])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.INVALID_NETWORK


# ============================================================================
# Tests: pay - Retry Proof Headers
# ============================================================================


class TestRetryProofHeaders:
    """Tests that proof headers are sent correctly on retry."""

    @pytest.mark.asyncio
    async def test_proof_header_sent_on_retry(self):
        """Retry request includes X-Payment-Tx-Id header."""
        captured_kwargs: Dict[str, Any] = {}
        call_count = 0

        async def tracking_fetch(url: str = "", **kwargs: Any) -> httpx.Response:
            nonlocal call_count, captured_kwargs
            call_count += 1
            if call_count == 1:
                return _mock_402_response()
            captured_kwargs = kwargs
            return _mock_response(200)

        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=tracking_fetch))
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert captured_kwargs.get("headers", {}).get(X402_PROOF_HEADERS["TX_ID"]) == result.tx_id


# ============================================================================
# Tests: Lifecycle Methods Raise
# ============================================================================


class TestLifecycleMethods:
    """Lifecycle methods must raise for atomic payments."""

    @pytest.mark.asyncio
    async def test_start_work_raises(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(RuntimeError, match="X402 is atomic"):
            await adapter.start_work("0x123")

    @pytest.mark.asyncio
    async def test_deliver_raises(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(RuntimeError, match="X402 is atomic"):
            await adapter.deliver("0x123")

    @pytest.mark.asyncio
    async def test_release_raises(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(RuntimeError, match="X402 is atomic"):
            await adapter.release("0x123")


# ============================================================================
# Tests: get_status
# ============================================================================


class TestGetStatus:
    """Tests for get_status() method."""

    @pytest.mark.asyncio
    async def test_returns_settled_for_completed_payment(self):
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))

        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        status = await adapter.get_status(result.tx_id)

        assert status["state"] == "SETTLED"
        assert status["can_start_work"] is False
        assert status["can_deliver"] is False
        assert status["can_release"] is False
        assert status["can_dispute"] is False

    @pytest.mark.asyncio
    async def test_raises_for_unknown_payment(self):
        adapter = X402Adapter(REQUESTER, _default_config())
        with pytest.raises(ValueError, match="not found"):
            await adapter.get_status("0x" + "9" * 64)


# ============================================================================
# Tests: Relay Fee Splitting
# ============================================================================


class TestRelayFeeSplitting:
    """Tests for X402Relay fee splitting path."""

    @pytest.fixture
    def relay_config(self) -> Dict[str, Any]:
        """Config with relay functions for fee splitting."""
        captured: Dict[str, Any] = {
            "approve_spender": None,
            "approve_amount": None,
            "relay_provider": None,
            "relay_gross": None,
            "relay_service_id": None,
        }

        async def mock_approve(spender: str, amount: str) -> str:
            captured["approve_spender"] = spender
            captured["approve_amount"] = amount
            return "0x" + "d" * 64

        async def mock_relay_pay(provider: str, gross_amount: str, service_id: str) -> str:
            captured["relay_provider"] = provider
            captured["relay_gross"] = gross_amount
            captured["relay_service_id"] = service_id
            return RELAY_TX_HASH

        return {
            "expected_network": "base-sepolia",
            "transfer_fn": _mock_transfer_fn,
            "relay_address": RELAY_ADDRESS,
            "approve_fn": mock_approve,
            "relay_pay_fn": mock_relay_pay,
            "platform_fee_bps": 100,
            "request_timeout": 5.0,
            "captured": captured,
        }

    def _make_relay_adapter(
        self, relay_config: Dict[str, Any], fetch_mock: Any
    ) -> X402Adapter:
        """Create adapter with relay config and custom fetch."""
        cfg = X402AdapterConfig(
            expected_network=relay_config["expected_network"],
            transfer_fn=relay_config["transfer_fn"],
            relay_address=relay_config["relay_address"],
            approve_fn=relay_config["approve_fn"],
            relay_pay_fn=relay_config["relay_pay_fn"],
            platform_fee_bps=relay_config.get("platform_fee_bps", 100),
            request_timeout=relay_config.get("request_timeout", 5.0),
            fetch_fn=fetch_mock,
        )
        return X402Adapter(REQUESTER, cfg)

    @pytest.mark.asyncio
    async def test_uses_relay_when_configured(self, relay_config: Dict[str, Any]):
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="100000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="100"))

        assert result.success is True
        assert result.tx_id == RELAY_TX_HASH

    @pytest.mark.asyncio
    async def test_approves_relay_for_gross_amount(self, relay_config: Dict[str, Any]):
        gross = "100000000"
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount=gross),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="100"))

        assert relay_config["captured"]["approve_spender"] == RELAY_ADDRESS
        assert relay_config["captured"]["approve_amount"] == gross

    @pytest.mark.asyncio
    async def test_passes_provider_and_gross_to_relay(self, relay_config: Dict[str, Any]):
        gross = "100000000"
        fetch_mock = _create_mock_fetch([
            _mock_402_response(payment_address=PROVIDER, amount=gross),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="100"))

        assert relay_config["captured"]["relay_provider"] == PROVIDER.lower()
        assert relay_config["captured"]["relay_gross"] == gross

    @pytest.mark.asyncio
    async def test_passes_service_id_from_headers(self, relay_config: Dict[str, Any]):
        svc_id = "my-service-123"
        fetch_mock = _create_mock_fetch([
            _mock_402_response(service_id=svc_id),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert relay_config["captured"]["relay_service_id"] == svc_id

    @pytest.mark.asyncio
    async def test_uses_zero_hash_when_no_service_id(self, relay_config: Dict[str, Any]):
        fetch_mock = _create_mock_fetch([
            _mock_402_response(),  # no service_id header
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert relay_config["captured"]["relay_service_id"] == "0x" + "0" * 64

    # -- Fee breakdown tests --

    @pytest.mark.asyncio
    async def test_fee_breakdown_1pct_on_100(self, relay_config: Dict[str, Any]):
        """$100 at 1% = $1 fee, $99 to provider."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="100000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="100"))

        assert result.fee_breakdown is not None
        assert result.fee_breakdown.gross_amount == "100000000"
        assert result.fee_breakdown.platform_fee == "1000000"  # $1
        assert result.fee_breakdown.provider_net == "99000000"  # $99
        assert result.fee_breakdown.fee_bps == 100
        assert result.fee_breakdown.estimated is True

    @pytest.mark.asyncio
    async def test_minimum_fee_enforced(self, relay_config: Dict[str, Any]):
        """$1 payment: 1% = $0.01, but MIN_FEE = $0.05."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="1000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="1"))

        assert result.fee_breakdown is not None
        assert result.fee_breakdown.gross_amount == "1000000"
        assert result.fee_breakdown.platform_fee == "50000"  # MIN_FEE = $0.05
        assert result.fee_breakdown.provider_net == "950000"  # $0.95

    @pytest.mark.asyncio
    async def test_fee_at_5_dollar_threshold(self, relay_config: Dict[str, Any]):
        """$5: 1% = $0.05 = MIN_FEE (exactly at threshold)."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="5000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="5"))

        assert result.fee_breakdown is not None
        assert result.fee_breakdown.platform_fee == "50000"

    @pytest.mark.asyncio
    async def test_custom_fee_bps(self, relay_config: Dict[str, Any]):
        """2% fee on $100 = $2."""
        relay_config["platform_fee_bps"] = 200
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="100000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="100"))

        assert result.fee_breakdown is not None
        assert result.fee_breakdown.platform_fee == "2000000"  # $2
        assert result.fee_breakdown.provider_net == "98000000"  # $98
        assert result.fee_breakdown.fee_bps == 200

    @pytest.mark.asyncio
    async def test_fee_breakdown_estimated_always_true(self, relay_config: Dict[str, Any]):
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="10000000"),
            _mock_response(200),
        ])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert result.fee_breakdown is not None
        assert result.fee_breakdown.estimated is True

    # -- Fallback / error tests --

    @pytest.mark.asyncio
    async def test_no_fee_breakdown_without_relay(self):
        """Legacy path (no relay) has no fee breakdown."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="10000000"),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(fetch_fn=fetch_mock))
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert result.fee_breakdown is None
        assert result.success is True

    @pytest.mark.asyncio
    async def test_fallback_to_legacy_when_partial_relay_config(self):
        """Only relayAddress set (no approve/relay fns) -> legacy path."""
        fetch_mock = _create_mock_fetch([
            _mock_402_response(amount="10000000"),
            _mock_response(200),
        ])
        adapter = X402Adapter(REQUESTER, _default_config(
            relay_address=RELAY_ADDRESS,
            fetch_fn=fetch_mock,
        ))
        result = await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))

        assert result.fee_breakdown is None

    @pytest.mark.asyncio
    async def test_approve_failure_raises_payment_failed(self, relay_config: Dict[str, Any]):
        async def failing_approve(spender: str, amount: str) -> str:
            raise RuntimeError("Approve rejected")

        relay_config["approve_fn"] = failing_approve
        fetch_mock = _create_mock_fetch([_mock_402_response()])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.PAYMENT_FAILED

    @pytest.mark.asyncio
    async def test_relay_pay_failure_raises_payment_failed(self, relay_config: Dict[str, Any]):
        async def failing_relay(provider: str, gross: str, svc_id: str) -> str:
            raise RuntimeError("Relay tx reverted")

        relay_config["relay_pay_fn"] = failing_relay
        fetch_mock = _create_mock_fetch([_mock_402_response()])
        adapter = self._make_relay_adapter(relay_config, fetch_mock)

        with pytest.raises(X402Error) as exc_info:
            await adapter.pay(UnifiedPayParams(to="https://api.example.com/service", amount="10"))
        assert exc_info.value.code == X402ErrorCode.PAYMENT_FAILED
