"""Tests for ``agirails.receipts.web_receipt.upload_receipt``.

Mocks the agirails.app HTTP surface via ``respx`` so we exercise the
real httpx client + EIP-712 signing path end-to-end without network.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_typed_data

from agirails.receipts import (
    ReceiptUploadFailure,
    ReceiptUploadOptions,
    ReceiptUploadPayload,
    ReceiptUploadSuccess,
    upload_receipt,
)
from agirails.receipts.web_receipt import _build_receipt_write_typed_data

BASE = "https://agirails.app"


def _payload(network: str = "base-sepolia", **overrides) -> ReceiptUploadPayload:
    defaults = dict(
        agentAddress="0x" + "1" * 40,
        service="text-generation",
        amountWei="1000000",
        feeWei="50000",
        netWei="950000",
        txId="0x" + "a" * 64,
        network=network,
        requesterAddress="0x" + "2" * 40,
        durationMs=420,
    )
    defaults.update(overrides)
    return ReceiptUploadPayload(**defaults)


# ============================================================================
# Endpoint routing + payload shape
# ============================================================================


class TestEndpointRouting:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mock_network_hits_mock_endpoint_with_api_key(self):
        route = respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": "rcpt_abc",
                    "url": "/r/rcpt_abc",
                    "milestone": None,
                },
            )
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="test-key"),
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.id == "rcpt_abc"
        # url is normalized to a full URL when server returns a path.
        assert result.url == "https://agirails.app/r/rcpt_abc"

        assert route.called
        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        # Mock receipts don't need kernelAddress; payload omits None fields.
        assert body["network"] == "mock"
        assert "kernelAddress" not in body

    @respx.mock
    @pytest.mark.asyncio
    async def test_on_chain_network_hits_main_endpoint(self):
        route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": "rcpt_xyz",
                    "url": "https://agirails.app/r/rcpt_xyz",
                    "milestone": "first-100-usd",
                },
            )
        )
        result = await upload_receipt(
            _payload(network="base-sepolia"),
            ReceiptUploadOptions(api_key="test-key"),
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.milestone == "first-100-usd"
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_credentials_returns_failure(self):
        result = await upload_receipt(
            _payload(network="base-sepolia"), ReceiptUploadOptions()
        )
        assert isinstance(result, ReceiptUploadFailure)
        assert "No credentials" in result.reason


# ============================================================================
# Wallet-sig auth path
# ============================================================================


class TestWalletSigAuth:
    @respx.mock
    @pytest.mark.asyncio
    async def test_wallet_sig_signs_typed_data_and_passes_headers(self):
        account = Account.create()
        respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
            return_value=httpx.Response(
                200, json={"nonce": "n-1", "issuedAt": 1_700_000_000}
            )
        )
        post_route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": "rcpt_signed",
                    "url": "/r/rcpt_signed",
                    "milestone": None,
                },
            )
        )

        payload = _payload(network="base-mainnet", agentAddress=account.address)
        result = await upload_receipt(
            payload, ReceiptUploadOptions(private_key=account.key.hex())
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.id == "rcpt_signed"

        request = post_route.calls[0].request
        # Header binding: server reads agent identity from headers, NOT body.
        assert request.headers["x-agent-address"].lower() == account.address.lower()
        sig = request.headers["x-agent-signature"]
        assert sig.startswith("0x") and len(sig) == 132

        # Body carries the nonce + issuedAt so server can rebuild the
        # signable struct and recover the signer.
        body = json.loads(request.content)
        assert body["nonce"] == "n-1"
        assert body["issuedAt"] == 1_700_000_000

        # Signature recovers to the signer address — server runs the
        # same check before persisting.
        typed_data = _build_receipt_write_typed_data(
            payload=payload, nonce="n-1", issued_at=1_700_000_000
        )
        signable = encode_typed_data(full_message=typed_data)
        recovered = Account.recover_message(signable, signature=sig)
        assert recovered.lower() == account.address.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_prepare_failure_short_circuits(self):
        account = Account.create()
        respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
            return_value=httpx.Response(503, json={"error": "down"})
        )
        # /receipts should never be hit when prepare fails.
        post_route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(200, json={"id": "x", "url": "/"})
        )

        result = await upload_receipt(
            _payload(network="base-sepolia"),
            ReceiptUploadOptions(private_key=account.key.hex()),
        )
        assert isinstance(result, ReceiptUploadFailure)
        assert "Nonce prepare failed" in result.reason
        assert "503" in result.reason
        assert post_route.called is False


# ============================================================================
# Server-side error handling
# ============================================================================


class TestErrorPaths:
    @respx.mock
    @pytest.mark.asyncio
    async def test_4xx_with_error_field_surfaces_message(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(409, json={"error": "duplicate txId"})
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        assert isinstance(result, ReceiptUploadFailure)
        assert result.reason == "duplicate txId"

    @respx.mock
    @pytest.mark.asyncio
    async def test_4xx_without_error_field_falls_back_to_http_code(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(429, text="too many requests")
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        assert isinstance(result, ReceiptUploadFailure)
        assert "429" in result.reason

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_exception_is_swallowed(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        # Best-effort: never raises, returns failure dataclass.
        assert isinstance(result, ReceiptUploadFailure)
        assert "connection refused" in result.reason

    @respx.mock
    @pytest.mark.asyncio
    async def test_success_with_relative_url_is_normalized(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(
                201, json={"id": "r1", "url": "/r/r1", "milestone": None}
            )
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.url == "https://agirails.app/r/r1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_success_with_absolute_url_passes_through(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": "r1",
                    "url": "https://cdn.example.com/r/r1",
                    "milestone": None,
                },
            )
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.url == "https://cdn.example.com/r/r1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_malformed_success_response_returns_failure(self):
        respx.post(f"{BASE}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(201, json={"unexpected": "shape"})
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k"),
        )
        assert isinstance(result, ReceiptUploadFailure)
        assert "Malformed" in result.reason


# ============================================================================
# Custom base URL + options
# ============================================================================


class TestCustomBaseUrl:
    @respx.mock
    @pytest.mark.asyncio
    async def test_base_url_override(self):
        custom = "https://staging.agirails.test"
        respx.post(f"{custom}/api/v1/receipts/mock").mock(
            return_value=httpx.Response(
                201, json={"id": "s1", "url": "/r/s1", "milestone": None}
            )
        )
        result = await upload_receipt(
            _payload(network="mock"),
            ReceiptUploadOptions(api_key="k", base_url=custom),
        )
        assert isinstance(result, ReceiptUploadSuccess)
        assert result.url == "https://staging.agirails.test/r/s1"
