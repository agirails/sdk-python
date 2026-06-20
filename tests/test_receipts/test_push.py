"""Tests for ``agirails.receipts.push`` — the AIP-7 §6 V2 receipt push path.

Mirrors ``sdk-js/src/receipts/push.ts``. The agirails.app HTTP surface is mocked
via ``respx`` so the real httpx client + EIP-712 V2 signing path runs end-to-end
without network. Smart-wallet vs EOA signerAddress handling, env-driven base URL,
and 400-vs-422 failure-reason disambiguation are all covered.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from eth_account import Account
from eth_account.messages import encode_typed_data

from agirails.receipts.push import (
    RECEIPT_WRITE_DOMAIN_V2,
    RECEIPT_WRITE_TYPES_V2,
    ZERO_BYTES32,
    FormatSettledLineArgs,
    PushReceiptArgs,
    chain_id_for_network,
    format_settled_line,
    push_receipt_on_settled,
)

BASE = "https://agirails.app"

# Anvil account #1 (matches the cross-SDK fixture private key).
PRIV = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
EOA = Account.from_key(PRIV)
SMART_WALLET = "0xAaAaAAAaAaAAaAaaAAAAaaAAAaAaaaAAaaAaAaA0"


def _args(**overrides) -> PushReceiptArgs:
    defaults = dict(
        signer=EOA,
        participant_role="provider",
        provider_address=EOA.address,
        requester_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        kernel_address="0x469CBADbACFFE096270594F0a31f0EEC53753411",
        tx_id="0x" + "11" * 32,
        network="base-sepolia",
        amount_wei="10000000",
        fee_wei="100000",
        net_wei="9900000",
        service="text-generation",
        duration_ms=4200,
    )
    defaults.update(overrides)
    return PushReceiptArgs(**defaults)


def _mock_prepare(nonce: str = "receipt-nonce-abc123") -> None:
    respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
        return_value=httpx.Response(200, json={"nonce": nonce})
    )


# ============================================================================
# Constants / helper parity
# ============================================================================


class TestConstants:
    def test_domain_v2(self) -> None:
        assert RECEIPT_WRITE_DOMAIN_V2 == {"name": "AGIRAILS Receipts", "version": "2"}

    def test_zero_bytes32(self) -> None:
        assert ZERO_BYTES32 == "0x" + "0" * 64

    def test_types_v2_field_names(self) -> None:
        names = [f["name"] for f in RECEIPT_WRITE_TYPES_V2["ReceiptWriteV2"]]
        assert names == [
            "signerAddress",
            "participantRole",
            "providerAddress",
            "requesterAddress",
            "kernelAddress",
            "txId",
            "network",
            "amountWei",
            "feeWei",
            "netWei",
            "serviceHash",
            "nonce",
            "issuedAt",
        ]

    def test_chain_id(self) -> None:
        assert chain_id_for_network("base-mainnet") == 8453
        assert chain_id_for_network("base-sepolia") == 84532
        assert chain_id_for_network("anything-else") == 84532


# ============================================================================
# Happy path
# ============================================================================


class TestHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success_returns_absolute_url(self) -> None:
        _mock_prepare()
        respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "r_abc123",
                    "url": "https://agirails.app/r/r_abc123",
                    "verified_on_chain": True,
                },
            )
        )
        res = await push_receipt_on_settled(_args())
        assert res.receipt_url == "https://agirails.app/r/r_abc123"
        assert res.receipt_id == "r_abc123"
        assert res.verified_on_chain is True
        assert res.reason is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_body_and_headers(self) -> None:
        _mock_prepare()
        route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                200, json={"id": "r_1", "url": "https://agirails.app/r/r_1"}
            )
        )
        await push_receipt_on_settled(_args())

        req = route.calls.last.request
        body = httpx.Request("POST", "x", content=req.content).read()
        sent = json.loads(body)
        # Algorithm tag + role + nonce/issuedAt are present (push.ts:183-186).
        assert sent["agentSignatureAlgorithm"] == "EIP712-ReceiptV2"
        assert sent["participantRole"] == "provider"
        assert sent["nonce"] == "receipt-nonce-abc123"
        assert "issuedAt" in sent
        # agentAddress mirrors providerAddress (push.ts:169).
        assert sent["agentAddress"] == EOA.address
        # Auth headers carry signer address + signature (push.ts:161-164).
        assert req.headers["X-Agent-Address"] == EOA.address
        assert req.headers["X-Agent-Signature"].startswith("0x")
        # The header signature recovers to the signer over the V2 typed data.
        sig = req.headers["X-Agent-Signature"]
        recovered = _recover_v2(sent, sig)
        assert recovered.lower() == EOA.address.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_default_service_hash_is_zero_bytes32(self) -> None:
        _mock_prepare()
        route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                200, json={"id": "r_1", "url": "https://agirails.app/r/r_1"}
            )
        )
        # No service_hash supplied -> signed payload uses ZERO_BYTES32, but the
        # POST body field stays None (push.ts:145 vs push.ts:177).
        res = await push_receipt_on_settled(_args(service_hash=None))
        assert res.receipt_url == "https://agirails.app/r/r_1"
        sent = json.loads(route.calls.last.request.content)
        assert sent["serviceHash"] is None  # body field
        # Signature still recovers (proves ZERO_BYTES32 was used in the payload).
        recovered = _recover_v2(
            {**sent, "serviceHash": ZERO_BYTES32},
            sent["agentSignature"],
        )
        assert recovered.lower() == EOA.address.lower()


# ============================================================================
# Smart-wallet vs EOA signerAddress (AIP-12 nuance)
# ============================================================================


class TestSmartWalletVsEoa:
    @respx.mock
    @pytest.mark.asyncio
    async def test_signer_address_is_resolved_active_wallet(self) -> None:
        """When an IWalletProvider-shaped signer reports a smart-wallet address,
        signerAddress and the prepare body bind to THAT address, not the EOA."""
        _mock_prepare()
        post_route = respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                200, json={"id": "r_1", "url": "https://agirails.app/r/r_1"}
            )
        )

        signer = _SmartWalletSigner(SMART_WALLET, EOA)
        res = await push_receipt_on_settled(
            _args(signer=signer, requester_address=SMART_WALLET)
        )
        assert res.receipt_url == "https://agirails.app/r/r_1"

        # prepare body bound to the smart wallet.
        prep_req = [
            c.request
            for c in respx.calls
            if c.request.url.path == "/api/v1/receipts/prepare"
        ][-1]
        assert json.loads(prep_req.content)["signerAddress"] == SMART_WALLET

        sent = json.loads(post_route.calls.last.request.content)
        assert sent["signerAddress"] == SMART_WALLET
        assert sent["requesterAddress"] == SMART_WALLET
        assert post_route.calls.last.request.headers["X-Agent-Address"] == SMART_WALLET


# ============================================================================
# Failure modes — reason disambiguation (push.ts:190-232)
# ============================================================================


class TestFailureModes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_prepare_failure_reason(self) -> None:
        respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
            return_value=httpx.Response(500, json={})
        )
        res = await push_receipt_on_settled(_args())
        assert res.receipt_url is None
        assert res.receipt_id is None
        assert res.verified_on_chain is False
        assert res.reason == "prepare_failed:500"

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_400_carries_error_detail(self) -> None:
        _mock_prepare()
        respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                400, json={"error": "missing_field", "detail": "durationMs"}
            )
        )
        res = await push_receipt_on_settled(_args())
        assert res.receipt_url is None
        assert res.reason == "post_failed:400 missing_field: durationMs"

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_422_distinguishable_from_400(self) -> None:
        _mock_prepare()
        respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                422, json={"error": "on_chain_verification_failed"}
            )
        )
        res = await push_receipt_on_settled(_args())
        assert res.reason == "post_failed:422 on_chain_verification_failed"
        # A 400 and a 422 surface as distinct reasons (the whole point).
        assert res.reason != "post_failed:400"

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_failure_without_body(self) -> None:
        _mock_prepare()
        respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(429, text="")
        )
        res = await push_receipt_on_settled(_args())
        assert res.reason == "post_failed:429"

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_is_non_fatal(self) -> None:
        respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
            side_effect=httpx.ConnectError("boom")
        )
        res = await push_receipt_on_settled(_args())
        assert res.receipt_url is None
        assert res.verified_on_chain is False
        assert res.reason  # some reason string, never raised


# ============================================================================
# Base URL resolution (push.ts:118-120)
# ============================================================================


class TestBaseUrl:
    @respx.mock
    @pytest.mark.asyncio
    async def test_env_override(self, monkeypatch) -> None:
        monkeypatch.setenv("AGIRAILS_BASE_URL", "https://staging.agirails.app/")
        respx.post("https://staging.agirails.app/api/v1/receipts/prepare").mock(
            return_value=httpx.Response(200, json={"nonce": "n"})
        )
        respx.post("https://staging.agirails.app/api/v1/receipts").mock(
            return_value=httpx.Response(
                200, json={"id": "r_s", "url": "https://staging.agirails.app/r/r_s"}
            )
        )
        res = await push_receipt_on_settled(_args())
        assert res.receipt_url == "https://staging.agirails.app/r/r_s"

    @respx.mock
    @pytest.mark.asyncio
    async def test_explicit_arg_beats_env(self, monkeypatch) -> None:
        monkeypatch.setenv("AGIRAILS_BASE_URL", "https://env.example/")
        respx.post(f"{BASE}/api/v1/receipts/prepare").mock(
            return_value=httpx.Response(200, json={"nonce": "n"})
        )
        respx.post(f"{BASE}/api/v1/receipts").mock(
            return_value=httpx.Response(
                200, json={"id": "r_x", "url": "https://agirails.app/r/r_x"}
            )
        )
        res = await push_receipt_on_settled(_args(api_base="https://agirails.app///"))
        assert res.receipt_url == "https://agirails.app/r/r_x"


# ============================================================================
# format_settled_line (push.ts:256-264)
# ============================================================================


class TestFormatSettledLine:
    def test_provider_with_url(self) -> None:
        line = format_settled_line(
            FormatSettledLineArgs(
                participant_role="provider",
                net_display="$4.95",
                gross_display="$5.00",
                counterparty_display="buyer-bot",
                receipt_url="https://agirails.app/r/r_1",
            )
        )
        assert line == (
            "[SETTLED] Earned $4.95 from buyer-bot\n"
            "           Receipt: https://agirails.app/r/r_1"
        )

    def test_requester_without_url(self) -> None:
        line = format_settled_line(
            FormatSettledLineArgs(
                participant_role="requester",
                net_display="$4.95",
                gross_display="$5.00",
                counterparty_display="seller-bot",
                receipt_url=None,
            )
        )
        assert line == "[SETTLED] Paid $5.00 to seller-bot"


# ============================================================================
# Helpers
# ============================================================================


def _recover_v2(sent: dict, signature: str) -> str:
    """Recover the signer of a V2 typed-data POST body."""
    domain = {
        "name": RECEIPT_WRITE_DOMAIN_V2["name"],
        "version": RECEIPT_WRITE_DOMAIN_V2["version"],
        "chainId": chain_id_for_network(sent["network"]),
    }
    message = {
        "signerAddress": sent["signerAddress"],
        "participantRole": sent["participantRole"],
        "providerAddress": sent["agentAddress"],
        "requesterAddress": sent["requesterAddress"],
        "kernelAddress": sent["kernelAddress"],
        "txId": sent["txId"],
        "network": sent["network"],
        "amountWei": int(sent["amountWei"]),
        "feeWei": int(sent["feeWei"]),
        "netWei": int(sent["netWei"]),
        # Source signs serviceHash ?? ZERO_BYTES32 (push.ts:145).
        "serviceHash": sent["serviceHash"]
        if sent.get("serviceHash") is not None
        else ZERO_BYTES32,
        "nonce": sent["nonce"],
        "issuedAt": int(sent["issuedAt"]),
    }
    full = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            **RECEIPT_WRITE_TYPES_V2,
        },
        "primaryType": "ReceiptWriteV2",
        "domain": domain,
        "message": message,
    }
    s = encode_typed_data(full_message=full)
    return Account.recover_message(s, signature=signature)


class _SmartWalletSigner:
    """IWalletProvider-shaped signer: reports a smart-wallet address but signs
    with the underlying EOA (mirrors AutoWalletProvider — the smart wallet is
    the on-chain participant, the EOA owner key produces the EIP-712 sig)."""

    def __init__(self, smart_wallet_address: str, eoa: "Account") -> None:
        self.address = smart_wallet_address
        self._eoa = eoa

    def sign_typed_data(self, full_message: dict) -> str:
        signable = encode_typed_data(full_message=full_message)
        sig = self._eoa.sign_message(signable).signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig
