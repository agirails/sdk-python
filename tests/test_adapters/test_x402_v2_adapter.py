"""
Tests for the native x402 v2 X402Adapter (EIP-3009 / Permit2).

Mirrors sdk-js/src/adapters/X402Adapter.ts behavior:
- opt-in safety gate (allowed_hosts / metadata.payment_method); NEVER auto-pays
- per-tx amount cap (maxAmountPerTx default $1)
- scheme=='exact' + network allowlist + canonical-USDC asset allowlist
- MEV cap on authorization validity
- payment-response settlement proof: missing -> error; payer-replay check
- EIP-3009 payload + X-PAYMENT header produced via the wallet provider's signer

@module tests/test_adapters/test_x402_v2_adapter
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import httpx
import pytest
from eth_account import Account

from agirails.adapters import UnifiedPayParams
from agirails.adapters.x402_adapter import (
    X402Adapter,
    X402AdapterConfig,
    format_usdc_amount,
    parse_usdc_amount,
    safe_big_int,
)
from agirails.types.x402 import (
    X402AmountExceededError,
    X402ConfigError,
    X402NetworkNotAllowedError,
    X402PaymentFailedError,
    X402SettlementProofMissingError,
)

# Anvil key #1
SIGNER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
SIGNER_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
PAY_TO = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
USDC_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"

URL = "https://api.example.com/paid"


# ---------------------------------------------------------------------------
# Mock wallet provider
# ---------------------------------------------------------------------------


class _WalletInfo:
    def __init__(self, tier: str) -> None:
        self.tier = tier


class MockWalletProvider:
    """Minimal IWalletProvider with real EIP-712 signing via eth_account."""

    def __init__(self, tier: str = "eoa") -> None:
        self._account = Account.from_key(SIGNER_KEY)
        self._tier = tier
        self.sent: List[Any] = []

    def get_address(self) -> str:
        return self._account.address

    def get_wallet_info(self) -> _WalletInfo:
        return _WalletInfo(self._tier)

    def sign_typed_data(self, typed_data: Dict[str, Any]) -> str:
        from eth_account.messages import encode_typed_data

        signable = encode_typed_data(full_message=typed_data)
        signed = self._account.sign_message(signable)
        sig = signed.signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig

    async def send_transaction(self, tx: Any) -> Any:
        self.sent.append(tx)

        class _R:
            success = True

        return _R()


def _requirements(
    *,
    scheme: str = "exact",
    network: str = "eip155:84532",
    asset: str = USDC_SEPOLIA,
    amount: str = "10000",
    max_timeout: int = 600,
    permit2: bool = False,
) -> Dict[str, Any]:
    extra: Dict[str, Any] = {"name": "USDC", "version": "2"}
    if permit2:
        extra["assetTransferMethod"] = "permit2"
    return {
        "scheme": scheme,
        "network": network,
        "asset": asset,
        "payTo": PAY_TO,
        "amount": amount,
        "maxTimeoutSeconds": max_timeout,
        "extra": extra,
    }


def _payment_response_header(
    *,
    transaction: str = "0x" + "ab" * 32,
    network: str = "base-sepolia",
    payer: str = SIGNER_ADDR,
    pay_to: str = PAY_TO,
    amount: str = "10000",
) -> str:
    obj = {
        "success": True,
        "transaction": transaction,
        "network": network,
        "payer": payer,
        "payTo": pay_to,
        "amount": amount,
    }
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _make_fetch(steps: List[httpx.Response]):
    idx = {"i": 0}
    captured: Dict[str, Any] = {"calls": []}

    async def fetch(url: str = "", **kwargs: Any) -> httpx.Response:
        captured["calls"].append({"url": url, **kwargs})
        i = min(idx["i"], len(steps) - 1)
        idx["i"] += 1
        return steps[i]

    fetch.captured = captured  # type: ignore[attr-defined]
    return fetch


def _resp(
    status: int,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        json=json_body if json_body is not None else {},
        headers=headers or {},
        request=httpx.Request("GET", URL),
    )


def _config(**overrides: Any) -> X402AdapterConfig:
    cfg: Dict[str, Any] = {"wallet_provider": MockWalletProvider()}
    cfg.update(overrides)
    return X402AdapterConfig(**cfg)


def _opt_in(metadata_method: str = "x402") -> Dict[str, str]:
    return {"payment_method": metadata_method}


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_returns_v2_adapter_for_v2_config(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        # Not a LegacyX402Adapter
        from agirails.adapters.x402_adapter import LegacyX402Adapter

        assert not isinstance(adapter, LegacyX402Adapter)
        assert adapter.metadata.id == "x402"
        assert adapter.metadata.priority == 70

    def test_requires_sign_typed_data(self) -> None:
        class NoSign:
            def get_address(self) -> str:
                return SIGNER_ADDR

            def get_wallet_info(self):  # noqa: ANN201
                return _WalletInfo("eoa")

        with pytest.raises(X402ConfigError, match="sign_typed_data"):
            X402Adapter(SIGNER_ADDR, X402AdapterConfig(wallet_provider=NoSign()))


# ---------------------------------------------------------------------------
# Opt-in safety gate
# ---------------------------------------------------------------------------


class TestOptInGate:
    def test_https_passes_can_handle(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        assert adapter.can_handle(UnifiedPayParams(to=URL, amount="1")) is True

    def test_http_rejected(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        assert adapter.can_handle(UnifiedPayParams(to="http://x.com", amount="1")) is False

    def test_validate_refuses_without_optin(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        with pytest.raises(X402ConfigError, match="refusing to auto-pay"):
            adapter.validate(UnifiedPayParams(to=URL, amount="1"))

    def test_validate_allows_with_metadata_optin(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        adapter.validate(
            UnifiedPayParams(to=URL, amount="1", metadata=_opt_in())  # type: ignore[arg-type]
        )

    def test_validate_allows_with_host_allowlist(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config(allowed_hosts=["api.example.com"]))
        adapter.validate(UnifiedPayParams(to=URL, amount="1"))

    @pytest.mark.asyncio
    async def test_pay_refuses_without_optin(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        with pytest.raises(X402ConfigError, match="refusing to auto-pay"):
            await adapter.pay(UnifiedPayParams(to=URL, amount="1"))


# ---------------------------------------------------------------------------
# Selection: network / asset allowlist + amount cap + MEV
# ---------------------------------------------------------------------------


class TestSelection:
    def _adapter(self, **overrides: Any) -> X402Adapter:
        return X402Adapter(SIGNER_ADDR, _config(**overrides))

    def test_rejects_non_exact_scheme(self) -> None:
        adapter = self._adapter()
        with pytest.raises(X402NetworkNotAllowedError):
            adapter._select_requirements([_requirements(scheme="upto")])

    def test_rejects_network_not_allowed(self) -> None:
        adapter = self._adapter(allowed_networks=["eip155:8453"])
        with pytest.raises(X402NetworkNotAllowedError):
            adapter._select_requirements([_requirements(network="eip155:84532")])

    def test_rejects_non_usdc_asset_by_default(self) -> None:
        adapter = self._adapter()
        scam = "0x" + "9" * 40
        with pytest.raises(X402NetworkNotAllowedError):
            adapter._select_requirements([_requirements(asset=scam)])

    def test_accepts_canonical_usdc(self) -> None:
        adapter = self._adapter()
        chosen = adapter._select_requirements([_requirements()])
        assert chosen["asset"].lower() == USDC_SEPOLIA

    def test_amount_cap_enforced(self) -> None:
        # default cap $1 = 1_000_000 base units; require 2_000_000
        adapter = self._adapter()
        with pytest.raises(X402AmountExceededError):
            adapter._select_requirements([_requirements(amount="2000000")])

    def test_amount_cap_configurable(self) -> None:
        adapter = self._adapter(max_amount_per_tx="5")
        chosen = adapter._select_requirements([_requirements(amount="2000000")])
        assert chosen["amount"] == "2000000"

    def test_mev_clamp_on_timeout(self) -> None:
        adapter = self._adapter(max_authorization_valid_sec=120)
        chosen = adapter._select_requirements([_requirements(max_timeout=99999)])
        assert chosen["maxTimeoutSeconds"] == 120

    def test_empty_asset_allowlist_allows_any(self) -> None:
        adapter = self._adapter(allowed_assets=[])
        scam = "0x" + "9" * 40
        chosen = adapter._select_requirements([_requirements(asset=scam)])
        assert chosen["asset"] == scam


# ---------------------------------------------------------------------------
# Full pay flow (402 -> sign -> retry -> settlement proof)
# ---------------------------------------------------------------------------


class TestPayFlow:
    @pytest.mark.asyncio
    async def test_happy_path_eip3009(self) -> None:
        fetch = _make_fetch(
            [
                _resp(402, json_body={"x402Version": 2, "accepts": [_requirements()]}),
                _resp(
                    200,
                    json_body={"data": "ok"},
                    headers={"payment-response": _payment_response_header()},
                ),
            ]
        )
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        result = await adapter.pay(
            UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
        )
        assert result.success is True
        assert result.adapter == "x402"
        assert result.state == "COMMITTED"
        assert result.release_required is False
        assert result.tx_id == "0x" + "ab" * 32
        assert result.requester.lower() == SIGNER_ADDR.lower()

        # X-PAYMENT header was sent on the retry, base64 of x402 envelope
        retry = fetch.captured["calls"][1]  # type: ignore[attr-defined]
        xp = retry["headers"]["X-PAYMENT"]
        env = json.loads(base64.b64decode(xp + "=" * (-len(xp) % 4)).decode())
        assert env["x402Version"] == 2
        assert env["scheme"] == "exact"
        assert env["network"] == "base-sepolia"
        assert env["payload"]["signature"].startswith("0x")
        assert env["payload"]["authorization"]["to"].lower() == PAY_TO.lower()

    @pytest.mark.asyncio
    async def test_missing_settlement_proof_raises(self) -> None:
        fetch = _make_fetch(
            [
                _resp(402, json_body={"x402Version": 2, "accepts": [_requirements()]}),
                _resp(200, json_body={"data": "ok"}),  # no payment-response header
            ]
        )
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        with pytest.raises(X402SettlementProofMissingError):
            await adapter.pay(
                UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_payer_replay_detected(self) -> None:
        other = "0x" + "1" * 40
        fetch = _make_fetch(
            [
                _resp(402, json_body={"x402Version": 2, "accepts": [_requirements()]}),
                _resp(
                    200,
                    json_body={"data": "ok"},
                    headers={"payment-response": _payment_response_header(payer=other)},
                ),
            ]
        )
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        with pytest.raises(X402SettlementProofMissingError, match="does not match our wallet"):
            await adapter.pay(
                UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_invalid_tx_hash_in_proof_raises(self) -> None:
        fetch = _make_fetch(
            [
                _resp(402, json_body={"x402Version": 2, "accepts": [_requirements()]}),
                _resp(
                    200,
                    json_body={"data": "ok"},
                    headers={
                        "payment-response": _payment_response_header(transaction="0xdead")
                    },
                ),
            ]
        )
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        with pytest.raises(X402SettlementProofMissingError, match="transaction"):
            await adapter.pay(
                UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_free_service_200_initial(self) -> None:
        fetch = _make_fetch([_resp(200, json_body={"free": True})])
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        result = await adapter.pay(
            UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
        )
        assert result.success is True
        assert result.tx_id == "0x" + "0" * 64
        assert result.amount == "0"

    @pytest.mark.asyncio
    async def test_non_402_non_2xx_raises(self) -> None:
        fetch = _make_fetch([_resp(403, json_body={})])
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        with pytest.raises(X402PaymentFailedError):
            await adapter.pay(
                UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_get_status_after_pay(self) -> None:
        fetch = _make_fetch(
            [
                _resp(402, json_body={"x402Version": 2, "accepts": [_requirements()]}),
                _resp(
                    200,
                    json_body={"data": "ok"},
                    headers={"payment-response": _payment_response_header()},
                ),
            ]
        )
        adapter = X402Adapter(SIGNER_ADDR, _config(fetch_fn=fetch))
        result = await adapter.pay(
            UnifiedPayParams(to=URL, amount="0.01", metadata=_opt_in())  # type: ignore[arg-type]
        )
        status = await adapter.get_status(result.tx_id)
        assert status["state"] == "COMMITTED"
        assert status["can_release"] is False


# ---------------------------------------------------------------------------
# Lifecycle methods raise
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_work_raises(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        with pytest.raises(RuntimeError, match="stateless"):
            await adapter.start_work("0x1")

    @pytest.mark.asyncio
    async def test_release_raises(self) -> None:
        adapter = X402Adapter(SIGNER_ADDR, _config())
        with pytest.raises(RuntimeError, match="no escrow"):
            await adapter.release("0x1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_parse_usdc_amount(self) -> None:
        assert parse_usdc_amount("1") == 1_000_000
        assert parse_usdc_amount("0.5") == 500_000
        assert parse_usdc_amount("$1.000000") == 1_000_000

    def test_parse_usdc_amount_invalid(self) -> None:
        with pytest.raises(X402ConfigError):
            parse_usdc_amount("abc")

    def test_format_usdc_amount(self) -> None:
        assert format_usdc_amount(1_000_000) == "1"
        assert format_usdc_amount(500_000) == "0.5"
        assert format_usdc_amount(10_000) == "0.01"

    def test_safe_big_int_raw_vs_decimal(self) -> None:
        assert safe_big_int("10000") == 10000
        assert safe_big_int("0.01") == 10000
        assert safe_big_int(5) == 5
        assert safe_big_int(-1) == 0
        assert safe_big_int("garbage") == 0
