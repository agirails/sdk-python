# PARITY: sdk-js/tests/evaluator-client.test.ts
"""
P2-6 — EvaluatorClient unit tests (Py side).

Mirrors ``sdk-js/tests/evaluator-client.test.ts`` 1:1 and consumes the SAME
shared cross-SDK fixture
``DISPUTE SYSTEM/test-vectors/evaluator-client-vectors.json``.

Proves, with mocked HTTP (no live evaluator, no live chain):
  1. §4.7 signature verification replicated client-side — 2-valid+1-unknown
     passes, two fixed pass, duplicate counted once, duplicate-under-threshold
     fails, stale fails, one-valid+unknown fails. (PARITY: the TS twin asserts
     the IDENTICAL fixture rows and recovers the SAME signers.)
  2. select_third_evaluator matches §4.7 step 4 (keccak(abi.encode(disputeId)) % len).
  3. request_evaluation runs the full STEP 0→5 handshake: POST /quote (declare,
     no money) → 402 → pay via the injected x402 buyer stub → POST /evaluate →
     parse signed response → §4.7 verify → return signed result.
  4. A proposeDirectly evaluate response surfaces a no-sig recommendation.
  5. A signed response that FAILS §4.7 downgrades to a proposeDirectly
     recommendation with NO signatures (never fabricates a signature).
  6. The client NEVER submits on-chain (no contract is constructed).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from agirails.dispute.evaluator_client import (
    EvaluatorClient,
    EvaluatorClientConfig,
    RequestEvaluationParams,
    BundleSource,
    QuoteRejectedError,
    verify_ruling_signatures,
    select_third_evaluator,
)
from agirails.dispute.evidence_bundle import compute_bundle_hash
from agirails.types.dispute import AIRuling, recover_ruling_signer, sign_ruling

# Shared cross-SDK fixtures (the SAME files the TS jest suite loads).
_VECTORS_DIR = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
FIXTURE = json.loads((_VECTORS_DIR / "evaluator-client-vectors.json").read_text())
BUNDLE_VECTORS = json.loads((_VECTORS_DIR / "bundle-vectors.json").read_text())

DOMAIN = FIXTURE["domain"]
RULING_FX = FIXTURE["ruling"]
REGISTRY = FIXTURE["registry"]
SIGS = FIXTURE["signatures"]


def _fixture_ruling() -> AIRuling:
    r = RULING_FX
    return AIRuling(
        dispute_id=r["disputeId"],
        ruling=r["ruling"],
        confidence=r["confidence"],
        split_bps=r["splitBps"],
        timestamp=r["timestamp"],
        reasoning_hash=r["reasoningHash"],
        bundle_hash=r["bundleHash"],
    )


# =====================================================================
# 1. §4.7 signature verification (pure — consumes the static golden fixture)
# =====================================================================


class TestVerification:
    def test_recovers_exact_fixture_signers(self):
        """PARITY anchor: recovers the SAME signers the TS twin recovers."""
        ruling = _fixture_ruling()
        rec = lambda key: recover_ruling_signer(  # noqa: E731
            ruling, SIGS[key], DOMAIN["chainId"], DOMAIN["verifyingContract"]
        )
        assert rec("fixedA").lower() == REGISTRY["fixedEvaluators"][0].lower()
        assert rec("fixedB").lower() == REGISTRY["fixedEvaluators"][1].lower()
        assert rec("rotating").lower() == REGISTRY["selectedRotatingEvaluator"].lower()
        assert rec("unknown").lower() == REGISTRY["unknownSigner"].lower()

    def test_select_third_evaluator(self):
        third = select_third_evaluator(RULING_FX["disputeId"], REGISTRY["rotatingPool"])
        assert third is not None
        assert third.lower() == REGISTRY["selectedRotatingEvaluator"].lower()
        assert select_third_evaluator(RULING_FX["disputeId"], []) is None

    @pytest.mark.parametrize(
        "name,case",
        [
            (k, v)
            for k, v in FIXTURE["verificationCases"].items()
            if not k.startswith("_")
        ],
        ids=lambda x: x if isinstance(x, str) else "",
    )
    def test_verification_cases(self, name, case):
        ruling = _fixture_ruling()
        signatures = [SIGS[k] for k in case["sigKeys"]]
        v = verify_ruling_signatures(
            ruling,
            signatures,
            chain_id=DOMAIN["chainId"],
            verifying_contract=DOMAIN["verifyingContract"],
            fixed_evaluators=REGISTRY["fixedEvaluators"],
            rotating_pool=REGISTRY["rotatingPool"],
            now=case["now"],
            freshness_seconds=REGISTRY["freshnessSeconds"],
        )
        assert v.valid is case["expectValid"]
        assert v.valid_count == case["expectValidCount"]
        if "expectStale" in case:
            assert v.stale is case["expectStale"]
        assert v.third_evaluator.lower() == REGISTRY["selectedRotatingEvaluator"].lower()


# =====================================================================
# 2. Full handshake (mocked /quote + injected x402 buyer stub)
# =====================================================================

EXAMPLE_A_BUNDLE = BUNDLE_VECTORS["vectors"][0]["bundle"]
EXAMPLE_A_HASH = compute_bundle_hash(EXAMPLE_A_BUNDLE, skip_token_check=True)

TEST_KEYS = {
    "fixedA": "0x" + "11" * 32,
    "fixedB": "0x" + "22" * 32,
    "rotating": "0x" + "33" * 32,
    "unknown": "0x" + "44" * 32,
}


def _build_signed_ruling_for_example_a(timestamp: int, signer_keys: List[str]):
    """Build + sign a ruling for Example A's bundle at a chosen timestamp."""
    ruling = AIRuling(
        dispute_id=RULING_FX["disputeId"],  # same disputeId so rotating selection holds
        ruling=1,
        confidence=9500,
        split_bps=0,
        timestamp=timestamp,
        reasoning_hash=RULING_FX["reasoningHash"],
        bundle_hash=EXAMPLE_A_HASH,  # OQ-10: ruling commits the bundle we send
    )
    signatures = [
        sign_ruling(ruling, pk, DOMAIN["chainId"], DOMAIN["verifyingContract"])
        for pk in signer_keys
    ]
    return ruling, signatures


@dataclass
class _MockResponse:
    """A minimal httpx-like response (status_code + json())."""

    status_code: int
    _body: Any

    def json(self) -> Any:
        return self._body


@dataclass
class _StubPayResult:
    response: Any


class _PaymentStub:
    """A stub x402 buyer that records the /evaluate POST and returns a canned 200."""

    def __init__(self, evaluate_body: Any):
        self._evaluate_body = evaluate_body
        self.calls: List[Any] = []

    async def pay(self, params: Any) -> _StubPayResult:
        self.calls.append(params)
        return _StubPayResult(response=_MockResponse(200, self._evaluate_body))


def _make_quote_fetch(quote_body: Any, status: int = 402):
    """A mock /quote fetch that returns the fixture 402 quote body and records calls."""
    calls: List[Dict[str, Any]] = []

    async def fetch_impl(url, *, method="POST", headers=None, body=None):
        calls.append({"url": url, "body": json.loads(body) if body else None})
        return _MockResponse(status, quote_body)

    return fetch_impl, calls


def _base_params() -> RequestEvaluationParams:
    return RequestEvaluationParams(
        bundle=EXAMPLE_A_BUNDLE,
        dispute_id=RULING_FX["disputeId"],
        payer="0x1DC48019D708f3d7f1adCAAfA2Ffa198A6897E8d",
        escrow_amount="5000000",
        tier=0,
        bundle_source=BundleSource(cid="bafyExampleACid"),
        chain_id=DOMAIN["chainId"],
        verifying_contract=DOMAIN["verifyingContract"],
        fixed_evaluators=REGISTRY["fixedEvaluators"],
        rotating_pool=REGISTRY["rotatingPool"],
        freshness_seconds=REGISTRY["freshnessSeconds"],
    )


class TestHandshake:
    @pytest.mark.asyncio
    async def test_signed_path(self):
        now = int(time.time())
        ruling, signatures = _build_signed_ruling_for_example_a(
            now, [TEST_KEYS["fixedA"], TEST_KEYS["rotating"]]
        )
        evaluate_body = {
            "apiVersion": "1.0.0",
            "outcome": "signed",
            "bundleHash": EXAMPLE_A_HASH,
            "tokenCount": 419,
            "ruling": ruling.to_dict(),
            "signatures": signatures,
            "evaluators": ["0xLyingEvaluator", "0xAlsoLying"],  # advisory; MUST be ignored
            "reasoning": "requester wins",
        }
        fetch_impl, quote_calls = _make_quote_fetch(FIXTURE["quoteResponse"])
        pay = _PaymentStub(evaluate_body)
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )

        result = await client.request_evaluation(_base_params())

        # STEP 0: declared to /quote with the SDK-derived bundleHash (no money).
        assert len(quote_calls) == 1
        assert quote_calls[0]["url"] == "https://evaluator.test/quote"
        assert quote_calls[0]["body"]["bundleHash"] == EXAMPLE_A_HASH
        assert quote_calls[0]["body"]["payer"] == _base_params().payer

        # STEP 2: paid via the x402 buyer stub against /evaluate, echoing the nonce.
        assert len(pay.calls) == 1
        assert pay.calls[0].to == "https://evaluator.test/evaluate"
        assert pay.calls[0].http_method == "POST"
        assert pay.calls[0].metadata["payment_method"] == "x402"
        assert (
            json.loads(pay.calls[0].http_body)["disputeNonce"]
            == FIXTURE["quoteResponse"]["disputeNonce"]
        )

        # STEP 5: signed result, §4.7 PASSED, signers re-recovered (evaluators[] ignored).
        assert result.outcome == "signed"
        assert result.verification.valid is True
        assert result.verification.valid_count == 2
        assert result.signatures == signatures
        assert int(result.ruling.ruling) == 1
        assert str(result.ruling.bundle_hash).lower() == EXAMPLE_A_HASH.lower()

    @pytest.mark.asyncio
    async def test_propose_directly_path(self):
        evaluate_body = dict(FIXTURE["evaluateProposeDirectlyResponse"])
        evaluate_body["bundleHash"] = EXAMPLE_A_HASH  # echo the bundle we send (OQ-10)
        fetch_impl, _ = _make_quote_fetch(FIXTURE["quoteResponse"])
        pay = _PaymentStub(evaluate_body)
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )

        result = await client.request_evaluation(_base_params())
        assert result.outcome == "proposeDirectly"
        assert result.reason == "server-recommended"
        assert int(result.recommendation.ruling) == 2
        assert result.recommendation.split_bps == 5000
        # No signatures are surfaced on the proposeDirectly result.
        assert result.signatures is None

    @pytest.mark.asyncio
    async def test_signed_but_stale_downgrades(self):
        stale_ts = int(time.time()) - (REGISTRY["freshnessSeconds"] + 10)
        ruling, signatures = _build_signed_ruling_for_example_a(
            stale_ts, [TEST_KEYS["fixedA"], TEST_KEYS["fixedB"]]
        )
        evaluate_body = {
            "apiVersion": "1.0.0",
            "outcome": "signed",
            "bundleHash": EXAMPLE_A_HASH,
            "tokenCount": 419,
            "ruling": ruling.to_dict(),
            "signatures": signatures,
        }
        fetch_impl, _ = _make_quote_fetch(FIXTURE["quoteResponse"])
        pay = _PaymentStub(evaluate_body)
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )

        result = await client.request_evaluation(_base_params())
        assert result.outcome == "proposeDirectly"
        assert result.reason == "verification-failed"
        assert result.verification.stale is True
        assert result.signatures is None  # never fabricated/surfaced

    @pytest.mark.asyncio
    async def test_signed_but_insufficient_downgrades(self):
        now = int(time.time())
        ruling, signatures = _build_signed_ruling_for_example_a(
            now, [TEST_KEYS["fixedA"], TEST_KEYS["unknown"]]
        )
        evaluate_body = {
            "apiVersion": "1.0.0",
            "outcome": "signed",
            "bundleHash": EXAMPLE_A_HASH,
            "tokenCount": 419,
            "ruling": ruling.to_dict(),
            "signatures": signatures,
        }
        fetch_impl, _ = _make_quote_fetch(FIXTURE["quoteResponse"])
        pay = _PaymentStub(evaluate_body)
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )

        result = await client.request_evaluation(_base_params())
        assert result.outcome == "proposeDirectly"
        assert result.reason == "verification-failed"
        assert result.verification.valid_count == 1

    @pytest.mark.asyncio
    async def test_quote_rejected_too_large(self):
        error_envelope = {
            "apiVersion": "1.0.0",
            "error": {
                "code": "BundleTooLargeError",
                "message": "Pinned bundle is 142113 tokens; cap 100000.",
            },
        }
        fetch_impl, _ = _make_quote_fetch(error_envelope, status=413)
        pay = _PaymentStub({})
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )

        with pytest.raises(QuoteRejectedError) as exc:
            await client.request_evaluation(_base_params())
        assert exc.value.status == 413
        assert exc.value.code == "BundleTooLargeError"
        # Never paid — the x402 stub was not invoked.
        assert len(pay.calls) == 0

    @pytest.mark.asyncio
    async def test_quote_rejected_non_402(self):
        fetch_impl, _ = _make_quote_fetch(
            {"error": {"code": "PricingUnavailableError"}}, status=503
        )
        pay = _PaymentStub({})
        client = EvaluatorClient(
            EvaluatorClientConfig(
                base_url="https://evaluator.test",
                payment_client=pay,
                fetch_impl=fetch_impl,
            )
        )
        with pytest.raises(QuoteRejectedError):
            await client.request_evaluation(_base_params())
