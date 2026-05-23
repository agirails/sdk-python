"""End-to-end `actp serve` daemon tests.

Audit follow-up #5. The existing tests/test_server/test_actp_serve.py
covers the FastAPI surface via TestClient with unit-shape inputs.
This file goes deeper: a real signed CounterOffer message generated
by the Python SDK is posted to the daemon over the full ASGI stack,
and we verify:

  1. JSON body round-trips through Starlette's request.json() path
     (Content-Type + encoding works)
  2. Path parameters extract correctly under FastAPI's TypeAdapter
  3. EIP-712 signature verification runs end-to-end inside the
     handler (not just as a stub)
  4. Policy evaluator runs against the parsed message
  5. Response body parses back via httpx + has the expected verdict
     shape

Plus a multi-roundtrip stress: same fixture twice → second response
must have `duplicate: true` (nonce dedup works end-to-end).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

# Skip the entire file if FastAPI isn't installed (server extras).
pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.server.app import create_app
from agirails.server.policy import PricingPolicy, ProviderPolicy
from agirails.server.quote_channel import build_channel_path
from eth_account import Account


KERNEL = "0x" + "A" * 40
TX_ID = "0x" + "a" * 64
QUOTE_HASH = "0x" + "b" * 64
CHAIN_ID = 84532


@pytest.fixture
def buyer():
    return Account.create()


@pytest.fixture
def provider():
    return Account.create()


@pytest.fixture
def policy():
    return ProviderPolicy(
        pricing=PricingPolicy(
            min_acceptable_amount=500_000,  # $0.50
            ideal_amount=1_000_000,  # $1.00
        ),
        services=["text-generation"],
        counter_strategy="concede",
        concede_pct=30,
    )


@pytest.fixture
def client(policy):
    app = create_app(
        policy=policy,
        kernel_address_by_chain_id={CHAIN_ID: KERNEL},
        signer_address="0x" + "9" * 40,
    )
    return TestClient(app)


def _make_signed_counter(buyer, provider, counter_amount: str):
    """Build + sign a real CounterOffer via the Python builder."""
    nm = MessageNonceManager()
    builder = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
    return builder.build(
        CounterOfferParams(
            txId=TX_ID,
            consumer=f"did:ethr:{CHAIN_ID}:{buyer.address}",
            provider=f"did:ethr:{CHAIN_ID}:{provider.address}",
            quoteAmount="1500000",
            counterAmount=counter_amount,
            maxPrice="2000000",
            inReplyTo=QUOTE_HASH,
            chainId=CHAIN_ID,
            kernelAddress=KERNEL,
        )
    )


def _to_wire(msg) -> dict:
    return {"type": "agirails.counteroffer.v1", "message": msg.to_dict()}


# ============================================================================
# Real signed message → daemon → response
# ============================================================================


class TestServeRealRoundtrip:
    def test_accept_above_ideal_full_stack(self, client, buyer, provider):
        """1.1 USDC counter ≥ 1.0 USDC ideal → ACCEPT verdict via
        full HTTP + ASGI + Starlette + EIP-712 sig recovery stack."""
        msg = _make_signed_counter(buyer, provider, "1100000")
        response = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_to_wire(msg),
        )
        assert response.status_code == 201
        body = response.json()
        assert body["accepted"] is True
        assert body["duplicate"] is False
        assert body["verdict"]["action"] == "ACCEPT"
        assert body["verdict"]["recommended_amount"] == "1100000"

    def test_counter_in_band_concede_strategy_full_stack(
        self, client, buyer, provider
    ):
        """0.6 USDC counter in band [0.5, 1.0) + concede strategy →
        COUNTER verdict with recommended_amount in the negotiation band."""
        msg = _make_signed_counter(buyer, provider, "600000")
        response = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_to_wire(msg),
        )
        assert response.status_code == 201
        body = response.json()
        assert body["verdict"]["action"] == "COUNTER"
        # concede 30% from ideal (1_000_000) toward floor (500_000)
        # = 1_000_000 - 150_000 = 850_000
        rec = int(body["verdict"]["recommended_amount"])
        assert 500_000 < rec < 1_000_000

    def test_reject_below_floor_full_stack(self, client, buyer, provider):
        """0.4 USDC < 0.5 USDC floor → REJECT verdict."""
        # build counter below floor needs >= platform min (50_000),
        # but we want above PLATFORM_MIN and below floor.
        msg = _make_signed_counter(buyer, provider, "400000")
        response = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_to_wire(msg),
        )
        assert response.status_code == 201
        body = response.json()
        assert body["verdict"]["action"] == "REJECT"
        assert "below provider floor" in body["verdict"]["reason"]


# ============================================================================
# Dedup over the wire — same fixture twice → second is "duplicate"
# ============================================================================


class TestServeDedupOverWire:
    def test_replay_returns_duplicate(self, client, buyer, provider):
        msg = _make_signed_counter(buyer, provider, "1100000")
        wire = _to_wire(msg)

        r1 = client.post(build_channel_path(CHAIN_ID, TX_ID), json=wire)
        assert r1.status_code == 201
        assert r1.json()["duplicate"] is False

        # Same bytes posted again — nonce dedup MUST kick in.
        r2 = client.post(build_channel_path(CHAIN_ID, TX_ID), json=wire)
        assert r2.status_code == 200
        assert r2.json()["duplicate"] is True


# ============================================================================
# Negative paths over the wire
# ============================================================================


class TestServeNegativeRoundtrip:
    def test_path_chain_id_mismatch_returns_400(self, client, buyer, provider):
        """URL says chainId 1, message has 84532 → 400 (T2/T5 mitigation)."""
        msg = _make_signed_counter(buyer, provider, "1100000")
        response = client.post(
            "/quote-channel/1/" + TX_ID,
            json=_to_wire(msg),
        )
        assert response.status_code == 400
        assert "chainId mismatch" in response.json()["reason"]

    def test_path_tx_id_mismatch_returns_400(self, client, buyer, provider):
        msg = _make_signed_counter(buyer, provider, "1100000")
        wrong_tx = "0x" + "f" * 64
        response = client.post(
            build_channel_path(CHAIN_ID, wrong_tx),
            json=_to_wire(msg),
        )
        assert response.status_code == 400
        assert "txId mismatch" in response.json()["reason"]

    def test_tampered_signature_returns_401(self, client, buyer, provider):
        msg = _make_signed_counter(buyer, provider, "1100000")
        wire = _to_wire(msg)
        # Flip byte in r (position 12 of signature).
        sig = wire["message"]["signature"]
        original = int(sig[12:14], 16)
        wire["message"]["signature"] = sig[:12] + f"{original ^ 0x01:02x}" + sig[14:]

        response = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=_to_wire(_make_signed_counter(buyer, provider, "1100000")),  # baseline known-good
        )
        # Sanity: the baseline must verify
        assert response.status_code == 201

        # Now post the tampered one with a FRESH nonce (re-build).
        # The tampered version is rejected at signature verify time.
        tampered_msg = _make_signed_counter(buyer, provider, "1100001")  # new nonce
        tampered_wire = _to_wire(tampered_msg)
        sig = tampered_wire["message"]["signature"]
        original = int(sig[12:14], 16)
        tampered_wire["message"]["signature"] = (
            sig[:12] + f"{original ^ 0x01:02x}" + sig[14:]
        )

        bad_response = client.post(
            build_channel_path(CHAIN_ID, TX_ID),
            json=tampered_wire,
        )
        assert bad_response.status_code == 401
        # Reason explicitly mentions signature recovery failure.
        reason = bad_response.json()["reason"].lower()
        assert "signature" in reason or "recover" in reason
