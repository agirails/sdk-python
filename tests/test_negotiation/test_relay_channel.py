"""Tests for the production RelayChannel (NegotiationChannel over HTTP).

Mirrors sdk-js/src/negotiation/RelayChannel.test.ts behaviours: post → correct
endpoint + body, GET poll → verify-before-deliver, dedup-after-verify,
unknown-chain drop, verify-failure drop, SSRF guard on base_url, agent-inbox
routing. HTTP is mocked via httpx.MockTransport — no real network IO.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from eth_account import Account

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.builders.quote import QuoteBuilder, QuoteParams
from agirails.negotiation.negotiation_channel import (
    COUNTEROFFER_ENVELOPE,
    QUOTE_ENVELOPE,
    NegotiationMessage,
    RelayChannel,
    RelayChannelConfig,
    _envelope_to_wire,
    _wire_to_envelope,
    is_counter_offer_envelope,
    is_quote_envelope,
)

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
CHAIN_ID = 84_532
TX_ID = "0x" + "a" * 64
BASE = "https://relay.example.com"


def _provider():
    acct = Account.create()
    return acct, f"did:ethr:{CHAIN_ID}:{acct.address}"


def _consumer():
    acct = Account.create()
    return acct, f"did:ethr:{CHAIN_ID}:{acct.address}"


def _build_quote(provider_acct, provider_did, consumer_did, quoted="7000000"):
    qb = QuoteBuilder(account=provider_acct, nonce_manager=MessageNonceManager())
    return qb.build(
        QuoteParams(
            tx_id=TX_ID,
            provider=provider_did,
            consumer=consumer_did,
            quoted_amount=quoted,
            original_amount="5000000",
            max_price="10000000",
            chain_id=CHAIN_ID,
            kernel_address=KERNEL,
        )
    )


def _channel(handler, **kw) -> RelayChannel:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cfg = RelayChannelConfig(
        kernel_address_by_chain_id={CHAIN_ID: KERNEL},
        base_url=BASE,
        http_client=client,
        allow_insecure_targets=True,
        poll_interval_ms=10,
        **kw,
    )
    return RelayChannel(cfg)


# ---------------------------------------------------------------------------
# wire round-trip
# ---------------------------------------------------------------------------


def test_wire_round_trip_is_lossless() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    env = NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
    wire = _envelope_to_wire(env)
    # wire is plain JSON-able
    json.dumps(wire)
    back = _wire_to_envelope(wire)
    assert back is not None
    assert is_quote_envelope(back)
    assert back.message.signature == quote.signature
    assert back.message.tx_id == quote.tx_id
    assert back.message.quoted_amount == quote.quoted_amount


def test_wire_to_envelope_rejects_malformed() -> None:
    assert _wire_to_envelope(None) is None
    assert _wire_to_envelope({"type": "bogus", "message": {}}) is None
    assert _wire_to_envelope({"type": QUOTE_ENVELOPE}) is None
    # extra field not on the dataclass → malformed → skipped
    assert _wire_to_envelope({"type": QUOTE_ENVELOPE, "message": {"nope": 1}}) is None


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------


def test_ssrf_guard_blocks_private_host_by_default() -> None:
    with pytest.raises(Exception):
        RelayChannel(
            RelayChannelConfig(
                kernel_address_by_chain_id={CHAIN_ID: KERNEL},
                base_url="http://127.0.0.1:3000",
            )
        )


def test_ssrf_guard_allows_private_host_when_opted_in() -> None:
    ch = RelayChannel(
        RelayChannelConfig(
            kernel_address_by_chain_id={CHAIN_ID: KERNEL},
            base_url="http://127.0.0.1:3000",
            allow_insecure_targets=True,
        )
    )
    assert ch is not None


# ---------------------------------------------------------------------------
# post
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_hits_correct_endpoint_and_body() -> None:
    captured: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"ok": True})

    ch = _channel(handler)
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    await ch.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))

    assert captured["method"] == "POST"
    assert captured["url"] == f"{BASE}/api/v1/negotiations/{TX_ID}/messages"
    assert captured["body"]["type"] == QUOTE_ENVELOPE
    assert captured["body"]["message"]["signature"] == quote.signature


@pytest.mark.asyncio
async def test_post_raises_on_non_2xx() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    ch = _channel(handler)
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    with pytest.raises(RuntimeError, match="Relay POST 500"):
        await ch.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))


# ---------------------------------------------------------------------------
# subscribe_tx_id — verify + deliver
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscribe_tx_id_delivers_verified_message() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    wire_item = {
        "cursor": "1",
        "envelope": _envelope_to_wire(
            NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
        ),
        "receivedAt": 1700,
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [wire_item]})

    ch = _channel(handler)
    received: list = []

    sub = ch.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    # Let the poll loop run a couple of ticks.
    for _ in range(20):
        await asyncio.sleep(0.01)
        if received:
            break
    sub.unsubscribe()
    await ch.close()

    assert len(received) == 1
    assert is_quote_envelope(received[0].envelope)
    assert received[0].envelope.message.signature == quote.signature
    assert received[0].cursor == "1"
    assert received[0].received_at == 1700


@pytest.mark.asyncio
async def test_subscribe_dedups_by_signature() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    item = {
        "cursor": "1",
        "envelope": _envelope_to_wire(
            NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
        ),
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        # Same item returned every poll — must dedup after first delivery.
        return httpx.Response(200, json={"messages": [item]})

    ch = _channel(handler)
    received: list = []
    sub = ch.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    for _ in range(15):
        await asyncio.sleep(0.01)
    sub.unsubscribe()
    await ch.close()
    assert len(received) == 1


@pytest.mark.asyncio
async def test_unknown_chain_dropped() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    item = {
        "cursor": "1",
        "envelope": _envelope_to_wire(
            NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
        ),
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [item]})

    # Channel knows a DIFFERENT chain only → message dropped.
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ch = RelayChannel(
        RelayChannelConfig(
            kernel_address_by_chain_id={1: KERNEL},  # not CHAIN_ID
            base_url=BASE,
            http_client=client,
            allow_insecure_targets=True,
            poll_interval_ms=10,
        )
    )
    received: list = []
    sub = ch.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    for _ in range(15):
        await asyncio.sleep(0.01)
    sub.unsubscribe()
    await ch.close()
    assert received == []


@pytest.mark.asyncio
async def test_verify_failure_dropped() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    wire = _envelope_to_wire(
        NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
    )
    # Tamper the amount AFTER signing → signature no longer recovers signer.
    wire["message"]["quoted_amount"] = "9999999"
    item = {"cursor": "1", "envelope": wire}

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [item]})

    ch = _channel(handler)
    received: list = []
    sub = ch.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    for _ in range(15):
        await asyncio.sleep(0.01)
    sub.unsubscribe()
    await ch.close()
    assert received == []


@pytest.mark.asyncio
async def test_subscribe_agent_routes_by_inbox() -> None:
    pacct, pdid = _provider()
    _, cdid = _consumer()
    quote = _build_quote(pacct, pdid, cdid)
    item = {
        "cursor": "1",
        "txId": TX_ID,
        "envelope": _envelope_to_wire(
            NegotiationMessage(type=QUOTE_ENVELOPE, message=quote)
        ),
    }
    captured_url: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured_url["url"] = str(request.url)
        return httpx.Response(200, json={"messages": [item]})

    ch = _channel(handler)
    received: list = []
    sub = ch.subscribe_agent(pdid, lambda tx, d: received.append((tx, d)))
    for _ in range(20):
        await asyncio.sleep(0.01)
        if received:
            break
    sub.unsubscribe()
    await ch.close()

    assert "/api/v1/negotiations/inbox/" in captured_url["url"]
    assert len(received) == 1
    assert received[0][0] == TX_ID
    assert is_quote_envelope(received[0][1].envelope)


@pytest.mark.asyncio
async def test_close_is_idempotent_and_cancels_polls() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": []})

    ch = _channel(handler)
    ch.subscribe_tx_id(TX_ID, lambda d: None)
    await ch.close()
    await ch.close()  # second close must not raise
    assert len(ch._poll_states) == 0
