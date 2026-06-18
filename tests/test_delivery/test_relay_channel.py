"""Tests for RelayDeliveryChannel (AIP-16 port) + channel logger.

HTTP is mocked via httpx.MockTransport so no real network IO happens. Covers
the request shapes, SSRF guard, dedup-after-verify on read, and the polling
subscribe path.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from eth_account import Account

from agirails.delivery import (
    BuildPublicEnvelopeParams,
    DeliveryEnvelopeBuilder,
    RelayDeliveryChannel,
    RelayDeliveryChannelOptions,
    noop_log,
)
from agirails.delivery.channel_log import noopLog

KERNEL = "0x469CBADbACFFE096270594F0a31f0EEC53753411"
CHAIN = 84532
TXID = "0x" + "ab" * 32
PROVIDER = Account.from_key("0x" + "22" * 32)


def _make_envelope_wire() -> dict:
    eb = DeliveryEnvelopeBuilder(signer=PROVIDER)
    res = eb.build_public(
        BuildPublicEnvelopeParams(
            tx_id=TXID,
            chain_id=CHAIN,
            kernel_address=KERNEL,
            provider_address=PROVIDER.address,
            signer_address=PROVIDER.address,
            payload={"a": 1},
        )
    )
    return res["wire"]


def test_noop_log_is_silent_and_aliased() -> None:
    assert noop_log is noopLog
    # Must not raise and return None.
    assert noop_log("warn", "msg", {"k": "v"}) is None


def test_ssrf_guard_blocks_private_host_by_default() -> None:
    with pytest.raises(Exception):
        RelayDeliveryChannel(
            RelayDeliveryChannelOptions(base_url="http://127.0.0.1:3000")
        )


def test_ssrf_guard_allows_private_host_when_opted_in() -> None:
    ch = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url="http://127.0.0.1:3000", allow_private_hosts=True
        )
    )
    assert ch is not None


@pytest.mark.asyncio
async def test_publish_setup_posts_to_correct_endpoint() -> None:
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ch = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url="https://relay.example.com",
            http_client=client,
            allow_private_hosts=True,  # skip DNS resolution of the test host
        )
    )
    wire = _make_envelope_wire()
    await ch.publish_envelope(wire)
    assert captured["method"] == "POST"
    assert captured["url"] == "https://relay.example.com/api/v1/delivery"
    assert captured["body"]["signed"]["txId"] == TXID
    await ch.close()


@pytest.mark.asyncio
async def test_publish_non_2xx_raises() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ch = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url="https://relay.example.com",
            http_client=client,
            allow_private_hosts=True,
        )
    )
    with pytest.raises(RuntimeError) as exc:
        await ch.publish_setup({"signed": {"txId": TXID}, "requesterSig": "0x"})
    assert "500" in str(exc.value)
    await ch.close()


@pytest.mark.asyncio
async def test_subscribe_envelopes_polls_and_delivers_verified_item() -> None:
    wire = _make_envelope_wire()
    served = {"count": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        # GET /api/v1/delivery/<txId>; serve the item once, then empty.
        assert request.method == "GET"
        assert f"/api/v1/delivery/{TXID}" in str(request.url)
        served["count"] += 1
        if served["count"] == 1:
            return httpx.Response(200, json={"items": [{"cursor": "c1", "wire": wire}]})
        return httpx.Response(200, json={"items": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ch = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url="https://relay.example.com",
            http_client=client,
            allow_private_hosts=True,
            poll_interval_ms=10,
        )
    )
    received = []
    sub = await ch.subscribe_envelopes(TXID, lambda w: received.append(w))
    # Let a couple of poll ticks run.
    await asyncio.sleep(0.1)
    sub.close()
    await ch.close()
    assert len(received) == 1
    assert received[0]["signed"]["txId"] == TXID


@pytest.mark.asyncio
async def test_subscribe_drops_unverified_item() -> None:
    wire = _make_envelope_wire()
    # Tamper the body so payloadHash verification fails -> item dropped.
    tampered = dict(wire)
    tampered["body"] = '{"a":2}'

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"items": [{"cursor": "c1", "wire": tampered}]}
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ch = RelayDeliveryChannel(
        RelayDeliveryChannelOptions(
            base_url="https://relay.example.com",
            http_client=client,
            allow_private_hosts=True,
            poll_interval_ms=10,
        )
    )
    received = []
    sub = await ch.subscribe_envelopes(TXID, lambda w: received.append(w))
    await asyncio.sleep(0.08)
    sub.close()
    await ch.close()
    assert len(received) == 0  # unverified item never delivered
