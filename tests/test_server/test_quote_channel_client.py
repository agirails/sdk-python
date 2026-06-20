"""QuoteChannelClient (send side) + SSRF guard tests — TS-parity.

Mirrors sdk-js/src/transport/QuoteChannel.test.ts client + assertSafePeerUrl
coverage: https-only by default, localhost / loopback / link-local / RFC1918 /
IPv6 ULA refusal, IPv4-mapped IPv6 bypass closure, and POST path binding.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from eth_account import Account

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.builders.quote import QuoteBuilder, QuoteParams
from agirails.server.quote_channel import (
    QuoteChannelClient,
    QuoteChannelClientConfig,
    assert_safe_peer_url,
    build_channel_path,
)

KERNEL = "0x1234567890123456789012345678901234567890"
CHAIN_ID = 84_532
TX_ID = "0x" + "a" * 64


# ============================================================================
# assert_safe_peer_url — SSRF guard
# ============================================================================


def test_safe_url_https_allowed():
    assert_safe_peer_url("https://provider.example.com/quote-channel/84532/0xabc", False)


@pytest.mark.parametrize(
    "url,needle",
    [
        ("http://provider.example.com/x", "https"),
        ("https://localhost/x", "localhost"),
        ("https://127.0.0.1/x", "loopback"),
        ("https://169.254.169.254/x", "link-local"),
        ("https://10.0.0.1/x", "RFC1918"),
        ("https://192.168.1.1/x", "RFC1918"),
        ("https://172.16.0.1/x", "RFC1918"),
        ("https://[::1]/x", "loopback"),
        ("https://[fe80::1]/x", "link-local"),
        ("https://[fc00::1]/x", "ULA"),
        # IPv4-mapped IPv6 must still be caught (dotted + hex folded forms).
        ("https://[::ffff:127.0.0.1]/x", "loopback"),
        ("https://[::ffff:169.254.169.254]/x", "link-local"),
    ],
)
def test_unsafe_urls_rejected(url, needle):
    with pytest.raises(ValueError) as exc:
        assert_safe_peer_url(url, False)
    assert needle.lower() in str(exc.value).lower()


def test_allow_insecure_targets_bypasses_guard():
    # http://localhost is fine when insecure targets explicitly allowed.
    assert_safe_peer_url("http://localhost:8080/x", True)


# ============================================================================
# build_channel_path
# ============================================================================


def test_build_channel_path():
    assert build_channel_path(CHAIN_ID, TX_ID) == f"/quote-channel/{CHAIN_ID}/{TX_ID}"


# ============================================================================
# send_quote / send_counter
# ============================================================================


def _make_quote(provider_acct, provider_did, consumer_did):
    return QuoteBuilder(account=provider_acct, nonce_manager=MessageNonceManager()).build(
        QuoteParams(
            tx_id=TX_ID,
            provider=provider_did,
            consumer=consumer_did,
            quoted_amount="7000000",
            original_amount="5000000",
            max_price="10000000",
            chain_id=CHAIN_ID,
            kernel_address=KERNEL,
        )
    )


def _make_counter(buyer_pk, provider_did, consumer_did):
    return CounterOfferBuilder(
        private_key=buyer_pk, nonce_manager=MessageNonceManager()
    ).build(
        CounterOfferParams(
            txId=TX_ID,
            consumer=consumer_did,
            provider=provider_did,
            quoteAmount="7000000",
            counterAmount="6000000",
            maxPrice="10000000",
            inReplyTo="0x" + "b" * 64,
            chainId=CHAIN_ID,
            kernelAddress=KERNEL,
        )
    )


@pytest.mark.asyncio
@respx.mock
async def test_send_quote_posts_to_channel_path():
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    quote = _make_quote(provider_acct, provider_did, consumer_did)

    expected_url = f"https://provider.example.com{build_channel_path(CHAIN_ID, TX_ID)}"
    route = respx.post(expected_url).mock(
        return_value=httpx.Response(201, json={"accepted": True, "duplicate": False})
    )

    client = QuoteChannelClient()
    await client.send_quote("https://provider.example.com", quote)

    assert route.called
    sent = route.calls.last.request
    import json as _json

    body = _json.loads(sent.content)
    assert body["type"] == "agirails.quote.v1"
    assert body["message"]["txId"] == TX_ID


@pytest.mark.asyncio
@respx.mock
async def test_send_counter_posts_to_channel_path():
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    counter = _make_counter(buyer_acct.key.hex(), provider_did, consumer_did)

    expected_url = f"https://provider.example.com{build_channel_path(CHAIN_ID, TX_ID)}"
    route = respx.post(expected_url).mock(
        return_value=httpx.Response(201, json={"accepted": True})
    )

    client = QuoteChannelClient()
    await client.send_counter("https://provider.example.com/", counter)  # trailing slash stripped

    assert route.called
    body = __import__("json").loads(route.calls.last.request.content)
    assert body["type"] == "agirails.counteroffer.v1"
    assert body["message"]["counterAmount"] == "6000000"


@pytest.mark.asyncio
@respx.mock
async def test_send_quote_raises_on_error_status():
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    quote = _make_quote(provider_acct, provider_did, consumer_did)

    expected_url = f"https://provider.example.com{build_channel_path(CHAIN_ID, TX_ID)}"
    respx.post(expected_url).mock(return_value=httpx.Response(500, text="relay boom"))

    client = QuoteChannelClient()
    with pytest.raises(RuntimeError) as exc:
        await client.send_quote("https://provider.example.com", quote)
    assert "500" in str(exc.value)


@pytest.mark.asyncio
async def test_send_quote_refuses_insecure_target_by_default():
    provider_acct = Account.create()
    buyer_acct = Account.create()
    provider_did = f"did:ethr:{CHAIN_ID}:{provider_acct.address}"
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    quote = _make_quote(provider_acct, provider_did, consumer_did)

    client = QuoteChannelClient()  # secure by default
    with pytest.raises(ValueError, match="https"):
        await client.send_quote("http://provider.example.com", quote)
