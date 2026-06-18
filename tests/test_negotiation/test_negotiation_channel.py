"""Tests for the in-memory NegotiationChannel (MockChannel) — TS-parity.

Mirrors sdk-js/src/negotiation/MockChannel.test.ts behaviours: post →
verified async fan-out, subscribe_tx_id / subscribe_agent filtering, dedup,
verify-failure drop, unknown-chain drop, replay of buffered messages.
"""

from __future__ import annotations

import pytest
from eth_account import Account

from agirails.builders.counter_offer import CounterOfferBuilder, CounterOfferParams, MessageNonceManager
from agirails.builders.quote import QuoteBuilder, QuoteParams
from agirails.negotiation.negotiation_channel import (
    QUOTE_ENVELOPE,
    COUNTEROFFER_ENVELOPE,
    DeliveredMessage,
    MockChannel,
    MockChannelConfig,
    NegotiationMessage,
    envelope_chain_id,
    envelope_tx_id,
    is_counter_offer_envelope,
    is_quote_envelope,
)

KERNEL = "0x1234567890123456789012345678901234567890"
CHAIN_ID = 84_532
TX_ID = "0x" + "a" * 64


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


def _build_counter(buyer_pk, provider_did, consumer_did, counter="6000000"):
    cb = CounterOfferBuilder(private_key=buyer_pk, nonce_manager=MessageNonceManager())
    return cb.build(
        CounterOfferParams(
            txId=TX_ID,
            consumer=consumer_did,
            provider=provider_did,
            quoteAmount="7000000",
            counterAmount=counter,
            maxPrice="10000000",
            inReplyTo="0x" + "b" * 64,
            chainId=CHAIN_ID,
            kernelAddress=KERNEL,
        )
    )


@pytest.mark.asyncio
async def test_post_then_subscribe_delivers_verified_quote():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)

    received: list[DeliveredMessage] = []
    channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()

    assert len(received) == 1
    assert received[0].envelope.type == QUOTE_ENVELOPE
    assert is_quote_envelope(received[0].envelope)
    assert envelope_tx_id(received[0].envelope).lower() == TX_ID
    assert envelope_chain_id(received[0].envelope) == CHAIN_ID
    await channel.close()


@pytest.mark.asyncio
async def test_replay_of_buffered_message_on_subscribe():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)
    # Post BEFORE subscribing — the message must be replayed to the new sub.
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()

    received: list[DeliveredMessage] = []
    channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    await channel.drain()

    assert len(received) == 1
    await channel.close()


@pytest.mark.asyncio
async def test_dedup_same_signature_not_delivered_twice():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)

    received: list[DeliveredMessage] = []
    channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()

    assert len(received) == 1  # same signature → delivered once
    await channel.close()


@pytest.mark.asyncio
async def test_verify_failure_drops_message():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)
    # Tamper the amount after signing — EIP-712 verify must fail → dropped.
    quote.quoted_amount = "9999999"

    received: list[DeliveredMessage] = []
    channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()

    assert received == []
    await channel.close()


@pytest.mark.asyncio
async def test_unknown_chain_dropped():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    # No kernel configured for the chain → silent drop.
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)

    received: list[DeliveredMessage] = []
    channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()

    assert received == []
    await channel.close()


@pytest.mark.asyncio
async def test_subscribe_agent_filters_by_provider_did():
    provider_acct, provider_did = _provider()
    buyer_acct = Account.create()
    consumer_did = f"did:ethr:{CHAIN_ID}:{buyer_acct.address}"
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    counter = _build_counter(buyer_acct.key.hex(), provider_did, consumer_did)

    seen: list[tuple[str, DeliveredMessage]] = []
    channel.subscribe_agent(provider_did, lambda tx, d: seen.append((tx, d)))
    await channel.post(TX_ID, NegotiationMessage(type=COUNTEROFFER_ENVELOPE, message=counter))
    await channel.drain()

    assert len(seen) == 1
    assert seen[0][0] == TX_ID
    assert is_counter_offer_envelope(seen[0][1].envelope)
    await channel.close()


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery_and_decrements_count():
    provider_acct, provider_did = _provider()
    _, consumer_did = _consumer()
    channel = MockChannel(MockChannelConfig(kernel_address_by_chain_id={CHAIN_ID: KERNEL}))
    quote = _build_quote(provider_acct, provider_did, consumer_did)

    received: list[DeliveredMessage] = []
    sub = channel.subscribe_tx_id(TX_ID, lambda d: received.append(d))
    assert channel.active_subscription_count() == 1
    sub.unsubscribe()
    assert channel.active_subscription_count() == 0
    # Idempotent unsubscribe.
    sub.unsubscribe()

    await channel.post(TX_ID, NegotiationMessage(type=QUOTE_ENVELOPE, message=quote))
    await channel.drain()
    assert received == []
    await channel.close()
