"""Parametrized schema-validation branch tests for AIP-2.1 builders.

Targets the ``_validate_message_schema`` rejection paths in both
``CounterOfferBuilder`` and ``CounterAcceptBuilder`` — each branch is a
one-liner ``raise`` that previously had no test. Without these, a
silent regression that loosens validation (or accepts a malformed
message) would pass CI.

Pattern: build a valid message via the actual builder, mutate a single
field to an invalid value, assert ``verify()`` raises with the
expected error fragment.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from eth_account import Account

from agirails.builders.counter_accept import (
    CounterAcceptBuilder,
    CounterAcceptParams,
)
from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferParams,
    MessageNonceManager,
)
from agirails.errors import SignatureVerificationError

KERNEL = "0x" + "A" * 40
TXID = "0x" + "a" * 64
QUOTE_HASH = "0x" + "b" * 64


@pytest.fixture
def buyer():
    return Account.create()


@pytest.fixture
def provider():
    return Account.create()


def _build_valid_counter_offer(buyer, provider):
    nm = MessageNonceManager()
    builder = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
    return builder.build(
        CounterOfferParams(
            txId=TXID,
            consumer=f"did:ethr:84532:{buyer.address}",
            provider=f"did:ethr:84532:{provider.address}",
            quoteAmount="1500000",
            counterAmount="800000",
            maxPrice="2000000",
            inReplyTo=QUOTE_HASH,
            chainId=84532,
            kernelAddress=KERNEL,
        )
    )


def _build_valid_counter_accept(buyer, provider):
    nm = MessageNonceManager()
    builder = CounterAcceptBuilder(private_key=provider.key.hex(), nonce_manager=nm)
    return builder.build(
        CounterAcceptParams(
            txId=TXID,
            provider=f"did:ethr:84532:{provider.address}",
            consumer=f"did:ethr:84532:{buyer.address}",
            acceptedAmount="800000",
            inReplyTo=QUOTE_HASH,
            chainId=84532,
            kernelAddress=KERNEL,
        )
    )


# ============================================================================
# CounterOfferBuilder.verify schema branches
# ============================================================================


@pytest.mark.parametrize(
    "field,bad_value,err_fragment",
    [
        ("type", "agirails.quote.v1", "Invalid message type"),
        ("version", "1.0", "Invalid version"),
        ("txId", "0xshort", "Invalid txId"),
        ("inReplyTo", "0xshort", "Invalid inReplyTo"),
        ("consumer", "0x1234", "Invalid consumer DID"),
        ("provider", "0x1234", "Invalid provider DID"),
        ("counterAmount", "abc", "Invalid counterAmount"),
        ("quoteAmount", "abc", "Invalid quoteAmount"),
        ("maxPrice", "abc", "Invalid maxPrice"),
        ("currency", "ETH", "Only USDC"),
        ("decimals", 18, "USDC must use 6"),
        ("chainId", 1, "Invalid chainId"),
        ("signature", "0xdeadbeef", "Invalid signature"),
    ],
)
def test_counter_offer_verify_rejects_malformed_field(
    buyer, provider, field, bad_value, err_fragment
):
    msg = _build_valid_counter_offer(buyer, provider)
    setattr(msg, field, bad_value)
    verifier = CounterOfferBuilder()
    with pytest.raises((ValueError, SignatureVerificationError)) as exc_info:
        verifier.verify(msg, KERNEL)
    assert err_fragment in str(exc_info.value)


# ============================================================================
# CounterAcceptBuilder.verify schema branches
# ============================================================================


@pytest.mark.parametrize(
    "field,bad_value,err_fragment",
    [
        ("type", "agirails.quote.v1", "Invalid message type"),
        ("version", "1.0", "Invalid version"),
        ("txId", "0xshort", "Invalid txId"),
        ("inReplyTo", "0xshort", "Invalid inReplyTo"),
        ("provider", "0x1234", "Invalid provider DID"),
        ("consumer", "0x1234", "Invalid consumer DID"),
        ("acceptedAmount", "abc", "Invalid acceptedAmount"),
        ("chainId", 1, "Invalid chainId"),
        ("signature", "0xdeadbeef", "Invalid signature"),
    ],
)
def test_counter_accept_verify_rejects_malformed_field(
    buyer, provider, field, bad_value, err_fragment
):
    msg = _build_valid_counter_accept(buyer, provider)
    setattr(msg, field, bad_value)
    verifier = CounterAcceptBuilder()
    with pytest.raises((ValueError, SignatureVerificationError)) as exc_info:
        verifier.verify(msg, KERNEL)
    assert err_fragment in str(exc_info.value)


# ============================================================================
# Build-time param validation branches
# ============================================================================


@pytest.mark.parametrize(
    "bad_param,err_fragment",
    [
        ({"txId": "0xshort"}, "txId"),
        ({"inReplyTo": "0xshort"}, "inReplyTo"),
        ({"kernelAddress": "0xshort"}, "kernelAddress"),
        ({"consumer": "ethr:abc"}, "consumer"),
        ({"provider": "ethr:abc"}, "provider"),
        ({"counterAmount": "not-a-number"}, "numeric"),
    ],
)
def test_counter_offer_build_rejects_malformed_param(
    buyer, provider, bad_param, err_fragment
):
    nm = MessageNonceManager()
    builder = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
    base = dict(
        txId=TXID,
        consumer=f"did:ethr:84532:{buyer.address}",
        provider=f"did:ethr:84532:{provider.address}",
        quoteAmount="1500000",
        counterAmount="800000",
        maxPrice="2000000",
        inReplyTo=QUOTE_HASH,
        chainId=84532,
        kernelAddress=KERNEL,
    )
    base.update(bad_param)
    with pytest.raises(ValueError, match=err_fragment):
        builder.build(CounterOfferParams(**base))


@pytest.mark.parametrize(
    "bad_param,err_fragment",
    [
        ({"txId": "0xshort"}, "txId"),
        ({"inReplyTo": "0xshort"}, "inReplyTo"),
        ({"kernelAddress": "0xshort"}, "kernelAddress"),
        ({"provider": "ethr:abc"}, "provider"),
        ({"consumer": "ethr:abc"}, "consumer"),
        ({"acceptedAmount": "not-a-number"}, "numeric"),
        ({"chainId": 1}, "chainId"),
    ],
)
def test_counter_accept_build_rejects_malformed_param(
    buyer, provider, bad_param, err_fragment
):
    nm = MessageNonceManager()
    builder = CounterAcceptBuilder(private_key=provider.key.hex(), nonce_manager=nm)
    base = dict(
        txId=TXID,
        provider=f"did:ethr:84532:{provider.address}",
        consumer=f"did:ethr:84532:{buyer.address}",
        acceptedAmount="800000",
        inReplyTo=QUOTE_HASH,
        chainId=84532,
        kernelAddress=KERNEL,
    )
    base.update(bad_param)
    with pytest.raises(ValueError, match=err_fragment):
        builder.build(CounterAcceptParams(**base))


def test_counter_accept_below_platform_min_at_build_time(buyer, provider):
    nm = MessageNonceManager()
    builder = CounterAcceptBuilder(private_key=provider.key.hex(), nonce_manager=nm)
    with pytest.raises(ValueError, match="platform minimum"):
        builder.build(
            CounterAcceptParams(
                txId=TXID,
                provider=f"did:ethr:84532:{provider.address}",
                consumer=f"did:ethr:84532:{buyer.address}",
                acceptedAmount="100",  # below 50000
                inReplyTo=QUOTE_HASH,
                chainId=84532,
                kernelAddress=KERNEL,
            )
        )


def test_counter_offer_expiresat_in_past_rejected(buyer, provider):
    """Caller-supplied expiresAt must be in the future."""
    nm = MessageNonceManager()
    builder = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
    with pytest.raises(ValueError, match="must be in the future"):
        builder.build(
            CounterOfferParams(
                txId=TXID,
                consumer=f"did:ethr:84532:{buyer.address}",
                provider=f"did:ethr:84532:{provider.address}",
                quoteAmount="1500000",
                counterAmount="800000",
                maxPrice="2000000",
                inReplyTo=QUOTE_HASH,
                chainId=84532,
                kernelAddress=KERNEL,
                expiresAt=1,  # 1970
            )
        )


def test_counter_offer_compute_hash_independent_of_signer():
    """compute_hash() works on verify-only builder (no private key)."""
    from agirails.builders.counter_offer import CounterOfferMessage

    msg = CounterOfferMessage(
        txId=TXID,
        consumer="did:ethr:84532:0x" + "a" * 40,
        provider="did:ethr:84532:0x" + "b" * 40,
        quoteAmount="1500000",
        counterAmount="800000",
        maxPrice="2000000",
        inReplyTo=QUOTE_HASH,
        counteredAt=1700000000,
        expiresAt=1700003600,
        chainId=84532,
        nonce=1,
        signature="0x" + "c" * 130,
    )
    verifier = CounterOfferBuilder()  # no signer
    h = verifier.compute_hash(msg)
    assert h.startswith("0x") and len(h) == 66


def test_counter_accept_compute_hash_independent_of_signer():
    """compute_hash() works on verify-only builder (no private key)."""
    from agirails.builders.counter_accept import CounterAcceptMessage

    msg = CounterAcceptMessage(
        txId=TXID,
        provider="did:ethr:84532:0x" + "a" * 40,
        consumer="did:ethr:84532:0x" + "b" * 40,
        acceptedAmount="800000",
        inReplyTo=QUOTE_HASH,
        acceptedAt=1700000000,
        chainId=84532,
        nonce=1,
        signature="0x" + "c" * 130,
    )
    verifier = CounterAcceptBuilder()
    h = verifier.compute_hash(msg)
    assert h.startswith("0x") and len(h) == 66
