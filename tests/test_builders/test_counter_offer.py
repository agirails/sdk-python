"""Tests for AIP-2.1 CounterOfferBuilder + CounterAcceptBuilder."""

from __future__ import annotations

import time

import pytest
from eth_account import Account

from agirails.builders import (
    CounterAcceptBuilder,
    CounterAcceptParams,
    CounterOfferBuilder,
    CounterOfferJustification,
    CounterOfferMessage,
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


@pytest.fixture
def did_pair(buyer, provider):
    return (
        f"did:ethr:84532:{buyer.address}",
        f"did:ethr:84532:{provider.address}",
    )


@pytest.fixture
def base_params(did_pair):
    buyer_did, provider_did = did_pair
    return CounterOfferParams(
        txId=TXID,
        consumer=buyer_did,
        provider=provider_did,
        quoteAmount="1000000",
        counterAmount="800000",
        maxPrice="1500000",
        inReplyTo=QUOTE_HASH,
        chainId=84532,
        kernelAddress=KERNEL,
    )


class TestCounterOfferBuilder:
    def test_build_signs_and_returns_message(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)

        assert msg.type == "agirails.counteroffer.v1"
        assert msg.version == "1.0.0"
        assert msg.counterAmount == "800000"
        assert msg.nonce == 1
        assert msg.signature.startswith("0x") and len(msg.signature) == 132

    def test_verify_accepts_valid_message(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)

        verifier = CounterOfferBuilder()  # signer-independent
        assert verifier.verify(msg, KERNEL) is True

    def test_verify_rejects_tampered_amount(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)
        msg.counterAmount = "700000"

        verifier = CounterOfferBuilder()
        with pytest.raises(SignatureVerificationError):
            verifier.verify(msg, KERNEL)

    def test_build_rejects_counter_above_quote(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        base_params.counterAmount = "1100000"  # > quoteAmount

        with pytest.raises(ValueError, match="must be strictly less"):
            b.build(base_params)

    def test_build_rejects_counter_below_platform_min(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        base_params.counterAmount = "1000"  # below $0.05

        with pytest.raises(ValueError, match="platform minimum"):
            b.build(base_params)

    def test_build_rejects_counter_above_max_price(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        base_params.maxPrice = "750000"
        # counter=800000 > maxPrice=750000 but still < quoteAmount=1000000

        with pytest.raises(ValueError, match="exceeds maxPrice"):
            b.build(base_params)

    def test_build_rejects_invalid_chain_id(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        base_params.chainId = 1  # Ethereum mainnet — not allowed

        with pytest.raises(ValueError, match="chainId"):
            b.build(base_params)

    def test_build_requires_signer(self, base_params):
        b = CounterOfferBuilder()  # no signer
        with pytest.raises(ValueError, match="requires private_key"):
            b.build(base_params)

    def test_compute_hash_is_deterministic(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)

        h1 = b.compute_hash(msg)
        h2 = b.compute_hash(msg)
        assert h1 == h2
        assert h1.startswith("0x") and len(h1) == 66

    def test_compute_hash_excludes_signature(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)

        h1 = b.compute_hash(msg)
        msg.signature = "0x" + "f" * 130  # different signature
        h2 = b.compute_hash(msg)
        assert h1 == h2

    def test_verify_rejects_expired_message(
        self, buyer, base_params, monkeypatch
    ):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg = b.build(base_params)

        # Fast-forward verifier's clock past expiresAt without tampering
        # with the signed payload.
        future = msg.expiresAt + 10
        import agirails.builders.counter_offer as co_mod
        monkeypatch.setattr(co_mod.time, "time", lambda: future)

        verifier = CounterOfferBuilder()
        with pytest.raises(ValueError, match="expired"):
            verifier.verify(msg, KERNEL)

    def test_nonce_increments_monotonically(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        msg1 = b.build(base_params)
        msg2 = b.build(base_params)
        assert msg2.nonce == msg1.nonce + 1

    def test_justification_hash_included_in_signature(self, buyer, base_params):
        nm = MessageNonceManager()
        b = CounterOfferBuilder(private_key=buyer.key.hex(), nonce_manager=nm)
        base_params.justification = CounterOfferJustification(
            reason="market rate lower",
            market_rate=0.75,
        )
        msg = b.build(base_params)
        # Tampering with justification should break verification
        msg.justification = CounterOfferJustification(reason="different")
        verifier = CounterOfferBuilder()
        with pytest.raises(SignatureVerificationError):
            verifier.verify(msg, KERNEL)


class TestCounterAcceptBuilder:
    def test_full_roundtrip_offer_then_accept(
        self, buyer, provider, did_pair, base_params
    ):
        buyer_did, provider_did = did_pair
        nm_buyer = MessageNonceManager()
        offer_b = CounterOfferBuilder(
            private_key=buyer.key.hex(), nonce_manager=nm_buyer
        )
        offer = offer_b.build(base_params)
        counter_hash = offer_b.compute_hash(offer)

        nm_prov = MessageNonceManager()
        ab = CounterAcceptBuilder(
            private_key=provider.key.hex(), nonce_manager=nm_prov
        )
        accept = ab.build(
            CounterAcceptParams(
                txId=TXID,
                provider=provider_did,
                consumer=buyer_did,
                acceptedAmount=offer.counterAmount,
                inReplyTo=counter_hash,
                chainId=84532,
                kernelAddress=KERNEL,
            )
        )

        verifier = CounterAcceptBuilder()
        assert verifier.verify(accept, KERNEL) is True
        assert accept.acceptedAmount == offer.counterAmount
        assert accept.inReplyTo == counter_hash

    def test_verify_rejects_tampered_accepted_amount(
        self, provider, did_pair
    ):
        buyer_did, provider_did = did_pair
        nm = MessageNonceManager()
        ab = CounterAcceptBuilder(
            private_key=provider.key.hex(), nonce_manager=nm
        )
        accept = ab.build(
            CounterAcceptParams(
                txId=TXID,
                provider=provider_did,
                consumer=buyer_did,
                acceptedAmount="800000",
                inReplyTo=QUOTE_HASH,
                chainId=84532,
                kernelAddress=KERNEL,
            )
        )
        accept.acceptedAmount = "100000"

        verifier = CounterAcceptBuilder()
        with pytest.raises(SignatureVerificationError):
            verifier.verify(accept, KERNEL)

    def test_build_requires_signer(self, did_pair):
        buyer_did, provider_did = did_pair
        ab = CounterAcceptBuilder()
        with pytest.raises(ValueError, match="requires private_key"):
            ab.build(
                CounterAcceptParams(
                    txId=TXID,
                    provider=provider_did,
                    consumer=buyer_did,
                    acceptedAmount="800000",
                    inReplyTo=QUOTE_HASH,
                    chainId=84532,
                    kernelAddress=KERNEL,
                )
            )

    def test_build_rejects_accepted_below_platform_min(
        self, provider, did_pair
    ):
        buyer_did, provider_did = did_pair
        nm = MessageNonceManager()
        ab = CounterAcceptBuilder(
            private_key=provider.key.hex(), nonce_manager=nm
        )
        with pytest.raises(ValueError, match="platform minimum"):
            ab.build(
                CounterAcceptParams(
                    txId=TXID,
                    provider=provider_did,
                    consumer=buyer_did,
                    acceptedAmount="100",
                    inReplyTo=QUOTE_HASH,
                    chainId=84532,
                    kernelAddress=KERNEL,
                )
            )


class TestMessageNonceManager:
    def test_get_next_nonce_starts_at_1(self):
        nm = MessageNonceManager()
        assert nm.get_next_nonce("foo") == 1

    def test_record_nonce_advances_high_water_mark(self):
        nm = MessageNonceManager()
        n1 = nm.get_next_nonce("foo")
        nm.record_nonce("foo", n1)
        assert nm.get_next_nonce("foo") == n1 + 1

    def test_record_nonce_rejects_non_monotonic(self):
        nm = MessageNonceManager()
        nm.record_nonce("foo", 5)
        with pytest.raises(ValueError, match="monotonic"):
            nm.record_nonce("foo", 5)
        with pytest.raises(ValueError, match="monotonic"):
            nm.record_nonce("foo", 3)

    def test_per_message_type_isolation(self):
        nm = MessageNonceManager()
        nm.record_nonce("foo", 10)
        # other types unaffected
        assert nm.get_next_nonce("bar") == 1
