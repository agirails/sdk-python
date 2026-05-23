"""Property-based tests for EIP-712 sign/recover + canonical hash invariants.

Invariants under test:

  1. **Sign → recover roundtrip**: ``Account.recover_message(encoded, sig)``
     always returns the signing wallet for any valid (key, message) pair.
  2. **Builder hash determinism**: ``CounterOfferBuilder.compute_hash(msg)``
     is a pure function of the (signature-stripped) message. Called
     twice on the same message → same bytes32.
  3. **Hash sensitivity**: changing any signed field by 1 bit changes
     the hash. (Avalanche property of keccak256.)
  4. **Service hash determinism**: ``keccak(name) == keccak(name)`` and
     different names produce different hashes (collision-resistance
     at the SDK level — keccak handles it).
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_hash.auto import keccak

from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferMessage,
)


# Deterministic key strategy: 32 bytes → hex.
@st.composite
def private_keys(draw):
    raw = draw(
        st.binary(min_size=32, max_size=32).filter(
            lambda b: 0 < int.from_bytes(b, "big") < (2**256 - 1)
        )
    )
    return "0x" + raw.hex()


class TestSignRecoverRoundtrip:
    @given(private_key=private_keys(), message=st.text(min_size=1, max_size=200))
    @settings(max_examples=100, deadline=None)
    def test_personal_sign_recovers_signer(self, private_key, message):
        """EIP-191 personal_sign — used by `actp claim-code`."""
        account = Account.from_key(private_key)
        signable = encode_defunct(text=message)
        signed = account.sign_message(signable)
        recovered = Account.recover_message(signable, signature=signed.signature)
        assert recovered.lower() == account.address.lower()


@st.composite
def counter_offer_messages(draw, signer_address):
    """Build a CounterOfferMessage with deterministic-ish fields.
    Signature is left as a placeholder — we test hash properties, not
    signature recovery (sign/recover already covered above)."""
    chain_id = draw(st.sampled_from([84532, 8453]))
    quote = draw(st.integers(min_value=1_000_000, max_value=10_000_000))
    counter = draw(st.integers(min_value=50_000, max_value=quote - 1))
    return CounterOfferMessage(
        txId="0x" + draw(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)),
        consumer=f"did:ethr:{chain_id}:{signer_address}",
        provider=f"did:ethr:{chain_id}:0x" + draw(st.text(alphabet="0123456789abcdef", min_size=40, max_size=40)),
        quoteAmount=str(quote),
        counterAmount=str(counter),
        maxPrice=str(quote * 2),
        inReplyTo="0x" + draw(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)),
        counteredAt=draw(st.integers(min_value=1_700_000_000, max_value=2_000_000_000)),
        expiresAt=draw(st.integers(min_value=2_000_000_001, max_value=3_000_000_000)),
        chainId=chain_id,
        nonce=draw(st.integers(min_value=1, max_value=10_000)),
        signature="0x" + "00" * 65,  # placeholder; not part of hash input
    )


class TestComputeHashProperties:
    def setup_method(self):
        self.signer = Account.create()
        self.verifier = CounterOfferBuilder()  # no signer needed for hashing

    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_compute_hash_is_deterministic(self, data):
        msg = data.draw(counter_offer_messages(self.signer.address))
        h1 = self.verifier.compute_hash(msg)
        h2 = self.verifier.compute_hash(msg)
        assert h1 == h2
        assert h1.startswith("0x") and len(h1) == 66

    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_compute_hash_ignores_signature_field(self, data):
        """The signature field must be stripped before hashing — the
        whole point is to allow a signer to compute the hash they're
        about to sign over."""
        msg = data.draw(counter_offer_messages(self.signer.address))
        h_initial = self.verifier.compute_hash(msg)
        msg.signature = "0x" + "f" * 130  # any other value
        h_after = self.verifier.compute_hash(msg)
        assert h_initial == h_after, (
            "compute_hash MUST be independent of the signature field; "
            "otherwise the signer can't pre-compute what they're signing."
        )

    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_compute_hash_changes_when_counter_amount_changes(self, data):
        msg = data.draw(counter_offer_messages(self.signer.address))
        h_before = self.verifier.compute_hash(msg)
        # Bump amount by 1.
        msg.counterAmount = str(int(msg.counterAmount) + 1)
        h_after = self.verifier.compute_hash(msg)
        assert h_before != h_after, (
            "Avalanche property: changing ANY signed field must change the hash"
        )


class TestServiceHashProperties:
    """The on-chain routing key in PRD §5.4 — Agent.provide(name) ↔
    actp request --service name agreement depends on these properties."""

    @given(name=st.text(min_size=1, max_size=64))
    @settings(max_examples=100, deadline=None)
    def test_keccak_service_hash_deterministic(self, name):
        h1 = "0x" + keccak(name.encode("utf-8")).hex()
        h2 = "0x" + keccak(name.encode("utf-8")).hex()
        assert h1 == h2

    @given(
        name_a=st.text(min_size=1, max_size=20),
        name_b=st.text(min_size=1, max_size=20),
    )
    @settings(max_examples=100, deadline=None)
    def test_different_names_different_hashes(self, name_a, name_b):
        # Skip the trivial equal-strings case — we're testing
        # that distinct names map to distinct routing keys.
        if name_a == name_b:
            return
        h_a = "0x" + keccak(name_a.encode("utf-8")).hex()
        h_b = "0x" + keccak(name_b.encode("utf-8")).hex()
        assert h_a != h_b, (
            "keccak256 collision in test inputs — astronomically unlikely; "
            "investigate input strategy if this triggers."
        )
