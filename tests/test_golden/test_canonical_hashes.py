"""Golden hash tests — pin specific bytes32 outputs for known inputs.

If anyone silently changes canonical-JSON key ordering, keccak input
encoding, EIP-712 type definitions, or struct serialization, these
tests catch it BEFORE the change reaches integrators.

Why both these AND the cross-SDK parity tests (test_aip21_parity)?
Cross-SDK parity proves Python ↔ TS agreement at a single point in
time (the TS-side fixture). Golden hashes pin the EXPECTED hash
explicitly in the Python test source — if both SDKs drift in the
same direction, parity tests still pass but golden hashes fail.

Adding a new golden:
  1. Build the input deterministically
  2. Compute the hash
  3. Paste the hex into ``EXPECTED_HASH``
  4. Add the test
  5. CI runs the test, sees green
  6. Anyone modifying serialization runs CI, sees red, asks
     "did I mean to change this?" before merging

Updating an existing golden requires:
  - Deliberate value change in the test source (visible in diff)
  - Code review that confirms intentional wire-format change
"""

from __future__ import annotations

from eth_hash.auto import keccak

from agirails.utils.canonical_json import canonical_json_dumps
from agirails.builders.counter_offer import CounterOfferBuilder, CounterOfferMessage
from agirails.builders.counter_accept import CounterAcceptBuilder, CounterAcceptMessage


# ============================================================================
# Canonical JSON golden snapshots
# ============================================================================


class TestCanonicalJsonGolden:
    def test_simple_dict_canonical_form(self):
        """Top-level dict — keys sorted, no whitespace, RFC 8259 compliant."""
        result = canonical_json_dumps({"b": 2, "a": 1, "c": 3})
        assert result == '{"a":1,"b":2,"c":3}'

    def test_nested_dict_canonical_form(self):
        """Recursive sort: inner dicts also have keys ordered."""
        result = canonical_json_dumps(
            {"outer": {"z": 1, "a": {"y": 2, "b": 3}}, "first": True}
        )
        assert result == '{"first":true,"outer":{"a":{"b":3,"y":2},"z":1}}'

    def test_list_preserves_order(self):
        """Lists are NOT sorted — only dicts are."""
        result = canonical_json_dumps([3, 1, 2])
        assert result == "[3,1,2]"

    def test_strings_use_ascii_only_escapes(self):
        """JSON spec: control characters always escaped; non-ASCII
        passes through (canonical_json uses ensure_ascii=False)."""
        result = canonical_json_dumps({"text": 'a "b" c'})
        assert result == '{"text":"a \\"b\\" c"}'

    def test_unicode_passthrough(self):
        result = canonical_json_dumps({"emoji": "🎉"})
        assert result == '{"emoji":"🎉"}'

    def test_keccak_of_canonical_dict(self):
        """Cross-SDK message-hash agreement depends on this exact
        byte sequence. Any change here means breaking the wire."""
        payload = {"service": "echo", "input": {"key": "value"}}
        canonical = canonical_json_dumps(payload)
        h = "0x" + keccak(canonical.encode("utf-8")).hex()
        # Expected: keccak('{"input":{"key":"value"},"service":"echo"}')
        assert (
            h
            == "0xe297e6c64be167fed87c06e008bb5346db6a1cc4595ba14057435bb6556d4690"
        ), (
            "keccak hash of canonical JSON changed — this is the message "
            "routing key for ACTP, do NOT update this golden without an "
            "explicit wire-format change."
        )


# ============================================================================
# Service hash golden snapshots
# ============================================================================


class TestServiceHashGolden:
    """The on-chain routing key in PRD §5.4. Stable values for the
    common service names used by Sentinel + integrators."""

    def test_onboarding(self):
        h = "0x" + keccak(b"onboarding").hex()
        assert (
            h
            == "0x68c24fc24acf5b51ccf67c01fea706e9e0e110825d4f88d07623f64f32f55d89"
        )

    def test_echo(self):
        h = "0x" + keccak(b"echo").hex()
        assert (
            h
            == "0x30aac30d8e1f24996aaf406e85b7281051192346b2dcbea9be2461c29b1bc590"
        )

    def test_translate(self):
        h = "0x" + keccak(b"translate").hex()
        assert (
            h
            == "0x026df89663caec67f83d01afc4bce454ea77643e98902cacd3d29e03d0923729"
        )


# ============================================================================
# Builder hash golden snapshots — exact bytes32 for a known message
# ============================================================================


_DETERMINISTIC_COUNTER_OFFER = CounterOfferMessage(
    txId="0x" + "a" * 64,
    consumer="did:ethr:84532:0x" + "1" * 40,
    provider="did:ethr:84532:0x" + "2" * 40,
    quoteAmount="1500000",
    counterAmount="800000",
    maxPrice="2000000",
    inReplyTo="0x" + "b" * 64,
    counteredAt=1_700_000_000,
    expiresAt=1_700_003_600,
    chainId=84532,
    nonce=1,
    signature="0x" + "c" * 130,  # ignored by compute_hash
)


_DETERMINISTIC_COUNTER_ACCEPT = CounterAcceptMessage(
    txId="0x" + "a" * 64,
    provider="did:ethr:84532:0x" + "2" * 40,
    consumer="did:ethr:84532:0x" + "1" * 40,
    acceptedAmount="800000",
    inReplyTo="0x" + "b" * 64,
    acceptedAt=1_700_000_000,
    chainId=84532,
    nonce=1,
    signature="0x" + "c" * 130,
)


class TestBuilderHashGolden:
    def test_counter_offer_compute_hash_pinned(self):
        """If this golden flips, the AIP-2.1 CounterOffer wire format
        has changed — sync with TS sdk-js or fail integrators."""
        h = CounterOfferBuilder().compute_hash(_DETERMINISTIC_COUNTER_OFFER)
        assert (
            h
            == "0x9b82757f3ff027061afffc4aaf5c63de9a8a414240391934f745bcf602b05441"
        )

    def test_counter_accept_compute_hash_pinned(self):
        h = CounterAcceptBuilder().compute_hash(_DETERMINISTIC_COUNTER_ACCEPT)
        assert (
            h
            == "0x0c9e3707a2d9035ddc1758b06d9c0c1bbe5624c95b57a16c4f9cf4611ecefeb0"
        )
