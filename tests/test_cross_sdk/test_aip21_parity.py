"""Cross-SDK wire-protocol parity tests.

Loads fixtures emitted by `scripts/generate_parity_vectors.js` — the
TypeScript SDK builders sign deterministic CounterOffer / CounterAccept
messages — and confirms the Python SDK verifies them byte-for-byte:

  - EIP-712 signature recovers to the TS-signed wallet address.
  - Schema validation accepts the message (no field shape drift).
  - ``compute_hash()`` returns the SAME bytes32 hash the TS side
    emitted, proving canonical-JSON encoding is identical.

These are the highest-signal tests in the suite: if either SDK drifts
on serialization, EIP-712 type definition ordering, or canonical-JSON
key ordering, this fails immediately. Without these, two SDKs could
silently diverge and integrators on different stacks would stop
agreeing on transaction hashes.

Regenerate fixtures after any change to the wire format:

    NODE_PATH="../sdk-js/node_modules" node scripts/generate_parity_vectors.js
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from agirails.builders.counter_accept import (
    CounterAcceptBuilder,
    CounterAcceptMessage,
)
from agirails.builders.counter_offer import (
    CounterOfferBuilder,
    CounterOfferJustification,
    CounterOfferMessage,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cross_sdk"
MANIFEST = FIXTURES / "manifest.json"


def _load_manifest():
    if not MANIFEST.exists():
        pytest.skip(
            f"Cross-SDK fixtures missing — regenerate with: "
            f"NODE_PATH=../sdk-js/node_modules node scripts/generate_parity_vectors.js"
        )
    return json.loads(MANIFEST.read_text())


def _load_fixture(label: str) -> dict:
    return json.loads((FIXTURES / f"{label}.json").read_text())


def _parse_counter_offer(raw: dict) -> CounterOfferMessage:
    """TS-emitted JSON → Python dataclass."""
    msg_raw = raw["message"]
    just_raw = msg_raw.get("justification")
    justification = None
    if isinstance(just_raw, dict) and just_raw:
        justification = CounterOfferJustification(
            reason=just_raw.get("reason"),
            market_rate=just_raw.get("marketRate"),
            breakdown=just_raw.get("breakdown") or {},
        )
    return CounterOfferMessage(
        txId=msg_raw["txId"],
        consumer=msg_raw["consumer"],
        provider=msg_raw["provider"],
        quoteAmount=msg_raw["quoteAmount"],
        counterAmount=msg_raw["counterAmount"],
        maxPrice=msg_raw["maxPrice"],
        inReplyTo=msg_raw["inReplyTo"],
        counteredAt=int(msg_raw["counteredAt"]),
        expiresAt=int(msg_raw["expiresAt"]),
        chainId=int(msg_raw["chainId"]),
        nonce=int(msg_raw["nonce"]),
        signature=msg_raw["signature"],
        type=msg_raw.get("type", "agirails.counteroffer.v1"),
        version=msg_raw.get("version", "1.0.0"),
        currency=msg_raw.get("currency", "USDC"),
        decimals=int(msg_raw.get("decimals", 6)),
        justification=justification,
    )


def _parse_counter_accept(raw: dict) -> CounterAcceptMessage:
    msg_raw = raw["message"]
    return CounterAcceptMessage(
        txId=msg_raw["txId"],
        provider=msg_raw["provider"],
        consumer=msg_raw["consumer"],
        acceptedAmount=msg_raw["acceptedAmount"],
        inReplyTo=msg_raw["inReplyTo"],
        acceptedAt=int(msg_raw["acceptedAt"]),
        chainId=int(msg_raw["chainId"]),
        nonce=int(msg_raw["nonce"]),
        signature=msg_raw["signature"],
        type=msg_raw.get("type", "agirails.counteraccept.v1"),
        version=msg_raw.get("version", "1.0.0"),
    )


# ============================================================================
# Sanity: fixtures present + manifest matches expected shape
# ============================================================================


def test_fixtures_directory_exists():
    """If this fails, regenerate fixtures (see module docstring)."""
    assert FIXTURES.exists(), f"Fixtures dir not found: {FIXTURES}"
    assert MANIFEST.exists(), f"Manifest not found: {MANIFEST}"


def test_manifest_lists_expected_fixtures():
    manifest = _load_manifest()
    assert "counter_offer_basic" in manifest["fixtures"]
    assert "counter_offer_with_justification" in manifest["fixtures"]
    assert "counter_accept_basic" in manifest["fixtures"]
    assert "counter_accept_mainnet" in manifest["fixtures"]
    assert manifest["ts_sdk_version"].startswith("4.")  # 4.x


# ============================================================================
# CounterOffer: TS signed → Python verifies
# ============================================================================


@pytest.mark.parametrize(
    "label",
    ["counter_offer_basic", "counter_offer_with_justification"],
)
def test_counter_offer_ts_signed_python_verifies(label):
    """The exact bytes the TS SDK emitted must verify in Python."""
    raw = _load_fixture(label)
    msg = _parse_counter_offer(raw)
    verifier = CounterOfferBuilder()

    # 1. Schema accepts the TS-emitted message (no field drift).
    # 2. EIP-712 signature recovers — drift in domain, type ordering, or
    #    field serialization breaks this.
    # The verifier also enforces expiresAt > now; the TS generator pins
    # expiresAt = now + 3600 from a frozen Date.now (1_700_000_000),
    # which is in the past by real-world time. Patch time inside the
    # verify call to the fixture's `counteredAt` so the expiry check
    # passes — we're testing signature parity, not expiry.
    import agirails.builders.counter_offer as co_mod
    orig_time = co_mod.time.time
    co_mod.time.time = lambda: msg.counteredAt
    try:
        assert verifier.verify(msg, raw["kernelAddress"]) is True
    finally:
        co_mod.time.time = orig_time


@pytest.mark.parametrize(
    "label",
    ["counter_offer_basic", "counter_offer_with_justification"],
)
def test_counter_offer_compute_hash_matches_ts(label):
    """compute_hash() — keccak256 of canonical-JSON minus signature.

    Identical inputs across SDKs MUST produce the identical hash. Drift
    in canonical-JSON key ordering, number serialization, or any
    structural change breaks this.
    """
    raw = _load_fixture(label)
    msg = _parse_counter_offer(raw)
    verifier = CounterOfferBuilder()
    py_hash = verifier.compute_hash(msg)
    assert py_hash == raw["expectedHash"], (
        f"Hash drift for {label}:\n"
        f"  TS:     {raw['expectedHash']}\n"
        f"  Python: {py_hash}"
    )


# ============================================================================
# CounterAccept: TS signed → Python verifies
# ============================================================================


@pytest.mark.parametrize(
    "label",
    ["counter_accept_basic", "counter_accept_mainnet"],
)
def test_counter_accept_ts_signed_python_verifies(label):
    raw = _load_fixture(label)
    msg = _parse_counter_accept(raw)
    verifier = CounterAcceptBuilder()
    # CounterAccept verify also checks acceptedAt vs now skew tolerance.
    # The fixture's acceptedAt is the frozen TS Date.now (1_700_000_000)
    # which is in the past — that's fine for the >now+grace check.
    assert verifier.verify(msg, raw["kernelAddress"]) is True


@pytest.mark.parametrize(
    "label",
    ["counter_accept_basic", "counter_accept_mainnet"],
)
def test_counter_accept_compute_hash_matches_ts(label):
    raw = _load_fixture(label)
    msg = _parse_counter_accept(raw)
    verifier = CounterAcceptBuilder()
    py_hash = verifier.compute_hash(msg)
    assert py_hash == raw["expectedHash"], (
        f"Hash drift for {label}:\n"
        f"  TS:     {raw['expectedHash']}\n"
        f"  Python: {py_hash}"
    )


# ============================================================================
# Negative: signature mutation rejected
# ============================================================================


def test_counter_offer_tampered_signature_rejected():
    """Sanity check the verifier actually checks the signature, not
    just the schema. Flip one byte → recovery fails."""
    from agirails.errors import SignatureVerificationError

    raw = _load_fixture("counter_offer_basic")
    msg = _parse_counter_offer(raw)
    # Flip a byte in the middle of r (first 32 bytes after 0x prefix).
    # This produces a different recovered address — different from the
    # consumer DID — and verify() must reject.
    sig = msg.signature
    # Index 12 is well within r. XOR with 0x01.
    pos = 12
    original_hex = sig[pos:pos + 2]
    flipped_byte = (int(original_hex, 16) ^ 0x01) & 0xFF
    msg.signature = sig[:pos] + f"{flipped_byte:02x}" + sig[pos + 2:]
    assert msg.signature != sig, "mutation must actually change signature"

    import agirails.builders.counter_offer as co_mod
    orig_time = co_mod.time.time
    co_mod.time.time = lambda: msg.counteredAt
    try:
        verifier = CounterOfferBuilder()
        with pytest.raises(SignatureVerificationError):
            verifier.verify(msg, raw["kernelAddress"])
    finally:
        co_mod.time.time = orig_time
