"""Reverse cross-SDK parity — Python side of the round-trip.

Step #4 of the post-F audit. Step B proved: TS signs → Python
verifies. This file proves the Python-side regenerator is
DETERMINISTIC and produces stable fixtures that the TS verifier
(``scripts/verify_python_vectors.js``) consumes.

What this catches:
  - Python-side signing drift (a refactor that subtly changes the
    EIP-712 struct field order or the signature output) — the
    regenerated fixture would differ from the committed one.
  - Stale fixtures after a wire-format change that wasn't propagated.

What this does NOT catch (handled separately):
  - TS verifies the bytes correctly — that requires the Node verifier
    in scripts/verify_python_vectors.js. CI step F's ``test-parity``
    job runs both Python and JS sides; this file is the Python half.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = (
    Path(__file__).parent.parent / "fixtures" / "cross_sdk"
)
MANIFEST = FIXTURES_DIR / "python_signed_manifest.json"
GENERATOR = (
    Path(__file__).parent.parent.parent
    / "scripts"
    / "generate_python_parity_vectors.py"
)


def _load_manifest():
    if not MANIFEST.exists():
        pytest.skip(
            "Python-signed fixtures missing — regenerate with: "
            "python3 scripts/generate_python_parity_vectors.py"
        )
    return json.loads(MANIFEST.read_text())


def test_python_signed_manifest_exists():
    """Sanity: committed fixtures present and stamped with the current SDK version."""
    from agirails import __version__

    assert MANIFEST.exists()
    manifest = _load_manifest()
    # Version-agnostic: the committed fixtures must be stamped with the SDK
    # version that generated them (regenerate via
    # scripts/generate_python_parity_vectors.py after a version bump).
    assert manifest["python_sdk_version"] == __version__
    assert len(manifest["fixtures"]) == 4


def test_regeneration_is_deterministic():
    """Running the generator twice produces byte-identical fixtures.

    If this fails, the generator has hidden non-determinism (e.g.
    walltime leakage, unstable dict iteration order, randomness in
    the signing layer). The cross-SDK parity guarantees rest on
    deterministic regeneration — without it, any CI verifier would
    flake.
    """
    # Snapshot current committed fixtures.
    snapshot = {}
    for label in _load_manifest()["fixtures"]:
        path = FIXTURES_DIR / f"{label}.json"
        snapshot[label] = path.read_text()

    # Re-run generator.
    result = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=GENERATOR.parent.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"Generator failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )

    # Compare bytes-identical.
    drift = []
    for label, before in snapshot.items():
        path = FIXTURES_DIR / f"{label}.json"
        after = path.read_text()
        if before != after:
            drift.append(label)

    assert not drift, (
        f"Fixtures drifted on regeneration: {drift}. "
        f"This means the Python builder is producing non-deterministic "
        f"output — review for walltime leakage, dict iteration order, "
        f"or randomness."
    )


def test_each_fixture_is_well_formed():
    """Each Python-signed fixture has the structure the JS verifier
    consumes: kernelAddress, expectedSigner, expectedHash, message."""
    manifest = _load_manifest()
    for label in manifest["fixtures"]:
        fixture = json.loads(
            (FIXTURES_DIR / f"{label}.json").read_text()
        )
        assert fixture["label"] == label
        assert fixture["fixtureKind"] in ("counter_offer", "counter_accept")
        assert fixture["kernelAddress"].startswith("0x") and len(fixture["kernelAddress"]) == 42
        assert fixture["expectedSigner"].startswith("0x") and len(fixture["expectedSigner"]) == 42
        assert fixture["expectedHash"].startswith("0x") and len(fixture["expectedHash"]) == 66
        assert "message" in fixture
        msg = fixture["message"]
        # EIP-712 signature is 65 bytes = 130 hex chars + 0x prefix.
        assert msg["signature"].startswith("0x") and len(msg["signature"]) == 132


def test_each_python_signed_fixture_self_verifies():
    """Sanity: Python's OWN verifier accepts each Python-signed fixture.

    If this fails, we have a bug in either the builder or the
    fixture-generator script. (Cross-SDK parity tests are upstream of
    this — if the builder verifies its own output, both sides should
    too.)
    """
    from agirails.builders.counter_offer import (
        CounterOfferBuilder,
        CounterOfferJustification,
        CounterOfferMessage,
    )
    from agirails.builders.counter_accept import (
        CounterAcceptBuilder,
        CounterAcceptMessage,
    )
    import agirails.builders.counter_offer as co_mod
    import agirails.builders.counter_accept as ca_mod

    manifest = _load_manifest()
    for label in manifest["fixtures"]:
        fixture = json.loads((FIXTURES_DIR / f"{label}.json").read_text())
        msg_raw = fixture["message"]

        if fixture["fixtureKind"] == "counter_offer":
            justification = None
            jr = msg_raw.get("justification")
            if isinstance(jr, dict) and jr:
                justification = CounterOfferJustification(
                    reason=jr.get("reason"),
                    market_rate=jr.get("marketRate"),
                    breakdown=jr.get("breakdown") or {},
                )
            msg = CounterOfferMessage(
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
            # Pin time so expiresAt check passes (fixture's pinned now
            # is in 2023-era).
            orig = co_mod.time.time
            co_mod.time.time = lambda: msg.counteredAt
            try:
                verifier = CounterOfferBuilder()
                assert verifier.verify(msg, fixture["kernelAddress"]) is True
                assert verifier.compute_hash(msg) == fixture["expectedHash"]
            finally:
                co_mod.time.time = orig
        else:
            msg = CounterAcceptMessage(
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
            orig = ca_mod.time.time
            ca_mod.time.time = lambda: msg.acceptedAt
            try:
                verifier = CounterAcceptBuilder()
                assert verifier.verify(msg, fixture["kernelAddress"]) is True
                assert verifier.compute_hash(msg) == fixture["expectedHash"]
            finally:
                ca_mod.time.time = orig
