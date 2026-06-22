"""
Evidence Bundle canonical serializer — Py golden + cross-SDK suite (PRD P2-3).

Loads the SHARED cross-SDK fixture ``DISPUTE SYSTEM/test-vectors/bundle-vectors.json``
(the SAME file the TS jest suite loads) and asserts, for every vector:
  - serialize_bundle → EXACT canonical bytes == fixture.canonicalBytesHex
  - bundle_hash      == fixture.bundleHash
  - cl100k_base token_count == fixture.tokenCount
Plus a CROSS-LANG assertion: the TS-produced hashes (written by the jest suite
to ``bundle-hashes.ts.json``) equal the Py-produced hashes == the fixture. And
malformed-bundle rejection parity.

Anchor: Example A bundle_hash
    0x379fb8140138f7d90cfbcb481898b6ec646e2c0378ff0d3a4a4572a6570ca257.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agirails.dispute.evidence_bundle import (
    BundleTooLargeError,
    InvalidBundleError,
    MAX_BUNDLE_TOKENS,
    UnsupportedBundleVersionError,
    bundle_hash,
    compute_bundle_hash,
    count_bundle_tokens,
    enforce_token_cap,
    pin_evidence_bundle,
    serialize_bundle,
    serialize_bundle_to_string,
    validate_bundle,
)

# ---------------------------------------------------------------------------
# Shared cross-SDK fixture (byte-identical to the copy the jest suite loads):
# <repo>/DISPUTE SYSTEM/test-vectors/bundle-vectors.json
# From this file: parents → tests/test_cross_sdk → tests → python-sdk-v2
#               → SDK and Runtime → AGIRAILS (repo root).
# ---------------------------------------------------------------------------

_VECTORS_DIR = (
    Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors"
)
_FIXTURE = _VECTORS_DIR / "bundle-vectors.json"
FIXTURE = json.loads(_FIXTURE.read_text(encoding="utf-8"))
VECTORS = FIXTURE["vectors"]

_TS_HASHES = _VECTORS_DIR / "bundle-hashes.ts.json"
_PY_HASHES = _VECTORS_DIR / "bundle-hashes.py.json"


def _by_name(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


# ---------------------------------------------------------------------------
# 1. Per-vector canonical bytes + bundle_hash + token_count
# ---------------------------------------------------------------------------


class TestGoldenVectors:
    def test_fixture_has_four_seed_vectors(self):
        assert [v["name"] for v in VECTORS] == ["A", "B", "C", "D"]

    @pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["name"])
    def test_exact_canonical_bytes(self, v):
        raw = serialize_bundle(v["bundle"])
        assert raw.hex() == v["canonicalBytesHex"]
        assert len(raw) == v["canonicalBytesUtf8Len"]

    @pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["name"])
    def test_bundle_hash_matches_fixture(self, v):
        assert bundle_hash(v["bundle"]) == v["bundleHash"]
        # alias parity
        assert compute_bundle_hash(v["bundle"], skip_token_check=True) == v["bundleHash"]

    @pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["name"])
    def test_token_count_matches_fixture(self, v):
        assert v["tokenizer"] == "cl100k_base"
        assert count_bundle_tokens(serialize_bundle_to_string(v["bundle"])) == v[
            "tokenCount"
        ]

    def test_example_a_is_frozen_schema_anchor(self):
        a = _by_name("A")
        assert (
            a["bundleHash"]
            == "0x379fb8140138f7d90cfbcb481898b6ec646e2c0378ff0d3a4a4572a6570ca257"
        )
        assert a["canonicalBytesUtf8Len"] == 719

    def test_vector_c_raw_utf8_not_escaped(self):
        c = _by_name("C")
        text = serialize_bundle_to_string(c["bundle"])
        assert "résultat incorrect — 図 missing 🎉" in text
        assert "\\u" not in text

    def test_vector_d_escape_parity(self):
        # Locks the escape + sort rules for arbitrary free-text fields so the
        # cross-SDK byte-identity assertion (Py == TS) can never silently
        # diverge on control-char / quote / backslash / slash / emoji handling.
        d = _by_name("D")
        text = serialize_bundle_to_string(d["bundle"])
        # Two-char escapes for \b \f \n \r \t and quote/backslash.
        for esc in ("\\b", "\\f", "\\n", "\\r", "\\t", '\\"', "\\\\"):
            assert esc in text
        # Other C0 control chars escape as \u00XX (lowercase hex).
        assert "\\u0007" in text  # BEL
        assert "\\u001f" in text  # unit separator
        # Forward slash NOT escaped; surrogate-pair emoji stays raw UTF-8.
        assert "slash=/" in text
        assert "🚀" in text
        assert "\\/" not in text
        assert "\\ud83d" not in text  # emoji not escaped to surrogate \u


# ---------------------------------------------------------------------------
# 2. Cross-language assertion (Py == TS == fixture)
# ---------------------------------------------------------------------------


class TestCrossLanguageIdentity:
    def test_write_py_produced_hashes(self):
        produced = [
            {
                "name": v["name"],
                "canonicalBytesHex": serialize_bundle(v["bundle"]).hex(),
                "bundleHash": bundle_hash(v["bundle"]),
            }
            for v in VECTORS
        ]
        _PY_HASHES.write_text(json.dumps(produced, indent=2), encoding="utf-8")
        # Self-consistency: Py production equals the fixture.
        for p, v in zip(produced, VECTORS):
            assert p["bundleHash"] == v["bundleHash"]
            assert p["canonicalBytesHex"] == v["canonicalBytesHex"]

    def test_ts_produced_hashes_equal_py_and_fixture(self):
        if not _TS_HASHES.exists():
            pytest.skip(
                f"{_TS_HASHES} not present — run the jest suite to cross-check."
            )
        ts = json.loads(_TS_HASHES.read_text(encoding="utf-8"))
        for v in VECTORS:
            ts_entry = next(t for t in ts if t["name"] == v["name"])
            # TS bytes == Py bytes == fixture bytes.
            assert ts_entry["canonicalBytesHex"] == serialize_bundle(v["bundle"]).hex()
            assert ts_entry["canonicalBytesHex"] == v["canonicalBytesHex"]
            # TS hash == Py hash == fixture hash.
            assert ts_entry["bundleHash"] == bundle_hash(v["bundle"])
            assert ts_entry["bundleHash"] == v["bundleHash"]


# ---------------------------------------------------------------------------
# 3. Token cap (schema §4 / OQ-9)
# ---------------------------------------------------------------------------


class TestTokenCap:
    def _a(self) -> dict:
        return json.loads(json.dumps(_by_name("A")["bundle"]))

    def test_within_cap_returns_count(self):
        count = enforce_token_cap(serialize_bundle_to_string(self._a()))
        assert count <= MAX_BUNDLE_TOKENS
        assert count == _by_name("A")["tokenCount"]

    def test_over_cap_raises_before_hashing(self):
        big = self._a()
        big["delivery"]["deliverableInline"] = "lorem ipsum dolor sit amet " * 20000
        with pytest.raises(BundleTooLargeError) as exc:
            bundle_hash(big)
        assert exc.value.token_count > MAX_BUNDLE_TOKENS

    def test_skip_token_check_bypasses_cap(self):
        a = _by_name("A")
        assert bundle_hash(a["bundle"], skip_token_check=True) == a["bundleHash"]


# ---------------------------------------------------------------------------
# 4. Malformed-bundle rejection (schema §6)
# ---------------------------------------------------------------------------


class TestMalformedRejection:
    def _a(self) -> dict:
        return json.loads(json.dumps(_by_name("A")["bundle"]))

    def test_missing_required_key(self):
        bad = self._a()
        del bad["spec"]
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_extra_top_level_key(self):
        bad = self._a()
        bad["extra"] = "nope"
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_non_integer_uint_float(self):
        bad = self._a()
        bad["delivery"]["deliveredAt"] = 1700000000.5
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_malformed_bytes32hex(self):
        bad = self._a()
        bad["disputeId"] = "0xnothex"
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_optional_key_present_as_null(self):
        bad = self._a()
        bad["delivery"]["deliverableInline"] = None
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_timeline_too_short(self):
        bad = self._a()
        bad["timeline"] = [bad["timeline"][0]]
        with pytest.raises(InvalidBundleError):
            validate_bundle(bad)

    def test_unknown_major_version(self):
        bad = self._a()
        bad["schemaVersion"] = "2.0.0"
        with pytest.raises(UnsupportedBundleVersionError):
            validate_bundle(bad)


# ---------------------------------------------------------------------------
# 5. pin_evidence_bundle round-trip (schema §5 — OQ-10)
# ---------------------------------------------------------------------------


class _FakePinner:
    def __init__(self) -> None:
        self.pinned: bytes | None = None

    def upload_binary(self, data, content_type, options=None):
        self.pinned = bytes(data)
        return {"cid": "bafyfakecid", "size": len(data)}


class TestPinEvidenceBundle:
    def test_pins_exact_canonical_bytes_and_round_trips(self):
        from eth_utils import keccak

        v = _by_name("A")
        pinner = _FakePinner()
        res = pin_evidence_bundle(v["bundle"], pinner)
        assert res.cid == "bafyfakecid"
        assert res.bundle_hash == v["bundleHash"]
        # The pinned bytes ARE the canonical bytes (no re-encoding).
        assert pinner.pinned.hex() == v["canonicalBytesHex"]
        # OQ-10: keccak256(fetched) == bundle_hash.
        assert "0x" + keccak(pinner.pinned).hex() == v["bundleHash"]
