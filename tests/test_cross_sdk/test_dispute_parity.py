# PARITY: sdk-js/tests/dispute-parity.test.ts
"""P2-10 CAPSTONE — cross-SDK META parity + golden-vector suite (Py side).

Mirrors ``sdk-js/tests/dispute-parity.test.ts`` 1:1 and consumes the SAME two
shared fixtures under ``DISPUTE SYSTEM/test-vectors/dispute/``:

  - ``parity-surface.json`` — the META manifest: every intentional public dispute
    symbol with its TS name + Py name + per-language required arity. This suite
    asserts the Py SDK matches its ``py`` column (presence + required arity); the
    TS suite asserts the ``ts`` column; and BOTH assert no symbol is
    single-language (each manifest row carries a ``ts`` AND a ``py`` name). The
    parity-surface DIFF is therefore the manifest itself — a symbol present in
    only one SDK could not appear here with both twins AND pass both suites.

  - ``golden-vectors.json`` — five byte/value-identical golden families (AIRuling
    digest, bundle-hash, BondEscalation calldata, DisputeSplitRecorded decode +
    ZERO-REMAINING rule, split-rate). Both SDKs load THIS file and MUST reproduce
    every expected value exactly.

PARITY: sdk-js/tests/dispute-parity.test.ts
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from web3 import Web3

# ── The dispute public surface the manifest enumerates ──────────────────────
import agirails.dispute as DISPUTE_NS
import agirails.types.dispute as TYPES_NS
import agirails.reputation.dispute_split_indexer as INDEXER_NS
from agirails.dispute import (
    BondEscalationClient,
    CompositeMediator,
    DisputeSplitRecorded,
    bundle_hash,
    compute_bundle_hash,
    compute_split_rate,
    decode_dispute_split_recorded,
    decode_resolution_proof,
    serialize_bundle,
    serialize_bundle_to_string,
)
from agirails.reputation.dispute_split_indexer import DisputeSplitIndexer
from agirails.types.dispute import (
    AIRuling,
    DISPUTE_EVALUATOR_DOMAIN_NAME,
    DISPUTE_EVALUATOR_DOMAIN_VERSION,
    DOMAIN_TYPEHASH,
    RULING_TYPEHASH,
    Ruling,
    compute_ruling_digest,
    compute_ruling_domain_separator,
    compute_ruling_struct_hash,
)

# Shared fixtures (the SAME files the TS jest suite loads).
_VECTORS = Path(__file__).resolve().parents[4] / "DISPUTE SYSTEM" / "test-vectors" / "dispute"
SURFACE = json.loads((_VECTORS / "parity-surface.json").read_text())
GOLDEN = json.loads((_VECTORS / "golden-vectors.json").read_text())

# Flattened runtime namespace of every public dispute symbol.
_NS: Dict[str, Any] = {}
for _mod in (DISPUTE_NS, TYPES_NS, INDEXER_NS):
    for _name in dir(_mod):
        if not _name.startswith("_"):
            _NS.setdefault(_name, getattr(_mod, _name))


def _required_arity(fn: Any) -> int:
    """Count REQUIRED parameters (excludes self/cls, *args/**kwargs, defaulted)."""
    sig = inspect.signature(fn)
    count = 0
    for name, p in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        if p.default is inspect._empty and p.kind in (
            p.POSITIONAL_OR_KEYWORD,
            p.POSITIONAL_ONLY,
            p.KEYWORD_ONLY,
        ):
            count += 1
    return count


def _want_arity(entry: Dict[str, Any]) -> int:
    """The Py-side required arity the manifest declares for this entry."""
    return entry["pyArity"] if "pyArity" in entry else entry["arity"]


# ===========================================================================
# META PARITY — Py surface == manifest (and every row has a TS twin)
# ===========================================================================


class TestMetaParity:
    def test_every_manifest_row_has_both_twins(self):
        """No symbol may be single-language: every row carries a ts AND a py name."""
        rows: List[Dict[str, Any]] = []
        rows += SURFACE["enums"]
        rows += SURFACE["constants"]
        rows += SURFACE["functions"]
        rows += SURFACE["types"]
        rows += SURFACE["classes"]
        for c in SURFACE["classes"]:
            rows += c["methods"]
            rows += c["staticMethods"]
            rows += c.get("accessors", [])
        rows += SURFACE["absent"]
        for r in rows:
            assert isinstance(r.get("ts"), str) and r["ts"], r
            assert isinstance(r.get("py"), str) and r["py"], r

    def test_enums_present_with_identical_member_values(self):
        for e in SURFACE["enums"]:
            cls = _NS.get(e["py"])
            assert cls is not None, f"enum missing: {e['py']}"
            for member, value in e["members"].items():
                assert int(getattr(cls, member)) == value, f"{e['py']}.{member}"

    def test_constants_present(self):
        for c in SURFACE["constants"]:
            assert c["py"] in _NS, f"constant missing: {c['py']}"

    def test_top_level_functions_present_with_py_arity(self):
        for f in SURFACE["functions"]:
            fn = _NS.get(f["py"])
            assert callable(fn), f"function missing: {f['py']}"
            assert _required_arity(fn) == _want_arity(f), (
                f"{f['py']} arity: want {_want_arity(f)} "
                f"got {_required_arity(fn)}"
            )

    def test_classes_expose_every_method_and_static_at_py_arity(self):
        for c in SURFACE["classes"]:
            cls = _NS.get(c["py"])
            assert inspect.isclass(cls), f"class missing: {c['py']}"
            for m in c["methods"] + c["staticMethods"]:
                fn = getattr(cls, m["py"], None)
                assert callable(fn), f"method missing: {c['py']}.{m['py']}"
                assert _required_arity(fn) == _want_arity(m), (
                    f"{c['py']}.{m['py']} arity: want {_want_arity(m)} "
                    f"got {_required_arity(fn)}"
                )

    def test_classes_expose_every_accessor_as_a_property_descriptor(self):
        """Accessors (Py ``@property``) MUST be validated via their STATIC
        descriptor — ``inspect.getattr_static`` returns the ``property`` object
        WITHOUT invoking its getter, which would otherwise raise on an
        unconfigured facade (e.g. ``DisputeClient.bond`` with no
        BondEscalationClient wired). Mirrors the TS twin's
        ``Object.getOwnPropertyDescriptor(proto, name).get`` check."""
        for c in SURFACE["classes"]:
            for a in c.get("accessors", []):
                cls = _NS.get(c["py"])
                assert inspect.isclass(cls), f"class missing: {c['py']}"
                descriptor = inspect.getattr_static(cls, a["py"], None)
                assert isinstance(descriptor, property), (
                    f"{c['py']}.{a['py']} should be a @property accessor"
                )

    def test_types_are_runtime_classes_in_python(self):
        """In Py ALL declared types are real runtime classes (dataclass / pydantic
        / Exception); the TS twin erases ``kind:type`` interfaces at runtime and
        enforces them at compile-time instead — a documented representation
        difference, not a parity gap."""
        for t in SURFACE["types"]:
            obj = _NS.get(t["py"])
            assert obj is not None, f"type missing: {t['py']}"
            assert inspect.isclass(obj), f"type not a class: {t['py']}"
            if t.get("kind") == "error":
                assert issubclass(obj, Exception), f"{t['py']} not an Exception"

    def test_intentionally_absent_symbols_are_absent(self):
        """resolve() is onlyBondEscalation — deliberately omitted from BOTH SDK
        clients. Present on the ABI (proving the omission is intentional)."""
        abi = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "src" / "agirails" / "abis" / "composite_mediator.json"
            ).read_text()
        )
        abi_fns = {x["name"] for x in abi if x.get("type") == "function"}
        for ab in SURFACE["absent"]:
            cls = _NS.get(ab["on"])
            assert cls is not None
            assert not hasattr(cls, ab["py"]), (
                f"{ab['on']}.{ab['py']} should be absent (onlyBondEscalation)"
            )
            assert ab["py"] in abi_fns  # exists on-chain

    def test_ts_only_wire_shapes_have_no_python_twin(self):
        """The 4 evaluate WIRE-PARSE shapes (SignedEvaluateResponse,
        ProposeDirectlyEvaluateResponse, EvaluateResponse, EvaluatorRuling) are
        TS-only: Py parses the evaluate response as a raw dict, so there is NO Py
        twin. The manifest declares ``pyTwin: null`` for each; this test locks
        that — none may appear on the Py public dispute surface, mirroring the TS
        twin's de-export assertion on the package entrypoint."""
        ts_only = SURFACE["tsOnlyDeExported"]
        assert len(ts_only) > 0
        for t in ts_only:
            assert t["pyTwin"] is None, f"{t['ts']} must declare pyTwin: null"
            # The TS symbol name must not resolve to anything on the Py surface
            # (and no snake_case twin should exist either).
            assert t["ts"] not in _NS, (
                f"{t['ts']} leaked onto the Py dispute surface"
            )


# ===========================================================================
# GOLDEN VECTOR 1 — AIRuling EIP-712 digest
# ===========================================================================


class TestGoldenAIRulingDigest:
    def _ruling(self) -> AIRuling:
        r = GOLDEN["airulingDigest"]["ruling"]
        return AIRuling(
            dispute_id=r["disputeId"],
            ruling=r["ruling"],
            confidence=r["confidence"],
            split_bps=r["splitBps"],
            timestamp=r["timestamp"],
            reasoning_hash=r["reasoningHash"],
            bundle_hash=r["bundleHash"],
        )

    def test_domain_identity_matches_frozen(self):
        d = GOLDEN["airulingDigest"]["domain"]
        assert DISPUTE_EVALUATOR_DOMAIN_NAME == d["name"]
        assert DISPUTE_EVALUATOR_DOMAIN_VERSION == d["version"]

    def test_struct_hash_matches_frozen(self):
        exp = GOLDEN["airulingDigest"]["expected"]["structHash"]
        assert "0x" + compute_ruling_struct_hash(self._ruling()).hex() == exp

    def test_domain_separator_matches_frozen(self):
        d = GOLDEN["airulingDigest"]["domain"]
        exp = GOLDEN["airulingDigest"]["expected"]["domainSeparator"]
        sep = compute_ruling_domain_separator(d["chainId"], d["verifyingContract"])
        assert "0x" + sep.hex() == exp

    def test_digest_matches_frozen(self):
        d = GOLDEN["airulingDigest"]["domain"]
        exp = GOLDEN["airulingDigest"]["expected"]["digest"]
        digest = compute_ruling_digest(self._ruling(), d["chainId"], d["verifyingContract"])
        assert "0x" + digest.hex() == exp

    def test_typehash_bytes_are_32_bytes(self):
        # Py exposes raw bytes; TS exposes 0x-hex strings — the 32 raw bytes match.
        assert len(RULING_TYPEHASH) == 32
        assert len(DOMAIN_TYPEHASH) == 32


# ===========================================================================
# GOLDEN VECTOR 2 — evidence bundle hash
# ===========================================================================


class TestGoldenBundleHash:
    def test_canonical_bytes_length_matches_frozen(self):
        g = GOLDEN["bundleHash"]
        assert len(serialize_bundle(g["bundle"])) == g["expected"]["canonicalBytesUtf8Len"]

    def test_bundle_hash_matches_frozen(self):
        g = GOLDEN["bundleHash"]
        assert bundle_hash(g["bundle"], skip_token_check=True) == g["expected"]["bundleHash"]
        assert compute_bundle_hash(g["bundle"], skip_token_check=True) == g["expected"]["bundleHash"]

    def test_canonical_string_stable(self):
        g = GOLDEN["bundleHash"]
        s = serialize_bundle_to_string(g["bundle"])
        assert json.loads(s)["schemaVersion"] == "1.0.0"


# ===========================================================================
# GOLDEN VECTOR 3 — BondEscalation calldata (byte-exact, both SDKs)
# ===========================================================================


class TestGoldenBondEscalationCalldata:
    _ABI = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "src" / "agirails" / "abis" / "bond_escalation.json"
        ).read_text()
    )

    def _client(self) -> BondEscalationClient:
        # A contract that builds calldata via encode_abi (the assertion surface the
        # client uses through encode_calldata) — exactly mirrors the TS twin's
        # `interface.encodeFunctionData` capture.
        ref = Web3().eth.contract(abi=self._ABI)

        class _C:
            def encode_abi(self, *, abi_element_identifier, args):
                return ref.encode_abi(abi_element_identifier=abi_element_identifier, args=args)

        return BondEscalationClient(_C(), address="0x00")

    def test_dispute_id_is_deterministic(self):
        g = GOLDEN["bondEscalationCalldata"]
        from eth_abi import encode as abi_encode
        from eth_utils import keccak

        tx_id = bytes.fromhex(g["txId"][2:])
        dispute_id = "0x" + keccak(abi_encode(["string", "bytes32"], ["ACTP_DISPUTE_V1", tx_id])).hex()
        assert dispute_id == g["disputeId"]

    def test_open_dispute_calldata_matches_frozen(self):
        g = GOLDEN["bondEscalationCalldata"]
        client = self._client()
        cd = client.encode_calldata("openDispute", [bytes.fromhex(g["txId"][2:])])
        assert cd == g["openDispute"]["calldata"]
        assert cd[:10] == g["openDispute"]["selector"]

    def test_challenge_calldata_matches_frozen(self):
        g = GOLDEN["bondEscalationCalldata"]
        client = self._client()
        a = g["challenge"]["args"]
        cd = client.encode_calldata(
            "challenge",
            [bytes.fromhex(g["disputeId"][2:]), a["counterRuling"], a["counterSplitBps"]],
        )
        assert cd == g["challenge"]["calldata"]

    def test_submit_ai_ruling_calldata_matches_frozen(self):
        g = GOLDEN["bondEscalationCalldata"]
        client = self._client()
        r = g["submitAIRuling"]["args"]["ruling"]
        tuple_arg = (
            bytes.fromhex(r["disputeId"][2:]),
            r["ruling"],
            r["confidence"],
            r["splitBps"],
            r["timestamp"],
            bytes.fromhex(r["reasoningHash"][2:]),
            bytes.fromhex(r["bundleHash"][2:]),
        )
        sigs = [bytes.fromhex(s[2:]) for s in g["submitAIRuling"]["args"]["signatures"]]
        cd = client.encode_calldata("submitAIRuling", [bytes.fromhex(r["disputeId"][2:]), tuple_arg, sigs])
        assert cd == g["submitAIRuling"]["calldata"]

    def test_escalate_to_uma_calldata_matches_frozen(self):
        g = GOLDEN["bondEscalationCalldata"]
        client = self._client()
        cd = client.encode_calldata(
            "escalateToUMA",
            [bytes.fromhex(g["disputeId"][2:]), g["escalateToUMA"]["args"]["evidenceCID"]],
        )
        assert cd == g["escalateToUMA"]["calldata"]


# ===========================================================================
# GOLDEN VECTOR 4 — DisputeSplitRecorded decode + ZERO-REMAINING rule
# ===========================================================================


class TestGoldenDisputeSplitRecordedDecode:
    def test_topic0_matches_frozen(self):
        from eth_utils import keccak

        topic0 = "0x" + keccak(text="DisputeSplitRecorded(bytes32,address,address,uint16)").hex()
        assert topic0 == GOLDEN["disputeSplitRecordedDecode"]["disputeSplitRecordedTopic0"]

    def test_decode_event_surfaces_fields(self):
        e = GOLDEN["disputeSplitRecordedDecode"]["event"]
        # A processed-log dict shaped like web3's AttributeDict (carries `args`).
        log = {
            "event": "DisputeSplitRecorded",
            "args": {
                "txId": bytes.fromhex(e["txId"][2:]),
                "requester": e["requester"],
                "provider": e["provider"],
                "splitBps": e["splitBps"],
            },
        }
        decoded: DisputeSplitRecorded = decode_dispute_split_recorded(log)
        assert decoded.tx_id == e["txId"]
        assert decoded.requester == e["requester"]
        assert decoded.provider == e["provider"]
        assert decoded.split_bps == e["splitBps"]

    @pytest.mark.parametrize(
        "proof_row",
        GOLDEN["disputeSplitRecordedDecode"]["resolutionProofs"],
        ids=[p["name"] for p in GOLDEN["disputeSplitRecordedDecode"]["resolutionProofs"]],
    )
    def test_resolution_proof_consumer_rule(self, proof_row):
        decoded = decode_resolution_proof(proof_row["proof"], int(proof_row["remaining"]))
        exp = proof_row["expected"]
        assert decoded.is_split == exp["isSplit"]
        assert decoded.phantom_sentinel == exp["phantomSentinel"]
        assert decoded.requester_amount == int(exp["requesterAmount"])
        assert decoded.provider_amount == int(exp["providerAmount"])
        assert decoded.provider_at_fault == exp["providerAtFault"]
        # ZERO-REMAINING hard assertion: a phantom sentinel NEVER surfaces as a payout.
        if exp["phantomSentinel"]:
            assert decoded.requester_amount != 1
            assert decoded.provider_amount != 1


# ===========================================================================
# GOLDEN VECTOR 5 — split-rate computation (OQ-11)
# ===========================================================================


class TestGoldenSplitRate:
    @pytest.mark.parametrize(
        "case",
        GOLDEN["splitRate"]["cases"],
        ids=[c["name"] for c in GOLDEN["splitRate"]["cases"]],
    )
    def test_compute_split_rate_matches_frozen(self, case):
        rate = compute_split_rate(
            case["splitRecorded"], case["kernelDisputedToCancelled"], case["totalDisputes"]
        )
        assert rate == pytest.approx(case["expectedSplitRate"], abs=1e-15)
        if "approxPercent" in case:
            assert round(rate * 100) == case["approxPercent"]

    def test_indexer_reuses_the_same_primitive(self):
        headline = next(
            c for c in GOLDEN["splitRate"]["cases"] if c["name"] == "headline_admin_cancelled_14pct"
        )
        provider = "0x2222222222222222222222222222222222222222"
        indexer = DisputeSplitIndexer()
        from agirails.reputation.dispute_split_indexer import DisputeOutcome

        # 1 admin-CANCELLED split + 6 settled = 1/7.
        indexer.add_outcome(
            DisputeOutcome(provider=provider, requester="0x1", kind="kernelDisputedToCancelled")
        )
        for _ in range(6):
            indexer.add_outcome(
                DisputeOutcome(provider=provider, requester="0x1", kind="settled")
            )
        r = indexer.get_split_rate(provider)
        assert r.split_count == 1
        assert r.total_disputes == 7
        assert r.split_rate == pytest.approx(headline["expectedSplitRate"], abs=1e-15)
        b = indexer.get_split_rate_breakdown(provider)
        assert b.admin_split_count == 1
        assert b.mediator_split_count == 0
