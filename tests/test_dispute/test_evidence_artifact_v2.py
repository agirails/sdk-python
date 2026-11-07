"""
Schema-2.0.0 evidence artifact — golden-vector parity with the sdk-js twin.

The GOLDEN canonical string + hash below MUST match sdk-js
`tests/evidence-artifact-v2.test.ts`. A diff here is an ABI-freeze-level event
(it would break every already-signed 9-field ruling's bundleHash), not a test to update.
"""
import pytest

from agirails.dispute.evidence_artifact_v2 import (
    EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION,
    compute_artifact_v2_hash,
    serialize_artifact_v2_to_string,
    validate_evidence_artifact_v2,
    UnsupportedArtifactVersionError,
    InvalidArtifactError,
)

D = "0x" + "11" * 32
T = "0x" + "22" * 32
R = "0x" + "33" * 32
A = "0x" + "44" * 32
REQ = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
PRV = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


def artifact():
    return {
        "schemaVersion": "2.0.0",
        "disputeId": D,
        "transaction": {
            "transactionId": T,
            "parties": {"requester": REQ, "provider": PRV},
            "amount": "1000000000",
            "initiator": REQ,
            "timestamps": {"createdAt": 1700000000, "deliveredAt": 1700000100, "disputedAt": 1700000200},
        },
        "agreement": {"bytes": "AGREEMENT: request+input+SLA", "quote": {"bytes": "QUOTE: 1000 USDC", "quoteHash": A}},
        "delivery": {"resultHash": R, "inline": "DELIVERABLE: content"},
    }


def test_golden_canonical_string_and_hash():
    # Byte-identical to the sdk-js golden (evidence-artifact-v2.test.ts). Built by
    # concatenation to avoid f-string brace escaping.
    expected = (
        '{"agreement":{"bytes":"AGREEMENT: request+input+SLA","quote":{"bytes":"QUOTE: 1000 USDC",'
        '"quoteHash":"' + A + '"}},"delivery":{"inline":"DELIVERABLE: content","resultHash":"' + R + '"},'
        '"disputeId":"' + D + '","schemaVersion":"2.0.0","transaction":{"amount":"1000000000",'
        '"initiator":"' + REQ + '","parties":{"provider":"' + PRV + '","requester":"' + REQ + '"},'
        '"timestamps":{"createdAt":1700000000,"deliveredAt":1700000100,"disputedAt":1700000200},'
        '"transactionId":"' + T + '"}}'
    )
    assert serialize_artifact_v2_to_string(artifact()) == expected
    # keccak of the SAME canonical text as the TS twin.
    from eth_utils import keccak
    assert compute_artifact_v2_hash(artifact(), skip_token_check=True) == "0x" + keccak(expected.encode("utf-8")).hex()


def test_hash_insensitive_to_source_key_order():
    a = artifact()
    reordered = {
        "delivery": a["delivery"], "transaction": a["transaction"],
        "agreement": a["agreement"], "disputeId": D, "schemaVersion": "2.0.0",
    }
    assert compute_artifact_v2_hash(reordered, skip_token_check=True) == compute_artifact_v2_hash(a, skip_token_check=True)


def test_cid_only_agreement_ok_neither_rejected():
    a = artifact()
    del a["agreement"]["bytes"]
    a["agreement"]["cid"] = "bafy-agreement"
    validate_evidence_artifact_v2(a)  # no raise
    del a["agreement"]["cid"]
    with pytest.raises(InvalidArtifactError):
        validate_evidence_artifact_v2(a)


def test_strict_exact_version():
    assert EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION == "2.0.0"
    for v in ("2.0.1", "2.1.0", "1.0.0"):
        a = artifact(); a["schemaVersion"] = v
        with pytest.raises(UnsupportedArtifactVersionError):
            validate_evidence_artifact_v2(a)
    a = artifact(); a["schemaVersion"] = ""
    with pytest.raises(InvalidArtifactError):
        validate_evidence_artifact_v2(a)


def test_rejects_forbidden_and_unknown_keys():
    for mutate in (
        lambda a: a.__setitem__("reasoning", {"notes": "smuggled"}),   # D6
        lambda a: a.__setitem__("timeline", []),                        # D5
        lambda a: a.__setitem__("extra", 1),
        lambda a: a["transaction"].__setitem__("extra", 1),
        lambda a: a["delivery"].__setitem__("extra", 1),
        lambda a: a["agreement"]["quote"].__setitem__("extra", 1),
    ):
        a = artifact(); mutate(a)
        with pytest.raises(InvalidArtifactError):
            validate_evidence_artifact_v2(a)


def test_rejects_malformed_fields():
    for mutate in (
        lambda a: a.__setitem__("disputeId", D.upper()),
        lambda a: a["transaction"]["parties"].__setitem__("requester", "not-an-address"),
        lambda a: a["transaction"].__setitem__("amount", "1.5"),
        lambda a: a["transaction"]["timestamps"].__setitem__("createdAt", 1.5),
        lambda a: a["delivery"].__setitem__("resultHash", "0x1234"),
        lambda a: a["transaction"]["timestamps"].__setitem__("createdAt", True),  # bool not int
    ):
        a = artifact(); mutate(a)
        with pytest.raises(InvalidArtifactError):
            validate_evidence_artifact_v2(a)
