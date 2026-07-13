"""
Golden agreement vector — the cross-language anchor (TS <-> Py).

The TS twin test `sdk-js/src/builders/AgreementSerializer.test.ts` pins the SAME
canonical bytes + hash. If either drifts, the agreementHash preimage serializer
(AIP-14c D3) is no longer byte-identical across SDKs.
"""

import pytest

from agirails.builders.agreement import (
    AGREEMENT_SCHEMA_VERSION,
    ZERO_AGREEMENT_HASH,
    InvalidAgreementError,
    UnsupportedAgreementVersionError,
    compute_agreement_hash,
    agreement_hash,
    serialize_agreement,
    validate_agreement,
)

GOLDEN_AGREEMENT = {
    "schemaVersion": "1.0.0",
    "request": {"service": "summarize", "url": "https://example.com/doc"},
    "input": {"lang": "en", "maxTokens": 500},
    "sla": {"deadlineSeconds": 3600, "minQualityBps": 9000},
}
GOLDEN_CANONICAL = (
    '{"input":{"lang":"en","maxTokens":500},'
    '"request":{"service":"summarize","url":"https://example.com/doc"},'
    '"schemaVersion":"1.0.0",'
    '"sla":{"deadlineSeconds":3600,"minQualityBps":9000}}'
)
GOLDEN_AGREEMENT_HASH = (
    "0xb2ef8cf734173588408b48793a43cc53e86f1f3d5702778a29f4460f5c8e9db4"
)


def test_serializes_to_frozen_canonical_bytes():
    assert serialize_agreement(GOLDEN_AGREEMENT) == GOLDEN_CANONICAL


def test_computes_golden_agreement_hash():
    assert compute_agreement_hash(GOLDEN_AGREEMENT) == GOLDEN_AGREEMENT_HASH
    assert agreement_hash(GOLDEN_AGREEMENT) == GOLDEN_AGREEMENT_HASH


def test_order_insensitive_canonical_sort():
    reordered = {
        "sla": {"minQualityBps": 9000, "deadlineSeconds": 3600},
        "input": {"maxTokens": 500, "lang": "en"},
        "request": {"url": "https://example.com/doc", "service": "summarize"},
        "schemaVersion": "1.0.0",
    }
    assert compute_agreement_hash(reordered) == GOLDEN_AGREEMENT_HASH


def test_frozen_schema_version_and_zero_sentinel():
    assert AGREEMENT_SCHEMA_VERSION == "1.0.0"
    assert ZERO_AGREEMENT_HASH == "0x" + "0" * 64


def test_rejects_missing_required_key():
    with pytest.raises(InvalidAgreementError):
        validate_agreement({"schemaVersion": "1.0.0", "request": {}, "input": {}})


def test_rejects_extra_key():
    with pytest.raises(InvalidAgreementError):
        validate_agreement(
            {"schemaVersion": "1.0.0", "request": {}, "input": {}, "sla": {}, "quote": {}}
        )


def test_rejects_non_dict():
    with pytest.raises(InvalidAgreementError):
        validate_agreement("nope")
    with pytest.raises(InvalidAgreementError):
        validate_agreement([])


def test_rejects_unsupported_major_version():
    with pytest.raises(UnsupportedAgreementVersionError):
        compute_agreement_hash(
            {"schemaVersion": "2.0.0", "request": {}, "input": {}, "sla": {}}
        )
