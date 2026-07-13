# PARITY: sdk-js/src/builders/AgreementSerializer.ts
# This file and its TypeScript twin MUST produce byte-identical canonical bytes
# and agreementHash for the same logical agreement; keep the schema, error names,
# and public API surface 1:1.
"""
Agreement serializer — the single CANONICAL ``agreementHash`` preimage
serializer (AIP-14c D3).

Python half of the cross-language (TS <-> Py) byte-identical serializer. Its
TypeScript twin is ``sdk-js/src/builders/AgreementSerializer.ts``. Both MUST
produce IDENTICAL canonical bytes and therefore an identical ``agreementHash``
for the same logical agreement.

What ``agreementHash`` commits (AIP-14c D3 — LOCKED):
    The creation-time ``agreementHash`` (7th arg of the v2 ``createTransaction``,
    stored in ``Transaction.agreementHash``) commits the **request + input + SLA
    ONLY** — deliberately NOT the quote. The quote arrives *after* creation
    (``INITIATED->QUOTED`` sets ``txn.metadata = quoteHash``; ``acceptQuote``
    sets the final ``txn.amount``). The evaluator verifies the effective
    agreement **triple**: ``{agreementHash, txn.metadata (quoteHash), txn.amount}``.

    ``agreementHash == bytes32(0)`` => NO automatic signed ruling (D3
    fail-closed). Use :data:`ZERO_AGREEMENT_HASH` to opt out explicitly.

Canonical byte rule (mirrors the evidence-bundle serializer):
    ``canonical_bytes = canonical_json_dumps(agreement).encode("utf-8")`` — the
    same cross-language-proven canonicalizer as the evidence bundle (byte-
    identical to JS ``JSON.stringify`` over sorted keys). ``agreement_hash =
    keccak256(canonical_bytes)``.
"""

from __future__ import annotations

from typing import Any

from eth_utils import keccak as _keccak

from agirails.utils.canonical_json import canonical_json_dumps

# Current frozen agreement schema version (semver).
AGREEMENT_SCHEMA_VERSION = "1.0.0"

# The major schema version this serializer understands.
SUPPORTED_AGREEMENT_MAJOR = 1

# bytes32(0) — the "no automatic AI ruling" sentinel for agreementHash (D3).
ZERO_AGREEMENT_HASH = "0x" + "00" * 32

_REQUIRED_KEYS = ("schemaVersion", "request", "input", "sla")


class InvalidAgreementError(ValueError):
    """Raised when the agreement is structurally invalid (missing/extra key)."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid agreement: {message}")


class UnsupportedAgreementVersionError(ValueError):
    """Raised when the agreement schemaVersion major is unknown to this serializer."""

    def __init__(self, schema_version: str) -> None:
        self.schema_version = schema_version
        super().__init__(
            f'Unsupported agreement schemaVersion "{schema_version}": '
            f"this SDK understands major version {SUPPORTED_AGREEMENT_MAJOR}."
        )


def assert_supported_agreement_version(schema_version: str) -> None:
    """
    Reject an agreement whose ``schemaVersion`` major is unknown.

    Raises:
        UnsupportedAgreementVersionError
    """
    major = schema_version.split(".")[0]
    if not major.isdigit() or int(major) != SUPPORTED_AGREEMENT_MAJOR:
        raise UnsupportedAgreementVersionError(schema_version)


def validate_agreement(agreement: Any) -> dict:
    """
    Validate + normalize a logical agreement into the frozen 4-key shape.

    Rejects: non-dict input, a missing required key, or any extra top-level key
    (exactly ``schemaVersion, request, input, sla`` — no additional properties).
    An unknown MAJOR schema version raises
    :class:`UnsupportedAgreementVersionError`.

    Returns:
        The validated agreement dict.

    Raises:
        InvalidAgreementError, UnsupportedAgreementVersionError
    """
    if not isinstance(agreement, dict):
        raise InvalidAgreementError(
            "must be a dict with keys {schemaVersion, request, input, sla}"
        )
    for req in _REQUIRED_KEYS:
        if req not in agreement:
            raise InvalidAgreementError(f'missing required key "{req}"')
    for key in agreement:
        if key not in _REQUIRED_KEYS:
            raise InvalidAgreementError(
                f'unexpected extra key "{key}" '
                f"(only {', '.join(_REQUIRED_KEYS)} allowed)"
            )
    if not isinstance(agreement["schemaVersion"], str):
        raise InvalidAgreementError("schemaVersion must be a string")
    assert_supported_agreement_version(agreement["schemaVersion"])
    return agreement


def serialize_agreement(agreement: Any) -> str:
    """
    Serialize an agreement to its canonical UTF-8 string form (the exact text
    that is hashed). Byte-identical to the TS twin's ``serializeAgreement``.

    Raises:
        InvalidAgreementError, UnsupportedAgreementVersionError
    """
    valid = validate_agreement(agreement)
    return canonical_json_dumps(valid)


def compute_agreement_hash(agreement: Any) -> str:
    """
    Compute ``agreement_hash = keccak256(utf8(serialize_agreement(agreement)))``
    (AIP-14c D3). Identical hex to the TS twin's ``computeAgreementHash``.

    Returns:
        ``0x`` + 64 lowercase hex chars.

    Raises:
        InvalidAgreementError, UnsupportedAgreementVersionError
    """
    canonical = serialize_agreement(agreement).encode("utf-8")
    return "0x" + _keccak(canonical).hex()


# Alias (symmetry with the evidence-bundle ``bundle_hash``).
agreement_hash = compute_agreement_hash


__all__ = [
    "AGREEMENT_SCHEMA_VERSION",
    "SUPPORTED_AGREEMENT_MAJOR",
    "ZERO_AGREEMENT_HASH",
    "InvalidAgreementError",
    "UnsupportedAgreementVersionError",
    "assert_supported_agreement_version",
    "validate_agreement",
    "serialize_agreement",
    "compute_agreement_hash",
    "agreement_hash",
]
