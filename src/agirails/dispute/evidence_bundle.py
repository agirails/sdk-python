"""
Evidence Bundle — the single CANONICAL evidence-bundle serializer (PRD P2-3).

Python half of a cross-language (TS ⇄ Py) byte-identical serializer. Its
TypeScript twin is ``sdk-js/src/dispute/EvidenceBundle.ts``. Both MUST produce
IDENTICAL ``canonical_bytes`` and therefore an identical ``bundle_hash`` for the
same logical bundle.

FROZEN schema (normative): ``DISPUTE SYSTEM/EVIDENCE-BUNDLE-SCHEMA.md``. No field
set, canonical byte rule, ``bundle_hash`` rule, or token cap is defined here
independently — they are pinned in the schema and reproduced 1:1.

Key invariants (schema §3, §4, §5):
  - ``canonical_bytes = canonical_json_dumps(bundle).encode("utf-8")`` — reuses
    the existing cross-language-proven canonicalizer (byte-identical to JS
    fast-json-stable-stringify), NOT a new one. Sorted keys at every level, no
    whitespace, ``ensure_ascii=False``.
  - ``bundle_hash = keccak256(canonical_bytes)`` — what the on-chain AIRuling
    commits and what OQ-10 binds to the pinned CID.
  - Bundles whose cl100k_base token count over the canonical bytes exceeds
    100_000 are rejected with :class:`BundleTooLargeError` BEFORE hashing/pinning.
  - All numeric fields are integers (``uint``); floats are rejected upstream so
    the JSON number-formatting divergence between TS and Py never arises.

Anchor: Example A (schema §7) → bundle_hash
    ``0x379fb8140138f7d90cfbcb481898b6ec646e2c0378ff0d3a4a4572a6570ca257``.
"""

# PARITY: sdk-js/src/dispute/EvidenceBundle.ts
# This file and its TypeScript twin MUST produce byte-identical canonical_bytes
# and bundle_hash for the same logical bundle; keep the schema, error names, and
# public API surface 1:1.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Union

from eth_utils import keccak as _keccak
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agirails.utils.canonical_json import canonical_json_dumps

# ---------------------------------------------------------------------------
# Schema version (schema §1)
# ---------------------------------------------------------------------------

#: Current frozen evidence-bundle schema version (semver, schema §1).
EVIDENCE_BUNDLE_SCHEMA_VERSION: str = "1.0.0"

#: The major version this deserializer understands (schema §1).
SUPPORTED_BUNDLE_MAJOR: int = 1

#: Canonical tokenizer cap (schema §4 / OQ-9).
MAX_BUNDLE_TOKENS: int = 100_000

_BYTES32HEX_RE = re.compile(r"^0x[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors (schema §6 — frozen names, identical to the TS twin)
# ---------------------------------------------------------------------------


class BundleTooLargeError(Exception):
    """Raised when the canonical-bytes token count exceeds ``MAX_BUNDLE_TOKENS``."""

    def __init__(self, token_count: int, max_tokens: int = MAX_BUNDLE_TOKENS) -> None:
        self.token_count = token_count
        self.max_tokens = max_tokens
        super().__init__(
            f"Evidence bundle too large: {token_count} tokens > {max_tokens} cap "
            f"(cl100k_base over canonical bytes). Submit large deliverables as "
            f"deliverableHash + deliverableCID + retrievalInstructions "
            f"(omit deliverableInline)."
        )


class UnsupportedBundleVersionError(Exception):
    """Raised when ``schemaVersion`` major number is unknown to this deserializer."""

    def __init__(self, schema_version: str) -> None:
        self.schema_version = schema_version
        super().__init__(
            f'Unsupported evidence-bundle schemaVersion "{schema_version}": '
            f"this SDK understands major version {SUPPORTED_BUNDLE_MAJOR}."
        )


class InvalidBundleError(Exception):
    """Raised on schema validation failure (missing/extra key, wrong type, etc.)."""

    def __init__(self, message: str, issues: Any = None) -> None:
        self.issues = issues
        super().__init__(f"Invalid evidence bundle: {message}")


# ---------------------------------------------------------------------------
# pydantic models (schema §2 / §6 — strict: forbid extra, integers only)
# ---------------------------------------------------------------------------


def _bytes32hex(value: str) -> str:
    if not isinstance(value, str) or not _BYTES32HEX_RE.match(value):
        raise ValueError("must be 0x + 64 lowercase hex chars (bytes32hex)")
    return value


def _cid(value: str) -> str:
    if not isinstance(value, str) or len(value) == 0:
        raise ValueError("CID must be a non-empty string")
    return value


class _StrictModel(BaseModel):
    # forbid extra keys at every object level (additionalProperties: false);
    # strict=True so a float is NOT silently coerced to int (integers only).
    model_config = ConfigDict(extra="forbid", strict=True, frozen=False)

    @model_validator(mode="before")
    @classmethod
    def _reject_explicit_null(cls, data: Any) -> Any:
        # schema §3.2.8: optional keys are EITHER present with a value OR
        # entirely absent — NEVER null. An explicit `null` is a different
        # (invalid) artifact and must be rejected, matching the TS/zod twin
        # (`z.string().optional()` rejects null, accepts only string|absent).
        if isinstance(data, Mapping):
            for key, value in data.items():
                if value is None:
                    raise ValueError(
                        f'optional key "{key}" present as null; '
                        f"omit it entirely (absent != null, schema §3.2.8)"
                    )
        return data


class EvidenceBundleSpec(_StrictModel):
    """The original service spec (schema §2.3)."""

    agirailsMdCID: str
    capabilities: List[str]
    slaHash: str

    _v_sla = field_validator("slaHash")(staticmethod(_bytes32hex))
    _v_cid = field_validator("agirailsMdCID")(staticmethod(_cid))


class EvidenceBundleDelivery(_StrictModel):
    """Deliverable-or-content-hash + retrieval instructions (schema §2.4)."""

    deliverableHash: str
    deliverableCID: str
    deliverableInline: Optional[str] = None
    retrievalInstructions: str
    deliveredAt: int = Field(ge=0)

    _v_hash = field_validator("deliverableHash")(staticmethod(_bytes32hex))
    _v_cid = field_validator("deliverableCID")(staticmethod(_cid))


class EvidenceBundleDispute(_StrictModel):
    """Why the dispute was opened (schema §2.5)."""

    reason: str
    evidenceCID: str
    evidenceInline: Optional[str] = None
    openedAt: int = Field(ge=0)

    _v_cid = field_validator("evidenceCID")(staticmethod(_cid))


class EvidenceBundleTimelineEvent(_StrictModel):
    """A single timeline event (schema §2.6)."""

    event: str = Field(min_length=1)
    at: int = Field(ge=0)


class EvidenceBundleReasoning(_StrictModel):
    """AI reasoning + evaluation metadata (schema §2.7)."""

    evaluatorPromptCID: str
    modelVersions: List[str]
    notes: str

    _v_cid = field_validator("evaluatorPromptCID")(staticmethod(_cid))


class EvidenceBundle(_StrictModel):
    """
    The canonical evidence bundle (schema §2). EXACTLY seven top-level keys —
    no additional properties at any object level.
    """

    schemaVersion: str
    disputeId: str
    spec: EvidenceBundleSpec
    delivery: EvidenceBundleDelivery
    dispute: EvidenceBundleDispute
    timeline: List[EvidenceBundleTimelineEvent] = Field(min_length=2)
    reasoning: EvidenceBundleReasoning

    _v_dispute = field_validator("disputeId")(staticmethod(_bytes32hex))

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Materialize the bundle as a plain dict with ONLY present keys (optional
        keys that are ``None`` are dropped — absent ≠ empty-string, schema §3.2.8).
        This is what the canonicalizer serializes.
        """
        return _drop_none(self.model_dump(exclude_none=True))


def _drop_none(obj: Any) -> Any:
    """Recursively drop ``None``-valued keys (schema §3.2.8: absent, not null)."""
    if isinstance(obj, Mapping):
        return {k: _drop_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [_drop_none(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Validation (schema §2 / §6)
# ---------------------------------------------------------------------------


def assert_supported_version(schema_version: str) -> None:
    """
    Reject a bundle whose ``schemaVersion`` major number is unknown (schema §1).

    The version string is an opaque semver token — only the major component is
    checked.

    Raises:
        UnsupportedBundleVersionError
    """
    major = schema_version.split(".")[0]
    if not major.isdigit() or int(major) != SUPPORTED_BUNDLE_MAJOR:
        raise UnsupportedBundleVersionError(schema_version)


def validate_bundle(bundle: Union[EvidenceBundle, Mapping[str, Any]]) -> EvidenceBundle:
    """
    Validate a logical bundle against the frozen schema (schema §2 / §6).

    Rejects: missing required key, extra key (extra="forbid" at every level),
    wrong type, non-integer where a ``uint`` is expected (strict mode → a float
    is NOT coerced), malformed ``bytes32hex``, optional key present as ``None``
    via an explicit-null path is treated as absent on output.

    ``schemaVersion`` is validated separately: an unknown MAJOR version raises
    :class:`UnsupportedBundleVersionError`, not :class:`InvalidBundleError`.

    Returns:
        The validated :class:`EvidenceBundle`.

    Raises:
        InvalidBundleError, UnsupportedBundleVersionError
    """
    if isinstance(bundle, EvidenceBundle):
        model = bundle
    else:
        try:
            model = EvidenceBundle.model_validate(bundle)
        except ValidationError as exc:
            issues = exc.errors()
            summary = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in issues
            )
            raise InvalidBundleError(summary, issues) from exc
    assert_supported_version(model.schemaVersion)
    return model


# ---------------------------------------------------------------------------
# Canonical serialization (schema §3) — reuse the existing canonicalizer
# ---------------------------------------------------------------------------


def serialize_bundle_to_string(
    bundle: Union[EvidenceBundle, Mapping[str, Any]],
) -> str:
    """
    Canonical bytes as a UTF-8 string (schema §3) — the exact text that is
    hashed, pinned, and token-counted. Byte-identical to the TS twin's
    ``serializeBundleToString``.
    """
    valid = validate_bundle(bundle)
    return canonical_json_dumps(valid.to_canonical_dict())


def serialize_bundle(bundle: Union[EvidenceBundle, Mapping[str, Any]]) -> bytes:
    """
    Serialize a bundle to its canonical UTF-8 byte form (schema §3).

    ``canonical_bytes = canonical_json_dumps(bundle).encode("utf-8")``. Keys are
    sorted at every nesting level, no whitespace, minimal escaping,
    ``ensure_ascii=False`` (raw UTF-8). Array order is preserved. Byte-identical
    to the TS twin's ``serializeBundle``.

    Raises:
        InvalidBundleError, UnsupportedBundleVersionError
    """
    return serialize_bundle_to_string(bundle).encode("utf-8")


def bundle_hash(
    bundle: Union[EvidenceBundle, Mapping[str, Any]],
    *,
    skip_token_check: bool = False,
) -> str:
    """
    Compute ``bundle_hash = keccak256(canonical_bytes)`` (schema §3.3).

    The value committed on-chain inside the AIRuling (§4.4) and bound to the
    pinned CID by OQ-10. Identical hex to the TS twin's ``bundleHash``.

    Enforces the token cap (schema §4) BEFORE hashing unless ``skip_token_check``.

    Returns:
        ``0x`` + 64 lowercase hex chars.

    Raises:
        BundleTooLargeError, InvalidBundleError, UnsupportedBundleVersionError
    """
    text = serialize_bundle_to_string(bundle)
    if not skip_token_check:
        enforce_token_cap(text)
    return "0x" + _keccak(text.encode("utf-8")).hex()


#: Alias matching the schema §8 acceptance-checklist name.
compute_bundle_hash = bundle_hash


# ---------------------------------------------------------------------------
# Token cap (schema §4 / OQ-9) — tiktoken cl100k_base over canonical bytes
# ---------------------------------------------------------------------------


class BundleTokenizer(Protocol):
    """Protocol for a cl100k_base tokenizer (schema §4)."""

    def encode(self, text: str) -> Sequence[int]:  # pragma: no cover - protocol
        ...


_tokenizer: Optional[BundleTokenizer] = None


def set_bundle_tokenizer(tokenizer: BundleTokenizer) -> None:
    """
    Inject the cl100k_base tokenizer (schema §4). Overrides the default
    ``tiktoken.get_encoding('cl100k_base')`` lookup. The object only needs an
    ``encode(text) -> Sequence[int]`` method.
    """
    global _tokenizer
    _tokenizer = tokenizer


def _resolve_tokenizer() -> Optional[BundleTokenizer]:
    global _tokenizer
    if _tokenizer is not None:
        return _tokenizer
    try:
        import tiktoken  # optional dependency

        _tokenizer = tiktoken.get_encoding("cl100k_base")
        return _tokenizer
    except Exception:  # pragma: no cover - only when tiktoken absent
        return None


def count_bundle_tokens(canonical_text: str) -> int:
    """
    Count cl100k_base tokens over the canonical-bytes TEXT (schema §4).

    Raises:
        RuntimeError: if no cl100k_base tokenizer is available — the cap must
            never be silently skipped. Install ``tiktoken`` or inject one via
            :func:`set_bundle_tokenizer`.
    """
    tk = _resolve_tokenizer()
    if tk is None:
        raise RuntimeError(
            "No cl100k_base tokenizer available. Install `tiktoken` or call "
            "set_bundle_tokenizer(tiktoken.get_encoding('cl100k_base')) before "
            "serializing bundles."
        )
    return len(tk.encode(canonical_text))


def enforce_token_cap(canonical_text: str) -> int:
    """
    Enforce the token cap (schema §4). Counts cl100k_base tokens over the
    canonical text; raises :class:`BundleTooLargeError` when ``> MAX_BUNDLE_TOKENS``.

    Returns:
        The token count (when within the cap).

    Raises:
        BundleTooLargeError
    """
    count = count_bundle_tokens(canonical_text)
    if count > MAX_BUNDLE_TOKENS:
        raise BundleTooLargeError(count, MAX_BUNDLE_TOKENS)
    return count


# ---------------------------------------------------------------------------
# IPFS pinning (schema §5 — INV-20 / OQ-10 integrity binding)
# ---------------------------------------------------------------------------


@dataclass
class PinEvidenceBundleResult:
    """
    Result of pinning an evidence bundle (schema §5).

    The integrity invariant (OQ-10) is ``keccak256(fetch(cid)) == bundle_hash``;
    the on-chain AIRuling commits ``bundle_hash``, the CID is the retrieval handle.
    """

    cid: str
    bundle_hash: str
    size: int


class EvidenceBundlePinner(Protocol):
    """
    Minimal binary-pinning surface the bundle pinner needs (schema §5). Satisfied
    by a G-IPFS client exposing ``upload_binary``. REUSED so bundles are pinned
    through the same hot-storage tier as the rest of the SDK.
    """

    def upload_binary(
        self,
        data: bytes,
        content_type: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:  # pragma: no cover - protocol
        ...


def pin_evidence_bundle(
    bundle: Union[EvidenceBundle, Mapping[str, Any]],
    pinner: EvidenceBundlePinner,
) -> PinEvidenceBundleResult:
    """
    Pin the EXACT canonical bytes of an evidence bundle to IPFS (schema §5.1).

    CRITICAL (OQ-10): the bytes pinned are exactly ``serialize_bundle(bundle)`` —
    not a re-encoded / re-ordered / pretty-printed copy — so
    ``keccak256(fetch(cid))`` round-trips to the returned ``bundle_hash``. The
    token cap (schema §4) is enforced BEFORE pinning.

    Args:
        bundle: the logical evidence bundle.
        pinner: an IPFS binary pinner exposing ``upload_binary``.

    Returns:
        :class:`PinEvidenceBundleResult` for the INV-20 / OQ-10 binding.

    Raises:
        BundleTooLargeError, InvalidBundleError, UnsupportedBundleVersionError
    """
    valid = validate_bundle(bundle)
    text = canonical_json_dumps(valid.to_canonical_dict())
    enforce_token_cap(text)  # schema §4 — before any pin/spend
    canonical_bytes = text.encode("utf-8")
    digest = "0x" + _keccak(canonical_bytes).hex()
    result = pinner.upload_binary(
        canonical_bytes,
        "application/json",
        {"metadata": {"bundleHash": digest, "schemaVersion": valid.schemaVersion}},
    )
    cid = result["cid"] if isinstance(result, dict) else getattr(result, "cid")
    return PinEvidenceBundleResult(
        cid=cid, bundle_hash=digest, size=len(canonical_bytes)
    )
