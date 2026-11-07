"""
evidence_artifact_v2.py — the Schema-2.0.0 IMMUTABLE evidence artifact serializer
(AIP-14c D5/D6). Python twin of the sdk-js ``dispute/EvidenceArtifactV2.ts``.

The 2.0.0 artifact is the evidence object a v2 dispute freezes + hashes BEFORE
evaluation. It differs from the 1.0.0 bundle in exactly the D5/D6 ways:
 - a top-level ``transaction`` block (authoritative economics/parties/timestamps,
   cross-checked against the on-chain ``TransactionView`` by the evaluator);
 - NO ``reasoning`` key (D6 — reasoning is a separate post-evaluation artifact,
   committed via ``reasoningHash``/``reasoningRefHash`` in the 9-field AIRuling);
 - NO ``timeline`` key (D5 — the timeline is derived from chain).

CANONICALIZATION IS UNCHANGED: ``canonical_bytes = canonical_json_dumps(validated)``
— the SAME frozen canonicalizer as the 1.0.0 bundle — and
``bundle_hash = keccak256(canonical_bytes)``. Validation is STRICT (no additional
properties at any level) so two different wire objects can never canonicalize to the
same bytes. Byte-identical to the TS twin (same golden vectors:
sdk-js ``tests/evidence-artifact-v2.test.ts``).
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from eth_utils import keccak as _keccak

from agirails.utils.canonical_json import canonical_json_dumps
from agirails.dispute.evidence_bundle import count_bundle_tokens, enforce_token_cap

EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION: str = "2.0.0"

_BYTES32_HEX = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DECIMAL = re.compile(r"^[0-9]+$")


class UnsupportedArtifactVersionError(Exception):
    """Raised when ``schemaVersion`` is not the exact frozen "2.0.0"."""

    def __init__(self, schema_version: str) -> None:
        super().__init__(
            f'Unsupported evidence-artifact schemaVersion "{schema_version}": only the '
            f'exact frozen "{EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION}" is accepted (strict — '
            "any other 2.x is rejected)."
        )
        self.schema_version = schema_version


class InvalidArtifactError(Exception):
    """Raised when the artifact shape is invalid (missing/extra/typed-wrong field)."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Invalid Schema 2.0.0 evidence artifact: {detail}")


def _is_mapping(x: Any) -> bool:
    return isinstance(x, Mapping)


def _require_str(obj: Mapping[str, Any], key: str, path: str, pattern: Optional[re.Pattern] = None) -> str:
    v = obj.get(key)
    if not isinstance(v, str) or len(v) == 0:
        raise InvalidArtifactError(f"{path}{key}: must be a non-empty string")
    if pattern is not None and not pattern.match(v):
        raise InvalidArtifactError(f"{path}{key}: does not match {pattern.pattern}")
    return v


def _require_uint(obj: Mapping[str, Any], key: str, path: str) -> int:
    v = obj.get(key)
    # bool is an int subclass in Python — reject it explicitly.
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise InvalidArtifactError(f"{path}{key}: must be a non-negative integer")
    return v


def _require_map(obj: Mapping[str, Any], key: str, path: str) -> Mapping[str, Any]:
    v = obj.get(key)
    if not _is_mapping(v):
        raise InvalidArtifactError(f"{path}{key}: must be an object")
    return v


def _no_extra_keys(obj: Mapping[str, Any], allowed: set[str], path: str) -> None:
    extra = set(obj.keys()) - allowed
    if extra:
        raise InvalidArtifactError(f"{path}: unexpected key(s) {sorted(extra)}")


def assert_artifact_v2_version(schema_version: Any) -> None:
    """Assert ``schemaVersion`` is EXACTLY "2.0.0" (strict D5)."""
    if not isinstance(schema_version, str) or len(schema_version) == 0:
        raise InvalidArtifactError("schemaVersion must be a non-empty semver string")
    if schema_version != EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION:
        raise UnsupportedArtifactVersionError(schema_version)


def validate_evidence_artifact_v2(artifact: Any) -> dict[str, Any]:
    """
    Strictly validate + narrow to a canonical dict. Rejects missing required keys,
    ANY extra key at ANY level (so a ``reasoning``/``timeline`` key — D6/D5 — is
    rejected), wrong types, non-integer timestamps, malformed bytes32hex/address,
    an agreement with neither ``bytes`` nor ``cid``.
    """
    if not _is_mapping(artifact):
        raise InvalidArtifactError("<root> must be an object")
    assert_artifact_v2_version(artifact.get("schemaVersion"))
    _no_extra_keys(artifact, {"schemaVersion", "disputeId", "transaction", "agreement", "delivery"}, "<root>")

    dispute_id = _require_str(artifact, "disputeId", "", _BYTES32_HEX)

    txn = _require_map(artifact, "transaction", "")
    _no_extra_keys(txn, {"transactionId", "parties", "amount", "initiator", "timestamps"}, "transaction")
    transaction_id = _require_str(txn, "transactionId", "transaction.", _BYTES32_HEX)
    amount = _require_str(txn, "amount", "transaction.", _DECIMAL)
    initiator = _require_str(txn, "initiator", "transaction.", _ADDRESS)
    parties = _require_map(txn, "parties", "transaction.")
    _no_extra_keys(parties, {"requester", "provider"}, "transaction.parties")
    requester = _require_str(parties, "requester", "transaction.parties.", _ADDRESS)
    provider = _require_str(parties, "provider", "transaction.parties.", _ADDRESS)
    ts = _require_map(txn, "timestamps", "transaction.")
    _no_extra_keys(ts, {"createdAt", "deliveredAt", "disputedAt"}, "transaction.timestamps")
    created_at = _require_uint(ts, "createdAt", "transaction.timestamps.")
    delivered_at = _require_uint(ts, "deliveredAt", "transaction.timestamps.")
    disputed_at = _require_uint(ts, "disputedAt", "transaction.timestamps.")

    agreement = _require_map(artifact, "agreement", "")
    _no_extra_keys(agreement, {"bytes", "cid", "quote"}, "agreement")
    agreement_bytes = agreement.get("bytes")
    agreement_cid = agreement.get("cid")
    if agreement_bytes is not None and not isinstance(agreement_bytes, str):
        raise InvalidArtifactError("agreement.bytes: must be a string")
    if agreement_cid is not None and (not isinstance(agreement_cid, str) or len(agreement_cid) == 0):
        raise InvalidArtifactError("agreement.cid: must be a non-empty string")
    if agreement_bytes is None and agreement_cid is None:
        raise InvalidArtifactError("agreement: requires an inline `bytes` preimage or a `cid` to fetch it")
    quote_out: Optional[dict[str, Any]] = None
    if "quote" in agreement and agreement.get("quote") is not None:
        q = _require_map(agreement, "quote", "agreement.")
        _no_extra_keys(q, {"bytes", "quoteHash"}, "agreement.quote")
        quote_out = {
            "bytes": _require_str(q, "bytes", "agreement.quote."),
            "quoteHash": _require_str(q, "quoteHash", "agreement.quote.", _BYTES32_HEX),
        }

    delivery = _require_map(artifact, "delivery", "")
    _no_extra_keys(delivery, {"resultHash", "encrypted", "inline", "cid", "retrievalInstructions"}, "delivery")
    result_hash = _require_str(delivery, "resultHash", "delivery.", _BYTES32_HEX)
    encrypted = delivery.get("encrypted")
    if encrypted is not None and not isinstance(encrypted, bool):
        raise InvalidArtifactError("delivery.encrypted: must be a boolean")
    inline = delivery.get("inline")
    if inline is not None and not isinstance(inline, str):
        raise InvalidArtifactError("delivery.inline: must be a string")
    cid = delivery.get("cid")
    if cid is not None and (not isinstance(cid, str) or len(cid) == 0):
        raise InvalidArtifactError("delivery.cid: must be a non-empty string")
    retrieval = delivery.get("retrievalInstructions")
    if retrieval is not None and not isinstance(retrieval, str):
        raise InvalidArtifactError("delivery.retrievalInstructions: must be a string")

    # Rebuild in a canonical shape (only present optional keys), mirroring the TS twin.
    agreement_out: dict[str, Any] = {}
    if agreement_bytes is not None:
        agreement_out["bytes"] = agreement_bytes
    if isinstance(agreement_cid, str) and len(agreement_cid) > 0:
        agreement_out["cid"] = agreement_cid
    if quote_out is not None:
        agreement_out["quote"] = quote_out

    # Mirror the TS twin (zod passthrough): only carry `encrypted` when the input had it,
    # so an artifact without the key canonicalizes byte-identically across SDKs.
    delivery_out: dict[str, Any] = {"resultHash": result_hash}
    if "encrypted" in delivery:
        delivery_out["encrypted"] = bool(encrypted is True)
    if inline is not None:
        delivery_out["inline"] = inline
    if isinstance(cid, str) and len(cid) > 0:
        delivery_out["cid"] = cid
    if retrieval is not None:
        delivery_out["retrievalInstructions"] = retrieval

    return {
        "schemaVersion": EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION,
        "disputeId": dispute_id,
        "transaction": {
            "transactionId": transaction_id,
            "parties": {"requester": requester, "provider": provider},
            "amount": amount,
            "initiator": initiator,
            "timestamps": {"createdAt": created_at, "deliveredAt": delivered_at, "disputedAt": disputed_at},
        },
        "agreement": agreement_out,
        "delivery": delivery_out,
    }


def serialize_artifact_v2_to_string(artifact: Any) -> str:
    """Canonical bytes as a UTF-8 string (the exact text that is hashed and pinned)."""
    return canonical_json_dumps(validate_evidence_artifact_v2(artifact))


def serialize_artifact_v2(artifact: Any) -> bytes:
    """Canonical UTF-8 bytes of a validated 2.0.0 artifact."""
    return serialize_artifact_v2_to_string(artifact).encode("utf-8")


def compute_artifact_v2_hash(artifact: Any, *, skip_token_check: bool = False) -> str:
    """
    ``bundle_hash = keccak256(canonical_bytes)`` for a Schema-2.0.0 evidence artifact —
    the value committed in the signed 9-field AIRuling and CID-bound into
    ``evidenceRefHash`` (D7). Enforces the 1.0.0 token cap unless ``skip_token_check``.
    Returns ``0x`` + 64 lowercase hex.
    """
    text = serialize_artifact_v2_to_string(artifact)
    if not skip_token_check:
        enforce_token_cap(text)
    return "0x" + _keccak(text.encode("utf-8")).hex()


def count_artifact_v2_tokens(artifact: Any) -> int:
    """Token count of the canonical artifact text (cl100k_base — same tokenizer as 1.0.0)."""
    return count_bundle_tokens(serialize_artifact_v2_to_string(artifact))
