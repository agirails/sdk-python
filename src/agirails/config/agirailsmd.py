"""AGIRAILS.md Parser + Canonical Hash.

Parses AGIRAILS.md files (YAML frontmatter + markdown body),
computes deterministic canonical hashes for on-chain verification.

Canonical Hash Algorithm
------------------------
1. Parse YAML frontmatter into a dict
2. Strip publish metadata keys (config_hash, published_at, config_cid, arweave_tx, template_source)
3. Canonicalize frontmatter:
   - Object keys: sorted lexicographically (recursive)
   - Primitive arrays (str/int/float/bool): sorted by str(x) using locale-aware comparison
   - Object arrays (list of dicts): preserve order
   - datetime objects: convert to ISO-8601 string with 'Z' suffix
   - None: preserved
4. structuredHash = keccak256(json.dumps(canonical))
5. Normalize body: CRLF->LF, CR->LF, strip trailing whitespace per line, trim
6. bodyHash = keccak256(normalized_body)
7. configHash = keccak256(structuredHash_bytes + bodyHash_bytes)

CRITICAL: JSON serialization must match JavaScript's JSON.stringify() exactly:
- No trailing comma
- No spaces after colons or commas (separators=(',', ':'))
- None -> null, True -> true, False -> false
- Floats that are whole numbers serialize without decimal (1.0 -> 1, not 1.0)
"""

from __future__ import annotations

import datetime
import json
import locale
from dataclasses import dataclass
from typing import Any, Dict, List, Union

import yaml
from eth_utils import keccak


# ============================================================================
# Types
# ============================================================================


@dataclass(frozen=True)
class AgirailsMdConfig:
    """Parsed AGIRAILS.md with frontmatter and body."""

    frontmatter: Dict[str, Any]
    body: str


@dataclass(frozen=True)
class AgirailsMdHashResult:
    """Hash computation result."""

    config_hash: str
    structured_hash: str
    body_hash: str


# ============================================================================
# Constants
# ============================================================================

PUBLISH_METADATA_KEYS: List[str] = [
    "config_hash",
    "published_at",
    "config_cid",
    "arweave_tx",
    "template_source",
]


# ============================================================================
# Custom JSON Encoder (match JS JSON.stringify behavior)
# ============================================================================


class _JSCompatEncoder(json.JSONEncoder):
    """JSON encoder that matches JavaScript's JSON.stringify() output.

    Key differences from Python's default:
    - Floats that are whole numbers serialize without decimal point (1.0 -> 1)
    - This matches JS behavior where typeof 1.0 === 'number' and JSON.stringify(1.0) === '1'
    """

    def default(self, o: Any) -> Any:
        # datetime should already be converted to string by canonicalize,
        # but handle as safety net
        if isinstance(o, (datetime.datetime, datetime.date)):
            return _datetime_to_iso(o)
        return super().default(o)

    def encode(self, o: Any) -> str:
        # Process the object to convert whole floats to ints before encoding
        processed = _convert_whole_floats(o)
        return super().encode(processed)


def _convert_whole_floats(value: Any) -> Any:
    """Recursively convert whole-number floats to ints to match JS JSON output."""
    if isinstance(value, float):
        if value.is_integer() and not (value != value):  # not NaN
            return int(value)
        return value
    if isinstance(value, dict):
        return {k: _convert_whole_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_convert_whole_floats(v) for v in value]
    return value


# ============================================================================
# Datetime helpers
# ============================================================================


def _datetime_to_iso(value: Union[datetime.datetime, datetime.date]) -> str:
    """Convert datetime/date to ISO-8601 string matching JS Date.toISOString().

    JS Date.toISOString() always produces: YYYY-MM-DDTHH:mm:ss.sssZ
    """
    if isinstance(value, datetime.datetime):
        # Ensure UTC timezone
        if value.tzinfo is None:
            # Assume UTC for naive datetimes (matches JS behavior)
            utc_dt = value.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_dt = value.astimezone(datetime.timezone.utc)
        # Format to match JS: 2026-02-15T00:00:00.000Z
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc_dt.microsecond // 1000:03d}Z"
    # datetime.date (not datetime) - treat as midnight UTC
    return f"{value.isoformat()}T00:00:00.000Z"


# ============================================================================
# Locale-aware comparison (matches JS String.localeCompare)
# ============================================================================


def _locale_compare_key(value: Any) -> Any:
    """Create a sort key matching JS String(x).localeCompare(String(y))."""
    s = str(value)
    try:
        return locale.strxfrm(s)
    except Exception:
        return s


# ============================================================================
# Public functions
# ============================================================================


def strip_publish_metadata(frontmatter: Dict[str, Any]) -> Dict[str, Any]:
    """Strip publish metadata keys from a frontmatter dict.

    Returns a shallow copy with the metadata keys removed.
    These keys are written by the publish pipeline and must not affect the hash.
    """
    return {k: v for k, v in frontmatter.items() if k not in PUBLISH_METADATA_KEYS}


def parse_agirails_md(content: str) -> AgirailsMdConfig:
    """Parse an AGIRAILS.md file into frontmatter + body.

    Args:
        content: Raw file content string.

    Returns:
        AgirailsMdConfig with frontmatter dict and body string.

    Raises:
        ValueError: If content has no valid YAML frontmatter.
    """
    trimmed = content.lstrip()

    if not trimmed.startswith("---"):
        raise ValueError("AGIRAILS.md must start with YAML frontmatter (---)")

    # Find closing ---
    closing_index = trimmed.find("\n---", 3)
    if closing_index == -1:
        raise ValueError("AGIRAILS.md frontmatter is not closed (missing closing ---)")

    yaml_content = trimmed[4:closing_index]  # skip opening ---\n
    body = trimmed[closing_index + 4:]  # skip \n---

    # Parse YAML
    try:
        frontmatter = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse YAML frontmatter: {e}") from e

    if not isinstance(frontmatter, dict):
        raise ValueError("YAML frontmatter must be an object")

    # Strip leading newline from body (matches TS behavior)
    if body.startswith("\n"):
        body = body[1:]

    return AgirailsMdConfig(frontmatter=frontmatter, body=body)


def canonicalize(value: Any) -> Any:
    """Recursively canonicalize a value for deterministic JSON serialization.

    - Object keys: sorted lexicographically
    - Primitive arrays: sorted by str(x) using locale-aware comparison
    - Object arrays: order preserved
    - datetime objects: converted to ISO-8601 string
    - None: preserved
    """
    if value is None:
        return value

    # Handle datetime objects (YAML parser may auto-create these)
    if isinstance(value, datetime.datetime):
        return _datetime_to_iso(value)
    if isinstance(value, datetime.date):
        return _datetime_to_iso(value)

    if isinstance(value, list):
        # Canonicalize each element
        canonicalized = [canonicalize(item) for item in value]

        # Only sort arrays of primitives (str, int, float, bool)
        # Arrays of objects maintain order (semantic ordering matters)
        all_primitive = all(
            isinstance(item, (str, int, float, bool))
            for item in canonicalized
        )

        if all_primitive and canonicalized:
            return sorted(canonicalized, key=_locale_compare_key)

        return canonicalized

    if isinstance(value, dict):
        sorted_dict: Dict[str, Any] = {}
        for key in sorted(value.keys()):
            sorted_dict[key] = canonicalize(value[key])
        return sorted_dict

    return value


def normalize_body(body: str) -> str:
    """Normalize markdown body for deterministic hashing.

    - CRLF -> LF
    - CR -> LF
    - Strip trailing whitespace per line
    - Trim leading/trailing whitespace
    """
    normalized = body.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    lines = [line.rstrip() for line in lines]
    return "\n".join(lines).strip()


def _keccak256_text(text: str) -> str:
    """Compute keccak256 of UTF-8 encoded text, return 0x-prefixed hex string."""
    hash_bytes = keccak(text=text)
    return "0x" + hash_bytes.hex()


def _keccak256_bytes(data: bytes) -> str:
    """Compute keccak256 of raw bytes, return 0x-prefixed hex string."""
    hash_bytes = keccak(primitive=data)
    return "0x" + hash_bytes.hex()


def compute_config_hash(content: str) -> AgirailsMdHashResult:
    """Compute the canonical config hash from raw AGIRAILS.md content.

    Args:
        content: Raw AGIRAILS.md file content.

    Returns:
        AgirailsMdHashResult with config_hash, structured_hash, and body_hash.
    """
    config = parse_agirails_md(content)
    return compute_config_hash_from_parts(config.frontmatter, config.body)


def compute_config_hash_from_parts(
    frontmatter: Dict[str, Any],
    body: str,
) -> AgirailsMdHashResult:
    """Compute the canonical config hash from parsed parts.

    Publish metadata keys are automatically stripped before hashing.

    Args:
        frontmatter: Parsed YAML frontmatter dict.
        body: Markdown body string.

    Returns:
        AgirailsMdHashResult with config_hash, structured_hash, and body_hash.
    """
    # Step 0: Strip publish metadata
    stripped = strip_publish_metadata(frontmatter)

    # Step 1: Canonical JSON of frontmatter
    canonical = canonicalize(stripped)
    canonical_json = json.dumps(
        canonical,
        separators=(",", ":"),
        ensure_ascii=False,
        cls=_JSCompatEncoder,
    )
    structured_hash = _keccak256_text(canonical_json)

    # Step 2: Normalized body hash
    normalized = normalize_body(body)
    body_hash = _keccak256_text(normalized)

    # Step 3: Combined hash (byte concatenation)
    combined = bytes.fromhex(structured_hash[2:]) + bytes.fromhex(body_hash[2:])
    config_hash = _keccak256_bytes(combined)

    return AgirailsMdHashResult(
        config_hash=config_hash,
        structured_hash=structured_hash,
        body_hash=body_hash,
    )


def serialize_agirails_md(frontmatter: Dict[str, Any], body: str) -> str:
    """Serialize config back to AGIRAILS.md format.

    Args:
        frontmatter: YAML frontmatter dict.
        body: Markdown body string.

    Returns:
        Complete AGIRAILS.md file content.
    """
    yaml_str = yaml.dump(
        frontmatter,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
        sort_keys=False,
    ).rstrip()

    normalized_body = body if body.startswith("\n") else f"\n{body}"

    return f"---\n{yaml_str}\n---\n{normalized_body}"
