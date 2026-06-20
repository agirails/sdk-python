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
    "wallet",
    "agent_id",
    "did",
    # Draft-adoption code embedded by the web owner doc — never part of the
    # canonical config. Mirror in web lib/ipfs/config-hash.ts.
    # Matches TS PUBLISH_METADATA_KEYS (config/agirailsmd.ts:66-69).
    "claim_code",
    # AIP-18 DEC-2: a buyer's budget is a PRIVATE operational cap and must never
    # appear in any hashed/published artifact. Stripping it from the canonical
    # hash means budget can never leak on-chain or to IPFS via the configHash.
    # Matches TS PUBLISH_METADATA_KEYS (config/agirailsmd.ts:70-73).
    "budget",
]


# ----------------------------------------------------------------------------
# Parse safety bounds (mirror TS config/agirailsmd.ts:108,118)
# ----------------------------------------------------------------------------

# Hard cap on raw AGIRAILS.md content size before YAML parsing.
#
# Apex audit FIND-016: the CLI runs in untrusted contexts — CI jobs, cloned
# repos, PR workspaces, generated project directories. Any of those can
# contain an attacker-controlled AGIRAILS.md parsed by health/verify/publish/
# init without ever crossing a network boundary. The size bound is a
# defence-in-depth wall against the YAML resource-exhaustion class (deep
# nesting, malicious anchors / aliases). Canonical AGIRAILS.md files are
# ~2-10 KB; 256 KB leaves headroom for legitimate long-form body content
# while still tripping on adversarial blobs.
MAX_AGIRAILSMD_BYTES = 256_000

# Tightened alias-count for the AGIRAILS.md frontmatter parse.
#
# Canonical AGIRAILS.md files never use YAML aliases / anchors. We pin the
# limit to a small constant (matching the TS `parseYaml({maxAliasCount:10})`)
# so a malicious file that plants aliases trips the parser early instead of
# consuming CPU walking an expansion graph (billion-laughs class).
FRONTMATTER_MAX_ALIAS_COUNT = 10


class _AliasCappedSafeLoader(yaml.SafeLoader):
    """SafeLoader subclass that caps the number of YAML aliases resolved.

    PyYAML's default SafeLoader resolves aliases without a low ceiling, leaving
    the alias-expansion DoS vector open. This loader mirrors the TS
    `yaml` parser's `maxAliasCount: 10` by counting alias (`*name`) resolutions
    and raising once the cap is exceeded.
    """

    _max_alias_count = FRONTMATTER_MAX_ALIAS_COUNT

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._alias_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        # An alias event resolves to an existing anchor. Count each one and
        # trip before the underlying anchor lookup walks the expansion graph.
        if self.check_event(yaml.events.AliasEvent):
            self._alias_count += 1
            if self._alias_count > self._max_alias_count:
                event = self.peek_event()
                raise yaml.YAMLError(
                    f"Maximum YAML alias count exceeded "
                    f"({self._max_alias_count}); refusing to expand "
                    f"a file with this many aliases. {event.start_mark}"
                )
        return super().compose_node(parent, index)


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
        ValueError: If content has no valid YAML frontmatter, exceeds the size
            bound, or uses more YAML aliases than the conservative cap.
    """
    # FIND-016 size bound — must fire before any YAML / regex work so a hostile
    # file can't burn CPU in normalisation either. Mirrors TS
    # config/agirailsmd.ts:128-136 (which compares against content.length).
    if len(content) > MAX_AGIRAILSMD_BYTES:
        raise ValueError(
            f"AGIRAILS.md exceeds {MAX_AGIRAILSMD_BYTES} bytes "
            f"(got {len(content)}). "
            "Canonical files are typically 2-10 KB; refusing to parse a "
            "file this large."
        )

    trimmed = content.lstrip()

    if not trimmed.startswith("---"):
        raise ValueError("AGIRAILS.md must start with YAML frontmatter (---)")

    # Find closing ---
    closing_index = trimmed.find("\n---", 3)
    if closing_index == -1:
        raise ValueError("AGIRAILS.md frontmatter is not closed (missing closing ---)")

    yaml_content = trimmed[4:closing_index]  # skip opening ---\n
    body = trimmed[closing_index + 4:]  # skip \n---

    # Parse YAML with a tightened alias-count cap (mirror TS maxAliasCount:10).
    try:
        frontmatter = yaml.load(yaml_content, Loader=_AliasCappedSafeLoader)
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


# ============================================================================
# V4 Typed Parser ({slug}.md) — AIP-18 intent-aware
# ----------------------------------------------------------------------------
# Composes on top of ``parse_agirails_md`` above, adding typed output,
# convention-over-config defaults, and validation. ADDITIVE — never modifies
# the v1 parser. Mirrors TS:
#   - config/defaults.ts (V4_DEFAULTS, V4_CONSTRAINTS)
#   - config/slugUtils.ts (generate_slug, validate_slug)
#   - config/agirailsmdV4.ts (parse_agirails_md_v4, validate_agirails_md_v4)
# ============================================================================

import re
from typing import Optional


# ----------------------------------------------------------------------------
# Convention-over-config defaults (mirror TS config/defaults.ts)
# ----------------------------------------------------------------------------

# Mirror TS V4_DEFAULTS (config/defaults.ts:14-38).
V4_DEFAULTS: Dict[str, Any] = {
    # What this agent does on the network:
    #   earn — provides services and gets paid (default)
    #   pay  — only requests services from other agents (no on-chain provider role)
    #   both — provides AND requests
    "intent": "earn",
    "pricing": {
        "currency": "USDC",
        "unit": "job",
        "negotiable": False,
    },
    "network": "mock",
    "sla": {
        "response": "2h",
        "delivery": "24h",
        "concurrency": 10,
        "dispute_window": "48h",
    },
    "payment": {
        "modes": ["actp"],
    },
}

# Mirror TS V4_CONSTRAINTS (config/defaults.ts:44-69).
V4_CONSTRAINTS: Dict[str, Any] = {
    # Minimum price in USDC
    "MIN_PRICE": 0.05,
    # Maximum slug length
    "MAX_SLUG_LENGTH": 64,
    # Allowed characters in slug (mirror TS SLUG_PATTERN)
    "SLUG_PATTERN": re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$"),
    # Known service types (for test job matching)
    "KNOWN_SERVICES": [
        "code-review",
        "translation",
        "security-audit",
        "data-analysis",
        "content-writing",
        "testing",
        "automation",
    ],
    # Valid network values
    "VALID_NETWORKS": ["mock", "testnet", "mainnet"],
    # Valid payment modes
    "VALID_PAYMENT_MODES": ["actp", "x402"],
    # Valid intent values
    "VALID_INTENTS": ["earn", "pay", "both"],
    # Heading that splits description from howToRequest
    "HOW_TO_REQUEST_HEADING": "## How to Request This Service",
}

# Display fee constants (mirror TS config/defaults.ts:82-95).
_MIN_FEE_WEI = 50_000  # $0.05
_FEE_BPS = 100  # 1%


def compute_display_fee(amount_wei: int) -> int:
    """Compute display fee for receipt rendering (cosmetic only).

    Mirrors TS ``computeDisplayFee`` (config/defaults.ts:92-95).
    Protocol contract: fee = max(amount * 1% , $0.05).

    Args:
        amount_wei: Transaction amount in USDC wei (6 decimals).

    Returns:
        Fee in USDC wei.
    """
    percent_fee = (amount_wei * _FEE_BPS) // 10_000
    return percent_fee if percent_fee > _MIN_FEE_WEI else _MIN_FEE_WEI


# ----------------------------------------------------------------------------
# Slug helpers (mirror TS config/slugUtils.ts)
# ----------------------------------------------------------------------------


def generate_slug(name: str) -> str:
    """Generate a URL-safe slug from an agent name.

    Mirrors TS ``generateSlug`` (config/slugUtils.ts:24-31):
      - lowercase
      - non-alphanumeric → hyphen
      - collapse multiple hyphens
      - strip leading/trailing hyphens
      - max 64 characters
    """
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)  # non-alphanumeric → hyphen
    s = re.sub(r"-+", "-", s)  # collapse multiple hyphens
    s = re.sub(r"^-|-$", "", s)  # strip leading/trailing hyphens
    return s[: V4_CONSTRAINTS["MAX_SLUG_LENGTH"]]


def validate_slug(slug: str) -> Optional[str]:
    """Validate a slug string.

    Mirrors TS ``validateSlug`` (config/slugUtils.ts:38-47).

    Returns:
        Error message if invalid, None if valid.
    """
    if not slug:
        return "Slug cannot be empty"
    if len(slug) > V4_CONSTRAINTS["MAX_SLUG_LENGTH"]:
        return f"Slug must be {V4_CONSTRAINTS['MAX_SLUG_LENGTH']} characters or less"
    if not V4_CONSTRAINTS["SLUG_PATTERN"].match(slug):
        return "Slug must contain only lowercase letters, numbers, and hyphens"
    return None


# ----------------------------------------------------------------------------
# V4 typed config dataclasses (mirror TS AgirailsMdV4Config interfaces)
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class AgirailsMdV4Pricing:
    """Pricing band (mirror TS AgirailsMdV4Pricing)."""

    base: float
    currency: str  # always 'USDC'
    unit: str
    negotiable: bool
    min_price: float
    max_price: float


@dataclass(frozen=True)
class AgirailsMdV4SLA:
    """SLA defaults (mirror TS AgirailsMdV4SLA)."""

    response: str
    delivery: str
    concurrency: int
    dispute_window: str


@dataclass(frozen=True)
class AgirailsMdV4Covenant:
    """Covenant accepts/returns (mirror TS AgirailsMdV4Covenant)."""

    accepts: Dict[str, str]
    returns: Dict[str, str]


@dataclass(frozen=True)
class AgirailsMdV4ServiceEntry:
    """Per-service descriptor (mirror TS AgirailsMdV4ServiceEntry).

    ``min_price`` / ``max_price`` are the bounds AgentRegistry enforces;
    ``price`` is the human-readable display value (kept as a string for
    YAML lossless round-trip).
    """

    type: str
    price: Optional[str] = None
    min_price: Optional[float] = None
    max_price: Optional[float] = None


@dataclass(frozen=True)
class AgirailsMdV4Config:
    """Fully typed V4 config (mirror TS AgirailsMdV4Config)."""

    name: str
    slug: str
    intent: str  # 'earn' | 'pay' | 'both'
    services: List[AgirailsMdV4ServiceEntry]
    services_needed: List[str]
    pricing: AgirailsMdV4Pricing
    network: str  # 'mock' | 'testnet' | 'mainnet'
    sla: AgirailsMdV4SLA
    covenant: AgirailsMdV4Covenant
    payment: Dict[str, List[str]]
    description: str
    how_to_request: str
    budget: Optional[float] = None
    endpoint: Optional[str] = None
    # Read-only publish metadata
    wallet: Optional[str] = None
    agent_id: Optional[str] = None
    did: Optional[str] = None


@dataclass(frozen=True)
class ValidationIssue:
    """Single validation issue (mirror TS ValidationIssue)."""

    field: str
    message: str
    severity: str  # 'error' | 'warning'


@dataclass(frozen=True)
class ValidationResult:
    """Validation result (mirror TS ValidationResult)."""

    valid: bool
    issues: List[ValidationIssue]


# ----------------------------------------------------------------------------
# Safe property access helpers (mirror TS getString/getNumber/... coercion)
# ----------------------------------------------------------------------------


def _v4_get_string(obj: Optional[Dict[str, Any]], key: str) -> str:
    """Mirror TS getString: '' for missing/None, else String(value)."""
    if not obj or obj.get(key) is None:
        return ""
    val = obj[key]
    if isinstance(val, bool):
        # match JS String(true) === 'true'
        return "true" if val else "false"
    return str(val)


def _v4_get_number(obj: Optional[Dict[str, Any]], key: str) -> Optional[float]:
    """Mirror TS getNumber: None for missing/None/NaN, else Number(value)."""
    if not obj or obj.get(key) is None:
        return None
    try:
        val = float(obj[key])
    except (TypeError, ValueError):
        return None
    if val != val:  # NaN
        return None
    return val


def _v4_get_boolean(obj: Optional[Dict[str, Any]], key: str) -> Optional[bool]:
    """Mirror TS getBoolean: None for missing/None, else Boolean(value)."""
    if not obj or obj.get(key) is None:
        return None
    return bool(obj[key])


def _v4_get_string_array(obj: Optional[Dict[str, Any]], key: str) -> List[str]:
    """Mirror TS getStringArray.

    For each item: strings pass through; objects with a 'type' key contribute
    String(item.type); everything else is dropped.
    """
    if not obj or not isinstance(obj.get(key), list):
        return []
    out: List[str] = []
    for item in obj[key]:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and "type" in item:
            out.append(str(item["type"]))
    return out


def _v4_get_object(obj: Optional[Dict[str, Any]], key: str) -> Dict[str, Any]:
    """Mirror TS getObject: {} unless value is a (non-None) object."""
    if not obj or not isinstance(obj.get(key), dict):
        return {}
    return obj[key]


def _v4_get_string_record(obj: Optional[Dict[str, Any]], key: str) -> Dict[str, str]:
    """Mirror TS getStringRecord: stringify each value of a nested object."""
    raw = _v4_get_object(obj, key)
    return {k: str(v) for k, v in raw.items()}


def _v4_parse_services(fm: Dict[str, Any]) -> List[AgirailsMdV4ServiceEntry]:
    """Parse ``services`` (fall back to legacy ``capabilities``) into a uniform
    list of AgirailsMdV4ServiceEntry. Mirrors TS parseServices
    (agirailsmdV4.ts:284-310).
    """
    services = fm.get("services")
    if isinstance(services, list) and len(services) > 0:
        raw = services
    elif isinstance(fm.get("capabilities"), list):
        raw = fm["capabilities"]
    else:
        raw = []

    out: List[AgirailsMdV4ServiceEntry] = []
    for entry in raw:
        if isinstance(entry, str):
            type_ = entry.strip()
            if type_:
                out.append(AgirailsMdV4ServiceEntry(type=type_))
            continue
        if isinstance(entry, dict):
            raw_type = entry.get("type")
            if raw_type is None:
                raw_type = entry.get("service_type")
            type_ = str(raw_type if raw_type is not None else "").strip()
            if not type_:
                continue
            price: Optional[str] = None
            if entry.get("price") is not None:
                price = str(entry["price"])
            min_price: Optional[float] = None
            if entry.get("min_price") is not None:
                try:
                    candidate = float(entry["min_price"])
                    if candidate == candidate and candidate not in (
                        float("inf"),
                        float("-inf"),
                    ):
                        min_price = candidate
                except (TypeError, ValueError):
                    min_price = None
            max_price: Optional[float] = None
            if entry.get("max_price") is not None:
                try:
                    candidate = float(entry["max_price"])
                    if candidate == candidate and candidate not in (
                        float("inf"),
                        float("-inf"),
                    ):
                        max_price = candidate
                except (TypeError, ValueError):
                    max_price = None
            out.append(
                AgirailsMdV4ServiceEntry(
                    type=type_,
                    price=price,
                    min_price=min_price,
                    max_price=max_price,
                )
            )
    return out


def _v4_parse_body(body: str) -> tuple[str, str]:
    """Split markdown body into (description, how_to_request).

    Mirrors TS parseBody (agirailsmdV4.ts:312-330):
      - description = everything before the heading
      - how_to_request = from the heading to next ``## `` or EOF
      - if heading missing, entire body = description
    """
    heading = V4_CONSTRAINTS["HOW_TO_REQUEST_HEADING"]
    idx = body.find(heading)

    if idx == -1:
        return body.strip(), ""

    description = body[:idx].strip()
    after_heading = body[idx + len(heading):]

    # Find next ## heading (mirror TS /\n## /)
    match = re.search(r"\n## ", after_heading)
    if match:
        how_to_request = after_heading[: match.start()].strip()
    else:
        how_to_request = after_heading.strip()

    return description, how_to_request


def parse_agirails_md_v4(content: str) -> AgirailsMdV4Config:
    """Parse a {slug}.md file into a fully typed V4 config with defaults applied.

    Composes on ``parse_agirails_md()`` — never modifies the v1 parser.
    Mirrors TS ``parseAgirailsMdV4`` (agirailsmdV4.ts:138-266).

    Args:
        content: Raw file content.

    Returns:
        Typed V4 config with all defaults applied.

    Raises:
        ValueError: If content has no valid YAML frontmatter or is missing
            required fields (name / services / servicesNeeded / pricing.base).
    """
    parsed = parse_agirails_md(content)
    return _build_v4_config(parsed.frontmatter, parsed.body)


def _build_v4_config(fm: Dict[str, Any], body: str) -> AgirailsMdV4Config:
    """Build a V4 config from parsed frontmatter and body, applying defaults.

    Mirrors TS buildV4Config (agirailsmdV4.ts:147-266).
    """
    # Required: name
    name = _v4_get_string(fm, "name")
    if not name:
        raise ValueError("Missing required field: name")

    # Slug: from YAML or generated from name
    slug = _v4_get_string(fm, "slug") or generate_slug(name)

    # Intent — earn (default), pay, or both.
    intent_raw = (_v4_get_string(fm, "intent") or V4_DEFAULTS["intent"]).lower()
    intent = intent_raw if intent_raw in V4_CONSTRAINTS["VALID_INTENTS"] else V4_DEFAULTS["intent"]

    # Services — accept legacy plain strings and canonical objects.
    services = _v4_parse_services(fm)
    if len(services) == 0 and intent != "pay":
        raise ValueError(
            "Missing required field: services (must be a non-empty array)"
        )

    # Services this agent wants to BUY. Required when intent is pay/both.
    services_needed = _v4_get_string_array(fm, "servicesNeeded")
    if len(services_needed) == 0:
        services_needed = _v4_get_string_array(fm, "services_needed")
    if intent != "earn" and len(services_needed) == 0:
        raise ValueError(
            f"Missing required field: servicesNeeded "
            f"(intent: {intent} requires at least one capability to buy)"
        )

    # Default budget per request — top-level, only meaningful for pay/both.
    budget = _v4_get_number(fm, "budget")

    # Pricing — required for earn/both; pay-only may omit pricing.base.
    pricing_raw = _v4_get_object(fm, "pricing")
    base_raw = _v4_get_number(pricing_raw, "base")
    if base_raw is None and intent != "pay":
        raise ValueError("Missing required field: pricing.base")
    base = base_raw if base_raw is not None else (budget if budget is not None else 0)

    negotiable = _v4_get_boolean(pricing_raw, "negotiable")
    if negotiable is None:
        negotiable = V4_DEFAULTS["pricing"]["negotiable"]
    min_price = _v4_get_number(pricing_raw, "min_price")
    max_price = _v4_get_number(pricing_raw, "max_price")
    pricing = AgirailsMdV4Pricing(
        base=base,
        currency="USDC",
        unit=_v4_get_string(pricing_raw, "unit") or V4_DEFAULTS["pricing"]["unit"],
        negotiable=negotiable,
        min_price=min_price if min_price is not None else base,
        max_price=max_price if max_price is not None else base,
    )

    # Network
    network_raw = _v4_get_string(fm, "network") or V4_DEFAULTS["network"]
    network = (
        network_raw
        if network_raw in V4_CONSTRAINTS["VALID_NETWORKS"]
        else V4_DEFAULTS["network"]
    )

    # SLA
    sla_raw = _v4_get_object(fm, "sla")
    sla_concurrency = _v4_get_number(sla_raw, "concurrency")
    sla = AgirailsMdV4SLA(
        response=_v4_get_string(sla_raw, "response") or V4_DEFAULTS["sla"]["response"],
        delivery=_v4_get_string(sla_raw, "delivery") or V4_DEFAULTS["sla"]["delivery"],
        concurrency=int(sla_concurrency)
        if sla_concurrency is not None
        else V4_DEFAULTS["sla"]["concurrency"],
        dispute_window=_v4_get_string(sla_raw, "dispute_window")
        or V4_DEFAULTS["sla"]["dispute_window"],
    )

    # Covenant
    covenant_raw = _v4_get_object(fm, "covenant")
    covenant = AgirailsMdV4Covenant(
        accepts=_v4_get_string_record(covenant_raw, "accepts"),
        returns=_v4_get_string_record(covenant_raw, "returns"),
    )

    # Payment
    payment_raw = _v4_get_object(fm, "payment")
    modes = _v4_get_string_array(payment_raw, "modes")
    payment = {
        "modes": modes if len(modes) > 0 else list(V4_DEFAULTS["payment"]["modes"])
    }

    # Endpoint (optional)
    endpoint = _v4_get_string(fm, "endpoint") or None

    # Publish metadata (read-only)
    wallet = _v4_get_string(fm, "wallet") or None
    agent_id = _v4_get_string(fm, "agent_id") or None
    did = _v4_get_string(fm, "did") or None

    # Parse markdown body by heading convention
    description, how_to_request = _v4_parse_body(body)

    return AgirailsMdV4Config(
        name=name,
        slug=slug,
        intent=intent,
        services=services,
        services_needed=services_needed,
        budget=budget,
        pricing=pricing,
        network=network,
        sla=sla,
        covenant=covenant,
        payment=payment,
        endpoint=endpoint,
        description=description,
        how_to_request=how_to_request,
        wallet=wallet,
        agent_id=agent_id,
        did=did,
    )


def validate_agirails_md_v4(config: AgirailsMdV4Config) -> ValidationResult:
    """Validate a parsed V4 config for completeness and correctness.

    Mirrors TS ``validateAgirailsMdV4`` (agirailsmdV4.ts:342-408).

    Args:
        config: Parsed V4 config.

    Returns:
        ValidationResult with issues.
    """
    issues: List[ValidationIssue] = []

    # Slug validation
    slug_error = validate_slug(config.slug)
    if slug_error:
        issues.append(
            ValidationIssue(field="slug", message=slug_error, severity="error")
        )

    # Price validation
    if config.pricing.base < 0:
        issues.append(
            ValidationIssue(
                field="pricing.base",
                message="Price cannot be negative",
                severity="error",
            )
        )
    elif config.pricing.base < V4_CONSTRAINTS["MIN_PRICE"]:
        issues.append(
            ValidationIssue(
                field="pricing.base",
                message=f"Price must be >= ${V4_CONSTRAINTS['MIN_PRICE']} USDC",
                severity="error",
            )
        )

    # Negotiable bounds
    if config.pricing.negotiable:
        if config.pricing.min_price > config.pricing.max_price:
            issues.append(
                ValidationIssue(
                    field="pricing.min_price",
                    message="min_price must be <= max_price",
                    severity="error",
                )
            )

    # SLA concurrency
    if config.sla.concurrency < 1:
        issues.append(
            ValidationIssue(
                field="sla.concurrency",
                message="Concurrency must be at least 1",
                severity="error",
            )
        )

    # Empty description warning
    if not config.description:
        issues.append(
            ValidationIssue(
                field="description",
                message="Agent has no description (markdown body is empty)",
                severity="warning",
            )
        )

    # Endpoint required for x402
    if "x402" in config.payment.get("modes", []) and not config.endpoint:
        issues.append(
            ValidationIssue(
                field="endpoint",
                message="endpoint is required when payment modes include x402",
                severity="error",
            )
        )

    valid = all(i.severity != "error" for i in issues)
    return ValidationResult(valid=valid, issues=issues)
