"""
Canonical JSON serialization for AGIRAILS SDK.

Provides deterministic JSON serialization for:
- Consistent hashing (same input always produces same hash)
- EIP-712 type hash computation
- Message signing

SECURITY: Key ordering and consistent serialization prevent hash collisions.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple


def canonical_json_dumps(
    obj: Any,
    *,
    sort_keys: bool = True,
    separators: Optional[Tuple[str, str]] = None,
    ensure_ascii: bool = False,
) -> str:
    """
    Serialize object to canonical JSON string, byte-identical to the
    TypeScript SDK's ``canonicalJsonStringify`` (fast-json-stable-stringify).

    PARITY CRITICAL: cross-SDK keccak hashes (delivery-proof resultHash,
    quote computeHash, justificationHash) depend on this being byte-for-byte
    identical to JavaScript ``JSON.stringify`` over canonically-sorted keys.

    Two JS behaviours that Python's ``json.dumps`` gets wrong and which this
    function reproduces:

    - **Numbers** follow the ECMAScript Number-to-String algorithm, so an
      integer-valued float renders without a fractional part (``1.0`` -> ``1``),
      negative zero collapses (``-0.0`` -> ``0``), and the positional vs.
      exponential boundary matches V8 (``1e16`` -> ``10000000000000000``,
      ``1e-7`` -> ``1e-7``). Non-finite floats become ``null`` like
      ``JSON.stringify``.
    - **Keys** are sorted and the output carries no whitespace.

    Args:
        obj: Object to serialize
        sort_keys: Sort dictionary keys (default: True — canonical mode)
        separators: Custom separators (default: (",", ":"))
        ensure_ascii: Escape non-ASCII characters (default: False for JS parity)

    Returns:
        Canonical JSON string

    Example:
        >>> canonical_json_dumps({"b": 2, "a": 1})
        '{"a":1,"b":2}'
        >>> canonical_json_dumps({"amount": 1.0})  # integer-valued float
        '{"amount":1}'
        >>> canonical_json_dumps({"emoji": "🎉"})  # Unicode preserved
        '{"emoji":"🎉"}'
    """
    # Canonical mode (the only mode any caller uses) goes through the
    # ECMAScript-faithful encoder. The legacy json.dumps path is retained
    # only for explicit non-canonical overrides.
    if sort_keys and ensure_ascii is False and separators in (None, (",", ":")):
        return _canonical_encode(obj)

    if separators is None:
        separators = (",", ":")
    return json.dumps(
        _deep_sort(obj) if sort_keys else obj,
        separators=separators,
        ensure_ascii=ensure_ascii,
        sort_keys=sort_keys,
    )


def _js_number_to_string(x: float) -> Optional[str]:
    """
    Format a Python float exactly like ECMAScript ``Number::toString`` /
    ``JSON.stringify`` (ECMA-262 §6.1.6.1.20).

    Returns ``None`` for non-finite values (``JSON.stringify`` renders NaN and
    Infinity as ``null``).
    """
    if x != x or x in (float("inf"), float("-inf")):
        return None
    if x == 0:
        return "0"  # also collapses -0.0
    sign = "-" if x < 0 else ""
    x = -x if x < 0 else x

    # repr() gives the shortest round-tripping decimal (same digit choice class
    # as V8); re-parse it into ECMA's (digits, n) form.
    r = repr(x)
    if "e" in r or "E" in r:
        mant, _, exp_s = r.replace("E", "e").partition("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    if "." in mant:
        int_part, frac_part = mant.split(".")
    else:
        int_part, frac_part = mant, ""

    digits = int_part + frac_part  # value = int(digits) * 10**point_exp
    point_exp = exp - len(frac_part)
    digits = digits.lstrip("0") or "0"
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        point_exp += 1

    k = len(digits)
    n = point_exp + k  # ECMA: value == digits × 10**(n − k)

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exp_str = ("e+" if e >= 0 else "e-") + str(abs(e))
        body = (digits if k == 1 else digits[0] + "." + digits[1:]) + exp_str

    return sign + body


def _canonical_encode(obj: Any) -> str:
    """
    Serialize to canonical JSON byte-identical to JS fast-json-stable-stringify:
    sorted object keys, no whitespace, ECMAScript number formatting, and
    JSON.stringify-equivalent string escaping (ensure_ascii=False).
    """
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, bool):  # defensive; covered above
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        s = _js_number_to_string(obj)
        return "null" if s is None else s
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canonical_encode(v) for v in obj) + "]"
    if isinstance(obj, dict):
        parts = []
        for key, value in sorted(obj.items(), key=lambda kv: str(kv[0])):
            key_str = key if isinstance(key, str) else _coerce_json_key(key)
            parts.append(json.dumps(key_str, ensure_ascii=False) + ":" + _canonical_encode(value))
        return "{" + ",".join(parts) + "}"
    # Match json.dumps for the remaining JSON-able scalars, else raise like it.
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _coerce_json_key(key: Any) -> str:
    """Coerce a non-string dict key to its JSON string form (JS JSON.stringify
    coerces object keys to strings: numbers, booleans, null)."""
    if key is True:
        return "true"
    if key is False:
        return "false"
    if key is None:
        return "null"
    if isinstance(key, float):
        s = _js_number_to_string(key)
        return "null" if s is None else s
    if isinstance(key, int):
        return str(key)
    return str(key)


def _deep_sort(obj: Any) -> Any:
    """
    Recursively sort dictionary keys (legacy helper for the non-canonical path).
    """
    if isinstance(obj, dict):
        return {k: _deep_sort(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_deep_sort(item) for item in obj]
    return obj


def compute_type_hash(primary_type: str, types: Dict[str, List[Dict[str, str]]]) -> str:
    """
    Compute EIP-712 type hash.

    Used for structured data hashing in EIP-712 signatures.

    Args:
        primary_type: The primary type name (e.g., "Quote", "DeliveryProof")
        types: Type definitions dictionary

    Returns:
        Keccak256 hash of the type string (0x-prefixed)

    Example:
        >>> types = {
        ...     "Quote": [
        ...         {"name": "txId", "type": "bytes32"},
        ...         {"name": "amount", "type": "uint256"},
        ...     ]
        ... }
        >>> compute_type_hash("Quote", types)
        '0x...'
    """
    type_string = _encode_type(primary_type, types)
    return _keccak256_hex(type_string)


def _encode_type(primary_type: str, types: Dict[str, List[Dict[str, str]]]) -> str:
    """
    Encode EIP-712 type to string format.

    Format: "TypeName(type1 name1,type2 name2,...)"
    Dependent types are included alphabetically.

    Args:
        primary_type: The primary type name
        types: Type definitions

    Returns:
        Encoded type string
    """
    # Get the primary type definition
    if primary_type not in types:
        raise ValueError(f"Type '{primary_type}' not found in types")

    # Find all dependent types
    deps = _find_dependencies(primary_type, types, set())

    # Sort dependencies alphabetically (excluding primary type)
    sorted_deps = sorted(deps - {primary_type})

    # Build type string: primary first, then alphabetically sorted deps
    result_types = [primary_type] + sorted_deps

    encoded_parts = []
    for type_name in result_types:
        type_def = types[type_name]
        params = ",".join(f"{field['type']} {field['name']}" for field in type_def)
        encoded_parts.append(f"{type_name}({params})")

    return "".join(encoded_parts)


def _find_dependencies(
    type_name: str,
    types: Dict[str, List[Dict[str, str]]],
    found: Set[str],
) -> Set[str]:
    """
    Recursively find all dependent types.

    Args:
        type_name: Type to find dependencies for
        types: Type definitions
        found: Already found types (to prevent cycles)

    Returns:
        Set of all dependent type names
    """
    if type_name not in types or type_name in found:
        return found

    found.add(type_name)

    for field in types[type_name]:
        field_type = field["type"]
        # Strip array notation
        field_type = field_type.replace("[]", "")

        # Check if it's a custom type (not a primitive)
        if field_type in types:
            _find_dependencies(field_type, types, found)

    return found


def _keccak256_hex(data: str) -> str:
    """
    Compute keccak256 hash of string.

    Args:
        data: String to hash (UTF-8 encoded)

    Returns:
        0x-prefixed hex hash
    """
    from eth_hash.auto import keccak

    hash_bytes = keccak(data.encode("utf-8"))
    return "0x" + hash_bytes.hex()


def hash_struct(
    type_name: str,
    data: Dict[str, Any],
    types: Dict[str, List[Dict[str, str]]],
) -> str:
    """
    Compute EIP-712 struct hash.

    Args:
        type_name: The struct type name
        data: The struct data
        types: Type definitions

    Returns:
        Keccak256 hash of the encoded struct
    """
    type_hash = compute_type_hash(type_name, types)
    encoded = _encode_data(type_name, data, types)

    from eth_abi import encode
    from eth_hash.auto import keccak

    # Combine type hash with encoded data
    full_encoded = bytes.fromhex(type_hash[2:]) + encoded
    return "0x" + keccak(full_encoded).hex()


def _encode_data(
    type_name: str,
    data: Dict[str, Any],
    types: Dict[str, List[Dict[str, str]]],
) -> bytes:
    """
    Encode struct data according to EIP-712.

    Args:
        type_name: The struct type name
        data: The struct data
        types: Type definitions

    Returns:
        ABI-encoded bytes
    """
    from eth_abi import encode
    from eth_hash.auto import keccak

    type_def = types[type_name]

    abi_types = []
    values = []

    for field in type_def:
        field_name = field["name"]
        field_type = field["type"]
        value = data.get(field_name)

        if field_type == "string":
            # Hash strings
            if value is None:
                value = ""
            hash_bytes = keccak(value.encode("utf-8"))
            abi_types.append("bytes32")
            values.append(hash_bytes)
        elif field_type == "bytes":
            # Hash bytes
            if isinstance(value, str):
                value = bytes.fromhex(value[2:] if value.startswith("0x") else value)
            hash_bytes = keccak(value or b"")
            abi_types.append("bytes32")
            values.append(hash_bytes)
        elif field_type in types:
            # Nested struct - hash recursively
            struct_hash = hash_struct(field_type, value or {}, types)
            abi_types.append("bytes32")
            values.append(bytes.fromhex(struct_hash[2:]))
        elif field_type.endswith("[]"):
            # Arrays - hash each element
            base_type = field_type[:-2]
            array_values = value or []
            if base_type in types:
                # Array of structs
                hashes = [bytes.fromhex(hash_struct(base_type, v, types)[2:]) for v in array_values]
                combined = b"".join(hashes)
                array_hash = keccak(combined)
            else:
                # Array of primitives
                encoded = encode([base_type] * len(array_values), array_values)
                array_hash = keccak(encoded)
            abi_types.append("bytes32")
            values.append(array_hash)
        else:
            # Primitive type
            abi_types.append(field_type)
            if value is None:
                if field_type.startswith("uint") or field_type.startswith("int"):
                    value = 0
                elif field_type == "bool":
                    value = False
                elif field_type == "address":
                    value = "0x" + "0" * 40
                elif field_type.startswith("bytes"):
                    value = b"\x00" * int(field_type[5:])
            values.append(value)

    return encode(abi_types, values)


def compute_domain_separator(
    name: str,
    version: str,
    chain_id: int,
    verifying_contract: str,
) -> str:
    """
    Compute EIP-712 domain separator.

    Args:
        name: Domain name
        version: Domain version
        chain_id: Chain ID
        verifying_contract: Contract address

    Returns:
        Keccak256 hash of the domain
    """
    domain_types = {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ]
    }

    domain_data = {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }

    return hash_struct("EIP712Domain", domain_data, domain_types)
