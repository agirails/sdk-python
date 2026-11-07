"""Canonical bytes and EIP-712 hashes checked against independent public APIs."""

import json
import math

import pytest
from eth_account.messages import encode_typed_data

from agirails.utils.canonical_json import canonical_json_dumps, compute_domain_separator, compute_type_hash, hash_struct


@pytest.mark.parametrize("value,expected", [
    (None, "null"), (True, "true"), (False, "false"), (0, "0"), (0.0, "0"), (-0.0, "0"),
    (1.0, "1"), (-1.25, "-1.25"), (1e-6, "0.000001"), (1e-7, "1e-7"),
    (1e20, "100000000000000000000"), (1e21, "1e+21"), (1.2e21, "1.2e+21"),
    (1.2345e-5, "0.000012345"), (-1e-7, "-1e-7"), (5e-324, "5e-324"),
    (float("nan"), "null"), (float("inf"), "null"), (float("-inf"), "null"),
    ("š\n🎉", '"š\\n🎉"'), ([1, None, True], "[1,null,true]"),
    ((2, 3), "[2,3]"), ({"z": 1, "a": {"d": 3, "b": 2}}, '{"a":{"b":2,"d":3},"z":1}'),
])
def test_canonical_bytes_at_ecmascript_number_boundaries(value, expected):
    assert canonical_json_dumps(value) == expected


@pytest.mark.parametrize("value", [{True: 1}, {False: 1}, {None: 1}, {1.5: 1}, {7: 1}])
def test_json_key_coercion_matches_json_data_model(value):
    actual = canonical_json_dumps(value)
    assert json.loads(actual) == json.loads(json.dumps(value))


@pytest.mark.parametrize("settings", [
    {"sort_keys": False}, {"ensure_ascii": True}, {"separators": (", ", ": ")},
])
def test_explicit_legacy_formatting_preserves_the_same_json_values(settings):
    value = {"z": [{"é": 1}, None], "a": True}
    assert json.loads(canonical_json_dumps(value, **settings)) == value


def test_unsupported_values_and_unknown_types_fail_explicitly():
    with pytest.raises(TypeError, match="not JSON serializable"):
        canonical_json_dumps(object())
    with pytest.raises(ValueError, match="not found"):
        compute_type_hash("Absent", {})


@pytest.mark.parametrize("field_type,value", [
    ("string", "hello"), ("bytes", b"\x01\x02"), ("bytes", "0x0102"),
    ("uint256", 2**200), ("int256", -7), ("bool", True),
    ("address", "0x" + "22" * 20), ("bytes32", bytes.fromhex("ab" * 32)),
    ("uint256[]", [1, 2, 3]), ("uint256[]", []),
])
def test_struct_hash_matches_eth_account_eip712_encoding(field_type, value):
    types = {"Item": [{"name": "value", "type": field_type}]}
    data = {"value": value}
    wire = {"domain": {}, "types": types, "primaryType": "Item", "message": data}
    oracle = encode_typed_data(full_message=wire)
    assert hash_struct("Item", data, types) == "0x" + oracle.body.hex()


@pytest.mark.parametrize("field_type,default", [
    ("uint256", 0), ("int64", 0), ("bool", False),
    ("address", "0x" + "00" * 20), ("bytes32", bytes(32)),
    ("string", ""), ("bytes", b""), ("uint256[]", []),
])
def test_absent_primitive_fields_use_documented_zero_defaults(field_type, default):
    types = {"Item": [{"name": "value", "type": field_type}]}
    assert hash_struct("Item", {}, types) == hash_struct("Item", {"value": default}, types)


def test_nested_struct_arrays_and_domain_match_eth_account():
    types = {
        "Item": [{"name": "name", "type": "string"}, {"name": "amount", "type": "uint256"}],
        "Bundle": [{"name": "first", "type": "Item"}, {"name": "others", "type": "Item[]"}],
    }
    data = {"first": {"name": "a", "amount": 1}, "others": [{"name": "b", "amount": 2}]}
    domain = {"name": "ACTP", "version": "1", "chainId": 84532, "verifyingContract": "0x" + "11" * 20}
    oracle = encode_typed_data(full_message={"types": types, "primaryType": "Bundle", "message": data, "domain": domain})
    assert hash_struct("Bundle", data, types) == "0x" + oracle.body.hex()
    assert compute_domain_separator("ACTP", "1", 84532, "0x" + "11" * 20) == "0x" + oracle.header.hex()
