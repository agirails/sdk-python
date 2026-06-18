"""
Parity tests for the AgentRegistry v2 ABI + AgentProfile decoding.

These tests pin the Python AgentRegistry wrapper to the TypeScript SDK
source of truth (sdk-js/src/abi/AgentRegistry.json + AgentRegistryClient.ts).
They prove:

1. The bundled abis/agent_registry.json contains the AgentRegistry v2 surface:
   setListed, publishConfig, MAX_CID_LENGTH, ConfigPublished, ListingChanged,
   and the 15-field getAgent struct / 14-field agents() struct including
   configHash, configCID, listed.
2. AgentProfile decodes the extended 15-field struct (and stays backward
   compatible with the legacy 12-field tuple).
3. The new contract functions encode to the canonical Solidity 4-byte
   selectors (so web3.py will not raise ABIFunctionNotFound at call time).
"""

from __future__ import annotations

import json
import os

import pytest

from agirails.protocol.agent_registry import (
    AgentProfile,
    _load_agent_registry_abi,
    compute_service_type_hash,
)

# ---------------------------------------------------------------------------
# ABI source-of-truth values (from sdk-js/src/abi/AgentRegistry.json) and
# canonical Solidity 4-byte selectors keccak256(signature)[:4].
# ---------------------------------------------------------------------------

# getAgent struct components in exact ABI order (15 fields).
GET_AGENT_FIELDS = [
    "agentAddress",
    "did",
    "endpoint",
    "serviceTypes",
    "stakedAmount",
    "reputationScore",
    "totalTransactions",
    "disputedTransactions",
    "totalVolumeUSDC",
    "registeredAt",
    "updatedAt",
    "isActive",
    "configHash",
    "configCID",
    "listed",
]

# agents(address) flattened storage struct (14 fields, no serviceTypes).
AGENTS_FIELDS = [
    "agentAddress",
    "did",
    "endpoint",
    "stakedAmount",
    "reputationScore",
    "totalTransactions",
    "disputedTransactions",
    "totalVolumeUSDC",
    "registeredAt",
    "updatedAt",
    "isActive",
    "configHash",
    "configCID",
    "listed",
]

# Canonical Solidity selectors (verified against keccak256 of the signature).
EXPECTED_SELECTORS = {
    "setListed": "0xab76c8fd",  # setListed(bool)
    "publishConfig": "0x44523043",  # publishConfig(string,bytes32)
    "MAX_CID_LENGTH": "0xa82da60d",  # MAX_CID_LENGTH()
}

ZERO_HASH = "0x" + "0" * 64


def _bundled_abi():
    """Load the on-disk abis/agent_registry.json directly (not the fallback)."""
    abi_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "src",
        "agirails",
        "abis",
        "agent_registry.json",
    )
    with open(abi_path, "r") as f:
        return json.load(f)


def _entry(abi, type_, name):
    for e in abi:
        if e.get("type") == type_ and e.get("name") == name:
            return e
    return None


# ---------------------------------------------------------------------------
# Bundled ABI parity
# ---------------------------------------------------------------------------


class TestBundledABIParity:
    def test_bundled_abi_has_v2_functions(self):
        abi = _bundled_abi()
        fns = {e["name"] for e in abi if e.get("type") == "function"}
        for name in ("setListed", "publishConfig", "MAX_CID_LENGTH"):
            assert name in fns, f"bundled ABI missing function {name}"

    def test_bundled_abi_has_v2_events(self):
        abi = _bundled_abi()
        evs = {e["name"] for e in abi if e.get("type") == "event"}
        for name in ("ConfigPublished", "ListingChanged"):
            assert name in evs, f"bundled ABI missing event {name}"

    def test_set_listed_signature_matches_ts(self):
        abi = _bundled_abi()
        entry = _entry(abi, "function", "setListed")
        assert entry is not None
        assert [i["type"] for i in entry["inputs"]] == ["bool"]
        assert entry["inputs"][0]["name"] == "_listed"
        assert entry["stateMutability"] == "nonpayable"

    def test_publish_config_signature_matches_ts(self):
        abi = _bundled_abi()
        entry = _entry(abi, "function", "publishConfig")
        assert entry is not None
        assert [i["type"] for i in entry["inputs"]] == ["string", "bytes32"]
        assert [i["name"] for i in entry["inputs"]] == ["cid", "hash"]
        assert entry["stateMutability"] == "nonpayable"

    def test_config_published_event_matches_ts(self):
        abi = _bundled_abi()
        ev = _entry(abi, "event", "ConfigPublished")
        assert ev is not None
        names = [i["name"] for i in ev["inputs"]]
        types = [i["type"] for i in ev["inputs"]]
        assert names == ["agent", "configCID", "configHash"]
        assert types == ["address", "string", "bytes32"]
        assert ev["inputs"][0]["indexed"] is True

    def test_listing_changed_event_matches_ts(self):
        abi = _bundled_abi()
        ev = _entry(abi, "event", "ListingChanged")
        assert ev is not None
        names = [i["name"] for i in ev["inputs"]]
        types = [i["type"] for i in ev["inputs"]]
        assert names == ["agent", "listed"]
        assert types == ["address", "bool"]
        assert ev["inputs"][0]["indexed"] is True

    def test_get_agent_struct_is_15_fields(self):
        abi = _bundled_abi()
        entry = _entry(abi, "function", "getAgent")
        comps = entry["outputs"][0]["components"]
        assert [c["name"] for c in comps] == GET_AGENT_FIELDS
        # config fields present with correct types
        by_name = {c["name"]: c["type"] for c in comps}
        assert by_name["configHash"] == "bytes32"
        assert by_name["configCID"] == "string"
        assert by_name["listed"] == "bool"

    def test_get_agent_by_did_struct_is_15_fields(self):
        abi = _bundled_abi()
        entry = _entry(abi, "function", "getAgentByDID")
        comps = entry["outputs"][0]["components"]
        assert [c["name"] for c in comps] == GET_AGENT_FIELDS

    def test_agents_struct_is_14_fields_with_config(self):
        abi = _bundled_abi()
        entry = _entry(abi, "function", "agents")
        outs = entry["outputs"]
        assert [o["name"] for o in outs] == AGENTS_FIELDS
        by_name = {o["name"]: o["type"] for o in outs}
        assert by_name["configHash"] == "bytes32"
        assert by_name["configCID"] == "string"
        assert by_name["listed"] == "bool"

    def test_bundled_abi_is_byte_identical_to_ts_source(self):
        """The bundled ABI must be a verbatim copy of the TS source of truth."""
        ts_path = (
            "/Users/damir/Arha/AGIRAILS/SDK and Runtime/"
            "sdk-js/src/abi/AgentRegistry.json"
        )
        if not os.path.exists(ts_path):
            pytest.skip("TS source ABI not available in this environment")
        with open(ts_path, "r") as f:
            ts_abi = json.load(f)
        assert _bundled_abi() == ts_abi


# ---------------------------------------------------------------------------
# Fallback ABI parity (used when the file is missing)
# ---------------------------------------------------------------------------


class TestFallbackABIParity:
    def test_fallback_loader_returns_v2_surface(self):
        abi = _load_agent_registry_abi()
        fns = {e["name"] for e in abi if e.get("type") == "function"}
        for name in ("setListed", "publishConfig", "MAX_CID_LENGTH"):
            assert name in fns


# ---------------------------------------------------------------------------
# Selector parity (web3 must be able to encode these calls)
# ---------------------------------------------------------------------------


class TestSelectorParity:
    @pytest.mark.parametrize("name,selector", EXPECTED_SELECTORS.items())
    def test_canonical_selectors(self, name, selector):
        pytest.importorskip("web3")
        from web3 import Web3

        w3 = Web3()
        contract = w3.eth.contract(
            address="0x" + "00" * 20, abi=_bundled_abi()
        )
        args = {
            "setListed": (True,),
            "publishConfig": ("bafyCID", b"\x11" * 32),
            "MAX_CID_LENGTH": (),
        }[name]
        fn = getattr(contract.functions, name)(*args)
        data = fn._encode_transaction_data()
        assert data[:10] == selector


# ---------------------------------------------------------------------------
# AgentProfile decode parity
# ---------------------------------------------------------------------------


class TestAgentProfileDecode:
    def test_decode_15_field_struct(self):
        tuple_data = (
            "0x" + "ab" * 20,  # agentAddress
            "did:agi:base:0xab",  # did
            "https://agent.example.com",  # endpoint
            [b"\x11" * 32],  # serviceTypes
            5,  # stakedAmount
            8500,  # reputationScore
            10,  # totalTransactions
            1,  # disputedTransactions
            1_000_000,  # totalVolumeUSDC
            100,  # registeredAt
            200,  # updatedAt
            True,  # isActive
            b"\x22" * 32,  # configHash
            "bafyConfigCID",  # configCID
            True,  # listed
        )
        p = AgentProfile.from_tuple(tuple_data)
        assert p.config_hash == "0x" + "22" * 32
        assert p.config_cid == "bafyConfigCID"
        assert p.listed is True
        assert p.is_active is True
        assert p.reputation_score == 8500
        # config fields surface through to_dict (TS getConfig read path)
        d = p.to_dict()
        assert d["configHash"] == "0x" + "22" * 32
        assert d["configCID"] == "bafyConfigCID"
        assert d["listed"] is True

    def test_decode_unpublished_config_zero_hash(self):
        tuple_data = (
            "0x" + "ab" * 20,
            "did:agi:base:0xab",
            "https://agent.example.com",
            [],
            0,
            0,
            0,
            0,
            0,
            100,
            200,
            True,
            b"\x00" * 32,  # configHash = zero -> not published
            "",  # configCID empty
            False,  # not listed
        )
        p = AgentProfile.from_tuple(tuple_data)
        assert p.config_hash == ZERO_HASH
        assert p.config_cid == ""
        assert p.listed is False

    def test_decode_legacy_12_field_tuple_backward_compat(self):
        legacy = (
            "0x" + "cd" * 20,
            "did:agi:base:0xcd",
            "https://legacy.example.com",
            [],
            0,
            7000,
            3,
            0,
            500_000,
            10,
            20,
            True,
        )
        p = AgentProfile.from_tuple(legacy)
        # config fields fall back to safe defaults
        assert p.config_hash == ZERO_HASH
        assert p.config_cid == ""
        assert p.listed is False
        assert p.reputation_score == 7000

    def test_default_profile_config_fields(self):
        p = AgentProfile(address="0x" + "ee" * 20)
        assert p.config_hash == ZERO_HASH
        assert p.config_cid == ""
        assert p.listed is False


# ---------------------------------------------------------------------------
# Service routing key parity (shared routing rule): the on-chain serviceHash
# is keccak256(utf8(serviceType STRING)) — a 32-byte hash, not a JSON blob.
# ---------------------------------------------------------------------------


class TestServiceTypeHashParity:
    def test_service_type_hash_is_keccak_of_string(self):
        pytest.importorskip("eth_utils")
        from eth_utils import keccak

        for service in ("echo", "translation", "image-gen"):
            expected = "0x" + keccak(text=service).hex()
            assert compute_service_type_hash(service) == expected
            # 32-byte hash (0x + 64 hex chars)
            assert len(compute_service_type_hash(service)) == 66
