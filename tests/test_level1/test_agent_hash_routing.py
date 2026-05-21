"""Tests for PRD §5.4 hash-based service routing in Agent + Provider.

Closes the post-3.0.0 audit gap (P3.3): ``actp request --service foo``
sets ``service_description = keccak256(toUtf8Bytes("foo"))`` on chain;
without these tests the previous Agent.provide / Provider.register_service
paths would silently miss because both tried to parse the description as
JSON / legacy / plain string and never reversed the keccak.

Note on test shape: ``Agent.__init__`` constructs an ``asyncio.Event``,
which on Python 3.9 needs a running loop. Sync pytest fixtures that
build an Agent break in full-suite runs (no loop in MainThread after
prior async tests have torn down theirs). All Agent-side tests are
therefore marked ``@pytest.mark.asyncio`` so pytest-asyncio guarantees
an event loop for the duration of the test. Provider-side tests have
no such constraint and stay sync.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from eth_hash.auto import keccak

from agirails.level0.provider import Provider
from agirails.level1.agent import Agent, AgentConfig


def _hash(name: str) -> str:
    return "0x" + keccak(name.encode("utf-8")).hex()


def _fake_tx(service_description: str) -> SimpleNamespace:
    return SimpleNamespace(service_description=service_description)


def _build_agent() -> Agent:
    """Build an Agent with two registered services. Must be called from
    inside an async test so asyncio.Event() in __init__ has a loop."""

    async def _h(job):
        return {"ok": True}

    a = Agent(AgentConfig(name="test-agent"))
    a.provide("onboarding", handler=_h)
    a.provide("translate", handler=_h)
    return a


# ============================================================================
# Agent (Level 1)
# ============================================================================


class TestAgentHashRouting:
    @pytest.mark.asyncio
    async def test_keccak_hash_resolves_to_registered_handler(self):
        agent = _build_agent()
        tx = _fake_tx(_hash("onboarding"))
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "onboarding"

    @pytest.mark.asyncio
    async def test_uppercase_hash_normalized_lowercase(self):
        # On-chain logs may surface bytes32 in mixed case; TS lowercases
        # before lookup. Python must do the same.
        agent = _build_agent()
        tx = _fake_tx(_hash("translate").upper().replace("0X", "0x"))
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "translate"

    @pytest.mark.asyncio
    async def test_unknown_hash_returns_none(self):
        agent = _build_agent()
        tx = _fake_tx("0x" + "f" * 64)
        assert agent._find_service_handler(tx) is None

    @pytest.mark.asyncio
    async def test_zero_hash_falls_through_to_string_dispatch(self):
        # ZeroHash means "no routing" (Level 0 `pay` semantics). The
        # primary hash path skips it; the string fallback finds nothing
        # for a non-name string either.
        agent = _build_agent()
        tx = _fake_tx("0x" + "0" * 64)
        assert agent._find_service_handler(tx) is None

    @pytest.mark.asyncio
    async def test_legacy_metadata_still_works_after_hash_branch(self):
        # Legacy ServiceHash.fromLegacy fixtures must keep resolving via
        # the string-dispatch fallback so pre-3.0 MockRuntime tests pass.
        # (Agent's JSON parse path is a Python-side parity gap with TS;
        # tracked separately, out of scope for this fix.)
        agent = _build_agent()
        tx = _fake_tx("service:onboarding;input:{}")
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "onboarding"


# ============================================================================
# Provider (Level 0) — sync, no event loop needed
# ============================================================================


class TestProviderHashRouting:
    @pytest.fixture
    def provider(self):
        async def _h(req, ctx):
            return {"ok": True}

        p = Provider()
        p.register_service("onboarding", _h)
        p.register_service("translate", _h)
        return p

    def test_keccak_hash_resolves_back_to_service_name(self, provider):
        tx = _fake_tx(_hash("onboarding"))
        assert provider._extract_service_name(tx) == "onboarding"

    def test_uppercase_hash_normalized(self, provider):
        tx = _fake_tx(_hash("translate").upper().replace("0X", "0x"))
        assert provider._extract_service_name(tx) == "translate"

    def test_unknown_hash_returns_unknown(self, provider):
        tx = _fake_tx("0x" + "f" * 64)
        # Explicit "unknown" rather than falling through to plain-string,
        # which would have leaked the raw hex hash into job logs.
        assert provider._extract_service_name(tx) == "unknown"

    def test_unregister_drops_hash_entry(self, provider):
        tx = _fake_tx(_hash("translate"))
        assert provider._extract_service_name(tx) == "translate"
        provider.unregister_service("translate")
        # After unregister the reverse-map entry is gone.
        assert provider._extract_service_name(tx) == "unknown"

    def test_json_legacy_path_still_supported(self, provider):
        tx = _fake_tx('{"service":"onboarding","input":{}}')
        assert provider._extract_service_name(tx) == "onboarding"

    def test_empty_service_description(self, provider):
        tx = _fake_tx("")
        assert provider._extract_service_name(tx) == "unknown"
