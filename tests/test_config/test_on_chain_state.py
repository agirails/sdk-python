"""Tests for on_chain_state.py models and scenario detection."""

from __future__ import annotations

import pytest

from agirails.config.on_chain_state import (
    ZERO_HASH,
    OnChainAgentState,
    OnChainConfigState,
)
from agirails.config.pending_publish import PendingPublishData
from agirails.cli.commands.publish import detect_lazy_publish_scenario


class TestOnChainConfigState:
    """Tests for OnChainConfigState dataclass."""

    def test_has_config_true(self) -> None:
        state = OnChainConfigState(config_hash="0x" + "ab" * 32, config_cid="bafytest")
        assert state.has_config is True

    def test_has_config_false_zero_hash(self) -> None:
        state = OnChainConfigState(config_hash=ZERO_HASH, config_cid="")
        assert state.has_config is False

    def test_has_config_false_empty(self) -> None:
        state = OnChainConfigState(config_hash="", config_cid="")
        assert state.has_config is False


class TestOnChainAgentState:
    """Tests for OnChainAgentState dataclass."""

    def test_is_registered_true(self) -> None:
        state = OnChainAgentState(
            registered_at=1700000000,
            config_hash="0x" + "ab" * 32,
            listed=True,
        )
        assert state.is_registered is True

    def test_is_registered_false_zero(self) -> None:
        state = OnChainAgentState(
            registered_at=0,
            config_hash=ZERO_HASH,
            listed=False,
        )
        assert state.is_registered is False

    def test_config_cid_default(self) -> None:
        state = OnChainAgentState(
            registered_at=100,
            config_hash="0xabc",
            listed=True,
        )
        assert state.config_cid == ""


# ============================================================================
# Scenario Detection
# ============================================================================


def _make_pending(config_hash: str = "0x" + "aa" * 32) -> PendingPublishData:
    return PendingPublishData(
        version=1,
        config_hash=config_hash,
        cid="bafytestcid",
        endpoint="https://agent.example.com",
        service_descriptors=[],
        created_at="2026-01-01T00:00:00Z",
        network="base-sepolia",
    )


class TestDetectLazyPublishScenario:
    """Tests for all 5 lazy publish scenarios."""

    def test_scenario_none_no_pending(self) -> None:
        on_chain = OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
        assert detect_lazy_publish_scenario(on_chain, None) == "none"

    def test_scenario_a_not_registered(self) -> None:
        on_chain = OnChainAgentState(registered_at=0, config_hash=ZERO_HASH, listed=False)
        pending = _make_pending()
        assert detect_lazy_publish_scenario(on_chain, pending) == "A"

    def test_scenario_b1_registered_hash_differs_not_listed(self) -> None:
        on_chain = OnChainAgentState(
            registered_at=1700000000,
            config_hash="0x" + "bb" * 32,
            listed=False,
        )
        pending = _make_pending("0x" + "aa" * 32)
        assert detect_lazy_publish_scenario(on_chain, pending) == "B1"

    def test_scenario_b2_registered_hash_differs_listed(self) -> None:
        on_chain = OnChainAgentState(
            registered_at=1700000000,
            config_hash="0x" + "bb" * 32,
            listed=True,
        )
        pending = _make_pending("0x" + "aa" * 32)
        assert detect_lazy_publish_scenario(on_chain, pending) == "B2"

    def test_scenario_c_hash_matches(self) -> None:
        same_hash = "0x" + "cc" * 32
        on_chain = OnChainAgentState(
            registered_at=1700000000,
            config_hash=same_hash,
            listed=True,
        )
        pending = _make_pending(same_hash)
        assert detect_lazy_publish_scenario(on_chain, pending) == "C"
