"""Tests for using_public_rpc (mirror TS config/networks.ts:31-36)."""

from __future__ import annotations

import pytest

from agirails.config.networks import using_public_rpc


@pytest.fixture(autouse=True)
def clear_rpc_env(monkeypatch):
    monkeypatch.delenv("BASE_SEPOLIA_RPC", raising=False)
    monkeypatch.delenv("BASE_MAINNET_RPC", raising=False)


class TestUsingPublicRpc:
    def test_mock_never_public(self) -> None:
        assert using_public_rpc("mock") is False

    def test_mock_substring(self) -> None:
        assert using_public_rpc("base-mock") is False

    def test_testnet_default_is_public(self) -> None:
        assert using_public_rpc("base-sepolia") is True

    def test_mainnet_default_is_public(self) -> None:
        assert using_public_rpc("base-mainnet") is True

    def test_unknown_network_treated_as_testnet(self) -> None:
        # n.includes('mainnet') false -> falls to the testnet branch
        assert using_public_rpc("something-else") is True

    def test_sepolia_override_suppresses(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_SEPOLIA_RPC", "https://my.rpc")
        assert using_public_rpc("base-sepolia") is False

    def test_mainnet_override_suppresses(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_MAINNET_RPC", "https://my.rpc")
        assert using_public_rpc("base-mainnet") is False

    def test_sepolia_override_does_not_affect_mainnet(self, monkeypatch) -> None:
        monkeypatch.setenv("BASE_SEPOLIA_RPC", "https://my.rpc")
        # mainnet still public (no mainnet override)
        assert using_public_rpc("base-mainnet") is True
