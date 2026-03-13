"""Tests for AAConfig in networks.py."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agirails.config.networks import (
    AAConfig,
    _resolve_coinbase_rpc_url,
    _resolve_pimlico_rpc_url,
    get_network,
)


class TestAAConfig:
    """Tests for AAConfig population on network configs."""

    def test_base_sepolia_has_aa(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        assert isinstance(net.aa, AAConfig)

    def test_base_mainnet_has_aa(self) -> None:
        net = get_network("base-mainnet")
        assert net.aa is not None
        assert isinstance(net.aa, AAConfig)

    def test_aa_is_frozen_dataclass(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        from dataclasses import is_dataclass
        assert is_dataclass(net.aa)

    def test_aa_has_entry_point(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        assert net.aa.entry_point.startswith("0x")

    def test_aa_has_smart_wallet_factory(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        assert net.aa.smart_wallet_factory.startswith("0x")

    def test_aa_bundler_urls_has_coinbase(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        assert "coinbase" in net.aa.bundler_urls
        assert net.aa.bundler_urls["coinbase"].startswith("https://")

    def test_aa_paymaster_urls_has_coinbase(self) -> None:
        net = get_network("base-sepolia")
        assert net.aa is not None
        assert "coinbase" in net.aa.paymaster_urls
        assert net.aa.paymaster_urls["coinbase"].startswith("https://")


class TestCoinbaseURLResolution:
    """Tests for _resolve_coinbase_rpc_url helper."""

    @patch.dict(os.environ, {"CDP_API_KEY": "test-cdp-key-123"}, clear=False)
    def test_cdp_api_key_override(self) -> None:
        url = _resolve_coinbase_rpc_url("base-sepolia", "CDP_BUNDLER_URL")
        assert "test-cdp-key-123" in url
        assert "api.developer.coinbase.com" in url

    def test_default_fallback_key(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "CDP_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            url = _resolve_coinbase_rpc_url("base-sepolia", "CDP_BUNDLER_URL")
            assert "api.developer.coinbase.com" in url
            # Uses default fallback key
            assert "2txciN85t41erCjveqgNnXYyHRcoo5xP" in url

    @patch.dict(os.environ, {"CDP_BUNDLER_URL": "https://custom-bundler.example.com"}, clear=False)
    def test_explicit_override_url(self) -> None:
        url = _resolve_coinbase_rpc_url("base-sepolia", "CDP_BUNDLER_URL")
        assert url == "https://custom-bundler.example.com"


class TestPimlicoURLResolution:
    """Tests for _resolve_pimlico_rpc_url helper."""

    @patch.dict(os.environ, {"PIMLICO_API_KEY": "test-pimlico-key"}, clear=False)
    def test_pimlico_api_key_resolution(self) -> None:
        url = _resolve_pimlico_rpc_url(84532)
        assert "test-pimlico-key" in url
        assert "api.pimlico.io" in url

    def test_missing_pimlico_returns_empty(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "PIMLICO_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            url = _resolve_pimlico_rpc_url(84532)
            assert url == ""
