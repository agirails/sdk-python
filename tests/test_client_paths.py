"""Coverage-focused tests for ACTPClient validation + helper paths.

Targets `_build_auto_wallet_provider` and `_maybe_register_x402` error
branches — these are critical entry points for `wallet="auto"` and
were undercovered (each error path was a single missing line).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails import ACTPClient, ACTPClientConfig, ValidationError


class TestWalletAutoValidationPaths:
    @pytest.mark.asyncio
    async def test_wallet_auto_requires_testnet_or_mainnet(self):
        """wallet='auto' on mock mode is rejected — no on-chain kernel."""
        with pytest.raises(ValidationError, match='wallet="auto"'):
            await ACTPClient.create(
                mode="mock",
                requester_address="0x" + "1" * 40,
                wallet="auto",
            )

    @pytest.mark.asyncio
    async def test_wallet_auto_requires_private_key(self):
        with pytest.raises(ValidationError, match="private_key"):
            await ACTPClient._build_auto_wallet_provider(
                ACTPClientConfig(
                    mode="testnet",
                    requester_address="0x" + "1" * 40,
                    wallet="auto",
                    private_key=None,
                )
            )

    @pytest.mark.asyncio
    async def test_wallet_auto_unknown_network_aa_config(self):
        """Network with no aa config should error clearly."""
        # Forge a config where network.aa is None.
        config = ACTPClientConfig(
            mode="testnet",
            requester_address="0x" + "1" * 40,
            wallet="auto",
            private_key="0x" + "ab" * 32,
        )
        with patch(
            "agirails.config.networks.get_network"
        ) as get_net:
            net = MagicMock()
            net.aa = None
            get_net.return_value = net
            with pytest.raises(ValidationError, match="aa config"):
                await ACTPClient._build_auto_wallet_provider(config)


class TestX402AutoRegistrationEdges:
    """`_maybe_register_x402` is best-effort; failures must not propagate."""

    @pytest.mark.asyncio
    async def test_unknown_network_logged_not_raised(self):
        """If get_network() raises, the registration is silently skipped."""
        from agirails.client import ACTPClientConfig, ACTPClientInfo
        from agirails.runtime.mock_runtime import MockRuntime

        # Build a client with a wallet that exposes send_transaction.
        bootstrap = await ACTPClient.create(
            mode="mock", requester_address="0x" + "a" * 40,
        )
        rt = bootstrap._runtime
        wallet = MagicMock()
        wallet.send_transaction = MagicMock()

        info = ACTPClientInfo(mode="testnet", address="0x" + "c" * 40)
        client = ACTPClient(rt, "0x" + "c" * 40, info, None, wallet_provider=wallet)

        # Force the helper into a network lookup that fails.
        cfg = ACTPClientConfig(
            mode="testnet",
            requester_address="0x" + "c" * 40,
            rpc_url="https://example.invalid/rpc",
        )
        # get_network is imported lazily inside _maybe_register_x402,
        # so patch at the source module rather than the caller.
        with patch(
            "agirails.config.networks.get_network",
            side_effect=RuntimeError("network broken"),
        ):
            # Must NOT raise — best-effort + log.
            ACTPClient._maybe_register_x402(client, cfg, wallet, "0x" + "c" * 40)
        # x402 was not registered (silent failure).
        assert "x402" not in client._registry.get_ids()


class TestClientFactoryEdges:
    @pytest.mark.asyncio
    async def test_explicit_config_object_takes_precedence(self):
        """Passing config= overrides individual kwargs."""
        cfg = ACTPClientConfig(
            mode="mock",
            requester_address="0x" + "5" * 40,
        )
        client = await ACTPClient.create(config=cfg)
        assert client.get_address() == "0x" + "5" * 40
        assert client.get_mode() == "mock"

    @pytest.mark.asyncio
    async def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError, match="mode"):
            await ACTPClient.create(
                mode="unknown",  # type: ignore[arg-type]
                requester_address="0x" + "1" * 40,
            )
