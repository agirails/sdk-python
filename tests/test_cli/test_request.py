"""Tests for ``actp request`` command + ``run_request`` helper."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.lib.run_request import (
    DeliveryTimeoutError,
    QuoteTimeoutError,
    run_request,
)
from agirails.cli.main import app

runner = CliRunner()


PROVIDER = "0x" + "5" * 40
SERVICE = "onboarding"
REQUESTER = "0x" + "1" * 40


# ============================================================================
# Stubs
# ============================================================================


class _StubTx:
    """Minimal Transaction stand-in returned by stub runtime.get_transaction."""

    def __init__(self, state: str, delivery_proof: Any = None):
        self.state = state
        self.delivery_proof = delivery_proof
        self.escrow_id = None


class _StubRuntime:
    """Drives state transitions on a configurable schedule for tests."""

    def __init__(self, schedule):
        self._schedule = list(schedule)  # list of (elapsed_s, state, proof?)
        self._created_at = time.time()
        self.mint_calls = []

    @property
    def maxTransactionAmount(self):
        return None

    def _state_at(self, t):
        elapsed = t - self._created_at
        current = "INITIATED"
        proof: Any = None
        for entry in self._schedule:
            if len(entry) == 3:
                at, s, p = entry
            else:
                at, s = entry
                p = None
            if elapsed >= at:
                current = s
                proof = p
            else:
                break
        return current, proof

    async def get_transaction(self, tx_id):
        state, proof = self._state_at(time.time())
        return _StubTx(state, proof)

    async def get_balance(self, address):
        return "10000000000"  # plenty

    async def mint_tokens(self, address, amount):
        self.mint_calls.append((address, amount))

    async def create_transaction(self, params):
        return "0x" + "a" * 64

    async def link_escrow(self, *, tx_id, amount):
        return "escrow-" + tx_id

    async def release_escrow(self, *, escrow_id, attestation_uid=""):
        pass


@pytest.fixture
def stub_runtime():
    return _StubRuntime(
        schedule=[
            (0.1, "COMMITTED"),
            (0.3, "IN_PROGRESS"),
            (0.5, "DELIVERED", '{"reflection":"hello"}'),
        ]
    )


# ============================================================================
# run_request helper (unit)
# ============================================================================


class TestRunRequest:
    @pytest.mark.asyncio
    async def test_happy_path_mock(self, stub_runtime):
        """End-to-end mock-mode flow: INITIATED → COMMITTED → DELIVERED → SETTLED."""
        # Patch ACTPClient.create to return a client wired to our stub runtime.
        from agirails.client import ACTPClient

        async def fake_create(**kwargs):
            client = ACTPClient.__new__(ACTPClient)
            client._runtime = stub_runtime
            client._requester_address = REQUESTER
            # Fake adapters that delegate to stub_runtime.
            standard = AsyncMock()
            standard.create_transaction = AsyncMock(return_value="0x" + "a" * 64)
            standard.link_escrow = AsyncMock(return_value="0x" + "a" * 64)
            standard.release_escrow = AsyncMock(return_value=None)
            # ACTPClient exposes `.standard` and `.runtime` as @property
            # backed by `._standard` / `._runtime`; setting the public name
            # is rejected, so wire the backing attributes instead.
            client._standard = standard
            return client

        transitions = []

        with patch(
            "agirails.cli.lib.run_request.ACTPClient.create",
            side_effect=fake_create,
        ):
            # Short polling window for the test runtime to drive transitions.
            with patch(
                "agirails.cli.lib.run_request._POLL_INTERVAL_S", 0.05
            ):
                result = await run_request(
                    provider=PROVIDER,
                    amount="0.05",
                    service=SERVICE,
                    network="mock",
                    quote_timeout_ms=2_000,
                    delivery_timeout_ms=5_000,
                    on_transition=lambda s, tx, t: transitions.append(s),
                )

        assert result.tx_id == "0x" + "a" * 64
        assert result.final_state == "SETTLED"
        assert result.settled is True
        assert result.payload == {"reflection": "hello"}
        # Sequence observed; tolerate first INITIATED emission.
        assert "DELIVERED" in transitions
        assert "SETTLED" in transitions

    @pytest.mark.asyncio
    async def test_quote_timeout(self):
        """State stuck at INITIATED → QuoteTimeoutError."""
        stuck = _StubRuntime(schedule=[])  # never moves off INITIATED

        from agirails.client import ACTPClient

        async def fake_create(**kwargs):
            c = ACTPClient.__new__(ACTPClient)
            c._runtime = stuck
            c._requester_address = REQUESTER
            standard = AsyncMock()
            standard.create_transaction = AsyncMock(return_value="0x" + "b" * 64)
            standard.link_escrow = AsyncMock()
            standard.release_escrow = AsyncMock()
            c._standard = standard
            return c

        with patch(
            "agirails.cli.lib.run_request.ACTPClient.create",
            side_effect=fake_create,
        ), patch(
            "agirails.cli.lib.run_request._POLL_INTERVAL_S", 0.05
        ):
            with pytest.raises(QuoteTimeoutError) as exc:
                await run_request(
                    provider=PROVIDER,
                    amount="0.05",
                    service=SERVICE,
                    network="mock",
                    quote_timeout_ms=200,
                    delivery_timeout_ms=1_000,
                )
        assert exc.value.tx_id == "0x" + "b" * 64
        assert exc.value.timeout_ms == 200

    @pytest.mark.asyncio
    async def test_invalid_provider_address(self):
        with pytest.raises(ValueError, match="Invalid provider"):
            await run_request(
                provider="not-an-address",
                amount="0.05",
                service=SERVICE,
                network="mock",
            )

    @pytest.mark.asyncio
    async def test_empty_service_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            await run_request(
                provider=PROVIDER,
                amount="0.05",
                service="   ",
                network="mock",
            )


# ============================================================================
# CLI surface
# ============================================================================


class TestRequestCli:
    def test_invalid_network_rejected(self):
        result = runner.invoke(
            app,
            [
                "request",
                PROVIDER,
                "0.05",
                "--service",
                SERVICE,
                "--network",
                "ethereum",
            ],
        )
        assert result.exit_code != 0
        assert "Invalid --network" in result.output

    def test_quote_timeout_exits_2(self):
        """PRD §5.6: quote timeout → exit code 2 (provider offline)."""

        async def fake_run_request(**kwargs):
            raise QuoteTimeoutError("0x" + "c" * 64, 500)

        with patch(
            "agirails.cli.commands.request.run_request",
            side_effect=fake_run_request,
        ):
            result = runner.invoke(
                app,
                [
                    "request",
                    PROVIDER,
                    "0.05",
                    "--service",
                    SERVICE,
                    "--network",
                    "mock",
                    "--json",
                ],
            )
        assert result.exit_code == 2
        body = json.loads(result.output)
        assert body["ok"] is False
        assert body["code"] == "QUOTE_TIMEOUT"
        assert body["details"]["timeoutMs"] == 500

    def test_delivery_timeout_exits_1(self):
        async def fake_run_request(**kwargs):
            raise DeliveryTimeoutError("0x" + "d" * 64, 1000, "IN_PROGRESS")

        with patch(
            "agirails.cli.commands.request.run_request",
            side_effect=fake_run_request,
        ):
            result = runner.invoke(
                app,
                [
                    "request",
                    PROVIDER,
                    "0.05",
                    "--service",
                    SERVICE,
                    "--network",
                    "mock",
                    "--json",
                ],
            )
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["code"] == "DELIVERY_TIMEOUT"
        assert body["details"]["lastState"] == "IN_PROGRESS"

    def test_happy_path_json(self):
        from agirails.cli.lib.run_request import RunRequestResult

        async def fake_run_request(**kwargs):
            return RunRequestResult(
                tx_id="0x" + "e" * 64,
                final_state="SETTLED",
                elapsed_ms=1234,
                settled=True,
                payload={"reflection": "ok"},
            )

        with patch(
            "agirails.cli.commands.request.run_request",
            side_effect=fake_run_request,
        ):
            result = runner.invoke(
                app,
                [
                    "request",
                    PROVIDER,
                    "0.05",
                    "--service",
                    SERVICE,
                    "--network",
                    "mock",
                    "--json",
                ],
            )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["ok"] is True
        assert body["txId"] == "0x" + "e" * 64
        assert body["finalState"] == "SETTLED"
        assert body["settled"] is True
        assert body["payload"] == {"reflection": "ok"}

    def test_quiet_mode_emits_only_tx_id(self):
        from agirails.cli.lib.run_request import RunRequestResult

        async def fake_run_request(**kwargs):
            return RunRequestResult(
                tx_id="0x" + "f" * 64,
                final_state="SETTLED",
                elapsed_ms=100,
                settled=True,
            )

        with patch(
            "agirails.cli.commands.request.run_request",
            side_effect=fake_run_request,
        ):
            result = runner.invoke(
                app,
                [
                    "request",
                    PROVIDER,
                    "0.05",
                    "--service",
                    SERVICE,
                    "--network",
                    "mock",
                    "--quiet",
                ],
            )
        assert result.exit_code == 0
        assert result.output.strip() == "0x" + "f" * 64
