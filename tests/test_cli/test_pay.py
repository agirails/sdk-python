"""Tests for ``actp pay`` parity surface (TS ``src/cli/commands/pay.ts``).

Covers:
  * ``--service`` rejection (canonical message + exit 64 EX_USAGE)
  * ``--dispute-window`` flag (-w, default 172800) threaded into params
  * agirails.app/a/<slug> URL resolution via discover_agents
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.commands.pay import (
    EX_USAGE,
    PAY_SERVICE_REJECTION_MESSAGE,
    _SLUG_URL_RE,
)
from agirails.cli.main import app

runner = CliRunner()

WALLET = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
EOA = "0x" + "5" * 40


# ============================================================================
# Stubs
# ============================================================================


@dataclass
class _StubAgent:
    slug: str
    wallet_address: str


@dataclass
class _StubDiscoverResult:
    agents: list
    total: int = 0


class _StubPayResult:
    def __init__(self) -> None:
        self.tx_id = "0xabc"
        self.escrow_id = "0xdef"
        self.state = "COMMITTED"
        self.amount = "5000000"
        self.deadline = 9999999999


class _StubClient:
    def __init__(self) -> None:
        self.pay_calls = []

    async def pay(self, params):
        self.pay_calls.append(params)
        return _StubPayResult()


# ============================================================================
# --service rejection (PRD §5.9)
# ============================================================================


class TestServiceRejection:
    def test_canonical_message_constant(self) -> None:
        assert "Level 0 primitive" in PAY_SERVICE_REJECTION_MESSAGE
        assert "actp request <provider> <amount> --service <name>" in PAY_SERVICE_REJECTION_MESSAGE

    def test_message_is_byte_identical_to_ts(self) -> None:
        # Mirrors TS src/cli/commands/pay.ts:69-73 verbatim.
        expected = (
            "Error: 'actp pay' is a Level 0 primitive and does not accept --service.\n"
            "For negotiated Level 1 job flow (where a provider's handler runs after quote/accept),\n"
            "use 'actp request <provider> <amount> --service <name>' instead.\n"
            "See https://agirails.io/docs/sdk/level-0-vs-level-1"
        )
        assert PAY_SERVICE_REJECTION_MESSAGE == expected

    def test_ex_usage_is_64(self) -> None:
        assert EX_USAGE == 64

    def test_service_flag_exits_64(self) -> None:
        result = runner.invoke(
            app, ["pay", EOA, "5", "--service", "onboarding"]
        )
        assert result.exit_code == EX_USAGE
        assert "Level 0 primitive" in result.stdout

    def test_service_flag_json_mode_includes_directive(self) -> None:
        result = runner.invoke(
            app, ["--json", "pay", EOA, "5", "--service", "x"]
        )
        assert result.exit_code == EX_USAGE
        payload = json.loads(result.stdout)
        assert payload["error"]["code"] == "PAY_SERVICE_REJECTED"
        assert "Level 0 primitive" in payload["error"]["message"]
        assert (
            payload["error"]["details"]["use"]
            == "actp request <provider> <amount> --service <name>"
        )


# ============================================================================
# slug regex
# ============================================================================


class TestSlugRegex:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("agirails.app/a/arha", "arha"),
            ("https://agirails.app/a/arha", "arha"),
            ("https://www.agirails.app/a/Arha", "Arha"),
            ("http://agirails.app/a/arha-dev", "arha-dev"),
            ("agirails.app/a/test_1", "test_1"),
        ],
    )
    def test_matches_slug_urls(self, url: str, expected: str) -> None:
        m = _SLUG_URL_RE.match(url)
        assert m is not None
        assert m.group(1) == expected

    @pytest.mark.parametrize(
        "value",
        [
            WALLET,
            "0x" + "1" * 40,
            "https://example.com/a/arha",
            "agirails.app/x/arha",
        ],
    )
    def test_does_not_match_non_slug(self, value: str) -> None:
        assert _SLUG_URL_RE.match(value) is None


# ============================================================================
# --dispute-window threading + slug resolution (end-to-end via CliRunner)
# ============================================================================


def _patch_pay_dependencies(client: _StubClient):
    """Patch get_client + ensure_initialized used by pay()."""
    return (
        patch(
            "agirails.cli.commands.pay.get_client",
            new=AsyncMock(return_value=client),
        ),
        patch(
            "agirails.cli.commands.pay.ensure_initialized",
            return_value=True,
        ),
    )


class TestDisputeWindow:
    def test_default_dispute_window_threaded(self) -> None:
        client = _StubClient()
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2:
            result = runner.invoke(app, ["--quiet", "pay", EOA, "5"])
        assert result.exit_code == 0, result.stdout
        assert len(client.pay_calls) == 1
        params = client.pay_calls[0]
        assert getattr(params, "dispute_window", None) == 172800

    def test_custom_dispute_window_threaded(self) -> None:
        client = _StubClient()
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2:
            result = runner.invoke(
                app, ["--quiet", "pay", EOA, "5", "-w", "3600"]
            )
        assert result.exit_code == 0, result.stdout
        params = client.pay_calls[0]
        assert getattr(params, "dispute_window", None) == 3600


class TestSlugResolution:
    def test_resolves_slug_to_wallet(self) -> None:
        client = _StubClient()
        discover = AsyncMock(
            return_value=_StubDiscoverResult(
                agents=[_StubAgent(slug="arha", wallet_address=WALLET)],
                total=1,
            )
        )
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2, patch(
            "agirails.api.discover.discover_agents", new=discover
        ):
            result = runner.invoke(
                app, ["--quiet", "pay", "agirails.app/a/arha", "5"]
            )
        assert result.exit_code == 0, result.stdout
        # Provider passed to client.pay should be the resolved wallet, not slug.
        assert client.pay_calls[0].to == WALLET

    def test_picks_exact_slug_among_fuzzy(self) -> None:
        client = _StubClient()
        discover = AsyncMock(
            return_value=_StubDiscoverResult(
                agents=[
                    _StubAgent(slug="arha-dev", wallet_address="0x" + "9" * 40),
                    _StubAgent(slug="arha", wallet_address=WALLET),
                ],
                total=2,
            )
        )
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2, patch(
            "agirails.api.discover.discover_agents", new=discover
        ):
            result = runner.invoke(
                app, ["--quiet", "pay", "agirails.app/a/arha", "5"]
            )
        assert result.exit_code == 0, result.stdout
        assert client.pay_calls[0].to == WALLET

    def test_exits_when_slug_not_found(self) -> None:
        client = _StubClient()
        discover = AsyncMock(
            return_value=_StubDiscoverResult(agents=[], total=0)
        )
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2, patch(
            "agirails.api.discover.discover_agents", new=discover
        ):
            result = runner.invoke(
                app, ["pay", "agirails.app/a/nope", "5"]
            )
        assert result.exit_code == 1
        assert len(client.pay_calls) == 0

    def test_plain_address_does_not_call_discover(self) -> None:
        client = _StubClient()
        discover = AsyncMock(
            return_value=_StubDiscoverResult(agents=[], total=0)
        )
        p1, p2 = _patch_pay_dependencies(client)
        with p1, p2, patch(
            "agirails.api.discover.discover_agents", new=discover
        ):
            result = runner.invoke(app, ["--quiet", "pay", WALLET, "5"])
        assert result.exit_code == 0, result.stdout
        discover.assert_not_called()
        assert client.pay_calls[0].to == WALLET
