"""Tests for actp test command."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.cli.commands.test import (
    AgentNotFoundError,
    InvalidAgentAddressError,
    parse_duration,
    resolve_agent,
)
from agirails.cli.lib.run_request import QuoteTimeoutError, RunRequestResult

runner = CliRunner()

_SENTINEL = "0x3813A642C57CF3c20ff1170C0646c309B4bf6d64"


class TestParseDuration:
    """Tests for parse_duration helper."""

    def test_hours(self) -> None:
        assert parse_duration("48h") == 172800

    def test_days(self) -> None:
        assert parse_duration("7d") == 604800

    def test_minutes(self) -> None:
        assert parse_duration("30m") == 1800

    def test_seconds(self) -> None:
        assert parse_duration("60s") == 60

    def test_empty_default(self) -> None:
        assert parse_duration("") == 172800

    def test_invalid_default(self) -> None:
        assert parse_duration("invalid") == 172800


class TestTestCommand:
    """Tests for the test CLI command."""

    def test_error_when_no_agirails_md(self, tmp_path: Path) -> None:
        """Should error when no AGIRAILS.md found."""
        result = runner.invoke(app, ["test", "--directory", str(tmp_path)])
        assert result.exit_code == 1
        assert "No AGIRAILS.md found" in result.output

    def test_happy_path(self, tmp_path: Path) -> None:
        """Should run mock lifecycle and print receipt."""
        agirails_md = tmp_path / "AGIRAILS.md"
        agirails_md.write_text(
            textwrap.dedent("""\
                ---
                slug: test-agent
                services:
                  - type: content-generation
                    description: Generate content
                pricing:
                  base: 10000000
                sla:
                  dispute_window: 48h
                ---
                # Test Agent
            """)
        )

        result = runner.invoke(app, ["test", "--directory", str(tmp_path)])
        assert result.exit_code == 0
        assert "ACTP Transaction Complete" in result.output
        assert "test-agent" in result.output

    def test_json_output(self, tmp_path: Path) -> None:
        """Should output valid JSON when --json flag is used."""
        agirails_md = tmp_path / "AGIRAILS.md"
        agirails_md.write_text(
            textwrap.dedent("""\
                ---
                slug: json-test-agent
                pricing:
                  base: 5000000
                ---
                # JSON Test
            """)
        )

        result = runner.invoke(app, ["test", "--json", "--directory", str(tmp_path)])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["agent"] == "json-test-agent"
        assert parsed["amount"] == "$5.00 USDC"
        assert "totalMs" in parsed["timing"]

    def test_quiet_output(self, tmp_path: Path) -> None:
        """Should output only tx_id when -q flag is used."""
        agirails_md = tmp_path / "AGIRAILS.md"
        agirails_md.write_text(
            textwrap.dedent("""\
                ---
                slug: quiet-agent
                pricing:
                  base: 1000000
                ---
                # Quiet Test
            """)
        )

        result = runner.invoke(app, ["test", "-q", "--directory", str(tmp_path)])
        assert result.exit_code == 0
        # Quiet mode returns just the tx_id
        output = result.output.strip()
        assert len(output) > 0
        assert "ACTP Transaction Complete" not in output

    def test_help_flag(self) -> None:
        """Should show help text."""
        result = runner.invoke(app, ["test", "--help"])
        assert result.exit_code == 0
        assert "mock ACTP earning loop" in result.output


class TestResolveAgent:
    """resolve_agent parity (sdk-js cli/lib/resolveAgent.ts)."""

    def test_sentinel_table_lookup(self) -> None:
        r = resolve_agent("sentinel", "base-sepolia")
        assert r["address"] == _SENTINEL
        assert r["source"] == "table"
        assert r["slug"] == "sentinel"

    def test_case_insensitive_slug(self) -> None:
        r = resolve_agent("SENTINEL", "base-sepolia")
        assert r["address"] == _SENTINEL

    def test_unknown_agent_raises(self) -> None:
        with pytest.raises(AgentNotFoundError):
            resolve_agent("nonesuch", "base-sepolia")

    def test_env_override(self, monkeypatch) -> None:
        override = "0x" + "9" * 40
        monkeypatch.setenv("ACTP_SENTINEL_ADDRESS", override)
        r = resolve_agent("sentinel", "base-sepolia")
        assert r["address"] == override
        assert r["source"] == "env"

    def test_invalid_env_override_raises(self, monkeypatch) -> None:
        monkeypatch.setenv("ACTP_SENTINEL_ADDRESS", "not-an-address")
        with pytest.raises(InvalidAgentAddressError):
            resolve_agent("sentinel", "base-sepolia")

    def test_blank_env_falls_through_to_table(self, monkeypatch) -> None:
        # A whitespace-only export means "no override" — fall through.
        monkeypatch.setenv("ACTP_SENTINEL_ADDRESS", "   ")
        r = resolve_agent("sentinel", "base-sepolia")
        assert r["address"] == _SENTINEL
        assert r["source"] == "table"


class TestLiveTestCommand:
    """Live Sentinel path: `actp test --network base-sepolia`."""

    def _fake_run_request(self, **overrides):
        async def _run(**kwargs):
            base = dict(
                tx_id="0x" + "ab" * 32,
                final_state="SETTLED",
                elapsed_ms=4200,
                settled=True,
                payload={"reflection": "the bug you ignore becomes the audit"},
                receipt_url="https://agirails.app/r/r_abc123",
                delivery_error=None,
            )
            base.update(overrides)
            return RunRequestResult(**base)

        return _run

    def test_live_wires_run_request_and_prints_receipt(self) -> None:
        captured = {}

        async def _run(**kwargs):
            captured.update(kwargs)
            return RunRequestResult(
                tx_id="0x" + "ab" * 32,
                final_state="SETTLED",
                elapsed_ms=4200,
                settled=True,
                payload={"reflection": "stay curious"},
                receipt_url="https://agirails.app/r/r_abc123",
            )

        with patch("agirails.cli.lib.run_request.run_request", side_effect=_run):
            result = runner.invoke(app, ["test", "--network", "base-sepolia"])

        assert result.exit_code == 0
        # AIP-16 delivery surface MUST be wired (the whole point of the gap).
        assert captured["delivery_channel"] is not None
        assert captured["expected_kernel_address"]
        assert isinstance(captured["expected_chain_id"], int)
        assert captured["delivery_privacy"] == "public"
        assert captured["provider"] == _SENTINEL
        assert captured["service"] == "onboarding"
        assert captured["amount"] == "10"  # default $10
        # Reflection + receipt URL printed.
        assert "stay curious" in result.output
        assert "Receipt: https://agirails.app/r/r_abc123" in result.output

    def test_live_json_output(self) -> None:
        with patch(
            "agirails.cli.lib.run_request.run_request",
            side_effect=self._fake_run_request(),
        ):
            result = runner.invoke(
                app, ["test", "--network", "base-sepolia", "--json"]
            )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["finalState"] == "SETTLED"
        assert body["settled"] is True
        assert body["receiptUrl"] == "https://agirails.app/r/r_abc123"
        assert "reflection" in body

    def test_live_quote_timeout_exits_2(self) -> None:
        async def _boom(**kwargs):
            raise QuoteTimeoutError("0x" + "cd" * 32, 30_000)

        with patch("agirails.cli.lib.run_request.run_request", side_effect=_boom):
            result = runner.invoke(app, ["test", "--network", "base-sepolia"])
        # Quote timeout gets its own exit code (2) — Sentinel offline signal.
        assert result.exit_code == 2

    def test_live_unsettled_warns(self) -> None:
        with patch(
            "agirails.cli.lib.run_request.run_request",
            side_effect=self._fake_run_request(
                settled=False, final_state="DELIVERED", receipt_url=None
            ),
        ):
            result = runner.invoke(app, ["test", "--network", "base-sepolia"])
        assert result.exit_code == 0
        assert "did NOT complete" in result.output
