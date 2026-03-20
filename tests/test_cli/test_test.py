"""Tests for actp test command."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.cli.commands.test import parse_duration

runner = CliRunner()


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
