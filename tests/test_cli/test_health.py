"""Tests for actp health command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

runner = CliRunner()

SAMPLE_AGIRAILS_MD = """---
name: test-agent
slug: test-agent
endpoint: https://agent.example.com/webhook
---

# Test Agent
A test agent.
"""

SAMPLE_NO_ENDPOINT = """---
name: test-agent
slug: test-agent
---

# Test Agent
"""

SAMPLE_PLACEHOLDER = """---
name: test-agent
slug: test-agent
endpoint: https://pending.agirails.io
---

# Test Agent
"""


class TestHealthParsing:
    """Tests for AGIRAILS.md parsing checks."""

    def test_parse_failure_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["health", str(tmp_path / "AGIRAILS.md")])
        assert result.exit_code == 0
        assert "fail" in result.output.lower() or "\u2717" in result.output

    def test_no_endpoint_fails(self, tmp_path: Path) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_NO_ENDPOINT)
        result = runner.invoke(app, ["health", str(md)])
        assert "fail" in result.output.lower() or "FAIL" in result.output

    def test_placeholder_endpoint_fails(self, tmp_path: Path) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_PLACEHOLDER)
        result = runner.invoke(app, ["health", str(md)])
        assert "fail" in result.output.lower() or "FAIL" in result.output


class TestHealthProbe:
    """Tests for endpoint probe behavior."""

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_head_success_200(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 200,
            "response_time_ms": 150,
        }
        result = runner.invoke(app, ["health", str(md)])
        assert "PASS" in result.output

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_head_405_passes(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        """405 Method Not Allowed = server alive for POST-only webhooks."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 405,
            "response_time_ms": 100,
        }
        result = runner.invoke(app, ["health", str(md)])
        assert "PASS" in result.output

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_head_503_reachable_with_warning(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        """5xx = reachable but warning."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 503,
            "response_time_ms": 200,
        }
        result = runner.invoke(app, ["health", str(md)])
        # Should be PASS with warning
        assert "PASS" in result.output
        assert "server error" in result.output.lower() or "503" in result.output

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_both_timeout_fails(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        """Both HEAD and GET fail = FAIL."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": False,
            "method": "GET",
            "response_time_ms": 0,
            "error": "Connection timeout",
        }
        result = runner.invoke(app, ["health", str(md)])
        assert "FAIL" in result.output

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_sla_warning(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        """Response time > 2000ms = SLA warning."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 200,
            "response_time_ms": 3000,
        }
        result = runner.invoke(app, ["health", str(md)])
        assert "PASS" in result.output
        assert "2000" in result.output or "SLA" in result.output.upper() or "exceeds" in result.output


class TestHealthOutput:
    """Tests for output formats."""

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_json_output(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 200,
            "response_time_ms": 100,
        }
        result = runner.invoke(app, ["health", str(md), "--json"])
        data = json.loads(result.output)
        assert "checks" in data
        assert "healthy" in data
        assert "warnings" in data
        assert data["healthy"] is True
        assert isinstance(data["checks"], list)

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_quiet_output(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 200,
            "response_time_ms": 100,
        }
        result = runner.invoke(app, ["health", str(md), "-q"])
        assert result.output.strip() in ("PASS", "FAIL")

    @patch("agirails.cli.commands.health._probe_endpoint")
    def test_json_flag_overrides_global(self, mock_probe: MagicMock, tmp_path: Path) -> None:
        """Command-level --json overrides global format."""
        md = tmp_path / "AGIRAILS.md"
        md.write_text(SAMPLE_AGIRAILS_MD)
        mock_probe.return_value = {
            "reachable": True,
            "method": "HEAD",
            "status_code": 200,
            "response_time_ms": 100,
        }
        # Global is not json, command-level --json should force JSON
        result = runner.invoke(app, ["health", str(md), "--json"])
        data = json.loads(result.output)
        assert data["healthy"] is True
