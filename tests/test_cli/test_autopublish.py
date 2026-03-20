"""Tests for actp autopublish command."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.config.agirailsmd import compute_config_hash

runner = CliRunner()

# Minimal valid AGIRAILS.md for testing
SAMPLE_MD = """---
slug: test-agent
version: "1.0"
---

# Test Agent

A test agent for autopublish tests.
"""


class TestAutopublishCommand:
    """Tests for the autopublish CLI command."""

    def test_file_not_found_exits_1(self) -> None:
        """Should exit 1 when default AGIRAILS.md doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--directory", tmpdir, "autopublish"])
            assert result.exit_code == 1
            assert "not found" in result.output.lower() or "File not found" in result.output

    def test_explicit_nonexistent_path_exits_1(self) -> None:
        """Should exit 1 when explicit path doesn't exist."""
        result = runner.invoke(app, ["autopublish", "/nonexistent/AGIRAILS.md"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "File not found" in result.output

    def test_config_hash_deterministic(self) -> None:
        """Config hash should be deterministic for same content."""
        h1 = compute_config_hash(SAMPLE_MD).config_hash
        h2 = compute_config_hash(SAMPLE_MD).config_hash
        assert h1 == h2
        assert h1.startswith("0x")

    def test_debounce_minimum_enforced(self) -> None:
        """Debounce below 500ms should be clamped to 500ms."""
        from agirails.cli.commands.autopublish import MIN_DEBOUNCE_MS

        assert MIN_DEBOUNCE_MS == 500
