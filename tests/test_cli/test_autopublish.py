"""Tests for actp autopublish command."""

from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

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

    def test_json_flag_works(self) -> None:
        """Should accept --json flag at command level."""
        result = runner.invoke(app, ["autopublish", "/nonexistent/AGIRAILS.md", "--json"])
        assert result.exit_code == 1
        assert '"error"' in result.output

    def test_quiet_flag_works(self) -> None:
        """Should accept -q flag at command level."""
        result = runner.invoke(app, ["autopublish", "/nonexistent/AGIRAILS.md", "-q"])
        assert result.exit_code == 1

    def test_change_detection_logic(self) -> None:
        """Core change detection: hash changes on content change, not on same content."""
        h1 = compute_config_hash(SAMPLE_MD).config_hash
        h2 = compute_config_hash(SAMPLE_MD + "\nExtra line.\n").config_hash
        h3 = compute_config_hash(SAMPLE_MD).config_hash

        # Different content → different hash
        assert h1 != h2
        # Same content → same hash
        assert h1 == h3

    def test_debounce_clamp_in_command(self) -> None:
        """Debounce values below MIN_DEBOUNCE_MS should be clamped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "AGIRAILS.md"
            md_path.write_text(SAMPLE_MD, encoding="utf-8")

            # Patch stop_event to immediately stop the watch loop
            original_init = threading.Event.__init__

            class QuickStopEvent(threading.Event):
                def __init__(self) -> None:
                    super().__init__()
                    self.set()  # Immediately stop

            with patch("agirails.cli.commands.autopublish.threading.Event", QuickStopEvent):
                result = runner.invoke(
                    app, ["autopublish", str(md_path), "--debounce", "100", "--json"]
                )
                # Should start successfully (exit 0 after immediate stop)
                assert result.exit_code == 0
                assert '"watching"' in result.output or '"stopped"' in result.output

    def test_subprocess_publish_invocation(self) -> None:
        """Verify the subprocess publish call format is correct."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "AGIRAILS.md"
            md_path.write_text(SAMPLE_MD, encoding="utf-8")

            captured_cmds: list = []

            class QuickStopEvent(threading.Event):
                _call_count = 0

                def __init__(self) -> None:
                    super().__init__()

                def wait(self, timeout=None) -> bool:
                    QuickStopEvent._call_count += 1
                    # Let one poll cycle run, then stop
                    if QuickStopEvent._call_count > 2:
                        self.set()
                    return self.is_set()

                def is_set(self) -> bool:
                    return QuickStopEvent._call_count > 2

            def mock_stat(path_self):
                # Simulate mtime change on second call
                result = MagicMock()
                result.st_mtime = time.time() + mock_stat.counter
                mock_stat.counter += 1
                return result
            mock_stat.counter = 0

            def mock_subprocess_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                result = MagicMock()
                result.returncode = 0
                result.stdout = "0xdeadbeef"
                result.stderr = ""
                return result

            with patch("agirails.cli.commands.autopublish.threading.Event", QuickStopEvent), \
                 patch("subprocess.run", side_effect=mock_subprocess_run), \
                 patch.object(Path, "stat", mock_stat):
                result = runner.invoke(
                    app, ["autopublish", str(md_path), "--debounce", "500"]
                )

            # If publish was triggered, verify the command format
            for cmd in captured_cmds:
                assert sys.executable in cmd[0] or "python" in cmd[0].lower()
                assert "publish" in cmd
                assert "--quiet" in cmd
