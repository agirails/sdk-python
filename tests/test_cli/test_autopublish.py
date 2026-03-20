"""Tests for actp autopublish command."""

from __future__ import annotations

import sys
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

        # Different content -> different hash
        assert h1 != h2
        # Same content -> same hash
        assert h1 == h3

    def test_debounce_clamp_in_command(self) -> None:
        """Debounce values below MIN_DEBOUNCE_MS should be clamped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "AGIRAILS.md"
            md_path.write_text(SAMPLE_MD, encoding="utf-8")

            class QuickStopEvent(threading.Event):
                def __init__(self) -> None:
                    super().__init__()
                    self.set()  # Immediately stop

            with patch("agirails.cli.commands.autopublish.threading.Event", QuickStopEvent):
                result = runner.invoke(
                    app, ["autopublish", str(md_path), "--debounce", "100", "--json"]
                )
                assert result.exit_code == 0
                assert '"watching"' in result.output or '"stopped"' in result.output

    def test_subprocess_publish_invocation(self) -> None:
        """Verify publish subprocess is called with correct args when file changes.

        Strategy: patch threading.Event so the poll loop runs exactly one cycle
        where a file change is detected, patch threading.Timer to fire immediately
        (no delay), and capture the subprocess.run call.
        """
        # Mutable state dict (avoids nonlocal issues in Python 3.9 closures)
        state = {"in_poll_loop": False, "stop_count": 0, "polled": False}

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "AGIRAILS.md"
            md_path.write_text(SAMPLE_MD, encoding="utf-8")

            captured_cmds: list = []

            class ImmediateTimer:
                """Timer mock that fires callback synchronously."""
                def __init__(self, interval, function, args=None, kwargs=None):
                    self._function = function
                    self._cancelled = False
                    self.daemon = True
                def start(self):
                    if not self._cancelled:
                        self._function()
                def cancel(self):
                    self._cancelled = True

            original_stat = Path.stat

            def mock_stat(path_self):
                # During init, return real stat
                if not state["in_poll_loop"]:
                    return original_stat(path_self)
                # First poll: write changed content so mtime + hash differ
                if not state["polled"]:
                    state["polled"] = True
                    md_path.write_text(
                        SAMPLE_MD + "\nChanged content.\n", encoding="utf-8"
                    )
                return original_stat(path_self)

            class ControlledStopEvent(threading.Event):
                def __init__(self):
                    super().__init__()
                def wait(self, timeout=None):
                    state["in_poll_loop"] = True
                    state["stop_count"] += 1
                    if state["stop_count"] >= 2:
                        self.set()
                    return self.is_set()

            def mock_subprocess_run(cmd, **kwargs):
                captured_cmds.append(cmd)
                r = MagicMock()
                r.returncode = 0
                r.stdout = "0xdeadbeef"
                r.stderr = ""
                return r

            with patch("agirails.cli.commands.autopublish.threading.Event", ControlledStopEvent), \
                 patch("agirails.cli.commands.autopublish.threading.Timer", ImmediateTimer), \
                 patch("agirails.cli.commands.autopublish.subprocess.run", side_effect=mock_subprocess_run), \
                 patch.object(Path, "stat", mock_stat):
                result = runner.invoke(
                    app, ["autopublish", str(md_path), "--debounce", "500"]
                )

            # Publish MUST have been triggered
            assert len(captured_cmds) > 0, "subprocess publish was never called"
            cmd = captured_cmds[0]
            assert "publish" in cmd, f"Expected 'publish' in command: {cmd}"
            assert "--path" in cmd
            assert "--quiet" in cmd
            assert "--network" in cmd
