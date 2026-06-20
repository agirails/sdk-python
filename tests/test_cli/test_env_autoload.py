"""Tests for AIP-18 (4.6.2) ``.env`` auto-load at CLI bootstrap.

Mirrors TS ``src/cli/index.ts:21-36`` — load ``.env`` from cwd with
``override=False`` so an auto-generated ``ACTP_KEY_PASSWORD`` is picked up by
every downstream command, while existing shell/CI exports win. The load is
best-effort: a missing ``python-dotenv`` or a malformed ``.env`` must never
block the CLI from importing/starting.

These tests run the bootstrap in a *subprocess* so that re-importing
``agirails.cli.main`` (and rebuilding the shared Typer ``app``) cannot pollute
``sys.modules`` for the rest of the in-process CLI test suite.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
    )


def test_main_imports_cleanly_without_dotenv() -> None:
    """Bootstrapping the CLI module must not raise even without python-dotenv.

    Simulate dotenv being unavailable by blocking the import; main.py must
    swallow the ImportError and still expose ``app`` / ``run``.
    """
    proc = _run(
        """
        import sys, builtins
        _real_import = builtins.__import__
        def _blocked(name, *a, **k):
            if name == "dotenv" or name.startswith("dotenv."):
                raise ImportError("blocked for test")
            return _real_import(name, *a, **k)
        builtins.__import__ = _blocked
        import agirails.cli.main as m
        assert hasattr(m, "app"), "app missing"
        assert hasattr(m, "run"), "run missing"
        print("OK")
        """
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_load_dotenv_called_with_override_false_when_available() -> None:
    """When python-dotenv is importable, main.py calls load_dotenv on cwd/.env
    with override=False (idempotent: shell exports win)."""
    proc = _run(
        """
        import sys, types
        fake = types.ModuleType("dotenv")
        record = {}
        def load_dotenv(path, override=True):
            record["path"] = str(path)
            record["override"] = override
            return True
        fake.load_dotenv = load_dotenv
        sys.modules["dotenv"] = fake
        import agirails.cli.main  # noqa: F401
        assert record.get("override") is False, record
        assert record.get("path", "").endswith(".env"), record
        print("OK")
        """
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
