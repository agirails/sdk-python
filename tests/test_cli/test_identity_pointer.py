"""Tests for resolve_identity_path (mirror TS cli/utils/config.ts:442-492)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agirails.cli.utils.identity import resolve_identity_path

BUYER_MD = """---
name: My Buyer
intent: pay
servicesNeeded:
  - code-review
budget: 5
---
buyer body
"""

PROVIDER_MD = """---
name: Code Reviewer
services:
  - code-review
pricing:
  base: 10
---
provider body
"""


def _write_config(root: Path, identity: str) -> None:
    actp = root / ".actp"
    actp.mkdir(parents=True, exist_ok=True)
    (actp / "config.json").write_text(json.dumps({"identity": identity, "address": "0x0"}))


class TestIdentityPointer:
    def test_pointer_primary(self, tmp_path: Path) -> None:
        (tmp_path / "code-reviewer.md").write_text(PROVIDER_MD)
        _write_config(tmp_path, "code-reviewer.md")
        result = resolve_identity_path(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "code-reviewer.md"

    def test_pointer_to_missing_file_falls_through(self, tmp_path: Path) -> None:
        _write_config(tmp_path, "ghost.md")
        # No identity files on disk -> None
        assert resolve_identity_path(str(tmp_path)) is None

    def test_fallback_scan_finds_buyer_file(self, tmp_path: Path) -> None:
        (tmp_path / "my-buyer.md").write_text(BUYER_MD)
        # No config.json pointer -> fallback scan should find the buyer file.
        result = resolve_identity_path(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "my-buyer.md"

    def test_fallback_scan_finds_provider_file(self, tmp_path: Path) -> None:
        (tmp_path / "code-reviewer.md").write_text(PROVIDER_MD)
        result = resolve_identity_path(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "code-reviewer.md"

    def test_skips_well_known_docs(self, tmp_path: Path) -> None:
        # AGIRAILS.md is a well-known doc and is skipped by the scan.
        (tmp_path / "AGIRAILS.md").write_text(PROVIDER_MD)
        (tmp_path / "README.md").write_text("# readme")
        assert resolve_identity_path(str(tmp_path)) is None

    def test_no_md_files_returns_none(self, tmp_path: Path) -> None:
        assert resolve_identity_path(str(tmp_path)) is None

    def test_actp_dir_env_honored(self, tmp_path: Path, monkeypatch) -> None:
        # Pointer lives in a custom ACTP_DIR.
        custom = tmp_path / "custom-actp"
        custom.mkdir()
        (custom / "config.json").write_text(
            json.dumps({"identity": "code-reviewer.md", "address": "0x0"})
        )
        (tmp_path / "code-reviewer.md").write_text(PROVIDER_MD)
        monkeypatch.setenv("ACTP_DIR", str(custom))
        result = resolve_identity_path(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "code-reviewer.md"
