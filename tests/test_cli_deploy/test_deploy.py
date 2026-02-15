"""
Tests for deploy:env and deploy:check CLI commands.
"""

import base64
import json
import os
import stat
import sys
from pathlib import Path
from typing import Generator

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app


@pytest.fixture
def runner() -> CliRunner:
    """Create CLI test runner."""
    return CliRunner()


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """Create a project directory with .actp/keystore.json and .gitignore."""
    actp_dir = tmp_path / ".actp"
    actp_dir.mkdir()

    keystore = {"version": 3, "address": "0x" + "a" * 40, "crypto": {"cipher": "aes-128-ctr"}}
    (actp_dir / "keystore.json").write_text(json.dumps(keystore), encoding="utf-8")

    # Set restrictive permissions
    if sys.platform != "win32":
        os.chmod(actp_dir / "keystore.json", 0o600)

    # Create .gitignore with required entries
    (tmp_path / ".gitignore").write_text(".actp/\n*.key\n", encoding="utf-8")

    return tmp_path


@pytest.fixture
def keystore_b64(project_dir: Path) -> str:
    """Return the expected base64-encoded keystore."""
    raw = (project_dir / ".actp" / "keystore.json").read_text(encoding="utf-8")
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


# ============================================================
# deploy env tests
# ============================================================


class TestDeployEnvShell:
    """Test deploy env shell format output."""

    def test_shell_format_default(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env outputs shell export statements by default."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir)])
        assert result.exit_code == 0
        assert f'export ACTP_KEYSTORE_BASE64="{keystore_b64}"' in result.stdout
        assert 'export ACTP_KEY_PASSWORD=' in result.stdout
        assert "Platform examples" in result.stdout

    def test_shell_format_explicit(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env with --format shell."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir), "--format", "shell"])
        assert result.exit_code == 0
        assert f'export ACTP_KEYSTORE_BASE64="{keystore_b64}"' in result.stdout


class TestDeployEnvDocker:
    """Test deploy env docker format."""

    def test_docker_format(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env with --format docker."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir), "--format", "docker"])
        assert result.exit_code == 0
        assert f'ENV ACTP_KEYSTORE_BASE64="{keystore_b64}"' in result.stdout
        assert 'ENV ACTP_KEY_PASSWORD=' in result.stdout
        assert "SECURITY" in result.stdout  # Security warning


class TestDeployEnvJson:
    """Test deploy env json format."""

    def test_json_format(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env with --format json."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir), "--format", "json"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["keystoreBase64"] == keystore_b64
        assert output["passwordVar"] == "ACTP_KEY_PASSWORD"

    def test_json_flag_shorthand(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env with --json flag (shorthand)."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir), "--json"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["keystoreBase64"] == keystore_b64


class TestDeployEnvQuiet:
    """Test deploy env quiet mode (base64 only)."""

    def test_quiet_outputs_only_base64(self, runner: CliRunner, project_dir: Path, keystore_b64: str) -> None:
        """Test deploy env --quiet outputs only the base64 string."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(project_dir), "--quiet"])
        assert result.exit_code == 0
        assert result.stdout.strip() == keystore_b64
        # Should NOT contain export or ENV
        assert "export" not in result.stdout
        assert "ENV" not in result.stdout


class TestDeployEnvMissingKeystore:
    """Test deploy env with missing keystore."""

    def test_missing_keystore_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test deploy env fails when no keystore.json exists."""
        result = runner.invoke(app, ["deploy", "env", "-d", str(tmp_path)])
        assert result.exit_code == 1

    def test_invalid_keystore_json(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test deploy env fails when keystore.json is not valid JSON."""
        actp_dir = tmp_path / ".actp"
        actp_dir.mkdir()
        (actp_dir / "keystore.json").write_text("not json {{{", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "env", "-d", str(tmp_path)])
        assert result.exit_code == 1


# ============================================================
# deploy check tests
# ============================================================


class TestDeployCheckAllPass:
    """Test deploy check all pass scenario."""

    def test_all_pass(self, runner: CliRunner, project_dir: Path) -> None:
        """Test deploy check passes when everything is configured correctly."""
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 0
        assert "PASS" in result.stdout
        assert "FAIL" not in result.stdout


class TestDeployCheckMissingGitignore:
    """Test deploy check missing gitignore FAIL."""

    def test_missing_gitignore_fails(self, runner: CliRunner, project_dir: Path) -> None:
        """Test deploy check fails when .gitignore is missing."""
        (project_dir / ".gitignore").unlink()
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1
        assert "FAIL" in result.stdout
        assert ".gitignore" in result.stdout

    def test_gitignore_missing_actp_entry(self, runner: CliRunner, project_dir: Path) -> None:
        """Test deploy check fails when .gitignore lacks .actp/ entry."""
        (project_dir / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1
        assert "FAIL" in result.stdout


class TestDeployCheckRawKeyInEnv:
    """Test deploy check raw key in .env FAIL."""

    def test_raw_key_in_env_fails(self, runner: CliRunner, project_dir: Path) -> None:
        """Test deploy check detects raw private key in .env file."""
        (project_dir / ".env").write_text(
            "PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1
        assert "FAIL" in result.stdout
        assert "private key" in result.stdout.lower() or "PRIVATE_KEY" in result.stdout

    def test_raw_key_in_env_local(self, runner: CliRunner, project_dir: Path) -> None:
        """Test deploy check detects raw key in .env.local."""
        (project_dir / ".env.local").write_text(
            "PRIVATE_KEY=0xdeadbeef1234\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1


class TestDeployCheckSymlink:
    """Test deploy check symlink detection."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Symlinks unreliable on Windows")
    def test_symlink_actp_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test deploy check fails when .actp/ is a symlink."""
        # Create a real directory elsewhere
        real_dir = tmp_path / "real_actp"
        real_dir.mkdir()
        keystore = {"version": 3, "address": "0x" + "a" * 40}
        (real_dir / "keystore.json").write_text(json.dumps(keystore), encoding="utf-8")

        # Create project dir with symlinked .actp
        project = tmp_path / "project"
        project.mkdir()
        (project / ".gitignore").write_text(".actp/\n*.key\n", encoding="utf-8")
        (project / ".actp").symlink_to(real_dir)

        result = runner.invoke(app, ["deploy", "check", "-d", str(project)])
        assert result.exit_code == 1
        assert "symlink" in result.stdout.lower()


class TestDeployCheckQuiet:
    """Test deploy check quiet mode hides PASS/WARN."""

    def test_quiet_hides_pass_and_warn(self, runner: CliRunner, project_dir: Path) -> None:
        """Test --quiet only shows FAIL, not PASS or WARN."""
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--quiet"])
        assert result.exit_code == 0
        # In quiet mode with all passing, output should have no PASS/WARN lines
        assert "PASS" not in result.stdout
        assert "WARN" not in result.stdout

    def test_quiet_still_shows_fail(self, runner: CliRunner, project_dir: Path) -> None:
        """Test --quiet still shows FAIL lines."""
        (project_dir / ".gitignore").unlink()
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--quiet"])
        assert result.exit_code == 1
        # FAIL should still appear in output
        assert "FAIL" in result.output


class TestDeployCheckExitCodes:
    """Test deploy check exit codes."""

    def test_exit_0_on_all_pass(self, runner: CliRunner, project_dir: Path) -> None:
        """Test exit code 0 when all checks pass."""
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 0

    def test_exit_1_on_any_fail(self, runner: CliRunner, project_dir: Path) -> None:
        """Test exit code 1 when any check fails."""
        (project_dir / ".gitignore").unlink()
        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1

    def test_warn_only_still_exits_0(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test exit code 0 when there are only warnings (no keystore)."""
        # Create .gitignore but no .actp/keystore.json
        (tmp_path / ".gitignore").write_text(".actp/\n*.key\n", encoding="utf-8")
        result = runner.invoke(app, ["deploy", "check", "-d", str(tmp_path)])
        assert result.exit_code == 0
        assert "WARN" in result.stdout


class TestDeployCheckRecursiveScan:
    """Test deploy check recursive scan skips node_modules."""

    def test_skips_node_modules(self, runner: CliRunner, project_dir: Path) -> None:
        """Test recursive scan does not descend into node_modules."""
        # Create node_modules with a bad .env (should be ignored)
        nm = project_dir / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / ".env").write_text("PRIVATE_KEY=0xdeadbeef\n", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 0  # node_modules .env should be ignored

    def test_scans_subdirectories(self, runner: CliRunner, project_dir: Path) -> None:
        """Test recursive scan finds issues in subdirectories."""
        # Create a subproject with a bad .env
        subdir = project_dir / "services" / "api"
        subdir.mkdir(parents=True)
        (subdir / ".env").write_text("PRIVATE_KEY=0xdeadbeef1234\n", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 1
        assert "FAIL" in result.stdout

    def test_skips_pycache(self, runner: CliRunner, project_dir: Path) -> None:
        """Test recursive scan skips __pycache__."""
        pycache = project_dir / "__pycache__"
        pycache.mkdir()
        (pycache / ".env").write_text("PRIVATE_KEY=0xdeadbeef\n", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 0

    def test_skips_venv(self, runner: CliRunner, project_dir: Path) -> None:
        """Test recursive scan skips .venv."""
        venv = project_dir / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / ".env").write_text("PRIVATE_KEY=0xbadkey\n", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir)])
        assert result.exit_code == 0


class TestDeployCheckFix:
    """Test deploy check --fix auto-generation."""

    def test_fix_creates_gitignore_entries(self, runner: CliRunner, project_dir: Path) -> None:
        """Test --fix adds missing entries to .gitignore."""
        (project_dir / ".gitignore").write_text("*.pyc\n", encoding="utf-8")

        result = runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--fix"])
        # Still exit 1 for the initial check, but entries should be added
        gitignore_content = (project_dir / ".gitignore").read_text()
        assert ".actp/" in gitignore_content
        assert "*.key" in gitignore_content
        # Original content preserved
        assert "*.pyc" in gitignore_content

    def test_fix_idempotent(self, runner: CliRunner, project_dir: Path) -> None:
        """Test --fix doesn't duplicate entries."""
        # .gitignore already has the entries
        runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--fix"])
        runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--fix"])

        gitignore_content = (project_dir / ".gitignore").read_text()
        assert gitignore_content.count(".actp/") == 1
        assert gitignore_content.count("*.key") == 1

    def test_fix_creates_dockerignore(self, runner: CliRunner, project_dir: Path) -> None:
        """Test --fix creates .dockerignore when Dockerfile exists."""
        (project_dir / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")

        runner.invoke(app, ["deploy", "check", "-d", str(project_dir), "--fix"])
        dockerignore = project_dir / ".dockerignore"
        assert dockerignore.exists()
        assert ".actp/" in dockerignore.read_text()
