"""
Tests for CLI commands.
"""

import json
import os
import tempfile
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
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestVersion:
    """Test version command."""

    def test_version_flag(self, runner: CliRunner) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "actp version" in result.stdout

    def test_version_short_flag(self, runner: CliRunner) -> None:
        """Test -v flag."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert "actp version" in result.stdout


class TestInit:
    """Test init command."""

    def test_init_creates_directory(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init creates .actp directory."""
        result = runner.invoke(app, ["-d", str(temp_dir), "init"])
        assert result.exit_code == 0
        assert (temp_dir / ".actp").exists()
        assert (temp_dir / ".actp" / "config.json").exists()

    def test_init_default_mode(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init sets default mode to mock."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        config_path = temp_dir / ".actp" / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        assert config["mode"] == "mock"

    def test_init_custom_mode(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init with custom mode."""
        runner.invoke(app, ["-d", str(temp_dir), "init", "--mode", "testnet"])
        config_path = temp_dir / ".actp" / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        assert config["mode"] == "testnet"

    def test_init_already_initialized(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init fails if already initialized."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "init"])
        assert result.exit_code == 1

    def test_init_force_reinitialize(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init with --force overwrites."""
        runner.invoke(app, ["-d", str(temp_dir), "init", "--mode", "mock"])
        result = runner.invoke(app, ["-d", str(temp_dir), "init", "--mode", "testnet", "--force"])
        assert result.exit_code == 0
        config_path = temp_dir / ".actp" / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        assert config["mode"] == "testnet"

    def test_init_json_output(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init with JSON output."""
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "init"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert "path" in output


class TestConfig:
    """Test config commands."""

    def test_config_show(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config show command."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "config", "show"])
        assert result.exit_code == 0
        assert "mode" in result.stdout

    def test_config_show_json(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config show with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "config", "show"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "config" in output
        assert output["config"]["mode"] == "mock"

    def test_config_set(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config set command."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "config", "set", "mode", "testnet"])
        assert result.exit_code == 0
        # Verify
        config_path = temp_dir / ".actp" / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        assert config["mode"] == "testnet"

    def test_config_set_invalid_key(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config set with invalid key."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "config", "set", "invalid_key", "value"])
        assert result.exit_code == 1

    def test_config_set_invalid_mode(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config set with invalid mode value."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "config", "set", "mode", "invalid"])
        assert result.exit_code == 1

    def test_config_get(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test config get command."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "config", "get", "mode"])
        assert result.exit_code == 0
        assert "mock" in result.stdout


class TestBalance:
    """Test balance command."""

    def test_balance_not_initialized(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test balance fails if not initialized."""
        result = runner.invoke(app, ["-d", str(temp_dir), "balance"])
        assert result.exit_code == 1

    def test_balance_default_address(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test balance with default address."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "balance"])
        assert result.exit_code == 0

    def test_balance_json_output(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test balance with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "balance"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "balance" in output
        assert "address" in output


class TestMint:
    """Test mint command."""

    def test_mint_not_initialized(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test mint fails if not initialized."""
        result = runner.invoke(app, ["-d", str(temp_dir), "mint", "0x" + "1" * 40, "1000"])
        assert result.exit_code == 1

    def test_mint_tokens(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test minting tokens."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        address = "0x" + "1" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "mint", address, "1000"])
        assert result.exit_code == 0

    def test_mint_json_output(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test mint with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        address = "0x" + "1" * 40
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "mint", address, "1000"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert output["address"] == address


class TestTime:
    """Test time commands."""

    def test_time_show(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time show command."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "time"])
        assert result.exit_code == 0

    def test_time_show_json(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time show with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "time"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "timestamp" in output

    def test_time_advance(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time advance command."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "time", "advance", "3600"])
        assert result.exit_code == 0

    def test_time_set(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time set command."""
        import time
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        # Use a future timestamp (current time + 1 hour)
        future_timestamp = str(int(time.time()) + 3600)
        result = runner.invoke(app, ["-d", str(temp_dir), "time", "set", future_timestamp])
        assert result.exit_code == 0


class TestPay:
    """Test pay command."""

    def test_pay_not_initialized(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay fails if not initialized."""
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", "0x" + "2" * 40, "10.00"])
        assert result.exit_code == 1

    def test_pay_creates_transaction(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay creates a transaction."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        # Mint tokens first
        requester = "0x" + "1" * 40
        runner.invoke(app, ["-d", str(temp_dir), "mint", requester, "1000"])
        # Pay
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "10.00"])
        assert result.exit_code == 0

    def test_pay_json_output(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        requester = "0x" + "1" * 40
        runner.invoke(app, ["-d", str(temp_dir), "mint", requester, "1000"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "pay", provider, "10.00"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert "txId" in output


class TestTx:
    """Test tx commands."""

    def test_tx_list_empty(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test tx list with no transactions."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "tx", "list"])
        assert result.exit_code == 0

    def test_tx_status_not_found(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test tx status with invalid ID."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "tx", "status", "0x" + "0" * 64])
        assert result.exit_code == 1

    def test_tx_list_json(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test tx list with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["--json", "-d", str(temp_dir), "tx", "list"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "transactions" in output
        assert "count" in output


class TestQuietMode:
    """Test quiet output mode."""

    def test_init_quiet(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init with quiet mode."""
        result = runner.invoke(app, ["--quiet", "-d", str(temp_dir), "init"])
        assert result.exit_code == 0
        # Should only output path
        assert str(temp_dir / ".actp") in result.stdout

    def test_balance_quiet(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test balance with quiet mode."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["--quiet", "-d", str(temp_dir), "balance"])
        assert result.exit_code == 0
        # Should only output the balance number
        lines = result.stdout.strip().split("\n")
        assert len(lines) == 1


class TestGlobalOptions:
    """Test global CLI options."""

    def test_directory_option(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test -d/--directory option."""
        result = runner.invoke(app, ["-d", str(temp_dir), "init"])
        assert result.exit_code == 0
        assert (temp_dir / ".actp").exists()

    def test_mode_option(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test -m/--mode option."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        # Mode option should override config
        result = runner.invoke(app, ["-m", "mock", "-d", str(temp_dir), "balance"])
        assert result.exit_code == 0

    def test_help_option(self, runner: CliRunner) -> None:
        """Test --help option."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AGIRAILS CLI" in result.stdout


class TestValidation:
    """Test input validation edge cases."""

    def test_invalid_address_format(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with invalid address format."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        # Too short
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", "0x123", "10"])
        assert result.exit_code == 1
        assert "Invalid" in result.stdout or "invalid" in result.stdout.lower()

    def test_address_missing_prefix(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with address missing 0x prefix."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", "1" * 40, "10"])
        assert result.exit_code == 1

    def test_address_invalid_hex(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with non-hex characters in address."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", "0x" + "G" * 40, "10"])
        assert result.exit_code == 1

    def test_invalid_amount_negative(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with negative amount."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "-10"])
        # Exit code 1 (our validation) or 2 (Typer parsing error) both indicate rejection
        assert result.exit_code in (1, 2)

    def test_invalid_amount_too_many_decimals(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with too many decimal places."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "10.1234567"])
        assert result.exit_code == 1

    def test_invalid_amount_not_number(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with non-numeric amount."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "abc"])
        assert result.exit_code == 1

    def test_invalid_tx_id_format(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test tx status with invalid tx_id format."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        # Too short (should be 64 hex chars after 0x)
        result = runner.invoke(app, ["-d", str(temp_dir), "tx", "status", "0x123"])
        assert result.exit_code == 1

    def test_invalid_state_value(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test tx list with invalid state filter."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "tx", "list", "--state", "INVALID_STATE"])
        assert result.exit_code == 1

    def test_invalid_time_advance_negative(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time advance with negative seconds."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "time", "advance", "-100"])
        # Exit code 1 (our validation) or 2 (Typer parsing error) both indicate rejection
        assert result.exit_code in (1, 2)

    def test_invalid_time_set_past(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test time set with timestamp in the past."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-d", str(temp_dir), "time", "set", "0"])
        assert result.exit_code == 1


class TestSecurityEdgeCases:
    """Test security-related edge cases."""

    def test_private_key_blocked_in_config(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test that private_key cannot be stored in config."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(
            app,
            ["-d", str(temp_dir), "config", "set", "private_key", "0x" + "a" * 64]
        )
        assert result.exit_code == 1
        # Verify it's not in config
        config_path = temp_dir / ".actp" / "config.json"
        with open(config_path) as f:
            config = json.load(f)
        assert "private_key" not in config

    def test_config_set_json_security_error(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test private_key rejection with JSON output."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(
            app,
            ["--json", "-d", str(temp_dir), "config", "set", "private_key", "secret"]
        )
        assert result.exit_code == 1
        output = json.loads(result.stdout)
        assert "error" in output
        assert "security" in output["error"].lower() or "private_key" in output["error"]


class TestAmountEdgeCases:
    """Test amount-related edge cases."""

    def test_amount_zero(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with zero amount."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "0"])
        assert result.exit_code == 1

    def test_amount_max_decimals(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test pay with exactly 6 decimal places (USDC precision)."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        requester = "0x" + "1" * 40
        runner.invoke(app, ["-d", str(temp_dir), "mint", requester, "1000"])
        provider = "0x" + "2" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "pay", provider, "10.123456"])
        assert result.exit_code == 0

    def test_mint_amount_with_decimals(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test mint with decimal amount."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        address = "0x" + "1" * 40
        result = runner.invoke(app, ["-d", str(temp_dir), "mint", address, "1000.50"])
        assert result.exit_code == 0


class TestModeValidation:
    """Test mode validation edge cases."""

    def test_invalid_mode_option(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test with invalid mode option."""
        runner.invoke(app, ["-d", str(temp_dir), "init"])
        result = runner.invoke(app, ["-m", "invalid", "-d", str(temp_dir), "balance"])
        assert result.exit_code == 1

    def test_init_invalid_mode(self, runner: CliRunner, temp_dir: Path) -> None:
        """Test init with invalid mode."""
        result = runner.invoke(app, ["-d", str(temp_dir), "init", "--mode", "invalid"])
        assert result.exit_code == 1
