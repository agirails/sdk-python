"""Time CLI drives the actual isolated MockRuntime and checks state readback."""

import asyncio
import importlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from agirails.client import ACTPClient
from agirails.cli.main import app

runner = CliRunner()
module = importlib.import_module("agirails.cli.commands.time")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    instance = asyncio.run(ACTPClient.create(mode="mock", requester_address="0x" + "11" * 20, state_directory=str(tmp_path / "state")))
    monkeypatch.setattr(module, "ensure_initialized", lambda directory: True)
    monkeypatch.setattr(module, "get_client", AsyncMock(return_value=instance))
    return instance


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]])
@pytest.mark.parametrize("command", [[], ["show"], ["advance", "3600"], ["set", "1900000000"]])
def test_time_commands_preserve_operator_output_and_runtime_state(client, flags, command):
    before = client.runtime.time.now()
    result = runner.invoke(app, [*flags, "time", *command])
    assert result.exit_code == 0, result.output
    after = client.runtime.time.now()
    if command[:1] == ["advance"]:
        assert after - before >= 3600
    elif command[:1] == ["set"]:
        assert 1900000000 <= after <= 1900000002
    if "--json" in flags:
        data = json.loads(result.stdout)
        if command and command[0] in ("advance", "set"):
            assert data["success"] is True
            assert data["newTime"] == after
        else:
            assert data["timestamp"] == after
    elif "--quiet" in flags:
        assert int(result.stdout.strip()) == after
    else:
        assert "Time" in result.stdout or "time" in result.stdout


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]])
@pytest.mark.parametrize("command", [["show"], ["advance", "1"], ["set", "1900000000"]])
@pytest.mark.parametrize("failure", ["uninitialized", "nonmock", "rpc_error"])
def test_time_refuses_unsupported_runtime_or_unavailable_client(client, monkeypatch, flags, command, failure):
    if failure == "uninitialized":
        monkeypatch.setattr(module, "ensure_initialized", lambda directory: False)
    elif failure == "nonmock":
        monkeypatch.setattr(module, "get_client", AsyncMock(return_value=SimpleNamespace(runtime=object())))
    else:
        monkeypatch.setattr(module, "get_client", AsyncMock(side_effect=RuntimeError("local fixture unavailable")))
    result = runner.invoke(app, [*flags, "time", *command])
    assert result.exit_code == 1
    if "--json" in flags:
        assert json.loads(result.stdout)["error"]


@pytest.mark.parametrize("command", [["advance", "-1"], ["set", "0"]])
def test_time_rejects_invalid_ranges(client, command):
    result = runner.invoke(app, ["--json", "time", *command])
    assert result.exit_code != 0
