"""Operator-facing CLI outcomes on local fixtures and real mock runtime."""

import importlib
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app

batch_module = importlib.import_module("agirails.cli.commands.batch")
watch_module = importlib.import_module("agirails.cli.commands.watch")
runner = CliRunner()
TX = "0x" + "ab" * 32
PROVIDER = "0x" + "22" * 20


@pytest.fixture(autouse=True)
def local_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]])
@pytest.mark.parametrize("amount,fee", [("1", "50000"), ("5", "50000"), ("10", "100000")])
def test_simulation_reports_fees_without_creating_a_transaction(flags, amount, fee):
    result = runner.invoke(app, [*flags, "simulate", "fee", amount])
    assert result.exit_code == 0, result.output
    if "--json" in flags:
        data = json.loads(result.stdout)
        assert data["amountWei"] == str(int(amount) * 1_000_000)
        assert data["feeWei"] == fee
        assert data["minimumApplied"] is (int(amount) < 5)
    else:
        assert "Fee" in result.stdout


@pytest.mark.parametrize("flags", [[], ["--json"]])
@pytest.mark.parametrize("to,amount,deadline,valid", [
    (PROVIDER, "1", "+24h", True),
    (PROVIDER, "100", "+1h", True),
    ("invalid", "1", "+24h", False),
    (PROVIDER, "zero", "+24h", False),
    (PROVIDER, "1", "1", False),
])
def test_payment_simulation_validates_inputs(flags, to, amount, deadline, valid, tmp_path):
    result = runner.invoke(app, [*flags, "simulate", "pay", to, amount, "--deadline", deadline])
    assert result.exit_code == (0 if valid else 1), result.output
    if "--json" in flags:
        data = json.loads(result.stdout)
        assert data["valid"] is valid
        if valid:
            assert data["simulation"]["provider"] == to.lower()
            assert data["simulation"]["action"] == "CREATE_AND_FUND_TRANSACTION"
        else:
            assert data["errors"]
    assert not (tmp_path / ".actp" / "state.json").exists()


@pytest.mark.parametrize("command", ["", "unknown", "tx", "tx unknown", "balance; echo no", "pay 'unterminated"])
def test_batch_rejects_invalid_commands_before_subprocess(command, monkeypatch):
    calls = []
    monkeypatch.setattr(batch_module.subprocess, "run", lambda *a, **kw: calls.append(a))
    success, message, duration = batch_module.execute_command(command)
    assert success is False
    assert message
    assert duration >= 0
    assert calls == []


@pytest.mark.parametrize("status,stdout,stderr,success,message", [
    (0, "  done  ", "", True, "done"),
    (0, "", "", True, "OK"),
    (1, "", '{"error":{"message":"denied"}}', False, "denied"),
    (2, "", "plain error", False, "plain error"),
    (7, "", "", False, "Exit code: 7"),
])
def test_batch_subprocess_result_and_argv_contract(monkeypatch, status, stdout, stderr, success, message):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=status, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(batch_module.subprocess, "run", run)
    ok, output, duration = batch_module.execute_command("balance")
    assert (ok, output) == (success, message)
    assert duration >= 0
    assert calls[0][0] == ["actp", "balance", "--json"]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 120


@pytest.mark.parametrize("error,message", [
    (FileNotFoundError(), "not found"),
    (subprocess.TimeoutExpired("actp", 120), "timed out"),
])
def test_batch_reports_execution_failures(monkeypatch, error, message):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(batch_module.subprocess, "run", fail)
    ok, output, _ = batch_module.execute_command("balance")
    assert ok is False
    assert message in output


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]])
@pytest.mark.parametrize("stop", [False, True])
def test_batch_dry_run_aggregates_results_and_preserves_line_numbers(tmp_path, flags, stop):
    path = tmp_path / "commands.txt"
    path.write_text("# ignored\n\nbalance\nunknown\ntime show\n")
    args = [*flags, "batch", str(path), "--dry-run"]
    if stop:
        args.append("--stop-on-error")
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    if "--json" in flags:
        data = json.loads(result.stdout)
        assert data["summary"]["failed"] == 1
        assert data["summary"]["succeeded"] == (1 if stop else 2)
        assert [r["line"] for r in data["results"]] == ([3, 4] if stop else [3, 4, 5])


@pytest.mark.parametrize("stop", [False, True])
def test_batch_execution_stops_and_counts_remaining_commands(monkeypatch, stop):
    responses = iter([(True, "ok", 1), (False, "failed", 2), (True, "next", 3)])
    calls = []
    def execute(command):
        calls.append(command)
        return next(responses)
    monkeypatch.setattr(batch_module, "execute_command", execute)
    args = ["--json", "batch", "-"] + (["--stop-on-error"] if stop else [])
    result = runner.invoke(app, args, input="balance\ntime show\nconfig show\n")
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["summary"] == {"total": 3, "succeeded": 1 if stop else 2, "failed": 1, "skipped": 1 if stop else 0}
    assert len(calls) == (2 if stop else 3)


@pytest.mark.parametrize("source", ["empty", "missing"])
def test_batch_handles_empty_and_missing_files(tmp_path, source):
    path = tmp_path / "commands.txt"
    if source == "empty":
        path.write_text("# no commands\n")
    result = runner.invoke(app, ["--json", "batch", str(path), "--dry-run"])
    assert result.exit_code == (0 if source == "empty" else 1)
    if source == "empty":
        assert json.loads(result.stdout)["total"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("json_output,quiet", [(False, False), (True, False), (False, True)])
@pytest.mark.parametrize("states,until,expected", [
    (["SETTLED"], None, 0),
    (["QUOTED"], "QUOTED", 0),
    (["INITIATED", "DELIVERED"], "DELIVERED", 0),
    (["INITIATED", "SETTLED"], None, 0),
    (["INITIATED", None], None, 1),
    ([None], None, 1),
])
async def test_watch_observes_states_and_returns_meaningful_exit_codes(monkeypatch, capsys, states, until, expected, json_output, quiet):
    txs = [None if state is None else SimpleNamespace(state=state, updated_at=1700000000) for state in states]
    get_transaction = AsyncMock(side_effect=txs)
    client = SimpleNamespace(standard=SimpleNamespace(get_transaction=get_transaction))
    monkeypatch.setattr(watch_module, "get_client", AsyncMock(return_value=client))
    code = await watch_module.run_watch(TX, 1, 0, until, json_output, quiet, None, "mock")
    assert code == expected
    assert get_transaction.await_count == len(states)
    output = capsys.readouterr().out
    if json_output and txs[0] is not None:
        events = [json.loads(line) for line in output.splitlines()]
        assert events[0]["toState"] == states[0]
        assert events[0]["txId"] == TX
    elif quiet and txs[0] is not None:
        assert states[0] in output


@pytest.mark.asyncio
@pytest.mark.parametrize("tx_id,until", [("invalid", None), (TX, "UNKNOWN"), ("0x" + "zz" * 32, None)])
async def test_watch_rejects_invalid_input_without_loading_client(monkeypatch, tx_id, until):
    get_client = AsyncMock()
    monkeypatch.setattr(watch_module, "get_client", get_client)
    assert await watch_module.run_watch(tx_id, 1, 0, until, True, False, None, "mock") == 1
    get_client.assert_not_awaited()


def test_watch_cli_retains_success_exit_code(monkeypatch):
    client = SimpleNamespace(standard=SimpleNamespace(get_transaction=AsyncMock(return_value=SimpleNamespace(state="SETTLED", updated_at=1700000000))))
    monkeypatch.setattr(watch_module, "get_client", AsyncMock(return_value=client))
    result = runner.invoke(app, ["--json", "watch", TX])
    assert result.exit_code == 0, result.output
    event = json.loads(result.stdout)
    assert event["toState"] == "SETTLED"


def test_tx_transition_forwards_explicit_proof(monkeypatch):
    module = importlib.import_module("agirails.cli.commands.tx")
    transition = AsyncMock()
    client = SimpleNamespace(standard=SimpleNamespace(transition_state=transition))
    monkeypatch.setattr(module, "ensure_initialized", lambda directory: True)
    monkeypatch.setattr(module, "get_client", AsyncMock(return_value=client))
    proof = "0x" + "cd" * 32
    result = runner.invoke(app, ["--json", "tx", "transition", TX, "DELIVERED", "--proof", proof])
    assert result.exit_code == 0, result.output
    transition.assert_awaited_once_with(tx_id=TX, new_state="DELIVERED", proof=proof)
