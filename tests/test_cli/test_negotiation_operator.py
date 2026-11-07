"""Supported negotiation CLI with local discovery and no transaction broadcast."""

import importlib
import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from agirails.cli.main import app
from agirails.api.discover import _parse_result
from tests.test_negotiation.test_buyer_orchestrator import MockRuntime, mock_agent

runner = CliRunner()
POLICY = {
    "task": "echo",
    "constraints": {
        "max_unit_price": {"amount": 1, "currency": "USDC", "unit": "request"},
        "max_daily_spend": {"amount": 10, "currency": "USDC"},
    },
    "negotiation": {"rounds_max": 2, "quote_ttl": "1s"},
    "selection": {"prioritize": ["price", "quality"]},
}


@pytest.fixture
def operator(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "buyer.json"
    path.write_text(json.dumps(POLICY))
    client = SimpleNamespace(runtime=MockRuntime(), address="0x" + "11" * 20)
    client_module = importlib.import_module("agirails.cli.utils.client")
    monkeypatch.setattr(client_module, "get_client", AsyncMock(return_value=client))
    return path, client


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]])
@pytest.mark.parametrize("has_candidates", [True, False])
def test_negotiate_dry_run_scores_real_candidates_without_creating_transactions(operator, monkeypatch, flags, has_candidates):
    path, client = operator
    module = importlib.import_module("agirails.negotiation.buyer_orchestrator")
    candidates = [mock_agent("provider", 0.5, 95, "0x" + "22" * 20)] if has_candidates else []
    discover = AsyncMock(return_value=_parse_result({"agents": candidates, "total": len(candidates)}))
    monkeypatch.setattr(module, "discover_agents", discover)
    result = runner.invoke(app, [*flags, "negotiate", "--policy", str(path), "--dry-run"])
    assert result.exit_code == (0 if has_candidates else 1), result.output
    assert client.runtime._transactions == {}
    assert discover.await_count == 1
    if "--json" in flags:
        data = json.loads(result.stdout)
        assert data["success"] is has_candidates
        assert data["rounds_used"] == 0
        assert len(data["rounds"]) == (1 if has_candidates else 0)
    elif not flags:
        assert ("Negotiation complete" if has_candidates else "No candidates") in result.stdout


@pytest.mark.parametrize("key,value,fragment", [
    ("task", "", "task"),
    ("constraints", {}, "max_unit_price"),
    ("negotiation", {"rounds_max": False, "quote_ttl": "1s"}, "rounds_max"),
    ("negotiation", {"rounds_max": 1, "quote_ttl": "wrong"}, "quote_ttl"),
    ("negotiation", {"rounds_max": 1}, "quote_ttl"),
    ("selection", {"prioritize": []}, "prioritize"),
])
def test_invalid_policy_returns_actionable_json(operator, key, value, fragment):
    path, _ = operator
    data = deepcopy(POLICY)
    data[key] = value
    path.write_text(json.dumps(data))
    result = runner.invoke(app, ["--json", "negotiate", "--policy", str(path), "--dry-run"])
    assert result.exit_code == 1
    assert fragment in json.loads(result.stdout)["error"]


@pytest.mark.parametrize("interval", ["bad", "99", "-1", "0.5"])
def test_invalid_poll_interval_is_rejected_before_execution(operator, interval):
    path, client = operator
    result = runner.invoke(app, ["--json", "negotiate", "--policy", str(path), "--poll-interval", interval])
    assert result.exit_code == 1
    assert "poll-interval" in json.loads(result.stdout)["error"]
    assert client.runtime._transactions == {}


@pytest.mark.parametrize("content", [None, "invalid-json"])
def test_missing_or_unreadable_policy_has_nonzero_exit(operator, content):
    path, _ = operator
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    result = runner.invoke(app, ["--json", "negotiate", "--policy", str(path)])
    assert result.exit_code == 1
    assert "Failed to load policy" in json.loads(result.stdout)["error"]
