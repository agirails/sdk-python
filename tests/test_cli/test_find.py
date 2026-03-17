"""Tests for the find CLI command and discover API client."""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, patch

from agirails.api.discover import (
    DiscoverParams,
    DiscoverResult,
    DiscoverAgent,
    DiscoverAgentConfig,
    DiscoverAgentPricing,
    DiscoverAgentStats,
    RankedAgent,
    RankingInfo,
    _build_query_string,
    _parse_result,
)


# ============================================================================
# discover API unit tests
# ============================================================================


class TestBuildQueryString:
    def test_empty_params(self):
        assert _build_query_string(DiscoverParams()) == ""

    def test_search_only(self):
        qs = _build_query_string(DiscoverParams(search="translator"))
        assert "search=translator" in qs

    def test_all_params(self):
        params = DiscoverParams(
            search="code",
            capability="review",
            payment_mode="actp",
            sort="reputation",
            limit=10,
            offset=5,
            max_price=50.0,
            rank="llm",
            priority="quality",
        )
        qs = _build_query_string(params)
        assert "search=code" in qs
        assert "capability=review" in qs
        assert "paymentMode=actp" in qs
        assert "sort=reputation" in qs
        assert "limit=10" in qs
        assert "offset=5" in qs
        assert "maxPrice=50.0" in qs
        assert "rank=llm" in qs
        assert "priority=quality" in qs

    def test_none_values_omitted(self):
        qs = _build_query_string(DiscoverParams(search="x", limit=None))
        assert "limit" not in qs


class TestParseResult:
    def test_empty_result(self):
        result = _parse_result({"agents": [], "total": 0})
        assert result.total == 0
        assert result.agents == []
        assert result.ranking is None

    def test_full_agent(self):
        raw = {
            "agents": [
                {
                    "slug": "test-agent",
                    "wallet_address": "0xABC",
                    "published_config": {
                        "name": "Test Agent",
                        "description": "Does stuff",
                        "capabilities": ["code-review"],
                        "pricing": {"amount": 10.0, "currency": "USDC", "unit": "per-call"},
                        "payment_mode": "actp",
                    },
                    "published_at": "2026-01-01T00:00:00Z",
                    "status": "active",
                    "stats": {
                        "reputation_score": 85.5,
                        "completed_transactions": 100,
                        "failed_transactions": 2,
                        "success_rate": 98.0,
                        "total_gmv_usdc": "5000",
                        "avg_completion_time_seconds": 30.5,
                    },
                }
            ],
            "total": 42,
        }
        result = _parse_result(raw)
        assert result.total == 42
        assert len(result.agents) == 1
        agent = result.agents[0]
        assert agent.slug == "test-agent"
        assert agent.wallet_address == "0xABC"
        assert agent.published_config is not None
        assert agent.published_config.name == "Test Agent"
        assert agent.published_config.pricing is not None
        assert agent.published_config.pricing.amount == 10.0
        assert agent.stats is not None
        assert agent.stats.reputation_score == 85.5
        assert agent.stats.completed_transactions == 100

    def test_ranking_parsed(self):
        raw = {
            "agents": [],
            "total": 0,
            "ranking": {
                "version": "v1",
                "model": "claude-haiku",
                "ranked": [
                    {"slug": "a1", "reason": "Good", "risk": "Slow", "confidence": "high"},
                    {"slug": "a2", "reason": "OK", "risk": "", "confidence": "low"},
                ],
            },
        }
        result = _parse_result(raw)
        assert result.ranking is not None
        assert result.ranking.version == "v1"
        assert len(result.ranking.ranked) == 2
        assert result.ranking.ranked[0].slug == "a1"
        assert result.ranking.ranked[0].confidence == "high"

    def test_missing_fields_default(self):
        raw = {"agents": [{"slug": "bare"}], "total": 1}
        result = _parse_result(raw)
        agent = result.agents[0]
        assert agent.slug == "bare"
        assert agent.wallet_address == ""
        assert agent.published_config is None
        assert agent.stats is None


# ============================================================================
# CLI command tests
# ============================================================================


class TestFindCommand:
    """Test find CLI command via typer test runner."""

    @pytest.fixture
    def runner(self):
        from typer.testing import CliRunner
        return CliRunner()

    @pytest.fixture
    def app(self):
        from agirails.cli.main import app
        return app

    def _mock_result(self, agents=None, total=None, ranking=None):
        if agents is None:
            agents = [
                DiscoverAgent(
                    slug="test-agent",
                    wallet_address="0xABC",
                    published_config=DiscoverAgentConfig(
                        name="Test Agent",
                        capabilities=["code-review"],
                        pricing=DiscoverAgentPricing(amount=10.0, currency="USDC", unit="per-call"),
                        payment_mode="actp",
                    ),
                ),
            ]
        return DiscoverResult(
            agents=agents,
            total=total if total is not None else len(agents),
            ranking=ranking,
        )

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_json_output(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result()
        result = runner.invoke(app, ["--json", "find", "test"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "agents" in data
        assert data["total"] == 1
        assert data["agents"][0]["slug"] == "test-agent"

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_quiet_output(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result()
        result = runner.invoke(app, ["--quiet", "find", "test"])
        assert result.exit_code == 0
        assert "test-agent" in result.output.strip()

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_human_table_output(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result()
        result = runner.invoke(app, ["find", "test"])
        assert result.exit_code == 0
        assert "test-agent" in result.output
        assert "SLUG" in result.output  # header

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_no_results_message(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result(agents=[], total=0)
        result = runner.invoke(app, ["find", "nonexistent"])
        assert result.exit_code == 0
        assert "No agents found" in result.output

    def test_invalid_sort(self, runner, app):
        result = runner.invoke(app, ["find", "--sort", "invalid"])
        assert result.exit_code == 1
        assert "sort" in result.output.lower()

    def test_invalid_payment_mode(self, runner, app):
        result = runner.invoke(app, ["find", "--payment-mode", "btc"])
        assert result.exit_code == 1
        assert "payment-mode" in result.output.lower()

    def test_invalid_max_price(self, runner, app):
        result = runner.invoke(app, ["find", "--max-price", "abc"])
        assert result.exit_code == 1
        assert "max-price" in result.output.lower()

    def test_negative_max_price(self, runner, app):
        result = runner.invoke(app, ["find", "--max-price", "-5"])
        assert result.exit_code == 1

    def test_rank_llm_requires_query(self, runner, app):
        result = runner.invoke(app, ["find", "--rank", "llm"])
        assert result.exit_code == 1
        assert "requires a search query" in result.output

    def test_invalid_rank(self, runner, app):
        result = runner.invoke(app, ["find", "--rank", "gpt"])
        assert result.exit_code == 1
        assert "rank" in result.output.lower()

    def test_invalid_priority(self, runner, app):
        result = runner.invoke(app, ["find", "--priority", "cheapest"])
        assert result.exit_code == 1
        assert "priority" in result.output.lower()

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_passes_params_correctly(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result(agents=[], total=0)
        runner.invoke(app, [
            "find", "translator",
            "--capability", "translation",
            "--max-price", "50",
            "--sort", "reputation",
            "--limit", "5",
            "--payment-mode", "actp",
            "--priority", "price",
        ])
        mock_discover.assert_called_once()
        params = mock_discover.call_args[0][0]
        assert params.search == "translator"
        assert params.capability == "translation"
        assert params.max_price == 50.0
        assert params.sort == "reputation"
        assert params.limit == 5
        assert params.payment_mode == "actp"
        assert params.priority == "price"

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_limit_clamped(self, mock_discover, runner, app):
        mock_discover.return_value = self._mock_result(agents=[], total=0)
        runner.invoke(app, ["find", "--limit", "999"])
        params = mock_discover.call_args[0][0]
        assert params.limit == 100

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_command_level_json(self, mock_discover, runner, app):
        """actp find --json test (flag AFTER command name)"""
        mock_discover.return_value = self._mock_result()
        result = runner.invoke(app, ["find", "--json", "test"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "agents" in data
        assert data["agents"][0]["slug"] == "test-agent"

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_command_level_quiet(self, mock_discover, runner, app):
        """actp find -q test (flag AFTER command name)"""
        mock_discover.return_value = self._mock_result()
        result = runner.invoke(app, ["find", "-q", "test"])
        assert result.exit_code == 0
        assert result.output.strip() == "test-agent"

    @patch("agirails.api.discover.discover_agents", new_callable=AsyncMock)
    def test_ranking_displayed(self, mock_discover, runner, app):
        ranking = RankingInfo(
            version="v1",
            model="claude-haiku",
            ranked=[RankedAgent(slug="best", reason="Excellent", risk="None", confidence="high")],
        )
        mock_discover.return_value = self._mock_result(ranking=ranking)
        result = runner.invoke(app, ["find", "test"])
        assert "AI Recommendations" in result.output
        assert "best" in result.output
        assert "Excellent" in result.output
