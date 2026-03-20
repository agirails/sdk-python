"""Tests for agirails.app API client."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agirails.api.agirails_app import (
    AgirailsAppError,
    ClaimAgentParams,
    UpsertAgentParams,
    check_slug,
    claim_agent,
    get_claim_challenge,
    upsert_agent,
)


class TestUpsertAgentParams:
    """Tests for UpsertAgentParams serialization."""

    def test_to_camel_case_dict(self) -> None:
        params = UpsertAgentParams(
            slug="my-agent",
            agent_id="123",
            wallet="0xWallet",
            config_cid="bafycid",
            config_hash="0xhash",
            signature="0xsig",
            message="msg",
            timestamp=1700000000,
        )
        d = params.to_camel_case_dict()
        assert d["agentId"] == "123"
        assert d["configCid"] == "bafycid"
        assert d["configHash"] == "0xhash"
        assert d["slug"] == "my-agent"
        assert d["wallet"] == "0xWallet"
        assert d["signature"] == "0xsig"
        assert d["message"] == "msg"
        # No snake_case keys
        assert "agent_id" not in d
        assert "config_cid" not in d
        assert "config_hash" not in d


class TestCheckSlug:
    """Tests for check_slug."""

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._get", new_callable=AsyncMock)
    async def test_slug_available(self, mock_get: AsyncMock) -> None:
        mock_get.return_value = {"available": True, "slug": "test-agent"}
        result = await check_slug("test-agent")
        assert result["available"] is True

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._get", new_callable=AsyncMock)
    async def test_slug_taken_with_suggestions(self, mock_get: AsyncMock) -> None:
        mock_get.return_value = {
            "available": False,
            "slug": "my-agent",
            "suggestions": ["my-agent-2", "my-agent-3"],
        }
        result = await check_slug("my-agent")
        assert result["available"] is False
        assert "suggestions" in result
        assert len(result["suggestions"]) == 2

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._get", new_callable=AsyncMock)
    async def test_slug_check_error(self, mock_get: AsyncMock) -> None:
        mock_get.side_effect = AgirailsAppError("check-slug failed", 500)
        with pytest.raises(AgirailsAppError):
            await check_slug("bad-slug")


class TestUpsertAgent:
    """Tests for upsert_agent."""

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._post", new_callable=AsyncMock)
    async def test_upsert_success(self, mock_post: AsyncMock) -> None:
        mock_post.return_value = {"success": True, "agentId": "123"}
        params = UpsertAgentParams(
            slug="agent",
            agent_id="123",
            wallet="0x123",
            config_cid="bafycid",
            config_hash="0xhash",
            signature="0xsig",
            message="msg",
            timestamp=1700000000,
        )
        result = await upsert_agent(params)
        assert result["success"] is True

        # Verify camelCase body
        call_args = mock_post.call_args
        body = call_args[0][1]
        assert "agentId" in body
        assert "configCid" in body

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._post", new_callable=AsyncMock)
    async def test_upsert_error(self, mock_post: AsyncMock) -> None:
        mock_post.side_effect = AgirailsAppError("upsert failed", 400)
        params = UpsertAgentParams(
            slug="agent", agent_id="123", wallet="0x123",
            config_cid="cid", config_hash="hash", signature="sig", message="msg",
            timestamp=1700000000,
        )
        with pytest.raises(AgirailsAppError):
            await upsert_agent(params)


class TestGetClaimChallenge:
    """Tests for get_claim_challenge."""

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._post", new_callable=AsyncMock)
    async def test_challenge_success(self, mock_post: AsyncMock) -> None:
        mock_post.return_value = {"challenge": "abc123"}
        result = await get_claim_challenge("0xWallet")
        assert result["challenge"] == "abc123"
        # Verify body
        body = mock_post.call_args[0][1]
        assert body == {"wallet": "0xWallet"}


class TestClaimAgent:
    """Tests for claim_agent."""

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._post", new_callable=AsyncMock)
    async def test_claim_success(self, mock_post: AsyncMock) -> None:
        mock_post.return_value = {"claimed": True}
        params = ClaimAgentParams(
            agent_id="12345", wallet="0xWallet", challenge="abc123", signature="0xsig"
        )
        result = await claim_agent(params)
        assert result["claimed"] is True

        # Verify agentId in POST body
        body = mock_post.call_args[0][1]
        assert body["agentId"] == "12345"
        assert body["wallet"] == "0xWallet"

    @pytest.mark.asyncio
    @patch("agirails.api.agirails_app._post", new_callable=AsyncMock)
    async def test_claim_error(self, mock_post: AsyncMock) -> None:
        mock_post.side_effect = AgirailsAppError("claim failed", 403)
        params = ClaimAgentParams(
            agent_id="12345", wallet="0xWallet", challenge="abc", signature="0xsig"
        )
        with pytest.raises(AgirailsAppError):
            await claim_agent(params)
