"""agirails.app API Client — Profile sync, slug check, claim.

Four functions matching TS src/api/agirailsApp.ts:
- check_slug: Pre-chain slug availability
- upsert_agent: Post-publish profile sync (dual auth)
- get_claim_challenge: Redis challenge generation
- claim_agent: Ownership verification
"""

from __future__ import annotations

import json as _json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

try:
    import aiohttp

    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# ============================================================================
# Constants
# ============================================================================

AGIRAILS_APP_BASE_URL = os.environ.get("AGIRAILS_APP_URL", "https://agirails.app")


# ============================================================================
# Types
# ============================================================================


class AgirailsAppError(Exception):
    """Error from agirails.app API."""

    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class UpsertAgentParams:
    """Parameters for upsert_agent (1:1 with TS UpsertAgentParams)."""

    slug: str
    agent_id: str  # agentId in TS
    wallet: str
    config_cid: str  # configCid in TS
    config_hash: str  # configHash in TS
    signature: str  # EIP-191 wallet signature
    message: str  # the signed message
    timestamp: int  # Unix seconds — part of signed message, server rejects >5min
    network: str = ""  # Network name (e.g. "base-sepolia") — bound in signed message

    def to_camel_case_dict(self) -> Dict[str, Any]:
        """Serialize to camelCase keys matching TS API contract."""
        return {
            "slug": self.slug,
            "agentId": self.agent_id,
            "wallet": self.wallet,
            "configCid": self.config_cid,
            "configHash": self.config_hash,
            "signature": self.signature,
            "message": self.message,
            "timestamp": self.timestamp,
            **({"network": self.network} if self.network else {}),
        }


@dataclass
class ClaimAgentParams:
    """Parameters for claim_agent."""

    agent_id: str
    wallet: str
    challenge: str
    signature: str


# ============================================================================
# HTTP Helpers (same fallback pattern as discover.py)
# ============================================================================


async def _get(url: str, timeout: float = 15.0) -> Dict[str, Any]:
    """HTTP GET with httpx → aiohttp → urllib fallback."""
    if _HAS_HTTPX:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers={"Accept": "application/json"}, timeout=timeout)
            if resp.status_code >= 400:
                raise AgirailsAppError(f"GET {url} failed: {resp.status_code}", resp.status_code)
            return resp.json()

    if _HAS_AIOHTTP:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"Accept": "application/json"}, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status >= 400:
                    raise AgirailsAppError(f"GET {url} failed: {resp.status}", resp.status)
                return await resp.json()

    from urllib.request import Request, urlopen

    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=int(timeout)) as resp:
        if resp.status >= 400:
            raise AgirailsAppError(f"GET {url} failed: {resp.status}", resp.status)
        return _json.loads(resp.read().decode("utf-8"))


async def _post(url: str, body: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
    """HTTP POST with httpx → aiohttp → urllib fallback."""
    if _HAS_HTTPX:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=timeout,
            )
            if resp.status_code >= 400:
                raise AgirailsAppError(f"POST {url} failed: {resp.status_code}", resp.status_code)
            return resp.json()

    if _HAS_AIOHTTP:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status >= 400:
                    raise AgirailsAppError(f"POST {url} failed: {resp.status}", resp.status)
                return await resp.json()

    from urllib.request import Request, urlopen

    data = _json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=int(timeout)) as resp:
        if resp.status >= 400:
            raise AgirailsAppError(f"POST {url} failed: {resp.status}", resp.status)
        return _json.loads(resp.read().decode("utf-8"))


# ============================================================================
# API Functions
# ============================================================================


async def check_slug(slug: str) -> Dict[str, Any]:
    """Check slug availability on agirails.app.

    Args:
        slug: Agent slug to check (3-64 chars).

    Returns:
        Dict with 'available' (bool), 'slug' (str), optionally 'suggestions' (list).
    """
    from urllib.parse import quote

    url = f"{AGIRAILS_APP_BASE_URL}/api/v1/agents/check-slug?slug={quote(slug)}"
    return await _get(url)


async def upsert_agent(params: UpsertAgentParams) -> Dict[str, Any]:
    """Create or update agent profile on agirails.app.

    Dual auth: session (Supabase JWT) + wallet-sig (SDK publish via EIP-712).

    Args:
        params: Agent data with EIP-712 signature.

    Returns:
        API response dict.
    """
    url = f"{AGIRAILS_APP_BASE_URL}/api/v1/agents"
    return await _post(url, params.to_camel_case_dict())


async def get_claim_challenge(wallet: str) -> Dict[str, Any]:
    """Get a Redis-backed challenge for agent claiming.

    Args:
        wallet: Wallet address.

    Returns:
        Dict with 'challenge' (str).
    """
    url = f"{AGIRAILS_APP_BASE_URL}/api/v1/agents/claim/challenge"
    return await _post(url, {"wallet": wallet})


async def claim_agent(params: ClaimAgentParams) -> Dict[str, Any]:
    """Claim agent ownership via on-chain ownerOf verification.

    Args:
        params: Claim parameters with challenge signature.

    Returns:
        API response dict.
    """
    url = f"{AGIRAILS_APP_BASE_URL}/api/v1/agents/claim"
    return await _post(url, {
        "agentId": params.agent_id,
        "wallet": params.wallet,
        "challenge": params.challenge,
        "signature": params.signature,
    })


__all__ = [
    "AgirailsAppError",
    "UpsertAgentParams",
    "ClaimAgentParams",
    "check_slug",
    "upsert_agent",
    "get_claim_challenge",
    "claim_agent",
]
