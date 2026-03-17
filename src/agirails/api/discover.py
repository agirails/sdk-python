"""
Discover API Client — Query agirails.app for published agents.

Public read-only endpoint, no auth required. 1:1 parity with
TypeScript SDK's discoverAgents() in src/api/agirailsApp.ts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlencode

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


@dataclass
class DiscoverAgentPricing:
    amount: Optional[float] = None
    currency: Optional[str] = None
    unit: Optional[str] = None


@dataclass
class DiscoverAgentConfig:
    name: Optional[str] = None
    description: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    pricing: Optional[DiscoverAgentPricing] = None
    payment_mode: Optional[str] = None
    sla: Optional[Dict[str, Any]] = None
    endpoints: Optional[Dict[str, str]] = None


@dataclass
class DiscoverAgentStats:
    reputation_score: float = 0
    completed_transactions: int = 0
    failed_transactions: int = 0
    success_rate: float = 0
    total_gmv_usdc: str = "0"
    avg_completion_time_seconds: Optional[float] = None


@dataclass
class DiscoverAgent:
    slug: str = ""
    wallet_address: str = ""
    published_config: Optional[DiscoverAgentConfig] = None
    published_at: Optional[str] = None
    status: Optional[str] = None
    stats: Optional[DiscoverAgentStats] = None


@dataclass
class RankedAgent:
    slug: str = ""
    reason: str = ""
    risk: str = ""
    confidence: str = "medium"  # high | medium | low


@dataclass
class RankingInfo:
    version: str = ""
    model: str = ""
    ranked: List[RankedAgent] = field(default_factory=list)


@dataclass
class DiscoverResult:
    agents: List[DiscoverAgent] = field(default_factory=list)
    total: int = 0
    ranking: Optional[RankingInfo] = None


@dataclass
class DiscoverParams:
    search: Optional[str] = None
    capability: Optional[str] = None
    payment_mode: Optional[str] = None
    sort: Optional[Literal["reputation", "price", "recent"]] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    max_price: Optional[float] = None
    rank: Optional[Literal["llm"]] = None
    priority: Optional[Literal["quality", "price", "speed"]] = None


# ============================================================================
# Parsing helpers
# ============================================================================


def _parse_pricing(raw: Optional[Dict[str, Any]]) -> Optional[DiscoverAgentPricing]:
    if not raw:
        return None
    return DiscoverAgentPricing(
        amount=raw.get("amount"),
        currency=raw.get("currency"),
        unit=raw.get("unit"),
    )


def _parse_config(raw: Optional[Dict[str, Any]]) -> Optional[DiscoverAgentConfig]:
    if not raw:
        return None
    return DiscoverAgentConfig(
        name=raw.get("name"),
        description=raw.get("description"),
        capabilities=raw.get("capabilities") or [],
        pricing=_parse_pricing(raw.get("pricing")),
        payment_mode=raw.get("payment_mode"),
        sla=raw.get("sla"),
        endpoints=raw.get("endpoints"),
    )


def _parse_stats(raw: Optional[Dict[str, Any]]) -> Optional[DiscoverAgentStats]:
    if not raw:
        return None
    return DiscoverAgentStats(
        reputation_score=raw.get("reputation_score", 0),
        completed_transactions=raw.get("completed_transactions", 0),
        failed_transactions=raw.get("failed_transactions", 0),
        success_rate=raw.get("success_rate", 0),
        total_gmv_usdc=raw.get("total_gmv_usdc", "0"),
        avg_completion_time_seconds=raw.get("avg_completion_time_seconds"),
    )


def _parse_agent(raw: Dict[str, Any]) -> DiscoverAgent:
    return DiscoverAgent(
        slug=raw.get("slug", ""),
        wallet_address=raw.get("wallet_address", ""),
        published_config=_parse_config(raw.get("published_config")),
        published_at=raw.get("published_at"),
        status=raw.get("status"),
        stats=_parse_stats(raw.get("stats")),
    )


def _parse_ranking(raw: Optional[Dict[str, Any]]) -> Optional[RankingInfo]:
    if not raw:
        return None
    ranked = [
        RankedAgent(
            slug=r.get("slug", ""),
            reason=r.get("reason", ""),
            risk=r.get("risk", ""),
            confidence=r.get("confidence", "medium"),
        )
        for r in raw.get("ranked", [])
    ]
    return RankingInfo(
        version=raw.get("version", ""),
        model=raw.get("model", ""),
        ranked=ranked,
    )


def _parse_result(data: Dict[str, Any]) -> DiscoverResult:
    agents = [_parse_agent(a) for a in data.get("agents", [])]
    return DiscoverResult(
        agents=agents,
        total=data.get("total", len(agents)),
        ranking=_parse_ranking(data.get("ranking")),
    )


# ============================================================================
# API Client
# ============================================================================


def _build_query_string(params: DiscoverParams) -> str:
    qs: Dict[str, str] = {}
    if params.search is not None:
        qs["search"] = params.search
    if params.capability is not None:
        qs["capability"] = params.capability
    if params.payment_mode is not None:
        qs["paymentMode"] = params.payment_mode
    if params.sort is not None:
        qs["sort"] = params.sort
    if params.limit is not None:
        qs["limit"] = str(params.limit)
    if params.offset is not None:
        qs["offset"] = str(params.offset)
    if params.max_price is not None:
        qs["maxPrice"] = str(params.max_price)
    if params.rank is not None:
        qs["rank"] = params.rank
    if params.priority is not None:
        qs["priority"] = params.priority
    return urlencode(qs) if qs else ""


async def discover_agents(params: Optional[DiscoverParams] = None) -> DiscoverResult:
    """
    Discover published agents on agirails.app.

    Public read-only endpoint, no auth required.

    Args:
        params: Discovery filter parameters

    Returns:
        Paginated list of agents with total count

    Raises:
        RuntimeError: If no HTTP client is available
        Exception: On network/API errors
    """
    if params is None:
        params = DiscoverParams()

    query_string = _build_query_string(params)
    url = f"{AGIRAILS_APP_BASE_URL}/api/v1/discover"
    if query_string:
        url = f"{url}?{query_string}"

    if _HAS_HTTPX:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers={"Accept": "application/json"}, timeout=15.0)
            if resp.status_code != 200:
                raise RuntimeError(f"discover API failed: {resp.status_code} {resp.reason_phrase}")
            return _parse_result(resp.json())

    if _HAS_AIOHTTP:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"Accept": "application/json"}, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"discover API failed: {resp.status} {resp.reason}")
                data = await resp.json()
                return _parse_result(data)

    # Fallback: synchronous urllib (works everywhere)
    import json
    from urllib.request import Request, urlopen

    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=15) as resp:
        if resp.status != 200:
            raise RuntimeError(f"discover API failed: {resp.status}")
        data = json.loads(resp.read().decode("utf-8"))
        return _parse_result(data)


__all__ = [
    "discover_agents",
    "DiscoverParams",
    "DiscoverResult",
    "DiscoverAgent",
    "DiscoverAgentConfig",
    "DiscoverAgentStats",
    "DiscoverAgentPricing",
    "RankedAgent",
    "RankingInfo",
]
