"""
Level 1 API for AGIRAILS SDK.

Provides the Agent class and related types for building AI agent services.

Example:
    >>> from agirails.level1 import Agent, AgentConfig, Job
    >>>
    >>> agent = Agent(AgentConfig(name="my-agent", network="mock"))
    >>> agent.provide("echo", lambda job, ctx: job.input)
    >>> await agent.start()
"""

from __future__ import annotations

from agirails.level1.agent import (
    Agent,
    AgentBalance,
    AgentStats,
    AgentStatus,
)
from agirails.level1.config import (
    DEFAULT_DELIVERY_CONFIG,
    AgentBehavior,
    AgentConfig,
    DeliveryMode,
    DeliveryPrivacy,
    DeliveryServiceConfig,
    NetworkOption,
    RetryConfig,
    ServiceConfig,
    ServiceFilter,
    WalletOption,
)
from agirails.level1.job import (
    Job,
    JobContext,
    JobHandler,
    JobResult,
)
from agirails.level1.pricing import (
    DEFAULT_PRICING_STRATEGY,
    CostModel,
    PriceCalculation,
    PricingStrategy,
    calculate_price,
    estimate_units,
)

__all__ = [
    # Job types
    "Job",
    "JobContext",
    "JobHandler",
    "JobResult",
    # Config types
    "AgentConfig",
    "AgentBehavior",
    "ServiceConfig",
    "ServiceFilter",
    "RetryConfig",
    "NetworkOption",
    "WalletOption",
    "DeliveryServiceConfig",
    "DEFAULT_DELIVERY_CONFIG",
    "DeliveryMode",
    "DeliveryPrivacy",
    # Pricing
    "PricingStrategy",
    "CostModel",
    "PriceCalculation",
    "DEFAULT_PRICING_STRATEGY",
    "calculate_price",
    "estimate_units",
    # Agent
    "Agent",
    "AgentStatus",
    "AgentStats",
    "AgentBalance",
]
