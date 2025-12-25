"""
Configuration types for AGIRAILS Level 1 API.

Provides configuration dataclasses for:
- AgentConfig: Main agent configuration
- AgentBehavior: Agent behavior settings
- ServiceConfig: Service-specific configuration
- ServiceFilter: Job filtering rules
- RetryConfig: Retry behavior settings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Literal, List, Optional, Union

if TYPE_CHECKING:
    from agirails.level1.job import Job
    from agirails.level1.pricing import PricingStrategy


# Type aliases
NetworkOption = Literal["mock", "testnet", "mainnet"]
WalletOption = Optional[str]  # Address or private key


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior.

    Attributes:
        attempts: Maximum number of retry attempts (default: 3)
        delay: Initial delay between retries in milliseconds (default: 1000)
        backoff: Backoff strategy - 'linear' or 'exponential' (default: 'exponential')
    """

    attempts: int = 3
    delay: int = 1000  # milliseconds
    backoff: Literal["linear", "exponential"] = "exponential"

    def get_delay_ms(self, attempt: int) -> int:
        """
        Calculate delay for a given attempt number.

        Args:
            attempt: Current attempt number (1-indexed)

        Returns:
            Delay in milliseconds
        """
        if self.backoff == "linear":
            return self.delay * attempt
        else:  # exponential
            return self.delay * (2 ** (attempt - 1))


@dataclass
class AgentBehavior:
    """
    Agent behavior configuration.

    Attributes:
        auto_accept: Whether to automatically accept jobs, or a function to decide
        concurrency: Maximum concurrent jobs (default: 10)
        timeout: Default job timeout in seconds (default: 300)
        retry: Retry configuration for failed jobs
    """

    auto_accept: Union[bool, Callable[["Job"], Union[bool, Awaitable[bool]]]] = True
    concurrency: int = 10
    timeout: int = 300  # seconds
    retry: Optional[RetryConfig] = None


@dataclass
class AgentConfig:
    """
    Main agent configuration.

    Attributes:
        name: Agent name (required, used for identification)
        description: Human-readable description
        network: Network mode - 'mock', 'testnet', or 'mainnet'
        wallet: Wallet address or private key (auto-generated if None)
        state_directory: Directory for state persistence
        rpc_url: Custom RPC URL (uses default for network if None)
        behavior: Agent behavior settings
        persistence: Persistence configuration (reserved for future use)
        logging: Logging configuration (reserved for future use)

    Example:
        >>> config = AgentConfig(
        ...     name="my-agent",
        ...     network="mock",
        ...     behavior=AgentBehavior(concurrency=5)
        ... )
    """

    name: str
    description: str = ""
    network: NetworkOption = "mock"
    wallet: WalletOption = None
    state_directory: Optional[Path] = None
    rpc_url: Optional[str] = None
    behavior: Optional[AgentBehavior] = None
    persistence: Optional[Dict[str, Any]] = None
    logging: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.name:
            raise ValueError("Agent name is required")
        if not self.name.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "Agent name must be alphanumeric (dashes and underscores allowed)"
            )
        if len(self.name) > 64:
            raise ValueError("Agent name cannot exceed 64 characters")

    def get_behavior(self) -> AgentBehavior:
        """Get behavior config, using defaults if not set."""
        return self.behavior or AgentBehavior()


@dataclass
class ServiceFilter:
    """
    Filter rules for incoming jobs.

    Attributes:
        min_budget: Minimum budget in USDC (reject jobs below this)
        max_budget: Maximum budget in USDC (reject jobs above this)
        custom: Custom filter function returning True to accept

    Example:
        >>> filter = ServiceFilter(
        ...     min_budget=1.0,
        ...     max_budget=1000.0,
        ...     custom=lambda job: "priority" in job.metadata
        ... )
    """

    min_budget: Optional[float] = None
    max_budget: Optional[float] = None
    custom: Optional[Callable[["Job"], bool]] = None

    def matches(self, job: Job) -> bool:
        """
        Check if a job matches this filter.

        Args:
            job: Job to check

        Returns:
            True if job passes all filter criteria
        """
        if self.min_budget is not None and job.budget < self.min_budget:
            return False
        if self.max_budget is not None and job.budget > self.max_budget:
            return False
        if self.custom is not None and not self.custom(job):
            return False
        return True


@dataclass
class ServiceConfig:
    """
    Configuration for a specific service.

    Attributes:
        name: Service name (must match the registered service)
        description: Human-readable service description
        filter: Filter for incoming jobs
        pricing: Pricing strategy for this service
        capabilities: List of capability tags
        timeout: Service-specific timeout (overrides agent default)

    Example:
        >>> config = ServiceConfig(
        ...     name="text-generation",
        ...     description="Generate text using GPT-4",
        ...     filter=ServiceFilter(min_budget=0.10),
        ...     capabilities=["gpt-4", "streaming"]
        ... )
    """

    name: str
    description: str = ""
    filter: Optional[ServiceFilter] = None
    pricing: Optional["PricingStrategy"] = None
    capabilities: Optional[List[str]] = None
    timeout: Optional[int] = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.name:
            raise ValueError("Service name is required")

    def get_timeout(self, default: int) -> int:
        """Get timeout, using default if not set."""
        return self.timeout if self.timeout is not None else default

    def matches_job(self, job: Job) -> bool:
        """Check if job matches this service's filter."""
        if self.filter is None:
            return True
        return self.filter.matches(job)
