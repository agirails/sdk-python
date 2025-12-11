__all__ = [
    "ACTPClientError",
    "TransactionError",
    "ValidationError",
    "InvalidStateTransitionError",
    "RpcError",
    "DeadlineError",
    "QueryCapExceededError",
]


class ACTPClientError(Exception):
    """Base exception for AGIRAILS SDK."""


class TransactionError(ACTPClientError):
    """Raised when a transaction-related call fails."""


class ValidationError(ACTPClientError):
    """Raised when input validation fails."""


class InvalidStateTransitionError(ValidationError):
    """Raised when requested state transition is not allowed."""


class RpcError(ACTPClientError):
    """Raised when RPC/provider request fails."""


class DeadlineError(ValidationError):
    """Raised when operation hits an expired deadline."""


class QueryCapExceededError(ACTPClientError):
    """Raised when agent registry query exceeds on-chain limit.

    When the registry contains more than the query cap (default 1000 agents),
    on-chain queries become too expensive. Use an off-chain indexer instead.

    Recommended indexers:
    - The Graph: https://thegraph.com/
    - Goldsky: https://goldsky.com/
    - Alchemy Subgraphs: https://docs.alchemy.com/docs/subgraphs-overview

    Events to index:
    - AgentRegistered(address indexed agent, string did, string endpoint)
    - AgentUpdated(address indexed agent, string endpoint)
    - ServiceTypeAdded(address indexed agent, bytes32 indexed serviceTypeHash)
    - ServiceTypeRemoved(address indexed agent, bytes32 indexed serviceTypeHash)
    - AgentStatusChanged(address indexed agent, bool isActive)

    Attributes:
        registry_size: Approximate number of agents in registry
        query_cap: Maximum allowed agents for on-chain query
    """

    def __init__(self, registry_size: int, query_cap: int = 1000):
        self.registry_size = registry_size
        self.query_cap = query_cap
        super().__init__(
            f"Registry contains ~{registry_size} agents, exceeding query cap of {query_cap}. "
            f"Use an off-chain indexer (The Graph, Goldsky, Alchemy) for large registries."
        )
