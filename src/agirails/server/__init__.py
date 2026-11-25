"""AGIRAILS server package — ``actp serve`` daemon for AIP-2.1 quote channel.

The ``create_app`` factory is the package's main entry point for callers
that want to embed the FastAPI app in their own ASGI host (instead of
running it through the ``actp serve`` CLI).

Example::

    from agirails.server import create_app, ProviderPolicy, PricingPolicy

    policy = ProviderPolicy(
        pricing=PricingPolicy(min_acceptable_amount=500_000, ideal_amount=1_000_000),
    )
    app = create_app(
        policy=policy,
        kernel_address_by_chain_id={84532: "0x9d25...0021b"},
        signer_address="0xMyAddr...",
    )
"""

from agirails.server.policy import (
    PLATFORM_MIN_BASE_UNITS,
    PricingPolicy,
    ProviderPolicy,
    load_policy_from_dict,
    load_policy_from_file,
)
from agirails.server.policy_engine import (
    Verdict,
    VerdictAction,
    evaluate_counter,
)
from agirails.server.quote_channel import (
    DEDUP_TTL_SECONDS,
    HandlerContext,
    HandlerResult,
    InMemoryDedupStore,
    QuoteChannelClient,
    QuoteChannelClientConfig,
    QuoteChannelHandler,
    TTL_GRACE_SECONDS,
    assert_safe_peer_url,
    build_channel_path,
)

def __getattr__(name):
    """Lazy-import ``create_app`` so ``agirails.server`` is importable
    without the optional ``[server]`` extra (FastAPI). The factory
    itself still requires FastAPI; the error only surfaces when the
    caller actually invokes ``create_app(...)``.
    """
    if name == "create_app":
        from agirails.server.app import create_app as _create_app
        return _create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "create_app",
    "PLATFORM_MIN_BASE_UNITS",
    "PricingPolicy",
    "ProviderPolicy",
    "load_policy_from_dict",
    "load_policy_from_file",
    "Verdict",
    "VerdictAction",
    "evaluate_counter",
    "DEDUP_TTL_SECONDS",
    "HandlerContext",
    "HandlerResult",
    "InMemoryDedupStore",
    "QuoteChannelHandler",
    "QuoteChannelClient",
    "QuoteChannelClientConfig",
    "assert_safe_peer_url",
    "TTL_GRACE_SECONDS",
    "build_channel_path",
]
