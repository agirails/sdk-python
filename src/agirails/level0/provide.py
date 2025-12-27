"""
Provide function for AGIRAILS Level 0 API.

Provides a simple functional interface for registering services
without needing to manage a Provider instance directly.

Example:
    >>> from agirails.level0 import provide
    >>>
    >>> @provide("echo", description="Echo service")
    ... async def echo_handler(data):
    ...     return data
    >>>
    >>> # Or without decorator
    >>> provide("text-gen", handler=generate_text, capabilities=["gpt-4"])
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union, overload

from agirails.level0.directory import ServiceEntry, get_global_directory
from agirails.level0.provider import Provider, ProviderConfig, ServiceHandler

# Global provider instance for functional API
_global_provider: Optional[Provider] = None
_global_lock = threading.Lock()


@dataclass
class ProvideOptions:
    """
    Options for the provide function.

    Attributes:
        description: Human-readable service description
        capabilities: List of capability tags
        schema: Optional JSON schema for input validation
        metadata: Additional metadata dictionary
        auto_start: Whether to auto-start the global provider
    """

    description: str = ""
    capabilities: Optional[List[str]] = None
    schema: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    auto_start: bool = False


def _get_global_provider() -> Provider:
    """
    Get or create the global provider instance.

    Returns:
        Global Provider instance
    """
    global _global_provider
    if _global_provider is None:
        with _global_lock:
            if _global_provider is None:
                _global_provider = Provider(
                    config=ProviderConfig(),
                    directory=get_global_directory(),
                )
    return _global_provider


def reset_global_provider() -> None:
    """
    Reset the global provider.

    Stops and clears the global provider. Mainly useful for testing.
    """
    global _global_provider
    with _global_lock:
        _global_provider = None


@overload
def provide(
    name: str,
    handler: ServiceHandler,
    *,
    description: str = "",
    capabilities: Optional[List[str]] = None,
    schema: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ServiceEntry: ...


@overload
def provide(
    name: str,
    handler: None = None,
    *,
    description: str = "",
    capabilities: Optional[List[str]] = None,
    schema: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Callable[[ServiceHandler], ServiceHandler]: ...


def provide(
    name: str,
    handler: Optional[ServiceHandler] = None,
    *,
    description: str = "",
    capabilities: Optional[List[str]] = None,
    schema: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Union[ServiceEntry, Callable[[ServiceHandler], ServiceHandler]]:
    """
    Register a service with the global provider.

    Can be used as a function or decorator.

    Args:
        name: Unique service identifier
        handler: Handler function (optional, for decorator usage)
        description: Human-readable description
        capabilities: List of capability tags
        schema: Optional JSON schema for input validation
        metadata: Additional metadata

    Returns:
        ServiceEntry when handler provided, decorator otherwise

    Example:
        >>> # As decorator
        >>> @provide("echo")
        ... async def echo(data):
        ...     return data
        >>>
        >>> # As function
        >>> provide("ping", lambda x: "pong")
    """
    provider = _get_global_provider()

    if handler is not None:
        # Direct registration
        return provider.register_service(
            name=name,
            handler=handler,
            description=description,
            capabilities=capabilities,
            schema=schema,
            metadata=metadata,
        )

    # Return decorator
    def decorator(fn: ServiceHandler) -> ServiceHandler:
        provider.register_service(
            name=name,
            handler=fn,
            description=description,
            capabilities=capabilities,
            schema=schema,
            metadata=metadata,
        )
        return fn

    return decorator


def unprovide(name: str) -> bool:
    """
    Unregister a service from the global provider.

    Args:
        name: Service identifier to remove

    Returns:
        True if service was removed
    """
    provider = _get_global_provider()
    return provider.unregister_service(name)


def list_provided() -> List[str]:
    """
    List all services registered with the global provider.

    Returns:
        List of service names
    """
    provider = _get_global_provider()
    return provider.services


def set_provider_client(client: "ACTPClient", address: Optional[str] = None) -> None:
    """
    Set the ACTP client for the global provider.

    Must be called before start_provider() to enable polling.

    Args:
        client: ACTP client instance
        address: Provider address (overrides client address for polling)
    """
    provider = _get_global_provider()
    provider._client = client
    if address:
        provider._config.address = address


async def start_provider() -> None:
    """
    Start the global provider.

    Begins polling for incoming transactions.

    Note: Call set_provider_client() first to enable polling.
    """
    provider = _get_global_provider()
    await provider.start()


async def stop_provider() -> None:
    """
    Stop the global provider.

    Stops polling and waits for active jobs.
    """
    provider = _get_global_provider()
    await provider.stop()


def get_provider() -> Provider:
    """
    Get the global provider instance.

    Returns:
        Global Provider instance
    """
    return _get_global_provider()
