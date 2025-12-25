"""
Level 0 API for AGIRAILS SDK.

Provides low-level primitives for building agent services:
- ServiceDirectory: Registry for service discovery
- Provider: Base class for service providers
- provide: Function to register services
- request: Function to request services

Example:
    >>> from agirails.level0 import ServiceDirectory, Provider, provide, request
    >>>
    >>> # Register a service
    >>> directory = ServiceDirectory()
    >>> directory.register("echo", description="Echo service")
    >>>
    >>> # Or use the provide function
    >>> async def echo_handler(input_data):
    ...     return input_data
    >>> provide("echo", echo_handler)
"""

from __future__ import annotations

from agirails.level0.directory import (
    ServiceDirectory,
    ServiceEntry,
    ServiceQuery,
)
from agirails.level0.provider import (
    Provider,
    ProviderConfig,
    ProviderStatus,
)
from agirails.level0.provide import (
    provide,
    ProvideOptions,
)
from agirails.level0.request import (
    request,
    RequestOptions,
    RequestResult,
)

__all__ = [
    # Directory
    "ServiceDirectory",
    "ServiceEntry",
    "ServiceQuery",
    # Provider
    "Provider",
    "ProviderConfig",
    "ProviderStatus",
    # Functions
    "provide",
    "ProvideOptions",
    "request",
    "RequestOptions",
    "RequestResult",
]
