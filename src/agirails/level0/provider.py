"""
Provider class for AGIRAILS Level 0 API.

Provides:
- Provider: Base class for service providers
- ProviderConfig: Provider configuration
- ProviderStatus: Provider status enum

The Provider class represents an entity that offers services
through the ACTP protocol. It manages service registration,
transaction handling, and lifecycle management.
"""

from __future__ import annotations

import asyncio
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Set, Union

from agirails.level0.directory import ServiceDirectory, ServiceEntry
from agirails.utils.logging import get_logger

if TYPE_CHECKING:
    from agirails.core import ACTPClient

_logger = get_logger(__name__)


class ProviderStatus(Enum):
    """Provider lifecycle status."""

    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ProviderConfig:
    """
    Provider configuration.

    Attributes:
        address: Ethereum address for this provider
        name: Human-readable provider name
        description: Provider description
        max_concurrent: Maximum concurrent jobs
        poll_interval: Interval in seconds for polling transactions
        auto_start: Whether to start automatically when services are added
    """

    address: Optional[str] = None
    name: str = ""
    description: str = ""
    max_concurrent: int = 10
    poll_interval: float = 5.0
    auto_start: bool = False


# Type for service handler functions
ServiceHandler = Callable[[Dict[str, Any]], Union[Awaitable[Any], Any]]


@dataclass
class RegisteredService:
    """
    Internal representation of a registered service handler.

    Attributes:
        entry: Service directory entry
        handler: Handler function for processing requests
        registered_at: When the service was registered
    """

    entry: ServiceEntry
    handler: ServiceHandler
    registered_at: datetime = field(default_factory=datetime.now)


class Provider:
    """
    Base class for service providers.

    Manages service registration, transaction polling, and request handling.
    Providers register services with handlers that process incoming requests.

    Example:
        >>> provider = Provider(ProviderConfig(address="0x..."))
        >>>
        >>> @provider.service("echo")
        ... async def echo_handler(data):
        ...     return data
        >>>
        >>> await provider.start()
    """

    def __init__(
        self,
        config: Optional[ProviderConfig] = None,
        client: "Optional[ACTPClient]" = None,
        directory: Optional[ServiceDirectory] = None,
    ) -> None:
        """
        Initialize provider.

        Args:
            config: Provider configuration
            client: ACTP client for blockchain interactions
            directory: Service directory (uses global if not provided)
        """
        self._config = config or ProviderConfig()
        self._client = client
        self._directory = directory or ServiceDirectory()
        self._status = ProviderStatus.IDLE
        self._services: Dict[str, RegisteredService] = {}
        self._lock = threading.RLock()
        self._poll_task: Optional[asyncio.Task[None]] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._active_jobs: Set[str] = set()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._started_at: Optional[datetime] = None
        self._stopped_at: Optional[datetime] = None

        # Statistics
        self._stats = {
            "jobs_received": 0,
            "jobs_completed": 0,
            "jobs_failed": 0,
            "total_earnings": 0.0,
        }

    @property
    def status(self) -> ProviderStatus:
        """Get current provider status."""
        return self._status

    @property
    def address(self) -> Optional[str]:
        """Get provider address."""
        if self._client is not None:
            return self._client.address
        return self._config.address

    @property
    def services(self) -> List[str]:
        """Get list of registered service names."""
        with self._lock:
            return list(self._services.keys())

    @property
    def directory(self) -> ServiceDirectory:
        """Get the service directory."""
        return self._directory

    @property
    def stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return self._stats.copy()

    @property
    def is_running(self) -> bool:
        """Check if provider is running."""
        return self._status == ProviderStatus.RUNNING

    def register_service(
        self,
        name: str,
        handler: ServiceHandler,
        description: str = "",
        capabilities: Optional[List[str]] = None,
        schema: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ServiceEntry:
        """
        Register a service with a handler.

        Args:
            name: Unique service identifier
            handler: Async or sync function to handle requests
            description: Human-readable description
            capabilities: List of capability tags
            schema: Optional JSON schema for input validation
            metadata: Additional metadata

        Returns:
            The created ServiceEntry

        Raises:
            ValueError: If service already registered
        """
        with self._lock:
            if name in self._services:
                raise ValueError(f"Service '{name}' is already registered")

            # Register in directory
            entry = self._directory.register(
                name=name,
                description=description,
                capabilities=capabilities,
                schema=schema,
                provider_address=self.address,
                metadata=metadata,
            )

            # Store handler
            self._services[name] = RegisteredService(
                entry=entry,
                handler=handler,
            )

            return entry

    def unregister_service(self, name: str) -> bool:
        """
        Unregister a service.

        Args:
            name: Service identifier to remove

        Returns:
            True if service was removed
        """
        with self._lock:
            if name not in self._services:
                return False

            del self._services[name]
            self._directory.unregister(name)
            return True

    def service(
        self,
        name: str,
        description: str = "",
        capabilities: Optional[List[str]] = None,
        schema: Optional[Dict[str, Any]] = None,
    ) -> Callable[[ServiceHandler], ServiceHandler]:
        """
        Decorator to register a service handler.

        Args:
            name: Unique service identifier
            description: Human-readable description
            capabilities: List of capability tags
            schema: Optional JSON schema for input validation

        Returns:
            Decorator function

        Example:
            >>> @provider.service("echo", description="Echo service")
            ... async def echo(data):
            ...     return data
        """

        def decorator(handler: ServiceHandler) -> ServiceHandler:
            self.register_service(
                name=name,
                handler=handler,
                description=description,
                capabilities=capabilities,
                schema=schema,
            )
            return handler

        return decorator

    def get_handler(self, service_name: str) -> Optional[ServiceHandler]:
        """
        Get the handler for a service.

        Args:
            service_name: Service identifier

        Returns:
            Handler function if found, None otherwise
        """
        with self._lock:
            registered = self._services.get(service_name)
            return registered.handler if registered else None

    async def start(self) -> None:
        """
        Start the provider.

        Begins polling for incoming transactions and processing requests.

        Raises:
            RuntimeError: If provider is already running
        """
        if self._status == ProviderStatus.RUNNING:
            raise RuntimeError("Provider is already running")

        _logger.info(
            "Starting provider",
            extra={
                "provider": self._config.name or "unnamed",
                "max_concurrent": self._config.max_concurrent,
                "services": len(self._services),
            },
        )

        self._status = ProviderStatus.STARTING
        self._stop_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent)
        self._started_at = datetime.now()
        self._stopped_at = None

        # Start polling task
        self._poll_task = asyncio.create_task(self._poll_loop())

        self._status = ProviderStatus.RUNNING
        _logger.info(
            "Provider started successfully",
            extra={"provider": self._config.name or "unnamed", "address": self.address},
        )

    async def stop(self) -> None:
        """
        Stop the provider.

        Stops polling and waits for active jobs to complete.
        """
        if self._status not in (ProviderStatus.RUNNING, ProviderStatus.STARTING):
            return

        _logger.info(
            "Stopping provider",
            extra={"provider": self._config.name or "unnamed", "active_jobs": len(self._active_jobs)},
        )
        self._status = ProviderStatus.STOPPING

        # Signal stop
        if self._stop_event is not None:
            self._stop_event.set()

        # Wait for poll task
        if self._poll_task is not None:
            try:
                await asyncio.wait_for(self._poll_task, timeout=30.0)
            except asyncio.TimeoutError:
                _logger.warning(
                    "Poll task timeout, cancelling",
                    extra={"provider": self._config.name or "unnamed"},
                )
                self._poll_task.cancel()
                try:
                    await self._poll_task
                except asyncio.CancelledError:
                    pass

        self._poll_task = None
        self._stopped_at = datetime.now()
        self._status = ProviderStatus.STOPPED
        _logger.info(
            "Provider stopped",
            extra={"provider": self._config.name or "unnamed", "stats": self._stats},
        )

    async def _poll_loop(self) -> None:
        """Main polling loop for incoming transactions."""
        _logger.debug("Starting poll loop", extra={"provider": self._config.name or "unnamed"})
        while self._stop_event is not None and not self._stop_event.is_set():
            try:
                await self._poll_for_requests()
            except Exception as e:
                _logger.error(
                    "Error in poll loop",
                    extra={
                        "provider": self._config.name or "unnamed",
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    },
                )

            # Wait for interval or stop signal
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.poll_interval,
                )
                break  # Stop event was set
            except asyncio.TimeoutError:
                continue  # Normal timeout, continue polling
        _logger.debug("Poll loop ended", extra={"provider": self._config.name or "unnamed"})

    async def _poll_for_requests(self) -> None:
        """
        Poll for incoming service requests.

        This is a placeholder that would be implemented with
        actual blockchain polling in a full implementation.
        """
        # In a real implementation, this would:
        # 1. Query the blockchain for pending transactions for our services
        # 2. Filter transactions by our registered service names
        # 3. Create tasks to handle each transaction
        pass

    async def handle_request(
        self,
        service_name: str,
        input_data: Dict[str, Any],
        transaction_id: Optional[str] = None,
    ) -> Any:
        """
        Handle a service request.

        Args:
            service_name: Name of the service to invoke
            input_data: Input data for the service
            transaction_id: Optional transaction ID for tracking

        Returns:
            Service handler result

        Raises:
            ValueError: If service not found
            RuntimeError: If provider not running
        """
        if self._status != ProviderStatus.RUNNING:
            raise RuntimeError("Provider is not running")

        handler = self.get_handler(service_name)
        if handler is None:
            raise ValueError(f"Service '{service_name}' not found")

        # Track job
        job_id = transaction_id or f"local-{id(input_data)}"
        self._active_jobs.add(job_id)
        self._stats["jobs_received"] += 1

        _logger.debug(
            "Handling request",
            extra={
                "provider": self._config.name or "unnamed",
                "service": service_name,
                "job_id": job_id,
            },
        )

        try:
            # Acquire semaphore for concurrency control
            if self._semaphore is not None:
                async with self._semaphore:
                    result = handler(input_data)
                    if asyncio.iscoroutine(result):
                        result = await result
            else:
                result = handler(input_data)
                if asyncio.iscoroutine(result):
                    result = await result

            self._stats["jobs_completed"] += 1
            _logger.info(
                "Request completed",
                extra={
                    "provider": self._config.name or "unnamed",
                    "service": service_name,
                    "job_id": job_id,
                },
            )
            return result

        except Exception as e:
            self._stats["jobs_failed"] += 1
            _logger.error(
                "Request failed",
                extra={
                    "provider": self._config.name or "unnamed",
                    "service": service_name,
                    "job_id": job_id,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                },
            )
            raise

        finally:
            self._active_jobs.discard(job_id)

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"Provider(status={self._status.value}, "
            f"services={len(self._services)})"
        )


async def create_provider(
    config: Optional[ProviderConfig] = None,
    client: "Optional[ACTPClient]" = None,
) -> Provider:
    """
    Factory function to create a Provider.

    Args:
        config: Provider configuration
        client: ACTP client for blockchain interactions

    Returns:
        Configured Provider instance
    """
    return Provider(config=config, client=client)
