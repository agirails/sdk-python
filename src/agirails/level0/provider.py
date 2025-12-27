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
    from agirails.client import ACTPClient

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

        PARITY: Matches TypeScript SDK's Agent.pollForJobs() method.

        Queries runtime for transactions where this provider is assigned
        and the transaction is in INITIATED state. For each pending
        transaction, links escrow to accept the job and processes it.
        """
        if self._client is None:
            return

        try:
            # Query for transactions assigned to this provider in INITIATED state
            runtime = self._client.runtime
            pending_txs: List[Any] = []  # Can be MockTransaction objects or dicts

            # Check if runtime has filtered query method
            if hasattr(runtime, "get_transactions_by_provider"):
                # Use optimized filtered query (max 100 per poll)
                pending_txs = await runtime.get_transactions_by_provider(
                    self.address,
                    state="INITIATED",
                    limit=100,
                )
            elif hasattr(runtime, "get_all_transactions"):
                # Fallback to getting all and filtering
                all_txs = await runtime.get_all_transactions()
                # PARITY FIX: Use attribute access for MockTransaction objects
                pending_txs = [
                    tx for tx in all_txs
                    if self._get_tx_field(tx, "provider") == self.address
                    and self._get_tx_field(tx, "state") == "INITIATED"
                ]

            if not pending_txs:
                return

            _logger.debug(
                f"Found {len(pending_txs)} pending transactions",
                extra={"provider": self._config.name or "unnamed"},
            )

            # Process each pending transaction
            for tx in pending_txs:
                tx_id = self._get_tx_field(tx, "id") or ""
                try:
                    # Skip if already being processed
                    if tx_id in self._active_jobs:
                        continue

                    # Find handler for this service
                    service_name = self._extract_service_name(tx)
                    handler = self.get_handler(service_name)
                    if handler is None:
                        _logger.debug(
                            f"No handler for service '{service_name}'",
                            extra={"tx_id": tx_id[:18]},
                        )
                        continue

                    # Mark as active to prevent reprocessing
                    self._active_jobs.add(tx_id)

                    # Link escrow to accept the job (transitions INITIATED -> COMMITTED)
                    amount = self._get_tx_field(tx, "amount") or "0"
                    if hasattr(runtime, "link_escrow"):
                        await runtime.link_escrow(tx_id, amount)

                    self._stats["jobs_received"] += 1
                    _logger.info(
                        "Job accepted",
                        extra={
                            "provider": self._config.name or "unnamed",
                            "service": service_name,
                            "tx_id": tx_id[:18],
                        },
                    )

                    # Process job asynchronously (don't await to continue polling)
                    asyncio.create_task(
                        self._process_job(tx_id, tx, service_name, handler)
                    )

                except Exception as e:
                    _logger.error(
                        f"Error processing transaction {tx_id[:18]}: {e}",
                        extra={"provider": self._config.name or "unnamed"},
                    )
                    self._active_jobs.discard(tx_id)

        except Exception as e:
            _logger.error(
                f"Polling error: {e}",
                extra={"provider": self._config.name or "unnamed"},
            )

    def _get_tx_field(self, tx: Any, field: str) -> Any:
        """
        Get a field from a transaction (supports both dict and MockTransaction).

        PARITY FIX: Runtime returns MockTransaction objects, not dicts.
        This helper handles both for compatibility.
        """
        # Handle dict
        if isinstance(tx, dict):
            return tx.get(field)

        # Handle MockTransaction object - use attribute access
        if hasattr(tx, field):
            value = getattr(tx, field)
            # State enum needs string value
            if field == "state" and hasattr(value, "value"):
                return value.value
            return value

        # Fallback for snake_case to camelCase mapping
        snake_field = self._to_snake_case(field)
        if hasattr(tx, snake_field):
            value = getattr(tx, snake_field)
            if hasattr(value, "value"):
                return value.value
            return value

        return None

    def _to_snake_case(self, name: str) -> str:
        """Convert camelCase to snake_case."""
        import re
        return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

    def _extract_service_name(self, tx: Any) -> str:
        """
        Extract service name from transaction metadata.

        PARITY FIX: Uses _get_tx_field for MockTransaction compatibility.

        Supports multiple formats:
        1. JSON: {"service": "name", "input": ...}
        2. Legacy: "service:name;input:..."
        3. Plain string (service name directly)
        """
        service_desc = (
            self._get_tx_field(tx, "serviceDescription")
            or self._get_tx_field(tx, "service_description")
            or ""
        )
        if not service_desc:
            return "unknown"

        # Try JSON format first
        try:
            import json
            parsed = json.loads(service_desc)
            if isinstance(parsed, dict) and "service" in parsed:
                return parsed["service"]
        except (json.JSONDecodeError, TypeError):
            pass

        # Try legacy format: "service:NAME;input:..."
        if service_desc.startswith("service:"):
            parts = service_desc.split(";", 1)
            if parts:
                return parts[0].replace("service:", "")

        # Plain string (if short enough)
        if len(service_desc) < 64:
            return service_desc

        return "unknown"

    def _extract_input(self, tx: Any) -> Any:
        """
        Extract input data from transaction metadata.

        PARITY FIX: Uses _get_tx_field for MockTransaction compatibility.

        Supports multiple formats:
        1. JSON: {"service": "name", "input": {...}}
        2. Legacy: "service:name;input:JSON"
        """
        service_desc = (
            self._get_tx_field(tx, "serviceDescription")
            or self._get_tx_field(tx, "service_description")
            or ""
        )
        if not service_desc:
            return {}

        # Try JSON format first
        try:
            import json
            parsed = json.loads(service_desc)
            if isinstance(parsed, dict) and "input" in parsed:
                return parsed["input"]
        except (json.JSONDecodeError, TypeError):
            pass

        # Try legacy format: "service:name;input:JSON"
        if ";input:" in service_desc:
            parts = service_desc.split(";input:", 1)
            if len(parts) > 1:
                try:
                    import json
                    return json.loads(parts[1])
                except (json.JSONDecodeError, TypeError):
                    return parts[1]

        return {}

    async def _process_job(
        self,
        tx_id: str,
        tx: Any,
        service_name: str,
        handler: ServiceHandler,
    ) -> None:
        """
        Process a job by invoking the handler and transitioning state.

        PARITY: Matches TypeScript SDK's Agent.processJob() method.

        Creates delivery proof with wrapper format:
        {
            type: 'delivery.proof',
            txId: ...,
            contentHash: ...,
            timestamp: ...,
            result: <handler_output>  // Original result included
        }
        """
        import json
        import time
        start_time = time.time()

        try:
            # Extract input from transaction
            input_data = self._extract_input(tx)

            # Call handler
            result = handler(input_data)
            if asyncio.iscoroutine(result):
                result = await result

            # Build delivery proof with wrapper format
            # PARITY: TS SDK Agent.ts creates: { ...deliveryProof, result }
            from agirails.builders.delivery_proof import compute_output_hash

            # Compute content hash
            # PARITY FIX: Use separators=(',', ':') to match JS JSON.stringify() (no whitespace)
            # PARITY FIX: Use ensure_ascii=False to match JS JSON.stringify() unicode handling
            deliverable = result if isinstance(result, str) else json.dumps(
                result, separators=(",", ":"), ensure_ascii=False
            )
            content_hash = compute_output_hash(deliverable)

            # Create wrapper matching TS SDK format
            # TS: { type: 'delivery.proof', txId, contentHash, timestamp, metadata, result }
            # PARITY FIX: Add size and mimeType to metadata (from TS ProofGenerator.ts)
            deliverable_size = len(deliverable.encode('utf-8')) if isinstance(deliverable, str) else len(deliverable)
            delivery_proof_wrapper = {
                "type": "delivery.proof",  # PARITY: Unique marker for request extraction
                "txId": tx_id,
                "contentHash": content_hash,
                "timestamp": int(time.time() * 1000),
                "metadata": {
                    "service": service_name,
                    "completedAt": int(time.time() * 1000),
                    "size": deliverable_size,  # PARITY: TS ProofGenerator includes size
                    "mimeType": "application/octet-stream",  # PARITY: TS ProofGenerator default mimeType
                },  # NOTE: TS does NOT include executionTimeMs
                "result": result,  # PARITY: Include original result for extraction
            }
            # PARITY FIX: Use ensure_ascii=False for unicode handling
            delivery_proof_json = json.dumps(delivery_proof_wrapper, ensure_ascii=False)

            # Transition to DELIVERED state with proof
            if self._client is not None:
                runtime = self._client.runtime

                # PARITY FIX: Pass proof to transition_state instead of separate set_delivery_proof
                # This matches TS SDK behavior where proof is stored during transition
                if hasattr(runtime, "transition_state"):
                    await runtime.transition_state(tx_id, "DELIVERED", proof=delivery_proof_json)

            # Update stats
            self._stats["jobs_completed"] += 1
            duration_ms = int((time.time() - start_time) * 1000)

            _logger.info(
                "Job completed",
                extra={
                    "provider": self._config.name or "unnamed",
                    "service": service_name,
                    "tx_id": tx_id[:18],
                    "duration_ms": duration_ms,
                },
            )

        except Exception as e:
            self._stats["jobs_failed"] += 1
            _logger.error(
                f"Job failed: {e}",
                extra={
                    "provider": self._config.name or "unnamed",
                    "service": service_name,
                    "tx_id": tx_id[:18],
                    "traceback": traceback.format_exc(),
                },
            )

        finally:
            self._active_jobs.discard(tx_id)

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
