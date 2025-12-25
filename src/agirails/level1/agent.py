"""
Agent class for AGIRAILS Level 1 API.

The Agent is the main class for building AI agent services. It handles:
- Service registration and job routing
- Job lifecycle management
- Polling for incoming transactions
- Concurrency control
- Event emission

Security Features (from TS SDK):
- C-1: Race condition prevention via processing locks
- C-2: Memory leak prevention via LRUCache for jobs
- MEDIUM-4: Concurrency limiting via Semaphore
- H-1: Filtered queries for transaction polling
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Union

from agirails.client import ACTPClient
from agirails.errors import NoProviderFoundError
from agirails.utils.logging import get_logger

# Module logger
_logger = get_logger(__name__)
from agirails.level1.config import (
    AgentConfig,
    NetworkOption,
    ServiceConfig,
    ServiceFilter,
)
from agirails.level1.job import Job, JobContext, JobHandler, JobResult
from agirails.level1.pricing import (
    DEFAULT_PRICING_STRATEGY,
    PricingStrategy,
    calculate_price,
)
from agirails.runtime.types import State
from agirails.utils.helpers import USDC, ServiceHash, ServiceMetadata
from agirails.utils.security import LRUCache
from agirails.utils.semaphore import Semaphore


class AgentStatus(str, Enum):
    """Agent lifecycle status."""

    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass
class AgentStats:
    """Agent statistics."""

    jobs_received: int = 0
    jobs_completed: int = 0
    jobs_failed: int = 0
    total_earned: float = 0.0
    total_spent: float = 0.0
    average_job_time: float = 0.0
    success_rate: float = 0.0

    def update_success_rate(self) -> None:
        """Recalculate success rate."""
        total = self.jobs_completed + self.jobs_failed
        if total > 0:
            self.success_rate = self.jobs_completed / total * 100


@dataclass
class AgentBalance:
    """Agent balance information."""

    eth: str = "0"
    usdc: str = "0.00"
    locked: str = "0.00"
    pending: str = "0.00"


@dataclass
class _ServiceRegistration:
    """Internal service registration."""

    config: ServiceConfig
    handler: JobHandler


class Agent:
    """
    Agent for processing jobs via ACTP protocol.

    The Agent is the main class for building AI services. Register services
    with handlers using `provide()`, then start the agent to begin
    processing jobs.

    Example:
        >>> agent = Agent(AgentConfig(name="echo-agent", network="mock"))
        >>>
        >>> @agent.provide("echo")
        ... async def handle_echo(job: Job, ctx: JobContext):
        ...     return {"echo": job.input}
        >>>
        >>> await agent.start()

    Security Features:
        - Race condition prevention (processing locks)
        - Memory leak prevention (LRU cache)
        - Concurrency limiting (semaphore)
    """

    # LRU cache limits (security measure C-2)
    MAX_ACTIVE_JOBS = 1000
    MAX_PROCESSED_JOBS = 10000

    # Polling interval in seconds
    POLL_INTERVAL = 2.0

    def __init__(self, config: AgentConfig) -> None:
        """
        Initialize agent.

        Args:
            config: Agent configuration
        """
        self._config = config
        self._status = AgentStatus.IDLE
        self._client: Optional[ACTPClient] = None

        # Service registrations
        self._services: Dict[str, _ServiceRegistration] = {}

        # Job tracking (security measure C-2: LRU cache)
        self._active_jobs: LRUCache[str, Job] = LRUCache(self.MAX_ACTIVE_JOBS)
        self._processed_jobs: LRUCache[str, bool] = LRUCache(self.MAX_PROCESSED_JOBS)

        # Race condition prevention (security measure C-1)
        self._processing_locks: Set[str] = set()

        # Concurrency control (security measure MEDIUM-4)
        behavior = config.get_behavior()
        self._concurrency_semaphore = Semaphore(behavior.concurrency)

        # Statistics
        self._stats = AgentStats()
        self._balance = AgentBalance()

        # Event handlers
        self._event_handlers: Dict[str, List[Callable[..., Any]]] = {}

        # Polling task
        self._polling_task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()

        # Generated address (if wallet not provided)
        self._address = self._resolve_address()

    # ═══════════════════════════════════════════════════════════
    # Properties
    # ═══════════════════════════════════════════════════════════

    @property
    def name(self) -> str:
        """Get agent name."""
        return self._config.name

    @property
    def description(self) -> str:
        """Get agent description."""
        return self._config.description

    @property
    def network(self) -> NetworkOption:
        """Get network mode."""
        return self._config.network

    @property
    def status(self) -> AgentStatus:
        """Get current status."""
        return self._status

    @property
    def address(self) -> str:
        """Get agent's Ethereum address."""
        return self._address

    @property
    def service_names(self) -> List[str]:
        """Get list of registered service names."""
        return list(self._services.keys())

    @property
    def jobs(self) -> List[Job]:
        """Get list of active jobs."""
        return list(self._active_jobs.values())

    @property
    def stats(self) -> AgentStats:
        """Get agent statistics."""
        return self._stats

    @property
    def balance(self) -> AgentBalance:
        """Get cached balance (use get_balance_async for real-time)."""
        return self._balance

    @property
    def client(self) -> Optional[ACTPClient]:
        """Get underlying ACTP client."""
        return self._client

    # ═══════════════════════════════════════════════════════════
    # Lifecycle Methods
    # ═══════════════════════════════════════════════════════════

    async def start(self) -> None:
        """
        Start the agent.

        Initializes the ACTP client and begins polling for jobs.

        Raises:
            RuntimeError: If agent is already running
        """
        if self._status in (AgentStatus.RUNNING, AgentStatus.STARTING):
            raise RuntimeError(f"Agent is already {self._status.value}")

        _logger.info(
            "Starting agent",
            extra={"agent": self.name, "network": self.network},
        )

        self._status = AgentStatus.STARTING
        self._emit("starting")

        try:
            # Initialize client
            self._client = await ACTPClient.create(
                mode=self._config.network,
                requester_address=self._address,
                state_directory=self._config.state_directory,
                rpc_url=self._config.rpc_url,
            )

            # Update balance
            await self._update_balance()

            # Start polling
            self._stop_event.clear()
            self._polling_task = asyncio.create_task(self._poll_loop())

            self._status = AgentStatus.RUNNING
            self._emit("started")

            _logger.info(
                "Agent started successfully",
                extra={
                    "agent": self.name,
                    "address": self.address,
                    "services": self.service_names,
                },
            )

        except Exception as e:
            _logger.error(
                "Failed to start agent",
                extra={
                    "agent": self.name,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                },
            )
            self._status = AgentStatus.STOPPED
            self._emit("error", e)
            raise

    async def stop(self) -> None:
        """
        Stop the agent.

        Gracefully stops polling and waits for active jobs to complete.
        """
        if self._status == AgentStatus.STOPPED:
            return

        _logger.info(
            "Stopping agent",
            extra={"agent": self.name, "active_jobs": self._active_jobs.size},
        )

        self._status = AgentStatus.STOPPING
        self._emit("stopping")

        # Signal polling to stop
        self._stop_event.set()

        # Wait for polling task to finish
        if self._polling_task is not None:
            try:
                await asyncio.wait_for(self._polling_task, timeout=5.0)
            except asyncio.TimeoutError:
                _logger.warning(
                    "Polling task did not stop in time, cancelling",
                    extra={"agent": self.name},
                )
                self._polling_task.cancel()
                try:
                    await self._polling_task
                except asyncio.CancelledError:
                    pass
            self._polling_task = None

        # Wait for active jobs (with timeout)
        await self._wait_for_active_jobs(timeout_ms=30000)

        self._status = AgentStatus.STOPPED
        self._emit("stopped")

        _logger.info(
            "Agent stopped",
            extra={
                "agent": self.name,
                "jobs_completed": self._stats.jobs_completed,
                "jobs_failed": self._stats.jobs_failed,
            },
        )

    def pause(self) -> None:
        """Pause the agent (stop accepting new jobs)."""
        if self._status == AgentStatus.RUNNING:
            self._status = AgentStatus.PAUSED
            self._emit("paused")

    def resume(self) -> None:
        """Resume the agent (start accepting new jobs)."""
        if self._status == AgentStatus.PAUSED:
            self._status = AgentStatus.RUNNING
            self._emit("resumed")

    async def restart(self) -> None:
        """Restart the agent."""
        await self.stop()
        await self.start()

    # ═══════════════════════════════════════════════════════════
    # Service Registration
    # ═══════════════════════════════════════════════════════════

    def provide(
        self,
        service: Union[str, ServiceConfig],
        handler: Optional[JobHandler] = None,
        *,
        filter: Optional[ServiceFilter] = None,
        pricing: Optional[PricingStrategy] = None,
        timeout: Optional[int] = None,
    ) -> Union[Agent, Callable[[JobHandler], JobHandler]]:
        """
        Register a service handler.

        Can be used as a method or decorator:

        Method:
            >>> agent.provide("echo", handler, filter=ServiceFilter(min_budget=0.10))

        Decorator:
            >>> @agent.provide("echo")
            ... async def handler(job, ctx):
            ...     return job.input

        Args:
            service: Service name or ServiceConfig
            handler: Job handler function (optional if using as decorator)
            filter: Optional filter for incoming jobs
            pricing: Optional pricing strategy
            timeout: Optional timeout override

        Returns:
            Self (for chaining) or decorator function
        """
        # Build ServiceConfig
        if isinstance(service, str):
            config = ServiceConfig(
                name=service,
                filter=filter,
                pricing=pricing,
                timeout=timeout,
            )
        else:
            config = service

        # If handler provided, register directly
        if handler is not None:
            self._register_service(config, handler)
            return self

        # Otherwise, return decorator
        def decorator(fn: JobHandler) -> JobHandler:
            self._register_service(config, fn)
            return fn

        return decorator

    def _register_service(self, config: ServiceConfig, handler: JobHandler) -> None:
        """Register a service internally."""
        self._services[config.name] = _ServiceRegistration(
            config=config,
            handler=handler,
        )
        self._emit("service:registered", config.name)

    # ═══════════════════════════════════════════════════════════
    # Request (as requester)
    # ═══════════════════════════════════════════════════════════

    async def request(
        self,
        service: str,
        input: Any,
        *,
        provider: Optional[str] = None,
        budget: float,
        timeout: int = 300,
    ) -> Any:
        """
        Make a request to another agent's service.

        Args:
            service: Service name to request
            input: Input data for the service
            provider: Specific provider address (optional)
            budget: Budget in USDC
            timeout: Timeout in seconds

        Returns:
            Service result

        Raises:
            NoProviderFoundError: If no provider found for service
            TimeoutError: If request times out
        """
        if self._client is None:
            raise RuntimeError("Agent not started")

        # Find provider if not specified
        if provider is None:
            # Import here to avoid circular import
            from agirails.level0.directory import service_directory

            entry = service_directory.find_one(service)
            if entry is None:
                raise NoProviderFoundError(service)
            provider = entry.provider_address

        # Create service metadata
        metadata = ServiceMetadata(service=service, input=input)
        service_hash = ServiceHash.hash(metadata)

        # Create transaction
        tx_id = await self._client.intermediate.create_transaction(
            {
                "provider": provider,
                "amount": budget,
                "description": service_hash,
            }
        )

        # Link escrow
        await self._client.intermediate.link_escrow(tx_id)

        # Wait for completion
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Request timed out after {timeout}s")

            tx = await self._client.intermediate.get_transaction(tx_id)
            if tx is None:
                raise RuntimeError(f"Transaction {tx_id} not found")

            if tx.state == "SETTLED":
                # Get result from delivery proof
                return {"tx_id": tx_id, "status": "completed"}

            if tx.state == "CANCELLED":
                raise RuntimeError("Transaction was cancelled")

            await asyncio.sleep(1.0)

    # ═══════════════════════════════════════════════════════════
    # Balance
    # ═══════════════════════════════════════════════════════════

    async def get_balance_async(self) -> AgentBalance:
        """
        Get real-time balance.

        Returns:
            Current balance information
        """
        await self._update_balance()
        return self._balance

    async def _update_balance(self) -> None:
        """Update cached balance from client."""
        if self._client is not None:
            usdc = await self._client.get_balance(self._address)
            self._balance.usdc = usdc

    # ═══════════════════════════════════════════════════════════
    # Events
    # ═══════════════════════════════════════════════════════════

    def on(self, event: str, handler: Callable[..., Any]) -> Callable[[], None]:
        """
        Register an event handler.

        Args:
            event: Event name
            handler: Handler function

        Returns:
            Function to unregister the handler

        Events:
            - starting: Agent is starting
            - started: Agent started
            - stopping: Agent is stopping
            - stopped: Agent stopped
            - paused: Agent paused
            - resumed: Agent resumed
            - error: Error occurred
            - job:received: New job received
            - job:started: Job processing started
            - job:completed: Job completed successfully
            - job:failed: Job failed
            - job:progress: Job progress update
            - service:registered: Service registered
            - log: Log message
        """
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)

        def unregister() -> None:
            if event in self._event_handlers:
                handlers = self._event_handlers[event]
                if handler in handlers:
                    handlers.remove(handler)

        return unregister

    def _emit(self, event: str, *args: Any) -> None:
        """Emit an event to all handlers."""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    handler(*args)
                except Exception:
                    # Don't let handler errors break the agent
                    pass

    # ═══════════════════════════════════════════════════════════
    # Internal: Polling
    # ═══════════════════════════════════════════════════════════

    async def _poll_loop(self) -> None:
        """Main polling loop for incoming transactions."""
        _logger.debug("Starting poll loop", extra={"agent": self.name})
        while not self._stop_event.is_set():
            try:
                await self._poll_for_jobs()
            except Exception as e:
                _logger.error(
                    "Error in poll loop",
                    extra={
                        "agent": self.name,
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    },
                )
                self._emit("error", e)

            # Wait for next poll interval or stop signal
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.POLL_INTERVAL,
                )
                _logger.debug("Poll loop received stop signal", extra={"agent": self.name})
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Continue polling
        _logger.debug("Poll loop ended", extra={"agent": self.name})

    async def _poll_for_jobs(self) -> None:
        """Poll for new jobs from transactions."""
        if self._client is None:
            return

        if self._status != AgentStatus.RUNNING:
            return

        # Get transactions addressed to this agent (H-1: filtered query)
        try:
            transactions = await self._client.runtime.get_transactions_by_provider(
                self._address,
                state=State.COMMITTED,
                limit=100,
            )
        except Exception as e:
            _logger.warning(
                "Failed to poll transactions",
                extra={"agent": self.name, "error": str(e)},
            )
            return

        if transactions:
            _logger.debug(
                "Found transactions to process",
                extra={"agent": self.name, "count": len(transactions)},
            )

        for tx in transactions:
            await self._process_transaction(tx)

    async def _process_transaction(self, tx: Any) -> None:
        """Process a single transaction."""
        tx_id = tx.id

        # Skip if already processed (C-1: race prevention)
        if self._processed_jobs.has(tx_id):
            return

        # Skip if currently processing (C-1: race prevention)
        if tx_id in self._processing_locks:
            return

        # Mark as processing
        self._processing_locks.add(tx_id)

        try:
            # Find matching service handler
            registration = self._find_service_handler(tx)
            if registration is None:
                # No handler for this service
                self._processed_jobs.set(tx_id, True)
                return

            # Check auto-accept
            job = self._create_job_from_transaction(tx, registration.config.name)
            if not await self._should_auto_accept(job, registration):
                self._processed_jobs.set(tx_id, True)
                return

            # Add to active jobs
            self._active_jobs.set(tx_id, job)
            self._stats.jobs_received += 1
            self._emit("job:received", job)

            # Process job with concurrency control
            asyncio.create_task(self._process_job(job, registration))

        finally:
            self._processing_locks.discard(tx_id)

    def _find_service_handler(self, tx: Any) -> Optional[_ServiceRegistration]:
        """Find service handler for a transaction."""
        service_name = self._extract_service_name(tx)
        if service_name is None:
            return None

        # Exact match only (no substring matching for security)
        return self._services.get(service_name)

    def _extract_service_name(self, tx: Any) -> Optional[str]:
        """Extract service name from transaction."""
        service_desc = getattr(tx, "service_description", None)
        if not service_desc:
            return None

        # Try to parse as ServiceMetadata hash
        try:
            metadata = ServiceHash.from_legacy(service_desc)
            if metadata:
                return metadata.service
        except Exception:
            pass

        return None

    def _extract_job_input(self, tx: Any) -> Any:
        """Extract job input from transaction."""
        service_desc = getattr(tx, "service_description", None)
        if not service_desc:
            return None

        try:
            metadata = ServiceHash.from_legacy(service_desc)
            if metadata:
                return metadata.input
        except Exception:
            pass

        return None

    def _create_job_from_transaction(self, tx: Any, service_name: str) -> Job:
        """Create Job from transaction."""
        return Job(
            id=tx.id,
            service=service_name,
            input=self._extract_job_input(tx),
            budget=float(USDC.from_wei(tx.amount)),
            deadline=datetime.fromtimestamp(tx.deadline),
            requester=tx.requester,
            metadata={
                "tx_id": tx.id,
                "service_description": getattr(tx, "service_description", None),
            },
        )

    async def _should_auto_accept(
        self, job: Job, registration: _ServiceRegistration
    ) -> bool:
        """Determine if job should be auto-accepted."""
        behavior = self._config.get_behavior()

        # Check service filter
        if not registration.config.matches_job(job):
            return False

        # Check pricing strategy
        pricing = registration.config.pricing or DEFAULT_PRICING_STRATEGY
        price_calc = calculate_price(pricing, job)
        if price_calc.decision == "reject":
            return False

        # Check auto_accept setting
        if isinstance(behavior.auto_accept, bool):
            return behavior.auto_accept

        # Call auto_accept function
        result = behavior.auto_accept(job)
        if hasattr(result, "__await__"):
            return await result
        return result

    # ═══════════════════════════════════════════════════════════
    # Internal: Job Processing
    # ═══════════════════════════════════════════════════════════

    async def _process_job(self, job: Job, registration: _ServiceRegistration) -> None:
        """Process a job with concurrency control."""
        # Acquire semaphore (MEDIUM-4: concurrency limiting)
        acquired = await self._concurrency_semaphore.acquire(timeout_ms=60000)
        if not acquired:
            self._emit("job:failed", job, "Concurrency limit reached")
            return

        try:
            await self._execute_job(job, registration)
        finally:
            self._concurrency_semaphore.release()

    async def _execute_job(self, job: Job, registration: _ServiceRegistration) -> None:
        """Execute a job handler."""
        self._emit("job:started", job)
        start_time = asyncio.get_event_loop().time()

        try:
            # Create context
            ctx = JobContext(self, job)

            # Get timeout
            behavior = self._config.get_behavior()
            timeout = registration.config.get_timeout(behavior.timeout)

            # Execute handler with timeout
            try:
                result = await asyncio.wait_for(
                    registration.handler(job, ctx),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"Job timed out after {timeout}s")

            # Handle result
            if isinstance(result, JobResult):
                if result.success:
                    await self._complete_job(job, result.output)
                else:
                    await self._fail_job(job, result.error or "Unknown error")
            else:
                # Treat any return value as success
                await self._complete_job(job, result)

        except Exception as e:
            await self._fail_job(job, str(e))

        finally:
            # Update stats
            elapsed = asyncio.get_event_loop().time() - start_time
            self._update_job_stats(elapsed)

            # Mark as processed
            self._processed_jobs.set(job.id, True)
            self._active_jobs.delete(job.id)

    async def _complete_job(self, job: Job, output: Any) -> None:
        """Mark job as completed."""
        self._stats.jobs_completed += 1
        self._stats.total_earned += job.budget
        self._stats.update_success_rate()

        _logger.info(
            "Job completed",
            extra={
                "agent": self.name,
                "job_id": job.id,
                "service": job.service,
                "budget": job.budget,
            },
        )

        # Transition to DELIVERED
        if self._client is not None:
            try:
                await self._client.intermediate.transition_state(job.id, "DELIVERED")
            except Exception as e:
                _logger.warning(
                    "Failed to transition job to DELIVERED",
                    extra={"job_id": job.id, "error": str(e)},
                )

        self._emit("job:completed", job, output)

    async def _fail_job(self, job: Job, error: str) -> None:
        """Mark job as failed."""
        self._stats.jobs_failed += 1
        self._stats.update_success_rate()

        _logger.error(
            "Job failed",
            extra={
                "agent": self.name,
                "job_id": job.id,
                "service": job.service,
                "error": error,
            },
        )

        self._emit("job:failed", job, error)

    def _update_job_stats(self, elapsed: float) -> None:
        """Update average job time."""
        total_jobs = self._stats.jobs_completed + self._stats.jobs_failed
        if total_jobs > 0:
            current_avg = self._stats.average_job_time
            self._stats.average_job_time = (
                current_avg * (total_jobs - 1) + elapsed
            ) / total_jobs

    async def _wait_for_active_jobs(self, timeout_ms: int) -> None:
        """Wait for active jobs to complete."""
        timeout = timeout_ms / 1000
        start = asyncio.get_event_loop().time()

        while self._active_jobs.size > 0:
            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                break
            await asyncio.sleep(0.1)

    # ═══════════════════════════════════════════════════════════
    # Internal: Address Generation
    # ═══════════════════════════════════════════════════════════

    def _resolve_address(self) -> str:
        """Resolve or generate agent address."""
        if self._config.wallet:
            # If it looks like a private key (64 hex chars), derive address
            wallet = self._config.wallet
            if len(wallet) == 64 or (len(wallet) == 66 and wallet.startswith("0x")):
                # For now, just generate a deterministic address from the key
                # In real implementation, use eth_account to derive address
                key_bytes = bytes.fromhex(wallet.replace("0x", ""))
                addr_hash = hashlib.sha256(key_bytes).hexdigest()
                return "0x" + addr_hash[:40]
            # Otherwise it's an address
            return wallet.lower()

        # Generate random address for testing
        return "0x" + secrets.token_hex(20)

    # ═══════════════════════════════════════════════════════════
    # String Representation
    # ═══════════════════════════════════════════════════════════

    def __repr__(self) -> str:
        """Safe string representation (no private keys)."""
        return (
            f"Agent(name={self.name!r}, network={self.network!r}, "
            f"status={self.status.value!r}, services={self.service_names!r})"
        )
