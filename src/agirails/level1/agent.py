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
import json
import secrets
import time
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
    DEFAULT_DELIVERY_CONFIG,
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

# For ABI encoding dispute window proof
try:
    from eth_abi import encode as abi_encode
except ImportError:
    abi_encode = None  # Will raise error when used


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


class _TxLike:
    """Minimal tx-shaped view derived from a Job.

    Used as the event-payload source for ``_emit_job_decision`` when the
    original transaction object is not threaded through. Exposes ``id``,
    ``requester`` and ``amount`` (in USDC base units) so the decline/filter
    payload matches the on-chain-sourced shape.
    """

    __slots__ = ("id", "requester", "amount", "service_description")

    def __init__(self, job: Job) -> None:
        self.id = job.id
        self.requester = job.requester
        # Job.budget is human USDC; convert back to 6-decimal base units so the
        # payload's amount round-trips through _convert_amount_to_number.
        try:
            self.amount = str(int(round(job.budget * 1_000_000)))
        except (TypeError, ValueError):
            self.amount = "0"
        self.service_description = (job.metadata or {}).get("service_description")


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

    # Bounded transient retry (TS Agent.MAX_JOB_ATTEMPTS = 3). A non-kernel
    # failure (e.g. a handler throwing on bad input) is retried as transient;
    # after this many recurrences it is treated as permanent and marked
    # processed so polling does not retry it forever.
    MAX_JOB_ATTEMPTS = 3

    # Kernel revert reasons that signal a PERMANENT failure (the tx can never
    # make forward progress). Mirrors TS permanentRevertReasons
    # (Agent.ts:2033-2040). Matched against both plaintext and ABI-hex form.
    _PERMANENT_REVERT_REASONS = (
        "Transaction expired",  # ACTPKernel _enforceTiming after deadline
        "Invalid transition",   # _isValidTransition reject (no recovery path)
        "Only requester",       # wrong msg.sender for requester-only fn
        "Only provider",        # wrong msg.sender for provider-only fn
        "Not authorized",       # settle-before-window or wrong party
        "Not participant",      # attestation anchoring without standing
    )

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
        # PRD §5.4 / TS parity (Agent.ts:644): keep a reverse map from the
        # on-chain routing key keccak256(toUtf8Bytes(name)) → registration so
        # BlockchainRuntime transactions whose service_description is a
        # bytes32 hash can dispatch to the same handler that the mock /
        # JSON path uses. Without this, `actp request --service foo`
        # creates an INITIATED tx whose service_description=keccak("foo"),
        # but Agent.provide("foo") couldn't reach the handler from that.
        self._handlers_by_hash: Dict[str, _ServiceRegistration] = {}

        # Job tracking (security measure C-2: LRU cache)
        self._active_jobs: LRUCache[str, Job] = LRUCache(self.MAX_ACTIVE_JOBS)
        self._processed_jobs: LRUCache[str, bool] = LRUCache(self.MAX_PROCESSED_JOBS)
        # Per-job failure counter for bounded retry (TS jobAttempts LRUCache).
        self._job_attempts: LRUCache[str, int] = LRUCache(self.MAX_PROCESSED_JOBS)

        # Race condition prevention (security measure C-1)
        self._processing_locks: Set[str] = set()

        # AIP-2.1 ProviderOrchestrator seam (TS Agent._providerOrchestrator).
        # When set via set_provider_orchestrator(), the counter-offer pricing
        # path would route the quote through it (BYO-brain / injectable
        # decider). Optional — agents that don't opt in keep the legacy hash
        # path. Stored here so the Agent honors an injected orchestrator
        # exactly where TS does.
        self._provider_orchestrator: Optional[Any] = None

        # AIP-16 Phase 2e/3 — delivery hook dependencies. Captured from config;
        # mutable so _ensure_aip16_auto_wire() can lazy-fill missing deps when
        # ACTP_DELIVERY_CHANNEL=v1 is set. The hook activates only when ALL of
        # (channel, signer, kernel_address, chain_id) are present AND the flag
        # is set; otherwise it is a no-op and the legacy settlement path runs.
        self._delivery_channel: Optional[Any] = config.delivery_channel
        self._delivery_signer: Optional[Any] = config.delivery_signer
        self._kernel_address: Optional[str] = config.kernel_address
        self._chain_id: Optional[int] = config.chain_id
        self._smart_wallet_nonce: Optional[int] = config.smart_wallet_nonce

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
        description: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        delivery: Optional[Any] = None,
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
        # Build ServiceConfig. When given a string service name, accept the
        # full ServiceConfig field set via keyword options (TS provide accepts
        # a Partial<ServiceConfig> options arg — Agent.ts:771-810).
        if isinstance(service, str):
            config = ServiceConfig(
                name=service,
                description=description or "",
                filter=filter,
                pricing=pricing,
                capabilities=capabilities,
                timeout=timeout,
                delivery=delivery,
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
        registration = _ServiceRegistration(
            config=config,
            handler=handler,
        )
        self._services[config.name] = registration
        # PRD §5.4: index by keccak256(toUtf8Bytes(name)) too so on-chain
        # routing keys from `actp request --service <name>` and the TS
        # BuyerOrchestrator find the same handler. lower() matches the TS
        # convention (handlersByHash.set(hashKey, ...)) so cross-SDK
        # transactions dispatch identically.
        from eth_hash.auto import keccak as _keccak

        hash_key = "0x" + _keccak(config.name.encode("utf-8")).hex()
        self._handlers_by_hash[hash_key.lower()] = registration
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
        tx_id = await self._client.standard.create_transaction(
            {
                "provider": provider,
                "amount": budget,
                "description": service_hash,
            }
        )

        # Link escrow
        await self._client.standard.link_escrow(tx_id)

        # Wait for completion
        start_time = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Request timed out after {timeout}s")

            tx = await self._client.standard.get_transaction(tx_id)
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

    def set_provider_orchestrator(self, orchestrator: Any) -> None:
        """Attach an AIP-2.1 ProviderOrchestrator (BYO-brain seam).

        Mirrors TS ``Agent.setProviderOrchestrator`` (Agent.ts:972-974). Once
        set, the counter-offer pricing path can route the quote through the
        orchestrator (which builds a signed AIP-2 QuoteMessage and may honor an
        injected counter-decider) instead of the legacy ad-hoc hash.

        Optional — agents that never call this keep the pre-AIP-2.1 hash
        format which the buyer-side verifier still accepts via §3.6 legacy
        fallback during the migration grace window.
        """
        self._provider_orchestrator = orchestrator

    def safe_emit_error(self, error: Any) -> None:
        """Emit 'error' only when a listener is attached; otherwise log it.

        Mirrors TS ``safeEmitError`` (Agent.ts:1029-1035). A long-running
        provider agent must NOT die on an unobserved error. Python never raises
        on an unhandled event, but a silent no-op hides failures from
        operators, so when no 'error' listener is attached we log at error
        level instead of swallowing silently. Callers that DO attach an 'error'
        listener still receive every error unchanged.
        """
        handlers = self._event_handlers.get("error")
        if handlers:
            self._emit("error", error)
        else:
            _logger.error(
                "Agent error (no error listener attached; not crashing)",
                extra={"agent": self.name, "error": str(error)},
            )

    def _emit_job_decision(
        self,
        event: str,
        tx: Any,
        registration: Optional[_ServiceRegistration],
        detail: Dict[str, Any],
    ) -> None:
        """Emit a ``job:declined`` (economic) or ``job:filtered`` (policy) event.

        Mirrors TS ``emitJobDecision`` (Agent.ts:1651-1691). These two events
        fire MID-DECISION (right before ``_should_auto_accept`` returns), so a
        misbehaving listener must never affect the accept/decline outcome.
        We build the same machine-readable payload and swallow listener
        exceptions.

        Semantics:
          * ``job:declined``  — economic: budget/price out of band. The agent
            would take it at a different price.
          * ``job:filtered``  — policy: a custom predicate / legacy filter /
            auto-accept opt-out rejected it. Price is irrelevant.

        Payload (second arg; first arg is the Job like other job:* events):
          ``{jobId, requester, amount, reason, ...extra}``
        """
        job: Optional[Job] = None
        try:
            if registration is not None:
                job = self._create_job_from_transaction(tx, registration.config.name)
        except Exception:
            job = None

        payload: Dict[str, Any] = {
            "jobId": getattr(tx, "id", None),
            "requester": getattr(tx, "requester", None),
            "amount": self._convert_amount_to_number(getattr(tx, "amount", None)),
            **detail,
        }

        for handler in list(self._event_handlers.get(event, [])):
            try:
                result = handler(job, payload)
                # Swallow async-listener rejections too: schedule the coroutine
                # but attach a no-op exception handler so it can never crash the
                # decision path.
                if asyncio.iscoroutine(result):
                    task = asyncio.ensure_future(result)
                    task.add_done_callback(lambda t: t.exception())
            except Exception:
                # sync listener throw — swallowed; the decision continues.
                pass

    def _convert_amount_to_number(self, amount: Any) -> float:
        """Convert a USDC base-unit amount to a float (6 decimals).

        Mirrors TS ``convertAmountToNumber`` (Agent.ts:1794-1797).
        """
        if amount is None:
            return 0.0
        try:
            return int(amount) / 1_000_000
        except (TypeError, ValueError):
            return 0.0

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
                # TS safeEmitError: emit only when a listener is attached, else
                # log — never crash the long-running daemon on an unobserved
                # error.
                self.safe_emit_error(e)

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
            if not await self._should_auto_accept(job, registration, tx):
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
        """Find service handler for a transaction.

        Dispatch order (mirrors TS Agent.ts findServiceHandler):

          PRIMARY (PRD §5.4): match by keccak256(name) against
            ``_handlers_by_hash``. This is how on-chain BlockchainRuntime
            transactions route — service_description is the bytes32
            routing key, not parsable metadata.
          FALLBACK: legacy JSON / "service:name;..." string parse for
            MockRuntime test fixtures and pre-3.0 callers.
        """
        # PRIMARY: on-chain hash routing.
        service_desc = getattr(tx, "service_description", None)
        # tx may carry the hash under either service_description (snake) or
        # serviceHash (camel) depending on the runtime source. Mirror TS which
        # reads tx.serviceHash; fall back to service_description for the
        # Python runtime shape.
        raw_hash = getattr(tx, "service_hash", None) or getattr(tx, "serviceHash", None)
        if not isinstance(raw_hash, str):
            raw_hash = service_desc if isinstance(service_desc, str) else None
        zero_hash = "0x" + "0" * 64
        normalized = raw_hash.lower() if isinstance(raw_hash, str) else None
        if normalized is not None and normalized.startswith("0x") and normalized != zero_hash:
            by_hash = self._handlers_by_hash.get(normalized)
            if by_hash is not None:
                return by_hash

        # ZeroHash / missing-hash sole-handler fallback (raw-pay routing).
        #
        # Mirrors TS findServiceHandler (Agent.ts:1269-1299). A Level 0
        # ``client.pay(provider, amount)`` creates an on-chain tx with
        # serviceHash == ZeroHash and no parsable serviceDescription. When
        # there is no routable hash AND exactly ONE handler is registered, the
        # routing is unambiguous — route the raw-pay job to that sole handler.
        #
        # Guards (deliberately conservative — never guess):
        #   * 0 handlers  → fall through (returns None, unchanged).
        #   * 2+ handlers → ambiguous, fall through (returns None, unchanged).
        #   * exactly 1   → route, with a warn-level log so operators can see
        #                   raw-pay activations in production.
        no_routable_hash = (
            normalized is None
            or normalized == zero_hash
            or not (isinstance(service_desc, str) and service_desc)
        )
        # Distinguish "no hash / zero hash" from "hash present but unknown".
        # When a non-zero routable hash was present but did not match a handler,
        # this is NOT a raw-pay case — do not route to the sole handler.
        hash_present_and_unmatched = (
            normalized is not None
            and normalized.startswith("0x")
            and normalized != zero_hash
        )
        if (
            not hash_present_and_unmatched
            and no_routable_hash
            and len(self._handlers_by_hash) == 1
        ):
            _logger.warning(
                "ZeroHash (raw-pay) tx routed to the sole registered handler",
                extra={"agent": self.name, "tx_id": getattr(tx, "id", None)},
            )
            return next(iter(self._handlers_by_hash.values()))

        # FALLBACK: legacy string-based dispatch.
        service_name = self._extract_service_name(tx)
        if service_name is None:
            return None
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
        """Create Job from transaction.

        PARITY: Matches TS SDK extractMetadata() - includes disputeWindow for DELIVERED proof.
        """
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
                # PARITY: Include disputeWindow for DELIVERED proof encoding
                "disputeWindow": getattr(tx, "dispute_window", 172800),
                "createdAt": getattr(tx, "created_at", None),
            },
        )

    async def _should_auto_accept(
        self, job: Job, registration: _ServiceRegistration, tx: Any = None
    ) -> bool:
        """Determine if a job should be auto-accepted.

        Mirrors TS ``shouldAutoAccept`` (Agent.ts:1379-1609) including the
        decline/filter event taxonomy:

          * service filter (min/max budget, custom) → job:declined /
            job:filtered with a machine-readable reason
          * pricing strategy → reject ⇒ job:declined; counter-offer ⇒ NOT a
            decline (the agent RESPONDED with a price), returns False without
            an event
          * agent-level auto_accept false / callback decline → job:filtered

        ``tx`` is the source transaction used to build the event payload; when
        omitted (legacy callers) the job's own fields are used.
        """
        behavior = self._config.get_behavior()
        # The event payload prefers the raw tx (carries requester/amount in
        # base units); fall back to a tx-like view derived from the job.
        ev_tx = tx if tx is not None else _TxLike(job)

        # --- Service-level filter (budget constraints + custom) ---
        svc_filter = registration.config.filter
        if svc_filter is not None:
            if svc_filter.min_budget is not None and job.budget < svc_filter.min_budget:
                self._emit_job_decision(
                    "job:declined",
                    ev_tx,
                    registration,
                    {"reason": "budget_below_minimum", "minBudget": svc_filter.min_budget},
                )
                return False
            if svc_filter.max_budget is not None and job.budget > svc_filter.max_budget:
                self._emit_job_decision(
                    "job:declined",
                    ev_tx,
                    registration,
                    {"reason": "budget_above_maximum", "maxBudget": svc_filter.max_budget},
                )
                return False
            if svc_filter.custom is not None:
                custom_result = svc_filter.custom(job)
                if hasattr(custom_result, "__await__"):
                    custom_result = await custom_result
                if not custom_result:
                    self._emit_job_decision(
                        "job:filtered",
                        ev_tx,
                        registration,
                        {"reason": "custom_filter", "filter": "custom"},
                    )
                    return False

        # --- Pricing strategy ---
        if registration.config.pricing is not None:
            try:
                calculation = calculate_price(registration.config.pricing, job)
            except Exception as e:  # pragma: no cover - defensive parity
                # If pricing calculation fails, reject the job for safety.
                _logger.error(
                    "Pricing calculation failed, rejecting job",
                    extra={"agent": self.name, "job_id": job.id, "error": str(e)},
                )
                self._emit_job_decision(
                    "job:declined",
                    ev_tx,
                    registration,
                    {"reason": "pricing_error", "detail": str(e)},
                )
                return False

            if calculation.decision == "reject":
                self._emit_job_decision(
                    "job:declined",
                    ev_tx,
                    registration,
                    {"reason": "pricing_rejected", "detail": calculation.reason},
                )
                return False

            # counter-offer: the agent RESPONDED with a price — NOT a decline.
            # Returning False here keeps the job out of the accept pipeline; the
            # buyer-side negotiation/quote path handles the counter. We do NOT
            # emit a decline/filter event (TS Agent.ts:1611-1614).
            if calculation.decision == "counter-offer":
                return False

        # --- Agent-level auto_accept behavior ---
        auto_accept = behavior.auto_accept

        if auto_accept is True:
            return True

        # Blanket opt-out: surface it so a consumer counting "every job we
        # didn't take" sees it (TS Agent.ts:1587-1593).
        if auto_accept is False:
            self._emit_job_decision(
                "job:filtered",
                ev_tx,
                registration,
                {"reason": "auto_accept_disabled", "filter": "auto_accept"},
            )
            return False

        # It's a function — evaluate it (per-job programmatic gate).
        if callable(auto_accept):
            decision = auto_accept(job)
            if hasattr(decision, "__await__"):
                decision = await decision
            if not decision:
                self._emit_job_decision(
                    "job:filtered",
                    ev_tx,
                    registration,
                    {"reason": "auto_accept_callback", "filter": "auto_accept"},
                )
            return bool(decision)

        return False

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
        """Execute a job handler.

        State transitions are state-gated for idempotency (TS processJob,
        Agent.ts:1928-1949): re-read the current tx state before transitioning,
        only do COMMITTED → IN_PROGRESS when state is COMMITTED, skip when
        already IN_PROGRESS, and bail for CANCELLED/DISPUTED/etc.

        Success marks the job processed + clears its retry counter; failure is
        routed through bounded retry (:meth:`_fail_job`) which decides whether
        to mark it processed (permanent / max-attempts) or leave it for the
        next poll (transient).
        """
        self._emit("job:started", job)
        start_time = asyncio.get_event_loop().time()

        # State-gated IN_PROGRESS transition (idempotent re-delivery safety).
        # For runtimes without get_transaction default to COMMITTED — matches
        # both the mock entry state (post-linkEscrow) and the blockchain
        # canonical entry state from polling.
        current_state = "COMMITTED"
        if self._client is not None:
            try:
                current_tx = await self._client.runtime.get_transaction(job.id)
                if current_tx is not None:
                    raw_state = getattr(current_tx, "state", None)
                    current_state = getattr(raw_state, "value", raw_state) or "COMMITTED"
            except Exception:
                current_state = "COMMITTED"

        if self._client is not None:
            if current_state == "COMMITTED":
                try:
                    await self._client.standard.transition_state(job.id, "IN_PROGRESS")
                    _logger.debug(
                        "Job transitioned to IN_PROGRESS",
                        extra={"agent": self.name, "job_id": job.id},
                    )
                except Exception as e:
                    _logger.warning(
                        "Failed to transition job to IN_PROGRESS",
                        extra={"agent": self.name, "job_id": job.id, "error": str(e)},
                    )
                    # Don't fail the job - it might already be IN_PROGRESS
            elif current_state != "IN_PROGRESS":
                # Tx is in some non-workable state (CANCELLED, DISPUTED, etc.) —
                # bail without acting on it (TS Agent.ts:1932-1940).
                _logger.warning(
                    "Skipping job; tx no longer in workable state",
                    extra={"agent": self.name, "job_id": job.id, "state": current_state},
                )
                self._active_jobs.delete(job.id)
                elapsed = asyncio.get_event_loop().time() - start_time
                self._update_job_stats(elapsed)
                return

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
                    await self._complete_job(job, result.output, registration)
                else:
                    await self._fail_job(job, result.error or "Unknown error")
            else:
                # Treat any return value as success
                await self._complete_job(job, result, registration)

        except Exception as e:
            await self._fail_job(job, str(e))

        finally:
            # Update stats. PROCESSED-marking is handled by _complete_job
            # (success) / _fail_job (bounded retry) — NOT here, so a
            # transiently-failed job can be retried on the next poll (TS does
            # NOT unconditionally mark processed in finally). We DO always
            # remove from active_jobs (idempotent; TS always removes too) so a
            # cancelled/aborted job does not strand the active set and block
            # stop()/_wait_for_active_jobs.
            elapsed = asyncio.get_event_loop().time() - start_time
            self._update_job_stats(elapsed)
            self._active_jobs.delete(job.id)

    async def _complete_job(
        self, job: Job, output: Any, registration: Optional[_ServiceRegistration] = None
    ) -> None:
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

        # Security: Use ProofGenerator to create an authenticated, structured
        # delivery proof (mirror TS Agent.ts:1842-1859). This carries txId,
        # keccak256 contentHash, timestamp, and metadata (service / completedAt
        # / size / mimeType) — NOT just the ABI-encoded disputeWindow uint256
        # the kernel needs for the DELIVERED transition. The structured JSON is
        # what a buyer reads off ``tx.delivery_proof`` (mock path) and what the
        # cross-SDK delivery-verification surface expects.
        delivery_proof_json = self._build_delivery_proof_json(job, output)

        # AIP-16 Phase 2e — publish a delivery envelope between handler
        # completion and the on-chain DELIVERED transition. Strictly opt-in
        # (ACTP_DELIVERY_CHANNEL=v1 + all four delivery deps). Failures are
        # logged and swallowed — they MUST NOT block settlement.
        await self._maybe_publish_delivery_envelope(job, output)

        # Transition to DELIVERED with dispute window proof
        # AUDIT FIX: Must encode disputeWindow as uint256 proof for DELIVERED transition
        if self._client is not None:
            try:
                # Get dispute window from metadata, fallback to 2 days (172800s) per Options.ts default
                dispute_window_seconds = job.metadata.get("disputeWindow", 172800)

                # ABI encode dispute window as uint256
                if abi_encode is not None:
                    dispute_window_proof = "0x" + abi_encode(["uint256"], [dispute_window_seconds]).hex()
                else:
                    # Fallback: manual encoding for uint256 (32 bytes, big-endian)
                    dispute_window_proof = "0x" + dispute_window_seconds.to_bytes(32, "big").hex()

                _logger.debug(
                    "Encoding dispute window proof",
                    extra={
                        "job_id": job.id,
                        "dispute_window": dispute_window_seconds,
                        "proof": dispute_window_proof[:20] + "...",
                    },
                )

                await self._client.standard.transition_state(job.id, "DELIVERED", dispute_window_proof)

                # Attach the structured delivery proof to the MockRuntime tx
                # state so a buyer reads the rich proof (not the disputeWindow
                # bytes). Mirror TS Agent.ts:1898-1906 — there the agent sets
                # ``tx.deliveryProof`` BEFORE transitioning and the MockRuntime
                # guard (MockRuntime.ts:729 ``if (proof && !tx.deliveryProof)``)
                # prevents the disputeWindow proof param from overwriting it.
                # The Python MockRuntime lacks that guard, so we instead
                # re-attach AFTER the transition to reach the identical
                # observable end-state without touching the runtime. Mock-only;
                # the real BlockchainRuntime has no ``_state_manager`` and the
                # on-chain DELIVERED proof is the kernel-submitted bytes.
                await self._attach_mock_delivery_proof(job.id, delivery_proof_json)
            except Exception as e:
                _logger.warning(
                    "Failed to transition job to DELIVERED",
                    extra={"job_id": job.id, "error": str(e)},
                )

        # SUCCESS: mark processed, clear active + retry counter (TS Agent.ts
        # 1952-1954). Do this only on success so transient failures retry.
        self._processed_jobs.set(job.id, True)
        self._active_jobs.delete(job.id)
        self._job_attempts.delete(job.id)

        self._emit("job:completed", job, output)

    def _build_delivery_proof_json(self, job: Job, result: Any) -> str:
        """Build the structured delivery-proof JSON string (TS Agent.ts:1842-1859).

        Mirrors ``ProofGenerator.generateDeliveryProof`` + the outer
        ``JSON.stringify({ ...deliveryProof, result })`` wrapper:

          * ``deliverable`` = ``result`` when already a string, else its
            compact JSON.stringify form (no whitespace).
          * ``contentHash`` = keccak256(utf8(deliverable)) — keccak256 per
            Yellow Paper §11.4.1, matching the TS ``ProofGenerator``.
          * computed ``size`` (UTF-8 byte length) + ``mimeType`` are enforced
            on top of user metadata so they cannot be spoofed.
          * the original ``result`` is spread back in for buyer convenience.

        The whole proof is best-effort: a serialization failure degrades to a
        minimal proof rather than aborting the DELIVERED transition.
        """
        from eth_hash.auto import keccak

        try:
            deliverable = (
                result
                if isinstance(result, str)
                else json.dumps(result, separators=(",", ":"), ensure_ascii=False)
            )
        except Exception:
            deliverable = str(result)

        deliverable_bytes = deliverable.encode("utf-8")
        content_hash = "0x" + keccak(deliverable_bytes).hex()

        # Spread user metadata first, then enforce computed fields (TS:112-114).
        user_metadata = dict(job.metadata) if isinstance(job.metadata, dict) else {}
        user_metadata.pop("size", None)
        mime_type = user_metadata.pop("mimeType", None) or "application/octet-stream"

        delivery_proof = {
            "type": "delivery.proof",  # Required per AIP-4 (TS:117)
            "txId": job.id,
            "contentHash": content_hash,
            "timestamp": int(time.time() * 1000),  # Date.now() — ms (TS:120)
            "metadata": {
                "service": job.service,
                "completedAt": int(time.time() * 1000),
                **user_metadata,
                "size": len(deliverable_bytes),  # Enforced (TS:124)
                "mimeType": mime_type,  # Enforced (TS:125)
            },
        }

        # Outer wrapper: include the original result for convenience (TS:1856-1859).
        try:
            return json.dumps(
                {**delivery_proof, "result": result},
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except Exception:
            # Result not JSON-serializable — fall back to the proof alone.
            return json.dumps(delivery_proof, separators=(",", ":"), ensure_ascii=False)

    async def _attach_mock_delivery_proof(
        self, tx_id: str, delivery_proof_json: str
    ) -> None:
        """Attach the structured proof to the MockRuntime tx (TS Agent.ts:1898-1906).

        Mock-only. The real BlockchainRuntime has no ``_state_manager`` and the
        on-chain DELIVERED proof is the kernel-submitted disputeWindow bytes, so
        this is a no-op there. Best-effort: any failure is swallowed so it can
        never block the (already-completed) DELIVERED transition.
        """
        if self._client is None:
            return
        runtime = getattr(self._client, "runtime", None)
        state_manager = getattr(runtime, "_state_manager", None)
        if state_manager is None:
            return  # BlockchainRuntime / non-mock — nothing to poke.

        try:
            async def _update(state: Any) -> Any:
                tx = state.transactions.get(tx_id)
                if tx is not None:
                    tx.delivery_proof = delivery_proof_json
                return state

            await state_manager.with_lock(_update)
        except Exception as e:
            _logger.warning(
                "Failed to attach structured delivery proof to mock state",
                extra={"job_id": tx_id, "error": str(e)},
            )

    async def _fail_job(self, job: Job, error: str) -> None:
        """Mark job as failed, applying bounded retry semantics.

        Mirrors TS processJob's catch block (Agent.ts:2020-2087):

          * permanent kernel revert (Transaction expired / Invalid transition /
            Only requester|provider / Not authorized|participant, plaintext OR
            ABI-hex) → mark processed so polling never retries.
          * otherwise transient: retry on the next poll, but after
            MAX_JOB_ATTEMPTS recurrences mark processed so a job that keeps
            failing (e.g. a handler throwing on bad input) does not spin every
            poll cycle forever.
        """
        error_message = error or ""
        error_message_lower = error_message.lower()

        # Permanent-failure detection — plaintext AND ABI-hex form. Bundler
        # simulation reverts surface the kernel reason ABI-encoded, so match
        # the UTF-8 bytes' hex too.
        is_permanent = False
        for reason in self._PERMANENT_REVERT_REASONS:
            if reason in error_message:
                is_permanent = True
                break
            hex_reason = reason.encode("utf-8").hex().lower()
            if hex_reason in error_message_lower:
                is_permanent = True
                break

        self._active_jobs.delete(job.id)

        if is_permanent:
            self._processed_jobs.set(job.id, True)
            _logger.warning(
                "Job failed with a permanent kernel revert — marking processed "
                "so polling does not retry forever",
                extra={"agent": self.name, "job_id": job.id, "reason": error_message[:200]},
            )
        else:
            attempts = (self._job_attempts.get(job.id) or 0) + 1
            if attempts >= self.MAX_JOB_ATTEMPTS:
                self._processed_jobs.set(job.id, True)
                self._job_attempts.delete(job.id)
                _logger.warning(
                    "Job failed repeatedly — marking processed after max attempts "
                    "so polling does not retry forever",
                    extra={
                        "agent": self.name,
                        "job_id": job.id,
                        "attempts": attempts,
                        "reason": error_message[:200],
                    },
                )
            else:
                self._job_attempts.set(job.id, attempts)
                # Leave job.id OUT of processed_jobs so the next poll re-attempts.
                self._processed_jobs.delete(job.id)

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

    # ═══════════════════════════════════════════════════════════
    # Internal: AIP-16 Delivery Hook
    # ═══════════════════════════════════════════════════════════

    async def _ensure_aip16_auto_wire(self) -> None:
        """AIP-16 4.6.1 zero-config wire-up of channel delivery deps.

        Mirrors TS ``ensureAip16AutoWire`` (Agent.ts:2151-2197). When
        ``ACTP_DELIVERY_CHANNEL=v1`` is set, lazily resolve any missing
        delivery dep:

          * delivery_channel → RelayDeliveryChannel(base_url=AGIRAILS_RELAY_URL)
          * kernel_address   → networkConfig.contracts.actp_kernel
          * chain_id         → networkConfig.chain_id
          * delivery_signer  → eth_account LocalAccount from the resolved key

        Idempotent — only fills holes. Any failure logs and leaves the field
        unset; the dependency gate then no-ops the publish (prior behavior).
        """
        import os

        if os.environ.get("ACTP_DELIVERY_CHANNEL") != "v1":
            return

        if self._delivery_channel is None:
            try:
                from agirails.delivery.relay_delivery_channel import (
                    RelayDeliveryChannel,
                    RelayDeliveryChannelOptions,
                )

                base_url = os.environ.get("AGIRAILS_RELAY_URL") or "https://www.agirails.app"
                self._delivery_channel = RelayDeliveryChannel(
                    RelayDeliveryChannelOptions(base_url=base_url)
                )
            except Exception as err:
                _logger.warning(
                    "AIP-16 auto-wire: RelayDeliveryChannel import/construct failed",
                    extra={"agent": self.name, "error": str(err)},
                )

        if self._kernel_address is None or not isinstance(self._chain_id, int):
            try:
                from agirails.config.networks import get_network

                network_name = (
                    "base-sepolia"
                    if self.network == "testnet"
                    else "base-mainnet"
                    if self.network == "mainnet"
                    else self.network
                )
                net = get_network(network_name)
                if self._kernel_address is None:
                    self._kernel_address = net.contracts.actp_kernel
                if not isinstance(self._chain_id, int):
                    self._chain_id = net.chain_id
            except Exception as err:
                _logger.warning(
                    "AIP-16 auto-wire: failed to derive kernel/chain_id",
                    extra={"agent": self.name, "error": str(err)},
                )

        if self._delivery_signer is None and self.network in ("testnet", "mainnet"):
            try:
                from eth_account import Account

                from agirails.wallet.keystore import (
                    ResolvePrivateKeyOptions,
                    resolve_private_key,
                )

                state_dir = (
                    str(self._config.state_directory)
                    if self._config.state_directory is not None
                    else None
                )
                pk = await resolve_private_key(
                    state_dir, ResolvePrivateKeyOptions(network=self.network)
                )
                if pk:
                    self._delivery_signer = Account.from_key(pk)
            except Exception as err:
                _logger.warning(
                    "AIP-16 auto-wire: failed to resolve delivery_signer",
                    extra={"agent": self.name, "error": str(err)},
                )

    async def _maybe_publish_delivery_envelope(self, job: Job, result: Any) -> None:
        """AIP-16 Phase 2e — build + publish a delivery envelope for ``job``.

        Mirrors TS ``maybePublishDeliveryEnvelope`` (Agent.ts:2199-2412).
        Strictly opt-in and best-effort:

          * Gated by ``ACTP_DELIVERY_CHANNEL=v1`` (read per-call so tests can
            flip it without reconstructing the agent).
          * Zero-config auto-wire lazily fills missing deps.
          * Requires ALL of (channel, signer, kernel_address, chain_id).
          * Per-service ``delivery.mode == 'channel'`` (default).
          * Idempotency: current tx state MUST be COMMITTED.
          * Channel publish / builder failures are logged and SWALLOWED — they
            MUST NOT throw out of this hook (settlement is the source of truth).
        """
        import os

        if os.environ.get("ACTP_DELIVERY_CHANNEL") != "v1":
            return

        await self._ensure_aip16_auto_wire()

        # Constructor-side dependency gate.
        if (
            self._delivery_channel is None
            or self._delivery_signer is None
            or self._kernel_address is None
            or not isinstance(self._chain_id, int)
        ):
            return

        # Service-config gate — fall back to DEFAULT_DELIVERY_CONFIG (channel).
        registration = self._services.get(job.service)
        delivery_cfg = (
            registration.config.delivery
            if registration is not None and registration.config.delivery is not None
            else DEFAULT_DELIVERY_CONFIG
        )
        if delivery_cfg.mode != "channel":
            return

        # Idempotency: tx state MUST be COMMITTED (skip on poll re-delivery).
        try:
            current_tx = None
            if self._client is not None:
                current_tx = await self._client.runtime.get_transaction(job.id)
            raw_state = getattr(current_tx, "state", None) if current_tx else None
            state = getattr(raw_state, "value", raw_state)
            if current_tx is None or state != "COMMITTED":
                _logger.debug(
                    "AIP-16: skipping envelope publish (tx not in COMMITTED)",
                    extra={"agent": self.name, "job_id": job.id, "state": state},
                )
                return
        except Exception as state_err:
            _logger.warning(
                "AIP-16: failed to read tx state before envelope publish; skipping hook",
                extra={"agent": self.name, "job_id": job.id, "error": str(state_err)},
            )
            return

        # Resolve signer/provider addresses.
        try:
            signer_address = self._delivery_signer.address
        except Exception as signer_err:
            _logger.warning(
                "AIP-16: delivery_signer.address failed; skipping envelope publish",
                extra={"agent": self.name, "job_id": job.id, "error": str(signer_err)},
            )
            return

        provider_address = self.address or signer_address
        if (
            not provider_address
            or not provider_address.startswith("0x")
            or len(provider_address) != 42
        ):
            _logger.warning(
                "AIP-16: unable to resolve provider_address; skipping envelope publish",
                extra={"agent": self.name, "job_id": job.id, "provider_address": provider_address},
            )
            return

        # Build + publish. The whole block is wrapped: channel/builder errors
        # NEVER throw out of this hook — they are logged at warn and swallowed.
        try:
            from agirails.delivery.envelope_builder import (
                BuildEncryptedEnvelopeParams,
                BuildPublicEnvelopeParams,
                DeliveryEnvelopeBuilder,
            )

            builder = DeliveryEnvelopeBuilder(self._delivery_signer)
            smart_wallet_nonce = (
                self._smart_wallet_nonce if self._smart_wallet_nonce is not None else 0
            )

            if delivery_cfg.privacy == "encrypted":
                get_setups = getattr(self._delivery_channel, "get_setups", None)
                if not callable(get_setups):
                    _logger.warning(
                        "AIP-16: encrypted service requires channel.get_setups; "
                        "skipping envelope publish",
                        extra={"agent": self.name, "job_id": job.id},
                    )
                    return
                try:
                    setups = await get_setups(job.id)
                except Exception:
                    setups = []
                setup = setups[0] if setups else None
                buyer_pubkey = None
                if setup is not None:
                    signed = setup.get("signed") if isinstance(setup, dict) else None
                    if isinstance(signed, dict):
                        buyer_pubkey = signed.get("buyerEphemeralPubkey")
                if not buyer_pubkey:
                    _logger.warning(
                        "AIP-16: encrypted service has no setup on channel; "
                        "skipping envelope publish",
                        extra={
                            "agent": self.name,
                            "job_id": job.id,
                            "setups_found": len(setups),
                        },
                    )
                    return
                built = builder.build_encrypted(
                    BuildEncryptedEnvelopeParams(
                        tx_id=job.id,
                        chain_id=self._chain_id,
                        kernel_address=self._kernel_address,
                        provider_address=provider_address,
                        signer_address=signer_address,
                        payload=result,
                        buyer_ephemeral_pubkey=buyer_pubkey,
                        smart_wallet_nonce=smart_wallet_nonce,
                    )
                )
                await self._delivery_channel.publish_envelope(built["wire"])
                _logger.info(
                    "AIP-16: encrypted envelope published",
                    extra={
                        "agent": self.name,
                        "job_id": job.id,
                        "scheme": built["wire"]["signed"]["scheme"],
                    },
                )
            else:
                built = builder.build_public(
                    BuildPublicEnvelopeParams(
                        tx_id=job.id,
                        chain_id=self._chain_id,
                        kernel_address=self._kernel_address,
                        provider_address=provider_address,
                        signer_address=signer_address,
                        payload=result,
                        smart_wallet_nonce=smart_wallet_nonce,
                    )
                )
                await self._delivery_channel.publish_envelope(built["wire"])
                _logger.info(
                    "AIP-16: public envelope published",
                    extra={
                        "agent": self.name,
                        "job_id": job.id,
                        "scheme": built["wire"]["signed"]["scheme"],
                    },
                )
        except Exception as publish_err:
            # CRITICAL: must NOT re-raise. Settlement is the source of truth.
            _logger.warning(
                "AIP-16: envelope publish failed; settlement continues",
                extra={"agent": self.name, "job_id": job.id, "error": str(publish_err)},
            )

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
