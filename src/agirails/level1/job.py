"""
Job types for AGIRAILS Level 1 API.

Provides:
- Job: Represents a job/task to be processed by an agent
- JobContext: Context passed to job handlers with utilities
- JobHandler: Type alias for job handler functions
- JobResult: Result of job processing
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

if TYPE_CHECKING:
    from agirails.level1.agent import Agent


@dataclass
class Job:
    """
    Represents a job to be processed by an agent.

    Jobs are created from incoming transactions and contain all the
    information needed to process the request.

    Attributes:
        id: Transaction ID (bytes32 hex string)
        service: Service name that this job is for
        input: Job input data (any JSON-serializable value)
        budget: Budget in USDC (float, e.g., 100.50)
        deadline: Job deadline
        requester: Requester's Ethereum address
        metadata: Additional metadata dictionary
        created_at: When the job was created
    """

    id: str
    service: str
    input: Any
    budget: float
    deadline: datetime
    requester: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def is_expired(self) -> bool:
        """Check if the job deadline has passed."""
        return datetime.now() > self.deadline

    def time_remaining(self) -> float:
        """Get remaining time in seconds until deadline."""
        remaining = (self.deadline - datetime.now()).total_seconds()
        return max(0, remaining)


class JobContext:
    """
    Context passed to job handlers.

    Provides utilities for:
    - Reporting progress
    - Logging
    - Storing state during job execution
    - Checking cancellation status

    Example:
        >>> async def handler(job: Job, ctx: JobContext):
        ...     ctx.log.info("Starting job")
        ...     ctx.progress(10, "Loading data")
        ...     # ... process job ...
        ...     ctx.progress(100, "Done")
        ...     return result
    """

    def __init__(self, agent: Agent, job: Job) -> None:
        """
        Initialize job context.

        Args:
            agent: The agent processing the job
            job: The job being processed
        """
        self._agent = agent
        self._job = job
        self._state: Dict[str, Any] = {}
        self._cancelled = False
        self._cancel_handlers: List[Callable[[], Union[Awaitable[None], None]]] = []
        self._progress_percent = 0
        self._progress_message = ""

    @property
    def agent(self) -> Agent:
        """Get the agent processing this job."""
        return self._agent

    @property
    def job(self) -> Job:
        """Get the job being processed."""
        return self._job

    @property
    def state(self) -> Dict[str, Any]:
        """
        Get/set state dictionary for storing data during job execution.

        This state is local to this job execution and is not persisted.
        """
        return self._state

    @property
    def cancelled(self) -> bool:
        """Check if the job has been cancelled."""
        return self._cancelled

    @property
    def log(self) -> _JobLogger:
        """Get logger for this job context."""
        return _JobLogger(self._agent, self._job.id)

    def progress(self, percent: int, message: str = "") -> None:
        """
        Report job progress.

        Args:
            percent: Progress percentage (0-100)
            message: Optional progress message

        Example:
            >>> ctx.progress(50, "Halfway done")
        """
        self._progress_percent = max(0, min(100, percent))
        self._progress_message = message

        # Emit progress event on agent
        self._agent._emit(
            "job:progress",
            {
                "job_id": self._job.id,
                "percent": self._progress_percent,
                "message": self._progress_message,
            },
        )

    def get_progress(self) -> Tuple[int, str]:
        """Get current progress (percent, message)."""
        return self._progress_percent, self._progress_message

    def on_cancel(
        self, handler: Callable[[], Union[Awaitable[None], None]]
    ) -> Callable[[], None]:
        """
        Register a cancellation handler.

        The handler will be called if the job is cancelled. Useful for
        cleaning up resources.

        Args:
            handler: Function to call on cancellation (sync or async)

        Returns:
            Function to unregister the handler

        Example:
            >>> def cleanup():
            ...     print("Job cancelled, cleaning up")
            >>> unregister = ctx.on_cancel(cleanup)
        """
        self._cancel_handlers.append(handler)

        def unregister() -> None:
            if handler in self._cancel_handlers:
                self._cancel_handlers.remove(handler)

        return unregister

    async def _trigger_cancel(self) -> None:
        """Trigger cancellation and call all handlers."""
        self._cancelled = True
        for handler in self._cancel_handlers:
            try:
                result = handler()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                # Log but don't fail on cancel handler errors
                pass


class _JobLogger:
    """Simple logger for job context."""

    def __init__(self, agent: Agent, job_id: str) -> None:
        self._agent = agent
        self._job_id = job_id

    def _log(self, level: str, message: str, **meta: Any) -> None:
        """Internal log method."""
        self._agent._emit(
            "log",
            {
                "level": level,
                "message": message,
                "job_id": self._job_id,
                **meta,
            },
        )

    def debug(self, message: str, **meta: Any) -> None:
        """Log debug message."""
        self._log("debug", message, **meta)

    def info(self, message: str, **meta: Any) -> None:
        """Log info message."""
        self._log("info", message, **meta)

    def warn(self, message: str, **meta: Any) -> None:
        """Log warning message."""
        self._log("warn", message, **meta)

    def error(self, message: str, **meta: Any) -> None:
        """Log error message."""
        self._log("error", message, **meta)


@dataclass
class JobResult:
    """
    Result of job processing.

    Returned by job handlers to indicate success or failure.

    Attributes:
        success: Whether the job completed successfully
        output: Job output data (any JSON-serializable value)
        error: Error message if job failed
    """

    success: bool
    output: Any = None
    error: Optional[str] = None

    @classmethod
    def ok(cls, output: Any = None) -> JobResult:
        """Create a successful result."""
        return cls(success=True, output=output)

    @classmethod
    def fail(cls, error: str) -> JobResult:
        """Create a failed result."""
        return cls(success=False, error=error)


# Type alias for job handler functions
# Handler takes (Job, JobContext) and returns any value (or JobResult)
JobHandler = Callable[[Job, JobContext], Awaitable[Any]]
