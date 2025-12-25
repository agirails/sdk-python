"""
Request function for AGIRAILS Level 0 API.

Provides a simple functional interface for requesting services
from providers through the ACTP protocol.

Example:
    >>> from agirails.level0 import request
    >>>
    >>> result = await request(
    ...     "text-generation",
    ...     input={"prompt": "Hello, world!"},
    ...     budget=1.0,
    ... )
    >>> print(result.output)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from agirails.utils.logging import get_logger

if TYPE_CHECKING:
    from agirails.core import ACTPClient

_logger = get_logger(__name__)


class RequestStatus(Enum):
    """Status of a service request."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class RequestOptions:
    """
    Options for the request function.

    Attributes:
        budget: Maximum budget in USDC
        deadline: Request deadline (datetime or seconds from now)
        timeout: Timeout in seconds for waiting on response
        provider: Specific provider address (optional)
        metadata: Additional metadata to include
        wait: Whether to wait for completion (default: True)
        poll_interval: Interval in seconds for polling status
    """

    budget: float = 1.0
    deadline: Optional[Union[datetime, int]] = None
    timeout: float = 300.0
    provider: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    wait: bool = True
    poll_interval: float = 2.0

    def get_deadline(self) -> datetime:
        """
        Get deadline as datetime.

        Returns:
            Deadline datetime
        """
        if self.deadline is None:
            return datetime.now() + timedelta(seconds=self.timeout)
        if isinstance(self.deadline, int):
            return datetime.now() + timedelta(seconds=self.deadline)
        return self.deadline


@dataclass
class RequestResult:
    """
    Result of a service request.

    Attributes:
        success: Whether the request completed successfully
        output: Output data from the service
        error: Error message if request failed
        transaction_id: On-chain transaction ID
        status: Current request status
        provider: Provider address that handled the request
        cost: Actual cost in USDC
        created_at: When the request was created
        completed_at: When the request was completed
        metadata: Additional result metadata
    """

    success: bool
    output: Any = None
    error: Optional[str] = None
    transaction_id: Optional[str] = None
    status: RequestStatus = RequestStatus.PENDING
    provider: Optional[str] = None
    cost: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, output: Any, **kwargs: Any) -> RequestResult:
        """Create a successful result."""
        return cls(
            success=True,
            output=output,
            status=RequestStatus.COMPLETED,
            completed_at=datetime.now(),
            **kwargs,
        )

    @classmethod
    def fail(cls, error: str, **kwargs: Any) -> RequestResult:
        """Create a failed result."""
        return cls(
            success=False,
            error=error,
            status=RequestStatus.FAILED,
            completed_at=datetime.now(),
            **kwargs,
        )

    @classmethod
    def timeout(cls, **kwargs: Any) -> RequestResult:
        """Create a timeout result."""
        return cls(
            success=False,
            error="Request timed out",
            status=RequestStatus.TIMEOUT,
            completed_at=datetime.now(),
            **kwargs,
        )


class RequestHandle:
    """
    Handle for tracking an in-progress request.

    Allows checking status and waiting for completion without
    blocking the initial request call.

    Example:
        >>> handle = await request("service", input=data, wait=False)
        >>> # Do other work...
        >>> result = await handle.wait()
    """

    def __init__(
        self,
        transaction_id: str,
        service: str,
        options: RequestOptions,
        client: "Optional[ACTPClient]" = None,
    ) -> None:
        """
        Initialize request handle.

        Args:
            transaction_id: On-chain transaction ID
            service: Service name
            options: Request options
            client: ACTP client for status checks
        """
        self._transaction_id = transaction_id
        self._service = service
        self._options = options
        self._client = client
        self._result: Optional[RequestResult] = None
        self._status = RequestStatus.PENDING

    @property
    def transaction_id(self) -> str:
        """Get the transaction ID."""
        return self._transaction_id

    @property
    def service(self) -> str:
        """Get the service name."""
        return self._service

    @property
    def status(self) -> RequestStatus:
        """Get current status."""
        return self._status

    @property
    def is_complete(self) -> bool:
        """Check if request is complete."""
        return self._status in (
            RequestStatus.COMPLETED,
            RequestStatus.FAILED,
            RequestStatus.CANCELLED,
            RequestStatus.TIMEOUT,
        )

    async def check_status(self) -> RequestStatus:
        """
        Check the current status of the request.

        Returns:
            Current RequestStatus
        """
        if self._client is None:
            return self._status

        # In a real implementation, this would query the blockchain
        # for the transaction status
        return self._status

    async def wait(self, timeout: Optional[float] = None) -> RequestResult:
        """
        Wait for the request to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            RequestResult when complete

        Raises:
            asyncio.TimeoutError: If timeout exceeded
        """
        if self._result is not None:
            return self._result

        effective_timeout = timeout or self._options.timeout
        deadline = datetime.now() + timedelta(seconds=effective_timeout)

        while datetime.now() < deadline:
            status = await self.check_status()
            if self.is_complete:
                if self._result is None:
                    self._result = RequestResult(
                        success=status == RequestStatus.COMPLETED,
                        status=status,
                        transaction_id=self._transaction_id,
                    )
                return self._result

            await asyncio.sleep(self._options.poll_interval)

        # Timeout
        self._status = RequestStatus.TIMEOUT
        self._result = RequestResult.timeout(transaction_id=self._transaction_id)
        return self._result

    async def cancel(self) -> bool:
        """
        Cancel the request.

        Returns:
            True if cancellation was successful
        """
        if self.is_complete:
            return False

        # In a real implementation, this would send a cancel
        # transaction to the blockchain
        self._status = RequestStatus.CANCELLED
        self._result = RequestResult(
            success=False,
            error="Request cancelled",
            status=RequestStatus.CANCELLED,
            transaction_id=self._transaction_id,
            completed_at=datetime.now(),
        )
        return True


# Global client for request function
_global_client: "Optional[ACTPClient]" = None


def set_request_client(client: ACTPClient) -> None:
    """
    Set the global client for request operations.

    Args:
        client: ACTP client to use for requests
    """
    global _global_client
    _global_client = client


def get_request_client() -> "Optional[ACTPClient]":
    """
    Get the global client for request operations.

    Returns:
        Global ACTPClient or None
    """
    return _global_client


async def request(
    service: str,
    *,
    input: Any,  # noqa: A002 - 'input' shadows builtin but is the natural name here
    budget: float = 1.0,
    deadline: Optional[Union[datetime, int]] = None,
    timeout: float = 300.0,
    provider: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    wait: bool = True,
    client: "Optional[ACTPClient]" = None,
) -> Union[RequestResult, RequestHandle]:
    """
    Request a service from a provider.

    Creates an ACTP transaction to request the specified service
    with the given input data and budget.

    Args:
        service: Name of the service to request
        input: Input data for the service
        budget: Maximum budget in USDC
        deadline: Request deadline (datetime or seconds)
        timeout: Timeout in seconds for waiting
        provider: Specific provider address (optional)
        metadata: Additional metadata to include
        wait: Whether to wait for completion
        client: ACTP client (uses global if not provided)

    Returns:
        RequestResult if wait=True, RequestHandle if wait=False

    Example:
        >>> # Wait for result
        >>> result = await request("echo", input={"msg": "hello"}, budget=0.10)
        >>> print(result.output)
        >>>
        >>> # Don't wait
        >>> handle = await request("slow-task", input=data, wait=False)
        >>> # ... do other work ...
        >>> result = await handle.wait()
    """
    options = RequestOptions(
        budget=budget,
        deadline=deadline,
        timeout=timeout,
        provider=provider,
        metadata=metadata or {},
        wait=wait,
    )

    effective_client = client or _global_client

    _logger.debug(
        "Creating request",
        extra={
            "service": service,
            "budget": budget,
            "timeout": timeout,
            "provider": provider,
            "wait": wait,
        },
    )

    # In a real implementation, this would:
    # 1. Create an ACTP transaction on the blockchain
    # 2. Wait for provider to accept and complete
    # 3. Return the result

    # For now, create a mock transaction ID
    import hashlib
    import time

    tx_data = f"{service}:{time.time()}:{id(input)}"
    transaction_id = "0x" + hashlib.sha256(tx_data.encode()).hexdigest()

    _logger.info(
        "Request created",
        extra={"service": service, "transaction_id": transaction_id[:18] + "..."},
    )

    handle = RequestHandle(
        transaction_id=transaction_id,
        service=service,
        options=options,
        client=effective_client,
    )

    if wait:
        return await handle.wait()

    return handle


async def request_batch(
    requests: List[Dict[str, Any]],
    *,
    client: "Optional[ACTPClient]" = None,
) -> List[RequestResult]:
    """
    Request multiple services in parallel.

    Args:
        requests: List of request dictionaries with keys:
            - service: Service name
            - input: Input data
            - budget: Budget in USDC
            - deadline: Optional deadline
            - provider: Optional provider address
        client: ACTP client (uses global if not provided)

    Returns:
        List of RequestResult in same order as requests

    Example:
        >>> results = await request_batch([
        ...     {"service": "echo", "input": {"msg": "a"}, "budget": 0.10},
        ...     {"service": "echo", "input": {"msg": "b"}, "budget": 0.10},
        ... ])
    """
    tasks = [
        request(
            service=req["service"],
            input=req["input"],
            budget=req.get("budget", 1.0),
            deadline=req.get("deadline"),
            timeout=req.get("timeout", 300.0),
            provider=req.get("provider"),
            metadata=req.get("metadata"),
            wait=True,
            client=client,
        )
        for req in requests
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Convert exceptions to failed results
    processed: List[RequestResult] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed.append(
                RequestResult.fail(
                    str(result),
                    metadata={"request_index": i},
                )
            )
        elif isinstance(result, RequestResult):
            processed.append(result)
        else:
            # Should be RequestHandle, but we waited
            processed.append(
                RequestResult.fail(
                    "Unexpected result type",
                    metadata={"request_index": i},
                )
            )

    return processed
