"""
Request function for AGIRAILS Level 0 API.

Provides a simple functional interface for requesting services
from providers through the ACTP protocol.

PARITY: This implementation matches the TypeScript SDK's level0/request.ts
exactly in behavior, including:
- Service validation
- Provider discovery
- Transaction creation with runtime
- State polling with timeout
- Auto-cancel on timeout
- Delivery proof extraction
- Escrow release handling

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
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from agirails.utils.logging import get_logger
from agirails.utils.security import safe_json_parse, validate_service_name

if TYPE_CHECKING:
    from agirails.client import ACTPClient

_logger = get_logger(__name__)


class RequestStatus(Enum):
    """Status of a service request."""

    PENDING = "pending"
    INITIATED = "initiated"
    COMMITTED = "committed"
    IN_PROGRESS = "in_progress"
    DELIVERED = "delivered"
    SETTLED = "settled"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DISPUTED = "disputed"
    TIMEOUT = "timeout"


@dataclass
class ProgressInfo:
    """Progress information for callbacks."""

    state: str
    progress: int  # 0-100
    message: str


OnProgressCallback = Callable[[ProgressInfo], None]


@dataclass
class RequestOptions:
    """
    Options for the request function.

    PARITY: Matches TypeScript SDK's RequestOptions interface.

    Attributes:
        budget: Maximum budget in USDC
        deadline: Request deadline (datetime, unix timestamp, or "+Xh" format)
        timeout: Timeout in milliseconds for waiting on response (default: 5 min)
        provider: Specific provider address or strategy ('any', 'best', 'cheapest')
        metadata: Additional metadata to include
        wait: Whether to wait for completion (default: True)
        poll_interval: Interval in milliseconds for polling status (default: 2000)
        dispute_window: Dispute window in seconds (default: 2 days)
        network: Network mode ('mock', 'testnet', 'mainnet')
        wallet: Wallet configuration
        rpc_url: RPC URL for blockchain connection
        state_directory: Directory for state storage
        on_progress: Progress callback function
    """

    budget: float = 1.0
    deadline: Optional[Union[datetime, int, str]] = None
    timeout: int = 300_000  # 5 minutes in ms
    provider: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    wait: bool = True
    poll_interval: int = 2000  # 2 seconds in ms
    dispute_window: int = 172800  # 2 days in seconds
    network: str = "mock"
    wallet: Optional[Union[str, Dict[str, str]]] = None
    rpc_url: Optional[str] = None
    state_directory: Optional[str] = None
    on_progress: Optional[OnProgressCallback] = None

    def get_deadline_timestamp(self) -> int:
        """
        Get deadline as Unix timestamp in seconds.

        Returns:
            Deadline timestamp
        """
        if self.deadline is None:
            # Default: now + timeout
            return int(time.time()) + (self.timeout // 1000)

        if isinstance(self.deadline, datetime):
            return int(self.deadline.timestamp())

        if isinstance(self.deadline, int):
            # If small number, treat as seconds from now
            # If large number, treat as Unix timestamp
            if self.deadline < 1_000_000_000:
                return int(time.time()) + self.deadline
            return self.deadline

        if isinstance(self.deadline, str):
            # Parse "+Xh" or "+Xd" format
            if self.deadline.startswith("+"):
                value = self.deadline[1:-1]
                unit = self.deadline[-1].lower()
                try:
                    num = int(value)
                    if unit == "h":
                        return int(time.time()) + (num * 3600)
                    elif unit == "d":
                        return int(time.time()) + (num * 86400)
                    elif unit == "m":
                        return int(time.time()) + (num * 60)
                except ValueError:
                    pass
            # Try parsing as ISO date
            try:
                from dateutil import parser
                return int(parser.isoparse(self.deadline).timestamp())
            except (ImportError, ValueError):
                pass

        # Default fallback
        return int(time.time()) + (self.timeout // 1000)


@dataclass
class TransactionInfo:
    """Transaction information in result."""

    id: str
    provider: str
    amount: float
    fee: float
    duration: int  # ms
    proof: str


@dataclass
class RequestResult:
    """
    Result of a service request.

    PARITY: Matches TypeScript SDK's RequestResult interface.

    Attributes:
        result: The actual result data from the service
        transaction: Transaction details
    """

    result: Any
    transaction: TransactionInfo

    @classmethod
    def from_delivery(
        cls,
        output: Any,
        tx_id: str,
        provider: str,
        budget: float,
        duration: int,
        proof: str,
    ) -> RequestResult:
        """Create result from delivery."""
        return cls(
            result=output,
            transaction=TransactionInfo(
                id=tx_id,
                provider=provider,
                amount=budget,
                fee=budget * 0.01,  # 1% ACTP fee
                duration=duration,
                proof=proof,
            ),
        )


@dataclass
class LegacyRequestResult:
    """
    Legacy result format for backwards compatibility.

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
    def ok(cls, output: Any, **kwargs: Any) -> LegacyRequestResult:
        """Create a successful result."""
        return cls(
            success=True,
            output=output,
            status=RequestStatus.COMPLETED,
            completed_at=datetime.now(),
            **kwargs,
        )

    @classmethod
    def fail(cls, error: str, **kwargs: Any) -> LegacyRequestResult:
        """Create a failed result."""
        return cls(
            success=False,
            error=error,
            status=RequestStatus.FAILED,
            completed_at=datetime.now(),
            **kwargs,
        )

    @classmethod
    def timeout(cls, **kwargs: Any) -> LegacyRequestResult:
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
        start_time: Optional[int] = None,
    ) -> None:
        """
        Initialize request handle.

        Args:
            transaction_id: On-chain transaction ID
            service: Service name
            options: Request options
            client: ACTP client for status checks
            start_time: Start time in ms for duration tracking
        """
        self._transaction_id = transaction_id
        self._service = service
        self._options = options
        self._client = client
        self._result: Optional[RequestResult] = None
        self._status = RequestStatus.INITIATED
        self._start_time = start_time or int(time.time() * 1000)

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
            RequestStatus.SETTLED,
            RequestStatus.DELIVERED,
            RequestStatus.FAILED,
            RequestStatus.CANCELLED,
            RequestStatus.TIMEOUT,
        )

    def _get_tx_field(self, tx: Any, field: str) -> Any:
        """
        Get a field from a transaction (supports both dict and MockTransaction).

        PARITY FIX: Runtime returns MockTransaction objects, not dicts.
        This helper handles both for compatibility.
        """
        if tx is None:
            return None

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

        # Fallback for snake_case mapping
        import re
        snake_field = re.sub(r'(?<!^)(?=[A-Z])', '_', field).lower()
        if hasattr(tx, snake_field):
            value = getattr(tx, snake_field)
            if hasattr(value, "value"):
                return value.value
            return value

        return None

    async def check_status(self) -> RequestStatus:
        """
        Check the current status of the request.

        Returns:
            Current RequestStatus
        """
        if self._client is None:
            return self._status

        try:
            tx = await self._client.runtime.get_transaction(self._transaction_id)
            if tx:
                # PARITY FIX: Handle MockTransaction objects (attribute access)
                state = self._get_tx_field(tx, "state")
                state = state.upper() if isinstance(state, str) else ""
                state_map = {
                    "INITIATED": RequestStatus.INITIATED,
                    "COMMITTED": RequestStatus.COMMITTED,
                    "IN_PROGRESS": RequestStatus.IN_PROGRESS,
                    "DELIVERED": RequestStatus.DELIVERED,
                    "SETTLED": RequestStatus.SETTLED,
                    "CANCELLED": RequestStatus.CANCELLED,
                    "DISPUTED": RequestStatus.DISPUTED,
                }
                self._status = state_map.get(state, self._status)
        except Exception as e:
            _logger.warning(f"Failed to check status: {e}")

        return self._status

    async def wait(self, timeout: Optional[int] = None) -> RequestResult:
        """
        Wait for the request to complete.

        Args:
            timeout: Maximum time to wait in milliseconds

        Returns:
            RequestResult when complete

        Raises:
            TimeoutError: If timeout exceeded
        """
        if self._result is not None:
            return self._result

        effective_timeout = timeout or self._options.timeout
        deadline = time.time() * 1000 + effective_timeout
        poll_interval_sec = self._options.poll_interval / 1000

        while time.time() * 1000 < deadline:
            status = await self.check_status()

            if status in (RequestStatus.DELIVERED, RequestStatus.SETTLED):
                # Success - extract result
                try:
                    tx = await self._client.runtime.get_transaction(self._transaction_id)
                    output = self._extract_result(tx)
                    duration = int(time.time() * 1000) - self._start_time

                    # PARITY FIX: Use _get_tx_field for MockTransaction compatibility
                    self._result = RequestResult.from_delivery(
                        output=output,
                        tx_id=self._transaction_id,
                        provider=self._get_tx_field(tx, "provider") or "",
                        budget=self._options.budget,
                        duration=duration,
                        proof=self._get_tx_field(tx, "deliveryProof") or self._get_tx_field(tx, "delivery_proof") or "",
                    )
                    return self._result
                except Exception as e:
                    _logger.error(f"Failed to extract result: {e}")

            if status in (RequestStatus.CANCELLED, RequestStatus.DISPUTED):
                raise Exception(f"Transaction {status.value}")

            # Update progress callback
            if self._options.on_progress:
                progress = min(90, int(
                    (time.time() * 1000 - self._start_time) / effective_timeout * 90
                ))
                self._options.on_progress(ProgressInfo(
                    state=status.value,
                    progress=progress,
                    message=f"Waiting for delivery ({status.value})...",
                ))

            await asyncio.sleep(poll_interval_sec)

        # Timeout - try to cancel
        self._status = RequestStatus.TIMEOUT
        await self._try_cancel()
        raise TimeoutError(f"Request timed out after {effective_timeout}ms")

    async def _try_cancel(self) -> None:
        """Try to cancel the transaction on timeout."""
        if self._client is None:
            return

        try:
            tx = await self._client.runtime.get_transaction(self._transaction_id)
            # PARITY FIX: Use _get_tx_field for MockTransaction compatibility
            state = self._get_tx_field(tx, "state")
            if tx and state in ("INITIATED", "COMMITTED"):
                _logger.warning(f"Cancelling timed-out transaction {self._transaction_id[:18]}...")
                await self._client.runtime.transition_state(self._transaction_id, "CANCELLED")
                _logger.info("Transaction cancelled successfully")
        except Exception as e:
            _logger.error(f"Failed to cancel transaction: {e}")

    def _extract_result(self, tx: Any) -> Any:
        """
        Extract result from transaction delivery proof.

        PARITY: Matches TypeScript SDK request.ts extraction logic.

        The delivery proof wrapper format is:
        { type: 'delivery.proof', result: <handler_output>, ... }
        """
        if not tx:
            return {}

        # PARITY FIX: Use _get_tx_field for MockTransaction compatibility
        delivery_proof = (
            self._get_tx_field(tx, "deliveryProof")
            or self._get_tx_field(tx, "delivery_proof")
            or ""
        )
        if not delivery_proof:
            return {}

        # Parse delivery proof JSON
        # PARITY FIX: Use schema whitelist exactly like TS SDK (request.ts line 242-251)
        # This validates structure and filters to expected fields only
        DELIVERY_PROOF_SCHEMA = {
            "result": "any",
            "data": "any",
            "metadata": "object",
            "proof": "string",
            "timestamp": "number",
            "contentHash": "string",
            "txId": "string",
            "type": "string",  # Unique marker: 'delivery.proof'
        }

        # PARITY: TS safeJSONParse returns null on error (no exceptions)
        parsed = safe_json_parse(delivery_proof, schema=DELIVERY_PROOF_SCHEMA)
        if parsed is None:
            return {"data": delivery_proof}

        # Extract handler result from wrapper
        # PARITY: Structure matches TS SDK: { type: 'delivery.proof', result: <handler_output>, ... }
        if (
            isinstance(parsed, dict)
            and parsed.get("type") == "delivery.proof"
            and "result" in parsed
        ):
            return parsed["result"]

        return parsed

    async def cancel(self) -> bool:
        """
        Cancel the request.

        Returns:
            True if cancellation was successful
        """
        if self.is_complete:
            return False

        if self._client is None:
            self._status = RequestStatus.CANCELLED
            return True

        try:
            await self._client.runtime.transition_state(self._transaction_id, "CANCELLED")
            self._status = RequestStatus.CANCELLED
            return True
        except Exception as e:
            _logger.error(f"Failed to cancel: {e}")
            return False


# Global client for request function
_global_client: "Optional[ACTPClient]" = None


def set_request_client(client: "ACTPClient") -> None:
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


def _find_provider(service: str, provider_option: Optional[str] = None) -> Optional[str]:
    """
    Find provider for service.

    PARITY: Matches TypeScript SDK's findProvider function.

    Args:
        service: Service name
        provider_option: Provider address or strategy

    Returns:
        Provider address or None
    """
    # If specific address provided, use it
    if provider_option and provider_option not in ("any", "best", "cheapest"):
        return provider_option

    # Try to find from service directory
    try:
        from agirails.level0.directory import get_global_directory, ServiceQuery
        directory = get_global_directory()
        entries = directory.find(ServiceQuery(name=service))
        if entries and entries[0].provider_address:
            return entries[0].provider_address
    except ImportError:
        pass

    # Default mock provider for testing
    if not provider_option or provider_option == "any":
        return "0x" + "provider".encode().hex().ljust(40, "0")[:40]

    return None


async def request(
    service: str,
    *,
    input: Any,  # noqa: A002 - 'input' shadows builtin but is natural name
    budget: float = 1.0,
    deadline: Optional[Union[datetime, int, str]] = None,
    timeout: int = 300_000,
    provider: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    wait: bool = True,
    network: str = "mock",
    wallet: Optional[Union[str, Dict[str, str]]] = None,
    rpc_url: Optional[str] = None,
    dispute_window: int = 172800,
    on_progress: Optional[OnProgressCallback] = None,
    client: "Optional[ACTPClient]" = None,
) -> Union[RequestResult, RequestHandle]:
    """
    Request a service from a provider.

    PARITY: This function matches the TypeScript SDK's request() function
    in level0/request.ts exactly.

    Creates an ACTP transaction to request the specified service
    with the given input data and budget.

    Args:
        service: Name of the service to request
        input: Input data for the service
        budget: Maximum budget in USDC
        deadline: Request deadline (datetime, unix timestamp, or "+Xh" format)
        timeout: Timeout in milliseconds for waiting (default: 5 min)
        provider: Specific provider address or strategy ('any', 'best', 'cheapest')
        metadata: Additional metadata to include
        wait: Whether to wait for completion
        network: Network mode ('mock', 'testnet', 'mainnet')
        wallet: Wallet configuration (address or {privateKey: ...})
        rpc_url: RPC URL for blockchain connection
        dispute_window: Dispute window in seconds (default: 2 days)
        on_progress: Progress callback function
        client: ACTP client (uses global if not provided)

    Returns:
        RequestResult if wait=True, RequestHandle if wait=False

    Example:
        >>> # Simple request
        >>> result = await request("echo", input={"msg": "hello"}, budget=0.10)
        >>> print(result.result)
        >>>
        >>> # With progress callback
        >>> result = await request(
        ...     "translation",
        ...     input={"text": "Hello", "from": "en", "to": "de"},
        ...     budget=5,
        ...     on_progress=lambda p: print(f"{p.state}: {p.progress}%"),
        ... )
        >>>
        >>> # Don't wait
        >>> handle = await request("slow-task", input=data, wait=False)
        >>> # ... do other work ...
        >>> result = await handle.wait()
    """
    # Validate service name
    validated_service = validate_service_name(service)

    # Build options
    options = RequestOptions(
        budget=budget,
        deadline=deadline,
        timeout=timeout,
        provider=provider,
        metadata=metadata or {},
        wait=wait,
        network=network,
        wallet=wallet,
        rpc_url=rpc_url,
        dispute_window=dispute_window,
        on_progress=on_progress,
    )

    _logger.debug(
        "Creating request",
        extra={
            "service": validated_service,
            "budget": budget,
            "timeout": timeout,
            "network": network,
            "wait": wait,
        },
    )

    # Find provider
    found_provider = _find_provider(validated_service, provider)
    if not found_provider:
        raise ValueError(f"No provider found for service: {validated_service}")

    # Get or create client
    effective_client = client or _global_client

    if effective_client is None:
        # Create client for this request
        from agirails.client import ACTPClient

        # Determine mode from network
        mode = "mock"
        if network == "testnet":
            mode = "testnet"
        elif network == "mainnet":
            mode = "mainnet"

        # Get requester address from wallet
        requester_address = _get_requester_address(wallet)

        effective_client = await ACTPClient.create(
            mode=mode,
            requester_address=requester_address,
            private_key=_get_private_key(wallet),
            rpc_url=rpc_url,
        )

    start_time = int(time.time() * 1000)

    try:
        # Calculate deadline timestamp
        deadline_ts = options.get_deadline_timestamp()

        # Convert budget to USDC wei (6 decimals)
        amount_wei = str(int(budget * 1_000_000))

        # Get requester address
        # PARITY FIX: Use client.address when client is provided, otherwise derive from wallet
        if effective_client is not None:
            requester_address = effective_client.address
        else:
            requester_address = _get_requester_address(wallet)

        # Build service metadata as JSON
        # PARITY FIX: Use separators=(',', ':') to match JS JSON.stringify() (no whitespace)
        # PARITY FIX: Use only {service, input, timestamp} - no extra metadata keys merged
        # PARITY FIX: Use ensure_ascii=False for unicode parity
        service_metadata = json.dumps(
            {
                "service": validated_service,
                "input": input,
                "timestamp": int(time.time() * 1000),
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )

        # Create transaction using proper snake_case params
        # PARITY FIX: Use snake_case keys to match CreateTransactionParams
        from agirails.runtime.base import CreateTransactionParams
        tx_params = CreateTransactionParams(
            provider=found_provider,
            requester=requester_address,
            amount=amount_wei,
            deadline=deadline_ts,
            dispute_window=dispute_window,
            service_description=service_metadata,
        )
        tx_id = await effective_client.runtime.create_transaction(tx_params)

        _logger.info(
            "Request created",
            extra={"service": validated_service, "transaction_id": tx_id[:18] + "..."},
        )

        # Update progress
        if on_progress:
            on_progress(ProgressInfo(
                state="initiated",
                progress=10,
                message="Transaction created, waiting for provider...",
            ))

        # Create handle
        handle = RequestHandle(
            transaction_id=tx_id,
            service=validated_service,
            options=options,
            client=effective_client,
            start_time=start_time,
        )

        if wait:
            return await handle.wait()

        return handle

    except Exception as e:
        _logger.error(f"Request failed: {e}")
        raise


def _get_requester_address(
    wallet: Optional[Union[str, Dict[str, str]]],
) -> str:
    """
    Get requester address from wallet configuration.

    PARITY: Matches TypeScript SDK's getRequesterAddress function.

    Args:
        wallet: Wallet configuration

    Returns:
        Ethereum address
    """
    if not wallet:
        # Mock mode default
        return "0x" + "requester".encode().hex().ljust(40, "0")[:40]

    if isinstance(wallet, str):
        # Check if it's an address or private key
        if wallet.startswith("0x") and len(wallet) == 42:
            return wallet.lower()
        if wallet.startswith("0x") and len(wallet) == 66:
            # It's a private key - derive address
            try:
                from eth_account import Account
                return Account.from_key(wallet).address.lower()
            except ImportError:
                raise ImportError(
                    "eth_account required for private key. "
                    "Install with: pip install eth-account"
                )
        return wallet

    if isinstance(wallet, dict) and "privateKey" in wallet:
        try:
            from eth_account import Account
            return Account.from_key(wallet["privateKey"]).address.lower()
        except ImportError:
            raise ImportError(
                "eth_account required for private key. "
                "Install with: pip install eth-account"
            )

    return "0x" + "requester".encode().hex().ljust(40, "0")[:40]


def _get_private_key(
    wallet: Optional[Union[str, Dict[str, str]]],
) -> Optional[str]:
    """
    Get private key from wallet configuration.

    PARITY: Matches TypeScript SDK's getPrivateKey function.

    Args:
        wallet: Wallet configuration

    Returns:
        Private key or None
    """
    if not wallet:
        return None

    if isinstance(wallet, str):
        # Check if it's a private key (0x + 64 hex chars)
        if wallet.startswith("0x") and len(wallet) == 66:
            return wallet
        return None

    if isinstance(wallet, dict) and "privateKey" in wallet:
        return wallet["privateKey"]

    return None


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
            timeout=req.get("timeout", 300_000),
            provider=req.get("provider"),
            metadata=req.get("metadata"),
            network=req.get("network", "mock"),
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
            # Create error result
            processed.append(RequestResult(
                result=None,
                transaction=TransactionInfo(
                    id="",
                    provider="",
                    amount=requests[i].get("budget", 1.0),
                    fee=0,
                    duration=0,
                    proof="",
                ),
            ))
        elif isinstance(result, RequestResult):
            processed.append(result)
        else:
            # Unexpected type
            processed.append(RequestResult(
                result=None,
                transaction=TransactionInfo(
                    id="",
                    provider="",
                    amount=requests[i].get("budget", 1.0),
                    fee=0,
                    duration=0,
                    proof="",
                ),
            ))

    return processed
