"""
Agent and job-related exceptions for ACTP protocol.

These exceptions are raised during agent operations including
service discovery, job handling, and agent lifecycle management.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agirails.errors.base import ACTPError


class NoProviderFoundError(ACTPError):
    """
    Raised when no provider can be found for a service.

    Example:
        >>> raise NoProviderFoundError("text-generation", timeout_ms=30000)
    """

    def __init__(
        self,
        service_name: str,
        *,
        timeout_ms: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["service_name"] = service_name
        if timeout_ms is not None:
            details["timeout_ms"] = timeout_ms
        if filters:
            details["filters"] = filters

        super().__init__(
            f"No provider found for service: {service_name}",
            code="NO_PROVIDER_FOUND",
            details=details,
        )
        self.service_name = service_name
        self.timeout_ms = timeout_ms
        self.filters = filters


class TimeoutError(ACTPError):
    """
    Raised when an operation times out.

    Note: Named TimeoutError but exported as ACTPTimeoutError to avoid
    shadowing the built-in TimeoutError.

    Example:
        >>> raise TimeoutError("request", 30000)
    """

    def __init__(
        self,
        operation: str,
        timeout_ms: int,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["operation"] = operation
        details["timeout_ms"] = timeout_ms

        super().__init__(
            f"Operation '{operation}' timed out after {timeout_ms}ms",
            code="TIMEOUT",
            details=details,
        )
        self.operation = operation
        self.timeout_ms = timeout_ms


class ProviderRejectedError(ACTPError):
    """
    Raised when a provider rejects a request.

    Example:
        >>> raise ProviderRejectedError(
        ...     "0xProvider...",
        ...     "Price too low",
        ...     service_name="text-generation"
        ... )
    """

    def __init__(
        self,
        provider_address: str,
        reason: str,
        *,
        service_name: Optional[str] = None,
        tx_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["provider"] = provider_address
        details["reason"] = reason
        if service_name:
            details["service_name"] = service_name

        super().__init__(
            f"Provider {provider_address[:10]}... rejected request: {reason}",
            code="PROVIDER_REJECTED",
            tx_hash=tx_id,
            details=details,
        )
        self.provider_address = provider_address
        self.reason = reason
        self.service_name = service_name


class DeliveryFailedError(ACTPError):
    """
    Raised when service delivery fails.

    Example:
        >>> raise DeliveryFailedError("0xProvider...", "Computation failed")
    """

    def __init__(
        self,
        provider_address: str,
        reason: str,
        *,
        tx_id: Optional[str] = None,
        partial_result: Any = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["provider"] = provider_address
        details["reason"] = reason
        if partial_result is not None:
            details["has_partial_result"] = True

        super().__init__(
            f"Delivery failed from {provider_address[:10]}...: {reason}",
            code="DELIVERY_FAILED",
            tx_hash=tx_id,
            details=details,
        )
        self.provider_address = provider_address
        self.reason = reason
        self.partial_result = partial_result


class DisputeRaisedError(ACTPError):
    """
    Raised when a dispute is raised on a transaction.

    Example:
        >>> raise DisputeRaisedError("0x123...", "Invalid output")
    """

    def __init__(
        self,
        tx_id: str,
        reason: str,
        *,
        raised_by: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["reason"] = reason
        if raised_by:
            details["raised_by"] = raised_by

        super().__init__(
            f"Dispute raised on transaction: {reason}",
            code="DISPUTE_RAISED",
            tx_hash=tx_id,
            details=details,
        )
        self.reason = reason
        self.raised_by = raised_by


class ServiceConfigError(ACTPError):
    """
    Raised when service configuration is invalid.

    Example:
        >>> raise ServiceConfigError("text-generation", "Missing handler")
    """

    def __init__(
        self,
        service_name: str,
        reason: str,
        *,
        config_field: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["service_name"] = service_name
        details["reason"] = reason
        if config_field:
            details["config_field"] = config_field

        super().__init__(
            f"Invalid service configuration for '{service_name}': {reason}",
            code="SERVICE_CONFIG_ERROR",
            details=details,
        )
        self.service_name = service_name
        self.reason = reason
        self.config_field = config_field


class AgentLifecycleError(ACTPError):
    """
    Raised when an agent lifecycle operation fails.

    Example:
        >>> raise AgentLifecycleError("start", "Already running")
    """

    def __init__(
        self,
        operation: str,
        reason: str,
        *,
        agent_address: Optional[str] = None,
        current_status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["operation"] = operation
        details["reason"] = reason
        if agent_address:
            details["agent_address"] = agent_address
        if current_status:
            details["current_status"] = current_status

        super().__init__(
            f"Agent lifecycle error during '{operation}': {reason}",
            code="AGENT_LIFECYCLE_ERROR",
            details=details,
        )
        self.operation = operation
        self.reason = reason
        self.agent_address = agent_address
        self.current_status = current_status


class QueryCapExceededError(ACTPError):
    """
    Raised when a query exceeds the configured cap limit.

    This is a security measure (H-1) to prevent DoS attacks
    by limiting the number of results returned.

    Example:
        >>> raise QueryCapExceededError(1000, 100)
    """

    def __init__(
        self,
        requested: int,
        limit: int,
        *,
        query_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["requested"] = requested
        details["limit"] = limit
        if query_type:
            details["query_type"] = query_type

        super().__init__(
            f"Query cap exceeded: requested {requested}, limit is {limit}",
            code="QUERY_CAP_EXCEEDED",
            details=details,
        )
        self.requested = requested
        self.limit = limit
        self.query_type = query_type
