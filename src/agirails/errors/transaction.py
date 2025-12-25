"""
Transaction-related exceptions for ACTP protocol.

These exceptions are raised during transaction lifecycle operations
including creation, state transitions, escrow management, and settlement.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from agirails.errors.base import ACTPError


class TransactionNotFoundError(ACTPError):
    """
    Raised when a transaction cannot be found by its ID.

    Example:
        >>> raise TransactionNotFoundError("0x123...")
    """

    def __init__(
        self,
        tx_id: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            f"Transaction not found: {tx_id}",
            code="TRANSACTION_NOT_FOUND",
            tx_hash=tx_id,
            details=details,
        )
        self.tx_id = tx_id


class InvalidStateTransitionError(ACTPError):
    """
    Raised when attempting an invalid state transition.

    The ACTP protocol enforces strict state transitions. This exception
    is raised when attempting to move to a state that is not allowed
    from the current state.

    Example:
        >>> raise InvalidStateTransitionError("INITIATED", "SETTLED")
    """

    def __init__(
        self,
        current_state: str,
        target_state: str,
        *,
        tx_id: Optional[str] = None,
        allowed_transitions: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["current_state"] = current_state
        details["target_state"] = target_state
        if allowed_transitions:
            details["allowed_transitions"] = allowed_transitions

        super().__init__(
            f"Invalid state transition: {current_state} -> {target_state}",
            code="INVALID_STATE_TRANSITION",
            tx_hash=tx_id,
            details=details,
        )
        self.current_state = current_state
        self.target_state = target_state
        self.allowed_transitions = allowed_transitions


class EscrowNotFoundError(ACTPError):
    """
    Raised when an escrow cannot be found.

    Example:
        >>> raise EscrowNotFoundError("escrow-0x123...")
    """

    def __init__(
        self,
        escrow_id: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            f"Escrow not found: {escrow_id}",
            code="ESCROW_NOT_FOUND",
            details=details,
        )
        self.escrow_id = escrow_id


class InsufficientBalanceError(ACTPError):
    """
    Raised when an account has insufficient balance for an operation.

    Example:
        >>> raise InsufficientBalanceError("0xRequester...", 1000000, 500000)
    """

    def __init__(
        self,
        address: str,
        required: int,
        available: int,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["address"] = address
        details["required_wei"] = str(required)
        details["available_wei"] = str(available)
        details["shortfall_wei"] = str(required - available)

        super().__init__(
            f"Insufficient balance: required {required}, available {available}",
            code="INSUFFICIENT_BALANCE",
            details=details,
        )
        self.address = address
        self.required = required
        self.available = available


class DeadlinePassedError(ACTPError):
    """
    Raised when attempting an operation after the deadline has passed.

    Example:
        >>> raise DeadlinePassedError(1700000000, 1699999000)
    """

    def __init__(
        self,
        deadline: int,
        current_time: int,
        *,
        tx_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["deadline"] = deadline
        details["current_time"] = current_time
        details["seconds_past"] = current_time - deadline

        super().__init__(
            f"Deadline has passed: deadline={deadline}, current={current_time}",
            code="DEADLINE_PASSED",
            tx_hash=tx_id,
            details=details,
        )
        self.deadline = deadline
        self.current_time = current_time


# Alias for API compatibility with TypeScript SDK
DeadlineExpiredError = DeadlinePassedError


class DisputeWindowActiveError(ACTPError):
    """
    Raised when attempting to finalize during an active dispute window.

    Example:
        >>> raise DisputeWindowActiveError(3600, escrow_id="escrow-0x123...")
    """

    def __init__(
        self,
        remaining_seconds: int,
        *,
        escrow_id: Optional[str] = None,
        tx_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["remaining_seconds"] = remaining_seconds
        if escrow_id:
            details["escrow_id"] = escrow_id

        super().__init__(
            f"Dispute window still active: {remaining_seconds} seconds remaining",
            code="DISPUTE_WINDOW_ACTIVE",
            tx_hash=tx_id,
            details=details,
        )
        self.remaining_seconds = remaining_seconds
        self.escrow_id = escrow_id


class ContractPausedError(ACTPError):
    """
    Raised when attempting an operation on a paused contract.

    Example:
        >>> raise ContractPausedError("ACTPKernel")
    """

    def __init__(
        self,
        contract_name: str = "ACTPKernel",
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        details = details or {}
        details["contract"] = contract_name

        super().__init__(
            f"Contract is paused: {contract_name}",
            code="CONTRACT_PAUSED",
            details=details,
        )
        self.contract_name = contract_name
