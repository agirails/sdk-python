"""Tests for agent error classes."""

from __future__ import annotations

import pytest

from agirails.errors.base import ACTPError
from agirails.errors.agent import (
    NoProviderFoundError,
    TimeoutError as ACTPTimeoutError,
    ProviderRejectedError,
    DeliveryFailedError,
    DisputeRaisedError,
    ServiceConfigError,
    AgentLifecycleError,
    QueryCapExceededError,
)


class TestNoProviderFoundError:
    """Tests for NoProviderFoundError."""

    def test_basic_creation(self) -> None:
        """Test creating with service name."""
        error = NoProviderFoundError("text-generation")

        assert "text-generation" in error.message
        assert error.code == "NO_PROVIDER_FOUND"
        assert error.service_name == "text-generation"

    def test_with_timeout(self) -> None:
        """Test with timeout value."""
        error = NoProviderFoundError(
            "image-gen",
            timeout_ms=30000,
        )

        assert error.timeout_ms == 30000
        assert error.details["timeout_ms"] == 30000

    def test_with_filters(self) -> None:
        """Test with search filters."""
        error = NoProviderFoundError(
            "audio",
            filters={"model": "whisper", "quality": "high"},
        )

        assert error.filters == {"model": "whisper", "quality": "high"}
        assert error.details["filters"] == {"model": "whisper", "quality": "high"}


class TestACTPTimeoutError:
    """Tests for TimeoutError (ACTPTimeoutError)."""

    def test_basic_creation(self) -> None:
        """Test creating with operation and timeout."""
        error = ACTPTimeoutError("request", 30000)

        assert "request" in error.message
        assert "30000" in error.message
        assert error.code == "TIMEOUT"
        assert error.operation == "request"
        assert error.timeout_ms == 30000


class TestProviderRejectedError:
    """Tests for ProviderRejectedError."""

    def test_basic_creation(self) -> None:
        """Test creating with provider and reason."""
        error = ProviderRejectedError(
            "0xProvider123456789012345678901234567890ab",
            "Price too low",
        )

        assert error.code == "PROVIDER_REJECTED"
        assert error.provider_address == "0xProvider123456789012345678901234567890ab"
        assert error.reason == "Price too low"

    def test_with_service_name(self) -> None:
        """Test with service name."""
        error = ProviderRejectedError(
            "0xProv",
            "Busy",
            service_name="compute",
        )

        assert error.service_name == "compute"
        assert error.details["service_name"] == "compute"

    def test_with_tx_id(self) -> None:
        """Test with transaction ID."""
        error = ProviderRejectedError(
            "0xProv",
            "Rejected",
            tx_id="0xtx123",
        )

        assert error.tx_hash == "0xtx123"


class TestDeliveryFailedError:
    """Tests for DeliveryFailedError."""

    def test_basic_creation(self) -> None:
        """Test creating with provider and reason."""
        error = DeliveryFailedError(
            "0xProvider1234567890123456789012345678901234",
            "Computation failed",
        )

        assert error.code == "DELIVERY_FAILED"
        assert error.provider_address == "0xProvider1234567890123456789012345678901234"
        assert error.reason == "Computation failed"

    def test_with_partial_result(self) -> None:
        """Test with partial result."""
        error = DeliveryFailedError(
            "0xProv",
            "Incomplete",
            partial_result={"progress": 50, "data": "partial"},
        )

        assert error.partial_result == {"progress": 50, "data": "partial"}
        assert error.details["has_partial_result"] is True


class TestDisputeRaisedError:
    """Tests for DisputeRaisedError."""

    def test_basic_creation(self) -> None:
        """Test creating with tx ID and reason."""
        error = DisputeRaisedError("0xtx123", "Invalid output")

        assert "Invalid output" in error.message
        assert error.code == "DISPUTE_RAISED"
        assert error.tx_hash == "0xtx123"
        assert error.reason == "Invalid output"

    def test_with_raised_by(self) -> None:
        """Test with raised_by address."""
        error = DisputeRaisedError(
            "0xtx",
            "Bad quality",
            raised_by="0xRequester",
        )

        assert error.raised_by == "0xRequester"
        assert error.details["raised_by"] == "0xRequester"


class TestServiceConfigError:
    """Tests for ServiceConfigError."""

    def test_basic_creation(self) -> None:
        """Test creating with service name and reason."""
        error = ServiceConfigError("my-service", "Missing handler")

        assert "my-service" in error.message
        assert "Missing handler" in error.message
        assert error.code == "SERVICE_CONFIG_ERROR"
        assert error.service_name == "my-service"
        assert error.reason == "Missing handler"

    def test_with_config_field(self) -> None:
        """Test with specific config field."""
        error = ServiceConfigError(
            "service",
            "Invalid value",
            config_field="timeout",
        )

        assert error.config_field == "timeout"
        assert error.details["config_field"] == "timeout"


class TestAgentLifecycleError:
    """Tests for AgentLifecycleError."""

    def test_basic_creation(self) -> None:
        """Test creating with operation and reason."""
        error = AgentLifecycleError("start", "Already running")

        assert "start" in error.message
        assert "Already running" in error.message
        assert error.code == "AGENT_LIFECYCLE_ERROR"
        assert error.operation == "start"
        assert error.reason == "Already running"

    def test_with_agent_info(self) -> None:
        """Test with agent address and status."""
        error = AgentLifecycleError(
            "stop",
            "Not running",
            agent_address="0xAgent",
            current_status="IDLE",
        )

        assert error.agent_address == "0xAgent"
        assert error.current_status == "IDLE"
        assert error.details["agent_address"] == "0xAgent"
        assert error.details["current_status"] == "IDLE"


class TestQueryCapExceededError:
    """Tests for QueryCapExceededError."""

    def test_basic_creation(self) -> None:
        """Test creating with requested and limit."""
        error = QueryCapExceededError(1000, 100)

        assert "1000" in error.message
        assert "100" in error.message
        assert error.code == "QUERY_CAP_EXCEEDED"
        assert error.requested == 1000
        assert error.limit == 100

    def test_with_query_type(self) -> None:
        """Test with query type."""
        error = QueryCapExceededError(
            500,
            50,
            query_type="transactions",
        )

        assert error.query_type == "transactions"
        assert error.details["query_type"] == "transactions"

    def test_details_include_counts(self) -> None:
        """Test details include requested and limit."""
        error = QueryCapExceededError(200, 100)

        assert error.details["requested"] == 200
        assert error.details["limit"] == 100
