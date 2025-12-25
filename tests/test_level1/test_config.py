"""Tests for Level 1 configuration types."""

import pytest
from agirails.level1.config import (
    AgentConfig,
    AgentBehavior,
    ServiceConfig,
    ServiceFilter,
    RetryConfig,
)
from agirails.level1.job import Job
from datetime import datetime, timedelta


class TestRetryConfig:
    """Tests for RetryConfig."""

    def test_default_values(self):
        """Test default retry configuration."""
        config = RetryConfig()
        assert config.attempts == 3
        assert config.delay == 1000
        assert config.backoff == "exponential"

    def test_linear_delay(self):
        """Test linear backoff delay calculation."""
        config = RetryConfig(delay=1000, backoff="linear")
        assert config.get_delay_ms(1) == 1000
        assert config.get_delay_ms(2) == 2000
        assert config.get_delay_ms(3) == 3000

    def test_exponential_delay(self):
        """Test exponential backoff delay calculation."""
        config = RetryConfig(delay=1000, backoff="exponential")
        assert config.get_delay_ms(1) == 1000
        assert config.get_delay_ms(2) == 2000
        assert config.get_delay_ms(3) == 4000
        assert config.get_delay_ms(4) == 8000


class TestAgentBehavior:
    """Tests for AgentBehavior."""

    def test_default_values(self):
        """Test default behavior settings."""
        behavior = AgentBehavior()
        assert behavior.auto_accept is True
        assert behavior.concurrency == 10
        assert behavior.timeout == 300
        assert behavior.retry is None

    def test_custom_values(self):
        """Test custom behavior settings."""
        retry = RetryConfig(attempts=5)
        behavior = AgentBehavior(
            auto_accept=False,
            concurrency=5,
            timeout=600,
            retry=retry,
        )
        assert behavior.auto_accept is False
        assert behavior.concurrency == 5
        assert behavior.timeout == 600
        assert behavior.retry.attempts == 5


class TestAgentConfig:
    """Tests for AgentConfig."""

    def test_required_name(self):
        """Test that name is required."""
        with pytest.raises(ValueError, match="name is required"):
            AgentConfig(name="")

    def test_valid_name(self):
        """Test valid agent names."""
        config = AgentConfig(name="my-agent")
        assert config.name == "my-agent"

        config = AgentConfig(name="my_agent_123")
        assert config.name == "my_agent_123"

    def test_invalid_name_characters(self):
        """Test invalid characters in name."""
        with pytest.raises(ValueError, match="alphanumeric"):
            AgentConfig(name="my agent")  # Space not allowed

        with pytest.raises(ValueError, match="alphanumeric"):
            AgentConfig(name="my.agent")  # Dot not allowed

    def test_name_too_long(self):
        """Test name length limit."""
        with pytest.raises(ValueError, match="64 characters"):
            AgentConfig(name="a" * 65)

        # Max length should work
        config = AgentConfig(name="a" * 64)
        assert len(config.name) == 64

    def test_default_values(self):
        """Test default configuration values."""
        config = AgentConfig(name="test")
        assert config.description == ""
        assert config.network == "mock"
        assert config.wallet is None
        assert config.behavior is None

    def test_get_behavior(self):
        """Test get_behavior helper."""
        config = AgentConfig(name="test")
        behavior = config.get_behavior()
        assert behavior.concurrency == 10  # Default

        custom_behavior = AgentBehavior(concurrency=5)
        config = AgentConfig(name="test", behavior=custom_behavior)
        assert config.get_behavior().concurrency == 5


class TestServiceFilter:
    """Tests for ServiceFilter."""

    def test_no_filter(self):
        """Test filter with no constraints."""
        filter = ServiceFilter()
        job = Job(
            id="0x123",
            service="test",
            input={},
            budget=100.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert filter.matches(job)

    def test_min_budget_filter(self):
        """Test minimum budget filtering."""
        filter = ServiceFilter(min_budget=10.0)

        job_ok = Job(
            id="0x123",
            service="test",
            input={},
            budget=15.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert filter.matches(job_ok)

        job_low = Job(
            id="0x123",
            service="test",
            input={},
            budget=5.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert not filter.matches(job_low)

    def test_max_budget_filter(self):
        """Test maximum budget filtering."""
        filter = ServiceFilter(max_budget=100.0)

        job_ok = Job(
            id="0x123",
            service="test",
            input={},
            budget=50.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert filter.matches(job_ok)

        job_high = Job(
            id="0x123",
            service="test",
            input={},
            budget=150.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert not filter.matches(job_high)

    def test_custom_filter(self):
        """Test custom filter function."""
        filter = ServiceFilter(
            custom=lambda job: job.metadata.get("priority") == "high"
        )

        job_priority = Job(
            id="0x123",
            service="test",
            input={},
            budget=10.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
            metadata={"priority": "high"},
        )
        assert filter.matches(job_priority)

        job_no_priority = Job(
            id="0x123",
            service="test",
            input={},
            budget=10.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert not filter.matches(job_no_priority)


class TestServiceConfig:
    """Tests for ServiceConfig."""

    def test_required_name(self):
        """Test that name is required."""
        with pytest.raises(ValueError, match="name is required"):
            ServiceConfig(name="")

    def test_basic_config(self):
        """Test basic service configuration."""
        config = ServiceConfig(
            name="text-gen",
            description="Generate text",
            capabilities=["gpt-4"],
        )
        assert config.name == "text-gen"
        assert config.description == "Generate text"
        assert config.capabilities == ["gpt-4"]

    def test_get_timeout(self):
        """Test timeout helper."""
        config = ServiceConfig(name="test")
        assert config.get_timeout(default=300) == 300

        config = ServiceConfig(name="test", timeout=600)
        assert config.get_timeout(default=300) == 600

    def test_matches_job(self):
        """Test job matching with filter."""
        config = ServiceConfig(
            name="test",
            filter=ServiceFilter(min_budget=10.0),
        )

        job_ok = Job(
            id="0x123",
            service="test",
            input={},
            budget=15.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert config.matches_job(job_ok)

        job_low = Job(
            id="0x123",
            service="test",
            input={},
            budget=5.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert not config.matches_job(job_low)

    def test_no_filter_matches_all(self):
        """Test that no filter matches all jobs."""
        config = ServiceConfig(name="test")

        job = Job(
            id="0x123",
            service="test",
            input={},
            budget=1.0,
            deadline=datetime.now() + timedelta(hours=1),
            requester="0x456",
        )
        assert config.matches_job(job)
