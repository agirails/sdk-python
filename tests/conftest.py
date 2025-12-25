"""
Pytest configuration and fixtures for AGIRAILS SDK tests.
"""

import asyncio
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator

import pytest

from agirails.runtime import MockRuntime, MockStateManager


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test state files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def state_manager(temp_dir: Path) -> MockStateManager:
    """Create a MockStateManager with a temporary directory."""
    return MockStateManager(state_directory=temp_dir / ".actp")


@pytest.fixture
async def mock_runtime(temp_dir: Path) -> AsyncGenerator[MockRuntime, None]:
    """
    Create a fresh MockRuntime for each test.

    The runtime uses a temporary directory, so each test gets isolated state.
    """
    runtime = MockRuntime(state_directory=temp_dir / ".actp")
    yield runtime
    # Clean up
    await runtime.reset()


@pytest.fixture
async def funded_runtime(mock_runtime: MockRuntime) -> MockRuntime:
    """
    Create a MockRuntime with pre-funded test accounts.

    Provides:
    - 0xRequester...111: 1,000,000 USDC (1_000_000_000_000 wei)
    - 0xProvider...222: 100,000 USDC (100_000_000_000 wei)
    """
    # Use valid checksum addresses
    requester = "0x" + "1" * 40
    provider = "0x" + "2" * 40

    await mock_runtime.mint_tokens(requester, "1000000000000")  # 1M USDC
    await mock_runtime.mint_tokens(provider, "100000000000")  # 100K USDC

    return mock_runtime


# Common test addresses
TEST_REQUESTER = "0x" + "1" * 40
TEST_PROVIDER = "0x" + "2" * 40
TEST_OTHER = "0x" + "3" * 40


@pytest.fixture
def requester_address() -> str:
    """Return test requester address."""
    return TEST_REQUESTER


@pytest.fixture
def provider_address() -> str:
    """Return test provider address."""
    return TEST_PROVIDER
