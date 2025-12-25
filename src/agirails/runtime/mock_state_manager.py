"""
Mock state persistence manager.

Handles file-based state persistence for the MockRuntime,
including atomic updates with file locking to prevent race conditions.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
from pathlib import Path
from typing import Awaitable, Callable, Optional, TypeVar, Union

from agirails.errors import (
    MockStateCorruptedError,
    MockStateVersionError,
    MockStateLockError,
)
from agirails.runtime.types import MockState, create_default_state, MOCK_STATE_DEFAULTS

T = TypeVar("T")

# Current state schema version
STATE_VERSION = "2.0.0"


class MockStateManager:
    """
    File-based state persistence for MockRuntime.

    Manages loading, saving, and atomic updates of mock state
    to `.actp/mock-state.json` with file locking for concurrent access.

    Example:
        >>> manager = MockStateManager()
        >>> state = await manager.load()
        >>> state.balances["0x123..."] = "1000000"
        >>> await manager.save(state)

        >>> # Atomic update with locking
        >>> async def update(state):
        ...     state.balances["0x123..."] = "2000000"
        ...     return state
        >>> await manager.with_lock(update)
    """

    def __init__(
        self,
        state_directory: Optional[Union[str, Path]] = None,
        state_filename: str = "mock-state.json",
        lock_timeout_ms: int = 5000,
    ) -> None:
        """
        Initialize MockStateManager.

        Args:
            state_directory: Directory for state file (default: .actp in cwd).
            state_filename: Name of the state file.
            lock_timeout_ms: Timeout for acquiring file lock in milliseconds.
        """
        if state_directory is None:
            state_directory = Path.cwd() / MOCK_STATE_DEFAULTS["state_directory"]
        else:
            state_directory = Path(state_directory)

        self._state_directory = state_directory
        self._state_filename = state_filename
        self._lock_timeout_ms = lock_timeout_ms
        self._lock_file: Optional[int] = None

    @property
    def state_file_path(self) -> Path:
        """Get the full path to the state file."""
        return self._state_directory / self._state_filename

    @property
    def lock_file_path(self) -> Path:
        """Get the full path to the lock file."""
        return self._state_directory / f"{self._state_filename}.lock"

    def _ensure_directory(self) -> None:
        """Create state directory if it doesn't exist."""
        self._state_directory.mkdir(parents=True, exist_ok=True)

    async def load(self) -> MockState:
        """
        Load state from file.

        Creates default state if file doesn't exist.

        Returns:
            Loaded or default MockState.

        Raises:
            MockStateCorruptedError: If state file is corrupted.
            MockStateVersionError: If state version is incompatible.
        """
        self._ensure_directory()

        if not self.state_file_path.exists():
            return create_default_state()

        try:
            # Use asyncio.to_thread for blocking I/O
            content = await asyncio.to_thread(self._read_file)
            data = json.loads(content)

            # Check version compatibility
            file_version = data.get("version", "1.0.0")
            if not self._is_version_compatible(file_version):
                raise MockStateVersionError(file_version, STATE_VERSION)

            return MockState.from_dict(data)

        except json.JSONDecodeError as e:
            raise MockStateCorruptedError(
                str(self.state_file_path),
                reason=f"Invalid JSON: {e}",
            )
        except KeyError as e:
            raise MockStateCorruptedError(
                str(self.state_file_path),
                reason=f"Missing required field: {e}",
            )

    def _read_file(self) -> str:
        """Synchronous file read (run in thread)."""
        with open(self.state_file_path, "r", encoding="utf-8") as f:
            return f.read()

    async def save(self, state: MockState) -> None:
        """
        Save state to file.

        Args:
            state: State to save.
        """
        self._ensure_directory()

        # Serialize state
        data = state.to_dict()
        content = json.dumps(data, indent=2, ensure_ascii=False)

        # Write atomically using temp file
        await asyncio.to_thread(self._write_file_atomic, content)

    def _write_file_atomic(self, content: str) -> None:
        """
        Atomic file write using temp file + rename.

        This ensures the state file is never corrupted if the process
        is interrupted during write.
        """
        temp_path = self.state_file_path.with_suffix(".tmp")

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            temp_path.rename(self.state_file_path)
        except Exception:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

    async def reset(self) -> None:
        """
        Reset state to default.

        Deletes the state file and creates a fresh default state.
        """
        if self.state_file_path.exists():
            await asyncio.to_thread(self.state_file_path.unlink)

        state = create_default_state()
        await self.save(state)

    async def with_lock(
        self,
        updater: Callable[[MockState], Awaitable[Union[MockState, T]]],
    ) -> T:
        """
        Perform atomic update with file locking.

        Acquires an exclusive lock on the state file, loads state,
        applies the updater function, and saves the result.

        Args:
            updater: Async function that takes current state and returns updated state.

        Returns:
            Result of the updater function.

        Raises:
            MockStateLockError: If lock cannot be acquired within timeout.

        Example:
            >>> async def add_balance(state):
            ...     state.balances["0x123"] = str(
            ...         int(state.balances.get("0x123", "0")) + 1000
            ...     )
            ...     return state
            >>> await manager.with_lock(add_balance)
        """
        self._ensure_directory()

        # Create lock file if it doesn't exist
        lock_file_path = self.lock_file_path
        if not lock_file_path.exists():
            lock_file_path.touch()

        lock_fd = None
        try:
            # Open lock file
            lock_fd = os.open(str(lock_file_path), os.O_RDWR | os.O_CREAT)

            # Try to acquire exclusive lock with timeout
            await self._acquire_lock(lock_fd)

            try:
                # Load current state
                state = await self.load()

                # Apply update
                result = await updater(state)

                # Save if updater returned a state
                if isinstance(result, MockState):
                    await self.save(result)

                return result  # type: ignore

            finally:
                # Release lock
                fcntl.flock(lock_fd, fcntl.LOCK_UN)

        finally:
            if lock_fd is not None:
                os.close(lock_fd)

    async def _acquire_lock(self, fd: int) -> None:
        """
        Acquire exclusive lock with timeout.

        Args:
            fd: File descriptor to lock.

        Raises:
            MockStateLockError: If lock cannot be acquired within timeout.
        """
        timeout_s = self._lock_timeout_ms / 1000
        start_time = asyncio.get_event_loop().time()

        while True:
            try:
                # Try non-blocking lock
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return  # Lock acquired
            except BlockingIOError:
                # Lock is held by another process
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed >= timeout_s:
                    raise MockStateLockError(
                        str(self.state_file_path),
                        timeout_ms=self._lock_timeout_ms,
                    )

                # Wait a bit before retrying
                await asyncio.sleep(0.01)

    def _is_version_compatible(self, file_version: str) -> bool:
        """
        Check if file version is compatible with current version.

        Currently only major version must match.

        Args:
            file_version: Version string from file.

        Returns:
            True if compatible.
        """
        try:
            file_major = int(file_version.split(".")[0])
            current_major = int(STATE_VERSION.split(".")[0])
            return file_major == current_major
        except (ValueError, IndexError):
            return False

    def exists(self) -> bool:
        """Check if state file exists."""
        return self.state_file_path.exists()

    async def delete(self) -> None:
        """Delete state file and lock file."""
        if self.state_file_path.exists():
            await asyncio.to_thread(self.state_file_path.unlink)
        if self.lock_file_path.exists():
            await asyncio.to_thread(self.lock_file_path.unlink)
