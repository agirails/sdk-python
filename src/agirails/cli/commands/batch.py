"""
Batch Command - Execute multiple commands from a file.

Agent-first feature: Process commands in bulk.
Perfect for:
- Scripted workflows
- Replaying transaction sequences
- Automated testing

Security: Commands are validated against an allowlist and arguments
are passed as an array to avoid shell injection attacks.

PARITY: Matches TypeScript SDK's cli/commands/batch.ts
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_success,
    print_warning,
    print_json,
)

# ============================================================================
# Security: Command Allowlist and Argument Parsing
# ============================================================================

# Allowlist of valid ACTP subcommands
VALID_SUBCOMMANDS = frozenset([
    "init", "pay", "tx", "balance", "mint", "config",
    "watch", "simulate", "time",
])

# Allowlist of valid 'tx' subcommands
VALID_TX_SUBCOMMANDS = frozenset([
    "create", "status", "list", "deliver", "settle", "cancel",
])

# Characters that are not allowed in command arguments (potential shell injection)
DANGEROUS_CHARS_PATTERN = re.compile(r'[;&|`$(){}[\]<>!\\]')


def parse_command_args(command: str) -> List[str]:
    """
    Parse a command string into an array of arguments safely.

    Uses shlex for safe parsing (no shell interpretation).

    Args:
        command: Raw command string

    Returns:
        List of parsed arguments

    Raises:
        ValueError: If command contains dangerous characters
    """
    # Remove quoted strings temporarily to check for dangerous chars
    clean_command = re.sub(r'"[^"]*"|\'[^\']*\'', '', command)

    if DANGEROUS_CHARS_PATTERN.search(clean_command):
        raise ValueError(
            "Command contains potentially dangerous characters. "
            "Shell metacharacters are not allowed for security reasons."
        )

    try:
        return shlex.split(command)
    except ValueError as e:
        raise ValueError(f"Invalid command syntax: {e}")


def validate_command(args: List[str]) -> bool:
    """
    Validate that a command only uses allowed subcommands.

    Args:
        args: Parsed command arguments

    Returns:
        True if command is valid

    Raises:
        ValueError: If command is not in allowlist
    """
    if not args:
        raise ValueError("Empty command")

    subcommand = args[0]

    if subcommand == "tx":
        if len(args) < 2:
            raise ValueError("tx command requires a subcommand")
        if args[1] not in VALID_TX_SUBCOMMANDS:
            raise ValueError(
                f"Unknown tx subcommand: {args[1]}. "
                f"Allowed: {', '.join(sorted(VALID_TX_SUBCOMMANDS))}"
            )
        return True

    if subcommand not in VALID_SUBCOMMANDS:
        raise ValueError(
            f"Unknown command: {subcommand}. "
            f"Allowed: {', '.join(sorted(VALID_SUBCOMMANDS))}"
        )

    return True


# ============================================================================
# Batch Execution
# ============================================================================

def execute_command(command: str) -> Tuple[bool, str, int]:
    """
    Execute a command by spawning a child process.

    SECURITY: Uses subprocess with shell=False.
    Arguments are passed as an array directly to the actp binary.

    Args:
        command: Command string to execute

    Returns:
        Tuple of (success, output/error, duration_ms)
    """
    start_time = time.time()

    try:
        # Parse command safely
        args = parse_command_args(command)
        validate_command(args)

        # Add --json flag for structured output
        args.append("--json")

        # Prepend 'actp' binary
        full_args = ["actp"] + args

        # SECURITY: Use shell=False and pass arguments as array
        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=120,  # 2 minute timeout per command
        )

        duration_ms = int((time.time() - start_time) * 1000)

        if result.returncode == 0:
            return True, result.stdout.strip() or "OK", duration_ms
        else:
            # Try to parse error from output
            error_output = result.stderr.strip() or result.stdout.strip()
            try:
                error_obj = json.loads(error_output)
                error_msg = error_obj.get("error", {}).get("message", "Command failed")
            except json.JSONDecodeError:
                error_msg = error_output or f"Exit code: {result.returncode}"
            return False, error_msg, duration_ms

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        return False, "Command timed out (120s)", duration_ms
    except FileNotFoundError:
        duration_ms = int((time.time() - start_time) * 1000)
        return False, "actp command not found. Is it installed?", duration_ms
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        return False, str(e), duration_ms


def parse_command_for_validation(command: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Parse and validate a command (for dry-run mode).

    Args:
        command: Command string

    Returns:
        Tuple of (valid, parsed_command, error)
    """
    try:
        args = parse_command_args(command)
        if not args:
            return False, None, "Empty command"

        validate_command(args)

        return True, f"actp {' '.join(args)}", None
    except Exception as e:
        return False, None, str(e)


# ============================================================================
# Command Definition
# ============================================================================

def batch(
    file: Optional[str] = typer.Argument(None, help="File containing commands (one per line), or - for stdin"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Parse and validate commands without executing"),
    stop_on_error: bool = typer.Option(False, "--stop-on-error", help="Stop execution on first error"),
) -> None:
    """
    Execute multiple commands from a file (agent-first feature).

    Commands are read from a file (one per line) or stdin.
    Lines starting with # are treated as comments.

    Examples:

        $ actp batch commands.txt

        $ actp batch commands.txt --dry-run

        $ cat commands.txt | actp batch -

        $ actp batch commands.txt --stop-on-error

    Security:
        Commands are validated against an allowlist.
        Shell metacharacters are not allowed.
    """
    global_opts = get_global_options()

    try:
        # Read commands
        if file == "-" or file is None:
            # Read from stdin
            if sys.stdin.isatty() and file is None:
                print_error("No file specified. Use - to read from stdin.")
                raise typer.Exit(code=1)
            commands = sys.stdin.read().splitlines()
        else:
            # Read from file
            file_path = Path(file)
            if not file_path.exists():
                print_error(f"File not found: {file}")
                raise typer.Exit(code=1)
            commands = file_path.read_text().splitlines()

        # Filter empty lines and comments
        commands_with_line = [
            (i + 1, line.strip())
            for i, line in enumerate(commands)
            if line.strip() and not line.strip().startswith("#")
        ]

        if not commands_with_line:
            if global_opts.json_output:
                print_json({"message": "No commands to execute", "total": 0})
            else:
                print_warning("No commands to execute.")
            return

        if not global_opts.quiet and not global_opts.json_output:
            print_info(f"Processing {len(commands_with_line)} command(s)...\n")

        results: List[Dict[str, Any]] = []
        success_count = 0
        error_count = 0
        skipped_count = 0

        for line_num, command in commands_with_line:
            if dry_run:
                # Dry run: just parse and validate
                valid, parsed, error = parse_command_for_validation(command)

                if valid:
                    results.append({
                        "line": line_num,
                        "command": command,
                        "status": "success",
                        "output": f"Would execute: {parsed}",
                    })
                    success_count += 1
                    if not global_opts.quiet and not global_opts.json_output:
                        print(f"[{line_num}] VALID   {command}")
                else:
                    results.append({
                        "line": line_num,
                        "command": command,
                        "status": "error",
                        "error": error,
                    })
                    error_count += 1
                    if not global_opts.quiet and not global_opts.json_output:
                        print(f"[{line_num}] INVALID {command}")
                        print(f"         {error}")

                    if stop_on_error:
                        if not global_opts.quiet and not global_opts.json_output:
                            print_error("Stopping on error (--stop-on-error)")
                        break
            else:
                # Execute command
                success, output, duration_ms = execute_command(command)

                if success:
                    results.append({
                        "line": line_num,
                        "command": command,
                        "status": "success",
                        "output": output,
                        "duration": duration_ms,
                    })
                    success_count += 1
                    if not global_opts.quiet and not global_opts.json_output:
                        print(f"[{line_num}] OK      {command} ({duration_ms}ms)")
                else:
                    results.append({
                        "line": line_num,
                        "command": command,
                        "status": "error",
                        "error": output,
                        "duration": duration_ms,
                    })
                    error_count += 1
                    if not global_opts.quiet and not global_opts.json_output:
                        print(f"[{line_num}] FAIL    {command} ({duration_ms}ms)")
                        print(f"         {output}")

                    if stop_on_error:
                        if not global_opts.quiet and not global_opts.json_output:
                            print_error("Stopping on error (--stop-on-error)")
                        skipped_count = len(commands_with_line) - success_count - error_count
                        break

        # Summary
        if global_opts.json_output:
            print_json({
                "results": results,
                "summary": {
                    "total": len(commands_with_line),
                    "succeeded": success_count,
                    "failed": error_count,
                    "skipped": skipped_count,
                },
            })
        elif not global_opts.quiet:
            print("\n=== Batch Summary ===")
            print(f"  Total Commands: {len(commands_with_line)}")
            print(f"  Succeeded:      {success_count}")
            print(f"  Failed:         {error_count}")
            if skipped_count > 0:
                print(f"  Skipped:        {skipped_count}")

        # Exit with appropriate code
        if error_count > 0:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        if global_opts.json_output:
            print_json({"error": {"code": "ERROR", "message": str(e)}})
        else:
            print_error(str(e))
        raise typer.Exit(code=1)


__all__ = ["batch"]
