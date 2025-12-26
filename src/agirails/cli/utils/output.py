"""
CLI Output Utilities.

Provides formatted output for CLI commands with support for:
- JSON output (--json flag)
- Quiet mode (--quiet flag)
- Pretty tables
- Colored messages
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rich_print

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Console instances
_console = Console() if HAS_RICH else None
_err_console = Console(stderr=True) if HAS_RICH else None


class OutputFormat(str, Enum):
    """Output format options."""

    PRETTY = "pretty"
    JSON = "json"
    QUIET = "quiet"


def format_output(
    data: Any,
    format_type: OutputFormat = OutputFormat.PRETTY,
    quiet_value: Optional[str] = None,
) -> str:
    """
    Format data based on output type.

    Args:
        data: Data to format
        format_type: Output format (pretty, json, quiet)
        quiet_value: Value to return in quiet mode (defaults to first value)

    Returns:
        Formatted string
    """
    if format_type == OutputFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    if format_type == OutputFormat.QUIET:
        if quiet_value is not None:
            return quiet_value
        # Extract first meaningful value
        if isinstance(data, dict):
            # Return txId, escrowId, or first value
            for key in ["txId", "tx_id", "escrowId", "escrow_id", "id", "address"]:
                if key in data:
                    return str(data[key])
            # Return first value
            if data:
                return str(next(iter(data.values())))
        return str(data)

    # Pretty format
    if isinstance(data, dict):
        lines = []
        for key, value in data.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)
    return str(data)


def print_json(data: Any) -> None:
    """Print data as formatted JSON."""
    output = json.dumps(data, indent=2, default=str)
    print(output)


def print_success(message: str, data: Optional[Dict[str, Any]] = None) -> None:
    """Print success message."""
    if HAS_RICH and _console:
        _console.print(f"[green]\u2713[/green] {message}")
        if data:
            for key, value in data.items():
                _console.print(f"  [dim]{key}:[/dim] {value}")
    else:
        print(f"\u2713 {message}")
        if data:
            for key, value in data.items():
                print(f"  {key}: {value}")


def print_error(message: str, details: Optional[str] = None) -> None:
    """Print error message to stderr."""
    if HAS_RICH and _err_console:
        _err_console.print(f"[red]\u2717 Error:[/red] {message}")
        if details:
            _err_console.print(f"  [dim]{details}[/dim]")
    else:
        print(f"\u2717 Error: {message}", file=sys.stderr)
        if details:
            print(f"  {details}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print warning message."""
    if HAS_RICH and _console:
        _console.print(f"[yellow]\u26a0[/yellow] {message}")
    else:
        print(f"\u26a0 {message}")


def print_info(message: str) -> None:
    """Print info message."""
    if HAS_RICH and _console:
        _console.print(f"[blue]\u2139[/blue] {message}")
    else:
        print(f"\u2139 {message}")


def print_table(
    headers: List[str],
    rows: List[List[Any]],
    title: Optional[str] = None,
) -> None:
    """
    Print data as a table.

    Args:
        headers: Column headers
        rows: Table rows (list of lists)
        title: Optional table title
    """
    if HAS_RICH and _console:
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        _console.print(table)
    else:
        # Simple text table
        if title:
            print(f"\n{title}")
            print("-" * len(title))

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        # Print header
        header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(header_line)
        print("-" * len(header_line))

        # Print rows
        for row in rows:
            row_line = " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
            print(row_line)


def print_transaction(tx: Dict[str, Any], format_type: OutputFormat = OutputFormat.PRETTY) -> None:
    """
    Print transaction details.

    Args:
        tx: Transaction data
        format_type: Output format
    """
    if format_type == OutputFormat.JSON:
        print_json(tx)
        return

    if format_type == OutputFormat.QUIET:
        print(tx.get("id", tx.get("tx_id", "")))
        return

    # Pretty format
    if HAS_RICH and _console:
        from rich.panel import Panel

        lines = []
        for key, value in tx.items():
            lines.append(f"[dim]{key}:[/dim] {value}")
        panel = Panel("\n".join(lines), title="Transaction")
        _console.print(panel)
    else:
        print("\nTransaction:")
        print("-" * 40)
        for key, value in tx.items():
            print(f"  {key}: {value}")


def format_usdc(wei: Union[int, str]) -> str:
    """Format wei amount as USDC string."""
    wei_int = int(wei)
    usdc = wei_int / 1_000_000
    return f"${usdc:.2f} USDC"


def format_address(address: str, chars: int = 6) -> str:
    """Truncate address for display."""
    if len(address) <= chars * 2 + 2:
        return address
    return f"{address[:chars + 2]}...{address[-chars:]}"


def format_state(state: str) -> str:
    """Format state with color coding."""
    colors = {
        "INITIATED": "blue",
        "QUOTED": "cyan",
        "COMMITTED": "yellow",
        "IN_PROGRESS": "yellow",
        "DELIVERED": "green",
        "SETTLED": "green",
        "DISPUTED": "red",
        "CANCELLED": "dim",
    }
    color = colors.get(state.upper(), "white")
    if HAS_RICH:
        return f"[{color}]{state}[/{color}]"
    return state


__all__ = [
    "OutputFormat",
    "format_output",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_table",
    "print_json",
    "print_transaction",
    "format_usdc",
    "format_address",
    "format_state",
]
