"""
Logger utility for AGIRAILS SDK.

Provides structured logging with JSON output support.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class Logger:
    """
    Structured logger for AGIRAILS SDK.

    Provides consistent logging with configurable levels and JSON output.

    Example:
        >>> logger = Logger("ACTPClient")
        >>> logger.info("Transaction created", {"tx_id": "0x123..."})
        >>> logger.error("Transaction failed", {"tx_id": "0x123..."}, exception=e)
    """

    LEVELS = {
        "debug": 10,
        "info": 20,
        "warn": 30,
        "error": 40,
    }

    def __init__(
        self,
        source: str,
        min_level: str = "info",
        json_output: bool = False,
    ) -> None:
        """
        Initialize Logger.

        Args:
            source: Source identifier (e.g., "ACTPClient", "MockRuntime").
            min_level: Minimum log level ("debug", "info", "warn", "error").
            json_output: If True, output logs as JSON.
        """
        self.source = source
        self.min_level = min_level.lower()
        self.json_output = json_output

        if self.min_level not in self.LEVELS:
            raise ValueError(f"Invalid log level: {min_level}")

    def _should_log(self, level: str) -> bool:
        """Check if message should be logged at given level."""
        return self.LEVELS.get(level, 0) >= self.LEVELS.get(self.min_level, 0)

    def _format_message(
        self,
        level: str,
        message: str,
        meta: Optional[Dict[str, Any]] = None,
        exception: Optional[BaseException] = None,
    ) -> str:
        """Format log message."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.json_output:
            log_entry = {
                "timestamp": timestamp,
                "level": level.upper(),
                "source": self.source,
                "message": message,
            }
            if meta:
                log_entry["meta"] = meta
            if exception:
                log_entry["error"] = {
                    "type": type(exception).__name__,
                    "message": str(exception),
                }
            return json.dumps(log_entry)

        # Human-readable format
        parts = [
            f"[{timestamp}]",
            f"[{level.upper():5}]",
            f"[{self.source}]",
            message,
        ]

        if meta:
            meta_str = " ".join(f"{k}={v}" for k, v in meta.items())
            parts.append(f"({meta_str})")

        if exception:
            parts.append(f"| Error: {type(exception).__name__}: {exception}")

        return " ".join(parts)

    def _log(
        self,
        level: str,
        message: str,
        meta: Optional[Dict[str, Any]] = None,
        exception: Optional[BaseException] = None,
    ) -> None:
        """Write log message."""
        if not self._should_log(level):
            return

        formatted = self._format_message(level, message, meta, exception)

        # Use stderr for errors, stdout for others
        stream = sys.stderr if level == "error" else sys.stdout
        print(formatted, file=stream)

    def debug(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """
        Log debug message.

        Args:
            message: Log message.
            meta: Optional metadata dictionary.
        """
        self._log("debug", message, meta)

    def info(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """
        Log info message.

        Args:
            message: Log message.
            meta: Optional metadata dictionary.
        """
        self._log("info", message, meta)

    def warn(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """
        Log warning message.

        Args:
            message: Log message.
            meta: Optional metadata dictionary.
        """
        self._log("warn", message, meta)

    def error(
        self,
        message: str,
        meta: Optional[Dict[str, Any]] = None,
        exception: Optional[BaseException] = None,
    ) -> None:
        """
        Log error message.

        Args:
            message: Log message.
            meta: Optional metadata dictionary.
            exception: Optional exception to include.
        """
        self._log("error", message, meta, exception)

    def child(self, source_suffix: str) -> "Logger":
        """
        Create a child logger with extended source name.

        Args:
            source_suffix: Suffix to append to source name.

        Returns:
            New Logger with combined source name.

        Example:
            >>> logger = Logger("ACTPClient")
            >>> child = logger.child("Transaction")
            >>> child.source
            'ACTPClient:Transaction'
        """
        return Logger(
            source=f"{self.source}:{source_suffix}",
            min_level=self.min_level,
            json_output=self.json_output,
        )
