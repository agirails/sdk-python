"""
Structured logging utilities for AGIRAILS SDK.

Provides:
- Configured logger for SDK components
- Structured log formatting
- Log level configuration

Example:
    >>> from agirails.utils.logging import get_logger
    >>> logger = get_logger(__name__)
    >>> logger.info("Transaction created", extra={"tx_id": "0x123", "amount": 100})
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, Optional


# Default log format with structured fields
DEFAULT_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)

# JSON-like structured format for production
STRUCTURED_FORMAT = (
    '{"time": "%(asctime)s", "level": "%(levelname)s", '
    '"logger": "%(name)s", "message": "%(message)s"}'
)


class StructuredFormatter(logging.Formatter):
    """
    Formatter that includes extra fields in log output.

    Automatically appends any extra fields passed to log methods
    to the log message in a structured format.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with extra fields."""
        # Get the base message
        message = super().format(record)

        # Find extra fields (those not in standard LogRecord)
        standard_fields = {
            'name', 'msg', 'args', 'created', 'filename', 'funcName',
            'levelname', 'levelno', 'lineno', 'module', 'msecs',
            'pathname', 'process', 'processName', 'relativeCreated',
            'stack_info', 'exc_info', 'exc_text', 'thread', 'threadName',
            'message', 'asctime',
        }

        extra = {
            k: v for k, v in record.__dict__.items()
            if k not in standard_fields and not k.startswith('_')
        }

        if extra:
            extra_str = " | " + " ".join(f"{k}={v}" for k, v in extra.items())
            message += extra_str

        return message


# Global logger cache
_loggers: Dict[str, logging.Logger] = {}

# SDK-wide log level
_sdk_level: int = logging.INFO


def configure_logging(
    level: int = logging.INFO,
    format: Optional[str] = None,
    structured: bool = False,
    handler: Optional[logging.Handler] = None,
) -> None:
    """
    Configure SDK-wide logging.

    Args:
        level: Log level (e.g., logging.DEBUG, logging.INFO)
        format: Custom log format string
        structured: Use structured JSON-like format
        handler: Custom log handler (default: StreamHandler to stderr)

    Example:
        >>> configure_logging(level=logging.DEBUG, structured=True)
    """
    global _sdk_level
    _sdk_level = level

    # Create or get the root SDK logger
    sdk_logger = logging.getLogger("agirails")
    sdk_logger.setLevel(level)

    # Remove existing handlers
    sdk_logger.handlers.clear()

    # Create handler
    if handler is None:
        handler = logging.StreamHandler(sys.stderr)

    # Set format
    if format is None:
        format = STRUCTURED_FORMAT if structured else DEFAULT_FORMAT

    formatter = StructuredFormatter(format)
    handler.setFormatter(formatter)

    sdk_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Configured logger

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Starting operation")
    """
    if name in _loggers:
        return _loggers[name]

    # Create logger as child of SDK logger
    if name.startswith("agirails"):
        logger = logging.getLogger(name)
    else:
        logger = logging.getLogger(f"agirails.{name}")

    logger.setLevel(_sdk_level)

    _loggers[name] = logger
    return logger


def set_level(level: int) -> None:
    """
    Set the log level for all SDK loggers.

    Args:
        level: New log level
    """
    global _sdk_level
    _sdk_level = level

    sdk_logger = logging.getLogger("agirails")
    sdk_logger.setLevel(level)

    for logger in _loggers.values():
        logger.setLevel(level)


def disable_logging() -> None:
    """Disable all SDK logging."""
    set_level(logging.CRITICAL + 1)


def enable_debug() -> None:
    """Enable debug-level logging."""
    set_level(logging.DEBUG)


# Log context manager for adding context to all logs in a block
class LogContext:
    """
    Context manager for adding fields to all log messages in a block.

    Example:
        >>> with LogContext(tx_id="0x123", service="echo"):
        ...     logger.info("Processing")  # Includes tx_id and service
    """

    _context: Dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        self._new_context = kwargs
        self._old_context: Dict[str, Any] = {}

    def __enter__(self) -> "LogContext":
        self._old_context = LogContext._context.copy()
        LogContext._context.update(self._new_context)
        return self

    def __exit__(self, *args: Any) -> None:
        LogContext._context = self._old_context

    @classmethod
    def get_context(cls) -> Dict[str, Any]:
        """Get current logging context."""
        return cls._context.copy()
