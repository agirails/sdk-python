"""
AIP-16 Delivery Surface — Pluggable Channel Logger (Python port).

Mirrors sdk-js/src/delivery/channelLog.ts. A ``LogFn`` is a callable
``(level, msg, details=None) -> None`` used by the channel implementations to
surface operational events without coupling to any logging framework.

``LogFn`` implementations MUST NOT throw and MUST be synchronous from the
channel's point of view (the channel never awaits them) — same contract as TS
(channelLog.ts:71).

Cite: sdk-js/src/delivery/channelLog.ts:100 (LogFn), :128 (noopLog).
"""

from __future__ import annotations

from typing import Callable, Dict, Literal, Optional

# TS channelLog.ts:100 — LogFn
# (level, msg, details?) -> void
LogLevel = Literal["info", "warn", "error"]
LogFn = Callable[[LogLevel, str, Optional[Dict[str, object]]], None]


def noop_log(level: str, msg: str, details: Optional[Dict[str, object]] = None) -> None:
    """Silent default LogFn — discards every event (TS channelLog.ts:128 noopLog)."""
    # Intentional no-op. See module docstring for rationale.
    return None


# Alias matching the TS export name for ergonomic 1:1 imports.
noopLog = noop_log


__all__ = [
    "LogFn",
    "LogLevel",
    "noop_log",
    "noopLog",
]
