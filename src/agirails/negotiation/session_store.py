"""
SessionStore -- Commerce session tracking and traceability.

Every negotiation carries a canonical ``commerce_session_id`` (UUID).
No createTransaction() is allowed without a session ID.

Persisted to ``.actp/sessions.json`` using atomic writes.
"""
from __future__ import annotations

import datetime
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional


# ============================================================================
# Types
# ============================================================================

@dataclass
class SessionMapping:
    commerce_session_id: str
    task: str
    candidates_tried: List[str]  # slugs of providers attempted
    status: Literal["active", "committed", "completed", "failed", "cancelled"]
    attempts: int
    created_at: str
    updated_at: str
    actp_tx_id: Optional[str] = None
    selected_provider: Optional[str] = None


@dataclass
class SessionsFile:
    version: int  # always 1
    sessions: List[SessionMapping] = field(default_factory=list)


# ============================================================================
# SessionStore
# ============================================================================

class SessionStore:
    def __init__(self, actp_dir: Optional[str] = None) -> None:
        self._actp_dir = actp_dir or os.environ.get("ACTP_DIR") or os.path.join(os.getcwd(), ".actp")
        self._sessions: Dict[str, SessionMapping] = {}
        self._load()

    def create(self, task: str) -> SessionMapping:
        """Create a new commerce session."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session = SessionMapping(
            commerce_session_id=str(uuid.uuid4()),
            task=task,
            candidates_tried=[],
            status="active",
            attempts=0,
            created_at=now,
            updated_at=now,
        )
        self._sessions[session.commerce_session_id] = session
        self._save()
        return session

    def get(self, session_id: str) -> Optional[SessionMapping]:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def find_by_tx_id(self, tx_id: str) -> Optional[SessionMapping]:
        """Find a session by ACTP transaction ID."""
        for session in self._sessions.values():
            if session.actp_tx_id == tx_id:
                return session
        return None

    def record_attempt(self, session_id: str, provider_slug: str) -> None:
        """Record a candidate attempt (provider tried)."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")

        if provider_slug not in session.candidates_tried:
            session.candidates_tried.append(provider_slug)
        session.attempts += 1
        session.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save()

    def link_transaction(self, session_id: str, tx_id: str, provider_slug: str) -> None:
        """Link a session to an ACTP transaction."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")

        session.actp_tx_id = tx_id
        session.selected_provider = provider_slug
        session.status = "committed"
        session.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save()

    def update_status(
        self,
        session_id: str,
        status: Literal["active", "committed", "completed", "failed", "cancelled"],
    ) -> None:
        """Update session status."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")

        session.status = status
        session.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save()

    def list(
        self,
        status: Optional[Literal["active", "committed", "completed", "failed", "cancelled"]] = None,
    ) -> List[SessionMapping]:
        """List all sessions, optionally filtered by status."""
        all_sessions = list(self._sessions.values())
        if status is None:
            return all_sessions
        return [s for s in all_sessions if s.status == status]

    # ========================================================================
    # Persistence
    # ========================================================================

    def _get_file_path(self) -> str:
        return os.path.join(self._actp_dir, "sessions.json")

    def _load(self) -> None:
        path = self._get_file_path()
        try:
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if raw.get("version") != 1:
                return
            for s in raw.get("sessions", []):
                session = SessionMapping(
                    commerce_session_id=s["commerce_session_id"],
                    actp_tx_id=s.get("actp_tx_id"),
                    task=s["task"],
                    candidates_tried=s.get("candidates_tried", []),
                    selected_provider=s.get("selected_provider"),
                    status=s["status"],
                    attempts=s.get("attempts", 0),
                    created_at=s["created_at"],
                    updated_at=s["updated_at"],
                )
                self._sessions[session.commerce_session_id] = session
            # Prune terminal sessions older than 30 days
            self._prune_old_sessions()
        except Exception:
            # Corrupted file -- start fresh
            pass

    def _prune_old_sessions(self, max_age_days: int = 30) -> None:
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max_age_days)
        terminal_statuses = ("completed", "failed", "cancelled")
        pruned = False
        to_delete: List[str] = []
        for sid, session in self._sessions.items():
            if session.status in terminal_statuses:
                try:
                    updated = datetime.datetime.fromisoformat(session.updated_at)
                    # Ensure timezone-aware comparison
                    if updated.tzinfo is None:
                        updated = updated.replace(tzinfo=datetime.timezone.utc)
                    if updated < cutoff:
                        to_delete.append(sid)
                        pruned = True
                except (ValueError, TypeError):
                    pass
        for sid in to_delete:
            del self._sessions[sid]
        if pruned:
            self._save()

    def _save(self) -> None:
        # Ensure directory exists (lexists detects broken symlinks too)
        if os.path.lexists(self._actp_dir):
            if os.path.islink(self._actp_dir) or not os.path.isdir(self._actp_dir):
                raise OSError(f"Security: {self._actp_dir} is not a real directory")
        else:
            os.makedirs(self._actp_dir, mode=0o700, exist_ok=True)

        data = {
            "version": 1,
            "sessions": [
                {
                    "commerce_session_id": s.commerce_session_id,
                    **({"actp_tx_id": s.actp_tx_id} if s.actp_tx_id is not None else {}),
                    "task": s.task,
                    "candidates_tried": s.candidates_tried,
                    **({"selected_provider": s.selected_provider} if s.selected_provider is not None else {}),
                    "status": s.status,
                    "attempts": s.attempts,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }
                for s in self._sessions.values()
            ],
        }

        file_path = self._get_file_path()

        # Guard against target file being a symlink (lexists detects broken symlinks too)
        if os.path.lexists(file_path) and os.path.islink(file_path):
            raise OSError(f"Security: {file_path} is a symlink -- refusing to overwrite")

        tmp_path = file_path + ".tmp"

        # Guard against tmp file being a symlink
        if os.path.lexists(tmp_path) and os.path.islink(tmp_path):
            raise OSError(f"Security: {tmp_path} is a symlink -- refusing to write")

        # Atomic write
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            fobj = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with fobj:
            json.dump(data, fobj, indent=2)
        os.rename(tmp_path, file_path)
