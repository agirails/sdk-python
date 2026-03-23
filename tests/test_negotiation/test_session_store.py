"""Tests for SessionStore — commerce session tracking."""

from __future__ import annotations

import pytest

from agirails.negotiation.session_store import SessionMapping, SessionStore


class TestSessionLifecycle:
    def test_create_session(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        session = store.create("Summarize document")
        assert session.task == "Summarize document"
        assert session.status == "active"
        assert session.attempts == 0
        assert session.candidates_tried == []
        assert len(session.commerce_session_id) == 36  # UUID

    def test_get_session(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        created = store.create("test")
        fetched = store.get(created.commerce_session_id)
        assert fetched is not None
        assert fetched.commerce_session_id == created.commerce_session_id

    def test_get_nonexistent_returns_none(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        assert store.get("nonexistent-id") is None

    def test_record_attempt(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        session = store.create("test")
        store.record_attempt(session.commerce_session_id, "agent-a")
        store.record_attempt(session.commerce_session_id, "agent-b")
        store.record_attempt(session.commerce_session_id, "agent-a")  # duplicate slug

        updated = store.get(session.commerce_session_id)
        assert updated.attempts == 3
        assert updated.candidates_tried == ["agent-a", "agent-b"]  # no duplicate slugs

    def test_link_transaction(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        session = store.create("test")
        store.link_transaction(session.commerce_session_id, "0xtx123", "best-agent")

        updated = store.get(session.commerce_session_id)
        assert updated.actp_tx_id == "0xtx123"
        assert updated.selected_provider == "best-agent"
        assert updated.status == "committed"

    def test_update_status(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        session = store.create("test")
        store.update_status(session.commerce_session_id, "failed")

        updated = store.get(session.commerce_session_id)
        assert updated.status == "failed"

    def test_find_by_tx_id(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        s1 = store.create("test1")
        s2 = store.create("test2")
        store.link_transaction(s2.commerce_session_id, "0xtx456", "agent-x")

        found = store.find_by_tx_id("0xtx456")
        assert found is not None
        assert found.commerce_session_id == s2.commerce_session_id

    def test_find_by_tx_id_not_found(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        assert store.find_by_tx_id("0xnonexistent") is None

    def test_list_all(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        store.create("task1")
        store.create("task2")
        assert len(store.list()) == 2

    def test_list_by_status(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        s1 = store.create("task1")
        s2 = store.create("task2")
        store.update_status(s1.commerce_session_id, "failed")

        active = store.list(status="active")
        failed = store.list(status="failed")
        assert len(active) == 1
        assert len(failed) == 1
        assert active[0].commerce_session_id == s2.commerce_session_id


class TestSessionPersistence:
    def test_persists_across_instances(self, tmp_path):
        store1 = SessionStore(actp_dir=str(tmp_path))
        session = store1.create("test")
        store1.link_transaction(session.commerce_session_id, "0xtx", "agent")

        store2 = SessionStore(actp_dir=str(tmp_path))
        loaded = store2.get(session.commerce_session_id)
        assert loaded is not None
        assert loaded.actp_tx_id == "0xtx"
        assert loaded.selected_provider == "agent"

    def test_record_attempt_unknown_session_raises(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Session not found"):
            store.record_attempt("nonexistent", "agent")

    def test_update_status_unknown_session_raises(self, tmp_path):
        store = SessionStore(actp_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Session not found"):
            store.update_status("nonexistent", "failed")
