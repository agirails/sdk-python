"""Tests for the buyer-link gasless gate marker (AIP-18).

Mirrors TS config/buyerLink.ts: save/load/has/delete + atomic, symlink-safe,
network-agnostic, mode-0600 writes.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from agirails.config.buyer_link import (
    BuyerLink,
    delete_buyer_link,
    get_buyer_link_path,
    has_buyer_link,
    load_buyer_link,
    save_buyer_link,
)
from agirails.config.pending_publish import SecurityError


@pytest.fixture
def actp_dir(tmp_path):
    return str(tmp_path / ".actp")


def _link() -> BuyerLink:
    return BuyerLink(slug="my-buyer", wallet="0x" + "ab" * 20, linked_at="2026-06-19T00:00:00.000Z")


class TestSaveLoad:
    def test_round_trip(self, actp_dir: str) -> None:
        link = _link()
        save_buyer_link(link, actp_dir)
        loaded = load_buyer_link(actp_dir=actp_dir)
        assert loaded is not None
        assert loaded.slug == "my-buyer"
        assert loaded.wallet == link.wallet
        assert loaded.linked_at == "2026-06-19T00:00:00.000Z"
        assert loaded.version == 1

    def test_load_absent_returns_none(self, actp_dir: str) -> None:
        assert load_buyer_link(actp_dir=actp_dir) is None

    def test_has_buyer_link(self, actp_dir: str) -> None:
        assert has_buyer_link(actp_dir=actp_dir) is False
        save_buyer_link(_link(), actp_dir)
        assert has_buyer_link(actp_dir=actp_dir) is True

    def test_delete(self, actp_dir: str) -> None:
        save_buyer_link(_link(), actp_dir)
        delete_buyer_link(actp_dir)
        assert load_buyer_link(actp_dir=actp_dir) is None

    def test_delete_absent_is_noop(self, actp_dir: str) -> None:
        # Best-effort: never raises even if nothing to delete.
        delete_buyer_link(actp_dir)

    def test_path_is_network_agnostic(self, actp_dir: str) -> None:
        p = get_buyer_link_path(actp_dir)
        assert p.endswith("buyer-link.json")
        # No network suffix in the filename.
        assert "base-sepolia" not in p and "base-mainnet" not in p


class TestOnDiskShape:
    def test_json_field_order_and_keys(self, actp_dir: str) -> None:
        save_buyer_link(_link(), actp_dir)
        with open(get_buyer_link_path(actp_dir), "r", encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
        # camelCase + version-first to match TS JSON.stringify(link, null, 2).
        assert list(data.keys()) == ["version", "slug", "wallet", "linkedAt"]
        assert data["version"] == 1
        assert data["linkedAt"] == "2026-06-19T00:00:00.000Z"

    def test_corrupt_marker_treated_as_absent(self, actp_dir: str) -> None:
        os.makedirs(actp_dir, exist_ok=True)
        with open(get_buyer_link_path(actp_dir), "w", encoding="utf-8") as f:
            f.write("{ not valid json")
        assert load_buyer_link(actp_dir=actp_dir) is None

    def test_file_mode_is_0600(self, actp_dir: str) -> None:
        save_buyer_link(_link(), actp_dir)
        mode = stat.S_IMODE(os.lstat(get_buyer_link_path(actp_dir)).st_mode)
        assert mode == 0o600


class TestSymlinkSafety:
    def test_symlinked_dir_rejected(self, tmp_path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link_dir = tmp_path / "link"
        os.symlink(real, link_dir)
        with pytest.raises(SecurityError):
            save_buyer_link(_link(), str(link_dir))
