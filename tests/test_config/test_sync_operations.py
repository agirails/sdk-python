"""Tests for sync operations — diff + pull + IPFS CID validation.

Covers the CID validation guard added before any IPFS gateway fetch
(SSRF / URL-injection guard, parity with TS syncOperations.ts:178-202).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agirails.config.on_chain_state import ZERO_HASH, OnChainConfigState
from agirails.config.sync_operations import (
    DiffStatus,
    diff_config,
    fetch_from_ipfs,
    pull_config,
)

VALID_CID_V0 = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
VALID_CID_V1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"


# ============================================================================
# fetch_from_ipfs — CID validation guard
# ============================================================================


class TestFetchFromIpfsCidValidation:
    @pytest.mark.parametrize(
        "bad_cid",
        [
            "",
            "not-a-cid",
            "../../../etc/passwd",
            "QmTooShort",
            "https://evil.example.com/payload",
            "Qm/../escape",
        ],
    )
    def test_rejects_malformed_cid_before_fetch(self, bad_cid: str) -> None:
        # The gateway must never be contacted for a malformed CID.
        with patch("agirails.config.sync_operations.httpx.get") as mock_get:
            with pytest.raises(ValueError, match="Invalid on-chain CID format"):
                fetch_from_ipfs(bad_cid)
        mock_get.assert_not_called()

    def test_accepts_valid_cidv0(self) -> None:
        class _Resp:
            status_code = 200
            text = "ok"

        with patch(
            "agirails.config.sync_operations.httpx.get", return_value=_Resp()
        ) as mock_get:
            assert fetch_from_ipfs(VALID_CID_V0) == "ok"
        mock_get.assert_called_once()

    def test_accepts_valid_cidv1(self) -> None:
        class _Resp:
            status_code = 200
            text = "payload"

        with patch(
            "agirails.config.sync_operations.httpx.get", return_value=_Resp()
        ):
            assert fetch_from_ipfs(VALID_CID_V1) == "payload"


# ============================================================================
# pull_config — rejects garbage on-chain CID before fetching
# ============================================================================


class TestPullConfigCidValidation:
    def test_pull_rejects_garbage_on_chain_cid(self, tmp_path) -> None:
        # On-chain state advertises a non-empty (but malformed) CID. pull must
        # validate it before constructing the gateway URL.
        local = tmp_path / "AGIRAILS.md"
        on_chain = OnChainConfigState(
            config_hash="0x" + "ab" * 32,
            config_cid="../../evil",
        )
        with patch("agirails.config.sync_operations.httpx.get") as mock_get:
            with pytest.raises(ValueError, match="Invalid on-chain CID format"):
                pull_config(str(local), on_chain)
        mock_get.assert_not_called()


# ============================================================================
# diff_config — sanity (status detection still intact)
# ============================================================================


class TestDiffConfig:
    def test_no_local_no_remote(self, tmp_path) -> None:
        local = tmp_path / "AGIRAILS.md"
        on_chain = OnChainConfigState(config_hash=ZERO_HASH, config_cid="")
        result = diff_config(str(local), on_chain)
        assert result.status == DiffStatus.NO_LOCAL
        assert result.in_sync is True

    def test_local_only_no_remote(self, tmp_path) -> None:
        local = tmp_path / "AGIRAILS.md"
        local.write_text("---\nname: x\n---\n# Body\n", encoding="utf-8")
        on_chain = OnChainConfigState(config_hash=ZERO_HASH, config_cid="")
        result = diff_config(str(local), on_chain)
        assert result.status == DiffStatus.NO_REMOTE
        assert result.in_sync is False
