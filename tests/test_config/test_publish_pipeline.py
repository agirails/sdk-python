"""Tests for the publish pipeline — registration extraction + AIP-18 pay-only.

Covers the pay-only (intent: pay) short-circuit that keeps a buyer's private
budget off-chain and off-IPFS, mirroring TS publishPipeline.ts:147-156,345-381.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agirails.config.publish_pipeline import (
    PENDING_ENDPOINT,
    extract_registration_params,
    publish_config,
)


# ============================================================================
# extract_registration_params — earn / both (provider) path
# ============================================================================


class TestExtractRegistrationParamsProvider:
    def test_extracts_services(self) -> None:
        fm = {
            "endpoint": "https://provider.example.com",
            "services": [{"type": "text-generation", "price": "1.0-100.0"}],
        }
        endpoint, descriptors = extract_registration_params(fm)
        assert endpoint == "https://provider.example.com"
        assert len(descriptors) == 1
        assert descriptors[0].service_type == "text-generation"
        assert descriptors[0].min_price == 1_000_000
        assert descriptors[0].max_price == 100_000_000

    def test_extracts_capabilities_fallback(self) -> None:
        fm = {"capabilities": ["analysis", "code-review"]}
        endpoint, descriptors = extract_registration_params(fm)
        assert endpoint == PENDING_ENDPOINT
        assert {d.service_type for d in descriptors} == {"analysis", "code-review"}

    def test_earn_intent_with_no_services_raises(self) -> None:
        fm = {"intent": "earn", "name": "provider"}
        with pytest.raises(ValueError, match="services"):
            extract_registration_params(fm)

    def test_both_intent_with_no_services_raises(self) -> None:
        fm = {"intent": "both", "name": "agent"}
        with pytest.raises(ValueError, match="services"):
            extract_registration_params(fm)


# ============================================================================
# extract_registration_params — AIP-18 pay-only short-circuit
# ============================================================================


class TestExtractRegistrationParamsPayOnly:
    """Pay-only buyers never register as providers — empty descriptors,
    no exception even when no services are present
    (parity with TS publishPipeline.ts:147-156).
    """

    def test_pay_intent_returns_empty_descriptors(self) -> None:
        fm = {"intent": "pay", "name": "buyer", "budget": 500}
        endpoint, descriptors = extract_registration_params(fm)
        assert descriptors == []
        assert endpoint == PENDING_ENDPOINT

    def test_pay_intent_is_case_insensitive(self) -> None:
        fm = {"intent": "PAY", "name": "buyer"}
        _endpoint, descriptors = extract_registration_params(fm)
        assert descriptors == []

    def test_pay_intent_ignores_services(self) -> None:
        # Even if a buyer file mistakenly lists services, pay-only short-circuits
        # and registers nothing on-chain.
        fm = {
            "intent": "pay",
            "endpoint": "https://buyer.example.com",
            "services": [{"type": "text-generation", "price": "1.0-2.0"}],
        }
        endpoint, descriptors = extract_registration_params(fm)
        assert descriptors == []
        assert endpoint == "https://buyer.example.com"

    def test_pay_intent_with_no_services_does_not_raise(self) -> None:
        fm = {"intent": "pay"}
        endpoint, descriptors = extract_registration_params(fm)
        assert descriptors == []
        assert endpoint == PENDING_ENDPOINT


# ============================================================================
# publish_config — AIP-18 pay-only upload skip
# ============================================================================


PAY_ONLY_MD = """---
name: buyer-agent
version: "1.0.0"
intent: pay
budget: 250.5
---
# Buyer
A pure buyer agent.
"""

EARN_MD = """---
name: provider-agent
version: "1.0.0"
intent: earn
capabilities:
  - text-generation
---
# Provider
"""


class TestPublishConfigPayOnly:
    def test_pay_only_skips_upload(self) -> None:
        # No upload helper should be touched; CID stays empty so the buyer's
        # budget never leaves the machine.
        with patch(
            "agirails.config.publish_pipeline.upload_via_proxy"
        ) as mock_proxy, patch(
            "agirails.config.publish_pipeline.upload_to_filebase"
        ) as mock_filebase:
            result = publish_config(PAY_ONLY_MD)
        mock_proxy.assert_not_called()
        mock_filebase.assert_not_called()
        assert result.cid == ""
        assert result.dry_run is False
        assert result.config_hash.startswith("0x")

    def test_earn_uploads_via_proxy(self) -> None:
        with patch(
            "agirails.config.publish_pipeline.upload_via_proxy",
            return_value="bafyearncid",
        ) as mock_proxy:
            result = publish_config(EARN_MD)
        mock_proxy.assert_called_once()
        assert result.cid == "bafyearncid"

    def test_dry_run_short_circuits_before_intent_check(self) -> None:
        with patch(
            "agirails.config.publish_pipeline.upload_via_proxy"
        ) as mock_proxy:
            result = publish_config(EARN_MD, dry_run=True)
        mock_proxy.assert_not_called()
        assert result.cid == "(dry-run)"
        assert result.dry_run is True

    def test_pay_only_config_hash_matches_compute(self) -> None:
        from agirails.config.agirailsmd import compute_config_hash

        result = publish_config(PAY_ONLY_MD)
        assert result.config_hash == compute_config_hash(PAY_ONLY_MD).config_hash
