"""Tests for the V4 typed parser, slug helpers, defaults, and display fee.

Mirrors TS config/agirailsmdV4.ts + slugUtils.ts + defaults.ts. The V4 parser
is ADDITIVE — these tests also confirm the v1 ``parse_agirails_md`` is untouched.
"""

from __future__ import annotations

import pytest

from agirails.config.agirailsmd import (
    V4_CONSTRAINTS,
    V4_DEFAULTS,
    AgirailsMdV4Config,
    compute_display_fee,
    generate_slug,
    parse_agirails_md,
    parse_agirails_md_v4,
    validate_agirails_md_v4,
    validate_slug,
)


# ============================================================================
# Slug helpers (mirror TS slugUtils.ts)
# ============================================================================


class TestGenerateSlug:
    def test_spaces_to_hyphens(self) -> None:
        assert generate_slug("Ultimate Lead Master") == "ultimate-lead-master"

    def test_strips_special_chars(self) -> None:
        assert generate_slug("Code Reviewer Pro!") == "code-reviewer-pro"

    def test_collapses_and_strips_hyphens(self) -> None:
        assert generate_slug("  --Foo   Bar-- ") == "foo-bar"

    def test_truncates_to_max_length(self) -> None:
        out = generate_slug("a" * 200)
        assert len(out) == V4_CONSTRAINTS["MAX_SLUG_LENGTH"]


class TestValidateSlug:
    def test_empty_is_invalid(self) -> None:
        assert validate_slug("") == "Slug cannot be empty"

    def test_too_long_is_invalid(self) -> None:
        assert "characters or less" in (validate_slug("a" * 65) or "")

    def test_uppercase_is_invalid(self) -> None:
        assert validate_slug("Foo") is not None

    def test_valid_slug(self) -> None:
        assert validate_slug("code-reviewer-pro") is None

    def test_single_char_valid(self) -> None:
        assert validate_slug("a") is None


# ============================================================================
# Display fee (mirror TS computeDisplayFee)
# ============================================================================


class TestComputeDisplayFee:
    def test_below_min_clamps_to_min(self) -> None:
        # $1 -> 1% = $0.01, below $0.05 floor
        assert compute_display_fee(1_000_000) == 50_000

    def test_above_min_uses_percent(self) -> None:
        # $100 -> 1% = $1.00 (1_000_000 wei)
        assert compute_display_fee(100_000_000) == 1_000_000

    def test_exactly_at_threshold(self) -> None:
        # $5 -> 1% = $0.05 == min, percent is NOT strictly greater -> min
        assert compute_display_fee(5_000_000) == 50_000


# ============================================================================
# V4 parser — provider (earn)
# ============================================================================

PROVIDER_MD = """---
name: Code Reviewer Pro
services:
  - code-review
  - testing
pricing:
  base: 10
  negotiable: true
  min_price: 5
  max_price: 20
network: testnet
payment:
  modes:
    - actp
---
Reviews your code thoroughly.

## How to Request This Service
Send an ACTP transaction.

## Pricing
Detailed pricing here.
"""


class TestV4Provider:
    def test_intent_defaults_to_earn(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert v4.intent == "earn"

    def test_services_normalized(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert [s.type for s in v4.services] == ["code-review", "testing"]

    def test_slug_generated_from_name(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert v4.slug == "code-reviewer-pro"

    def test_pricing_band(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert v4.pricing.base == 10
        assert v4.pricing.min_price == 5
        assert v4.pricing.max_price == 20
        assert v4.pricing.negotiable is True

    def test_network_coerced(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert v4.network == "testnet"

    def test_body_split_by_heading(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        assert v4.description == "Reviews your code thoroughly."
        assert v4.how_to_request == "Send an ACTP transaction."

    def test_validate_clean(self) -> None:
        v4 = parse_agirails_md_v4(PROVIDER_MD)
        res = validate_agirails_md_v4(v4)
        assert res.valid is True
        assert all(i.severity != "error" for i in res.issues)


# ============================================================================
# V4 parser — buyer (pay)
# ============================================================================

BUYER_MD = """---
name: My Buyer
intent: pay
servicesNeeded:
  - code-review
  - translation
budget: 5
---
I buy services.
"""


class TestV4Buyer:
    def test_intent_pay(self) -> None:
        v4 = parse_agirails_md_v4(BUYER_MD)
        assert v4.intent == "pay"

    def test_no_services_allowed_for_pay(self) -> None:
        v4 = parse_agirails_md_v4(BUYER_MD)
        assert v4.services == []

    def test_services_needed_parsed(self) -> None:
        v4 = parse_agirails_md_v4(BUYER_MD)
        assert v4.services_needed == ["code-review", "translation"]

    def test_budget_parsed(self) -> None:
        v4 = parse_agirails_md_v4(BUYER_MD)
        assert v4.budget == 5

    def test_pricing_base_falls_back_to_budget(self) -> None:
        # pay-only file omits pricing.base; base falls back to budget
        v4 = parse_agirails_md_v4(BUYER_MD)
        assert v4.pricing.base == 5

    def test_services_needed_snake_case_alias(self) -> None:
        md = """---
name: Snake Buyer
intent: pay
services_needed:
  - data-analysis
---
buyer
"""
        v4 = parse_agirails_md_v4(md)
        assert v4.services_needed == ["data-analysis"]


# ============================================================================
# V4 parser — error paths + defaults
# ============================================================================


class TestV4Errors:
    def test_missing_name_raises(self) -> None:
        with pytest.raises(ValueError, match="name"):
            parse_agirails_md_v4("---\nservices:\n  - x\n---\nbody")

    def test_earn_without_services_raises(self) -> None:
        with pytest.raises(ValueError, match="services"):
            parse_agirails_md_v4("---\nname: X\n---\nbody")

    def test_pay_without_services_needed_raises(self) -> None:
        with pytest.raises(ValueError, match="servicesNeeded"):
            parse_agirails_md_v4("---\nname: X\nintent: pay\n---\nbody")

    def test_earn_without_pricing_base_raises(self) -> None:
        with pytest.raises(ValueError, match="pricing.base"):
            parse_agirails_md_v4(
                "---\nname: X\nservices:\n  - code-review\n---\nbody"
            )


class TestV4Defaults:
    def test_defaults_applied_when_omitted(self) -> None:
        md = """---
name: Minimal
services:
  - code-review
pricing:
  base: 1
---
body
"""
        v4 = parse_agirails_md_v4(md)
        assert v4.network == V4_DEFAULTS["network"]
        assert v4.pricing.unit == V4_DEFAULTS["pricing"]["unit"]
        assert v4.pricing.negotiable == V4_DEFAULTS["pricing"]["negotiable"]
        assert v4.sla.response == V4_DEFAULTS["sla"]["response"]
        assert v4.payment["modes"] == V4_DEFAULTS["payment"]["modes"]

    def test_invalid_network_falls_back_to_default(self) -> None:
        md = """---
name: Bad Net
services:
  - x
pricing:
  base: 1
network: solana
---
body
"""
        v4 = parse_agirails_md_v4(md)
        assert v4.network == V4_DEFAULTS["network"]

    def test_invalid_intent_falls_back_to_earn(self) -> None:
        md = """---
name: Bad Intent
intent: lurk
services:
  - x
pricing:
  base: 1
---
body
"""
        v4 = parse_agirails_md_v4(md)
        assert v4.intent == "earn"


class TestV4Validation:
    def test_x402_requires_endpoint(self) -> None:
        md = """---
name: X402 Agent
services:
  - x
pricing:
  base: 1
payment:
  modes:
    - x402
---
body
"""
        v4 = parse_agirails_md_v4(md)
        res = validate_agirails_md_v4(v4)
        assert res.valid is False
        assert any(i.field == "endpoint" for i in res.issues)

    def test_negotiable_min_gt_max_invalid(self) -> None:
        md = """---
name: Bad Band
services:
  - x
pricing:
  base: 10
  negotiable: true
  min_price: 20
  max_price: 5
---
body
"""
        v4 = parse_agirails_md_v4(md)
        res = validate_agirails_md_v4(v4)
        assert res.valid is False
        assert any(i.field == "pricing.min_price" for i in res.issues)

    def test_below_min_price_invalid(self) -> None:
        md = """---
name: Cheap
services:
  - x
pricing:
  base: 0.01
---
body
"""
        v4 = parse_agirails_md_v4(md)
        res = validate_agirails_md_v4(v4)
        assert res.valid is False
        assert any(i.field == "pricing.base" for i in res.issues)


# ============================================================================
# v1 parser untouched (additive guarantee)
# ============================================================================


class TestV1ParserUntouched:
    def test_v1_parse_still_works(self) -> None:
        cfg = parse_agirails_md(PROVIDER_MD)
        assert cfg.frontmatter["name"] == "Code Reviewer Pro"
        assert "Reviews your code" in cfg.body
