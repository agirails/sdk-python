"""
Tests for AdapterRouter and AdapterRegistry.

Covers:
1. Explicit adapter selection
2. Escrow/dispute capability filtering (strict enforcement)
3. HTTP endpoint routing to x402
4. ERC-8004 agent ID detection
5. Priority-based fallback
6. Path traversal rejection
7. Script injection rejection
8. Null byte rejection
9. Description length validation
10. selectAndResolve with mock bridge
11. No compatible adapter error
12. Basic fallback
"""

from __future__ import annotations

import dataclasses
from typing import Any
from unittest.mock import AsyncMock

import pytest

from agirails.adapters.adapter_registry import AdapterRegistry
from agirails.adapters.adapter_router import AdapterRouter
from agirails.adapters.types import (
    AdapterMetadata,
    UnifiedPayParams,
)
from agirails.errors import ValidationError


# ============================================================================
# Mock Adapter
# ============================================================================


class MockAdapter:
    """Mock adapter for testing."""

    def __init__(
        self,
        adapter_id: str = "mock",
        priority: int = 50,
        uses_escrow: bool = False,
        supports_disputes: bool = False,
        release_required: bool = False,
        handles_all: bool = True,
    ) -> None:
        self._metadata = AdapterMetadata(
            id=adapter_id,
            priority=priority,
            uses_escrow=uses_escrow,
            supports_disputes=supports_disputes,
            release_required=release_required,
        )
        self._handles_all = handles_all

    @property
    def metadata(self) -> AdapterMetadata:
        return self._metadata

    def can_handle(self, params: UnifiedPayParams) -> bool:
        return self._handles_all

    def validate(self, params: UnifiedPayParams) -> None:
        pass

    async def pay(self, params: UnifiedPayParams) -> Any:
        return {"adapter": self._metadata.id, "to": params.to, "amount": params.amount}


class MockERC8004Bridge:
    """Mock ERC-8004 bridge for testing."""

    def __init__(self, wallet_map: dict[str, str] | None = None) -> None:
        self._wallet_map = wallet_map or {}

    async def get_agent_wallet(self, agent_id: str) -> str:
        if agent_id in self._wallet_map:
            return self._wallet_map[agent_id]
        raise RuntimeError(f"Agent {agent_id} not found")


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def basic_adapter() -> MockAdapter:
    return MockAdapter(adapter_id="basic", priority=10, uses_escrow=True, release_required=True)


@pytest.fixture
def standard_adapter() -> MockAdapter:
    return MockAdapter(
        adapter_id="standard",
        priority=60,
        uses_escrow=True,
        supports_disputes=True,
        release_required=True,
    )


@pytest.fixture
def x402_adapter() -> MockAdapter:
    return MockAdapter(
        adapter_id="x402",
        priority=40,
        uses_escrow=False,
        supports_disputes=False,
        release_required=False,
    )


@pytest.fixture
def registry(basic_adapter: MockAdapter, standard_adapter: MockAdapter) -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(basic_adapter)
    reg.register(standard_adapter)
    return reg


@pytest.fixture
def router(registry: AdapterRegistry) -> AdapterRouter:
    return AdapterRouter(registry)


@pytest.fixture
def simple_params() -> UnifiedPayParams:
    return UnifiedPayParams(to="0x1234567890abcdef1234567890abcdef12345678", amount="100")


# ============================================================================
# AdapterRegistry Tests
# ============================================================================


class TestAdapterRegistry:
    def test_register_and_get(self, basic_adapter: MockAdapter) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        assert reg.get("basic") is basic_adapter
        assert reg.size == 1

    def test_register_without_metadata_raises(self) -> None:
        class BadAdapter:
            metadata = None  # type: ignore[assignment]

        with pytest.raises(ValueError, match="metadata.id"):
            AdapterRegistry().register(BadAdapter())  # type: ignore[arg-type]

    def test_get_nonexistent_returns_none(self) -> None:
        reg = AdapterRegistry()
        assert reg.get("nonexistent") is None

    def test_get_by_priority(
        self, basic_adapter: MockAdapter, standard_adapter: MockAdapter
    ) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        reg.register(standard_adapter)
        by_priority = reg.get_by_priority()
        assert by_priority[0].metadata.id == "standard"  # priority 60
        assert by_priority[1].metadata.id == "basic"  # priority 10

    def test_get_all(
        self, basic_adapter: MockAdapter, standard_adapter: MockAdapter
    ) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        reg.register(standard_adapter)
        assert len(reg.get_all()) == 2

    def test_get_ids(
        self, basic_adapter: MockAdapter, standard_adapter: MockAdapter
    ) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        reg.register(standard_adapter)
        ids = reg.get_ids()
        assert "basic" in ids
        assert "standard" in ids

    def test_has(self, basic_adapter: MockAdapter) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        assert reg.has("basic") is True
        assert reg.has("nonexistent") is False

    def test_unregister(self, basic_adapter: MockAdapter) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        assert reg.unregister("basic") is True
        assert reg.get("basic") is None
        assert reg.unregister("basic") is False

    def test_clear(
        self, basic_adapter: MockAdapter, standard_adapter: MockAdapter
    ) -> None:
        reg = AdapterRegistry()
        reg.register(basic_adapter)
        reg.register(standard_adapter)
        reg.clear()
        assert reg.size == 0

    def test_register_replaces_existing(self) -> None:
        reg = AdapterRegistry()
        adapter1 = MockAdapter(adapter_id="basic", priority=10)
        adapter2 = MockAdapter(adapter_id="basic", priority=99)
        reg.register(adapter1)
        reg.register(adapter2)
        assert reg.size == 1
        assert reg.get("basic").metadata.priority == 99  # type: ignore[union-attr]


# ============================================================================
# AdapterRouter Tests
# ============================================================================


class TestAdapterRouterExplicitSelection:
    """Test 1: Explicit adapter selection."""

    def test_explicit_preferred_adapter(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"preferred_adapter": "basic"}
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "basic"

    def test_explicit_preferred_adapter_standard(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"preferred_adapter": "standard"}
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "standard"

    def test_explicit_nonexistent_adapter_raises(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"preferred_adapter": "nonexistent"}
        with pytest.raises(RuntimeError, match="Preferred adapter 'nonexistent' not found"):
            router.select(simple_params)


class TestAdapterRouterEscrowDispute:
    """Test 2: Escrow/dispute capability filtering (strict enforcement)."""

    def test_requires_escrow_selects_standard(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"requires_escrow": True}
        adapter = router.select(simple_params)
        assert adapter.metadata.uses_escrow is True

    def test_requires_dispute_selects_standard(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"requires_dispute": True}
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "standard"
        assert adapter.metadata.supports_disputes is True

    def test_requires_dispute_no_compatible_raises(
        self, simple_params: UnifiedPayParams
    ) -> None:
        """No adapter supports disputes -> strict error."""
        reg = AdapterRegistry()
        reg.register(MockAdapter(adapter_id="basic", priority=10, uses_escrow=False))
        router = AdapterRouter(reg)
        simple_params.metadata = {"requires_dispute": True}
        with pytest.raises(RuntimeError, match="No adapter found that supports"):
            router.select(simple_params)

    def test_requires_escrow_and_dispute(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.metadata = {"requires_escrow": True, "requires_dispute": True}
        adapter = router.select(simple_params)
        assert adapter.metadata.uses_escrow is True
        assert adapter.metadata.supports_disputes is True


class TestAdapterRouterHttpEndpoint:
    """Test 3: HTTP endpoint routing to x402."""

    def test_http_endpoint_routes_to_x402(
        self, registry: AdapterRegistry, simple_params: UnifiedPayParams
    ) -> None:
        x402 = MockAdapter(adapter_id="x402", priority=40)
        registry.register(x402)
        router = AdapterRouter(registry)
        simple_params.to = "https://api.example.com/pay"
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "x402"

    def test_http_endpoint_without_x402_raises_error(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.to = "https://api.example.com/pay"
        # No x402 registered — should raise clear error, not silently fall through
        with pytest.raises(RuntimeError, match="requires X402Adapter"):
            router.select(simple_params)


class TestAdapterRouterERC8004:
    """Test 4: ERC-8004 agent ID detection."""

    def test_numeric_string_is_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("12345") is True

    def test_zero_is_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("0") is True

    def test_large_number_is_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id(str(2**255)) is True

    def test_hex_address_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("0x1234") is False

    def test_url_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("https://example.com") is False
        assert AdapterRouter.is_erc8004_agent_id("http://example.com") is False

    def test_empty_string_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("") is False

    def test_non_numeric_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("hello") is False

    def test_negative_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id("-1") is False

    def test_too_large_is_not_agent_id(self) -> None:
        assert AdapterRouter.is_erc8004_agent_id(str(2**256)) is False

    def test_http_endpoint_detection(self) -> None:
        assert AdapterRouter.is_http_endpoint("https://api.example.com") is True
        assert AdapterRouter.is_http_endpoint("http://localhost:3000") is True
        assert AdapterRouter.is_http_endpoint("0x1234") is False
        assert AdapterRouter.is_http_endpoint("12345") is False
        assert AdapterRouter.is_http_endpoint("ftp://example.com") is False


class TestAdapterRouterPriority:
    """Test 5: Priority-based fallback."""

    def test_selects_highest_priority_adapter(self, simple_params: UnifiedPayParams) -> None:
        reg = AdapterRegistry()
        low = MockAdapter(adapter_id="low", priority=10)
        mid = MockAdapter(adapter_id="mid", priority=50)
        high = MockAdapter(adapter_id="high", priority=90)
        reg.register(low)
        reg.register(mid)
        reg.register(high)
        router = AdapterRouter(reg)
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "high"

    def test_skips_adapter_that_cannot_handle(self, simple_params: UnifiedPayParams) -> None:
        reg = AdapterRegistry()
        cant_handle = MockAdapter(adapter_id="cant", priority=90, handles_all=False)
        can_handle = MockAdapter(adapter_id="can", priority=50)
        reg.register(cant_handle)
        reg.register(can_handle)
        router = AdapterRouter(reg)
        adapter = router.select(simple_params)
        assert adapter.metadata.id == "can"


class TestAdapterRouterPathTraversal:
    """Test 6: Path traversal rejection."""

    def test_path_traversal_in_to(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="../etc/passwd", amount="100")
        with pytest.raises(ValidationError, match="path traversal"):
            router.select(params)

    def test_path_traversal_double_dot(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="0x1234..5678", amount="100")
        with pytest.raises(ValidationError, match="path traversal"):
            router.select(params)


class TestAdapterRouterScriptInjection:
    """Test 7: Script injection rejection."""

    def test_script_tag_in_to(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="<script>alert(1)</script>", amount="100")
        with pytest.raises(ValidationError, match="HTML/script"):
            router.select(params)

    def test_html_angle_brackets(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="foo<bar>baz", amount="100")
        with pytest.raises(ValidationError, match="HTML/script"):
            router.select(params)


class TestAdapterRouterNullByte:
    """Test 8: Null byte rejection."""

    def test_null_byte_in_to(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="0x1234\x00abcd", amount="100")
        with pytest.raises(ValidationError, match="null bytes"):
            router.select(params)


class TestAdapterRouterDescriptionLength:
    """Test 9: Description length validation."""

    def test_description_over_1000_chars(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(
            to="0x1234567890abcdef1234567890abcdef12345678",
            amount="100",
            description="x" * 1001,
        )
        with pytest.raises(ValidationError, match="Description too long"):
            router.select(params)

    def test_description_at_limit_is_ok(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        simple_params.description = "x" * 1000
        # Should not raise
        adapter = router.select(simple_params)
        assert adapter is not None


class TestAdapterRouterSelectAndResolve:
    """Test 10: selectAndResolve with mock bridge."""

    async def test_resolves_agent_id_to_wallet(
        self, registry: AdapterRegistry
    ) -> None:
        wallet = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        bridge = MockERC8004Bridge({"12345": wallet})
        router = AdapterRouter(registry, erc8004_bridge=bridge)
        params = UnifiedPayParams(to="12345", amount="100")

        result = await router.select_and_resolve(params)

        assert result.was_agent_id_resolved is True
        assert result.resolved_params.to == wallet
        assert result.resolved_params.erc8004_agent_id == "12345"
        assert result.adapter is not None

    async def test_non_agent_id_passes_through(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        result = await router.select_and_resolve(simple_params)

        assert result.was_agent_id_resolved is False
        assert result.resolved_params.to == simple_params.to

    async def test_agent_id_without_bridge_raises(
        self, registry: AdapterRegistry
    ) -> None:
        router = AdapterRouter(registry)  # no bridge
        params = UnifiedPayParams(to="12345", amount="100")

        with pytest.raises(ValidationError, match="ERC-8004 resolution requires"):
            await router.select_and_resolve(params)

    async def test_agent_id_not_found_raises(
        self, registry: AdapterRegistry
    ) -> None:
        bridge = MockERC8004Bridge({})  # empty map
        router = AdapterRouter(registry, erc8004_bridge=bridge)
        params = UnifiedPayParams(to="99999", amount="100")

        with pytest.raises(ValidationError, match="Failed to resolve ERC-8004 agent"):
            await router.select_and_resolve(params)

    async def test_set_bridge_after_init(
        self, registry: AdapterRegistry
    ) -> None:
        wallet = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        router = AdapterRouter(registry)
        bridge = MockERC8004Bridge({"42": wallet})
        router.set_erc8004_bridge(bridge)

        params = UnifiedPayParams(to="42", amount="50")
        result = await router.select_and_resolve(params)

        assert result.was_agent_id_resolved is True
        assert result.resolved_params.to == wallet


class TestAdapterRouterNoCompatible:
    """Test 11: No compatible adapter error."""

    def test_empty_registry_raises(self) -> None:
        reg = AdapterRegistry()
        router = AdapterRouter(reg)
        params = UnifiedPayParams(
            to="0x1234567890abcdef1234567890abcdef12345678", amount="100"
        )
        with pytest.raises(RuntimeError, match="No suitable adapter found"):
            router.select(params)


class TestAdapterRouterBasicFallback:
    """Test 12: Basic fallback."""

    def test_fallback_to_basic_when_nothing_else_handles(self) -> None:
        reg = AdapterRegistry()
        # Register a high-priority adapter that can't handle anything
        cant_handle = MockAdapter(adapter_id="picky", priority=90, handles_all=False)
        basic = MockAdapter(adapter_id="basic", priority=10)
        reg.register(cant_handle)
        reg.register(basic)
        router = AdapterRouter(reg)
        params = UnifiedPayParams(
            to="0x1234567890abcdef1234567890abcdef12345678", amount="100"
        )
        adapter = router.select(params)
        assert adapter.metadata.id == "basic"

    def test_basic_returned_even_if_canhandle_false(self) -> None:
        """Basic is the ultimate fallback - returned even without canHandle check."""
        reg = AdapterRegistry()
        basic = MockAdapter(adapter_id="basic", priority=10, handles_all=False)
        reg.register(basic)
        router = AdapterRouter(reg)
        params = UnifiedPayParams(
            to="0x1234567890abcdef1234567890abcdef12345678", amount="100"
        )
        # basic.can_handle returns False, but fallback returns it anyway
        adapter = router.select(params)
        assert adapter.metadata.id == "basic"


# ============================================================================
# AdapterRouter.canHandle / getCompatibleAdapters
# ============================================================================


class TestAdapterRouterHelpers:
    def test_can_handle_returns_true(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        assert router.can_handle(simple_params) is True

    def test_can_handle_returns_false_for_invalid(self, router: AdapterRouter) -> None:
        params = UnifiedPayParams(to="", amount="100")
        assert router.can_handle(params) is False

    def test_get_compatible_adapters(
        self, router: AdapterRouter, simple_params: UnifiedPayParams
    ) -> None:
        compatible = router.get_compatible_adapters(simple_params)
        assert len(compatible) == 2  # basic + standard both handle all

    def test_get_compatible_filters_by_canhandle(
        self, simple_params: UnifiedPayParams
    ) -> None:
        reg = AdapterRegistry()
        handles = MockAdapter(adapter_id="handles", priority=50)
        doesnt = MockAdapter(adapter_id="doesnt", priority=90, handles_all=False)
        reg.register(handles)
        reg.register(doesnt)
        router = AdapterRouter(reg)
        compatible = router.get_compatible_adapters(simple_params)
        assert len(compatible) == 1
        assert compatible[0].metadata.id == "handles"
