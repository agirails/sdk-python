"""
Tests for the unified adapter surface parity with TS SDK 4.8.0.

Covers:
- P1: UnifiedPayResult dataclass + BasicAdapter.pay / StandardAdapter.pay
  returning it (with backward-compat attrs preserved).
- P1: UnifiedPayParams / BasicPayParams new fields (dispute_window, http_method,
  http_body, http_headers) and dispute_window bounds validation.
- P2: AdapterMetadata TS-parity fields (name, requires_identity,
  settlement_mode, supported_identity_types).
- P2: IAdapter Protocol declares get_status / start_work / deliver / release.
- P2: AdapterRouter strict amount validation + dict-shaped ERC-8004 identity.

Mirrors TS sdk-js/src/types/adapter.ts, BasicAdapter.ts, StandardAdapter.ts,
AdapterRouter.ts, IAdapter.ts.
"""

import pytest

from agirails import ACTPClient
from agirails.adapters import (
    AdapterMetadata,
    AdapterRegistry,
    AdapterRouter,
    BasicAdapter,
    BasicPayParams,
    IAdapter,
    StandardAdapter,
    UnifiedPayParams,
)
from agirails.adapters.types import (
    MAX_DISPUTE_WINDOW,
    MIN_DISPUTE_WINDOW,
    UnifiedPayResult,
)
from agirails.errors import ValidationError


PROVIDER = "0x" + "b" * 40
REQUESTER = "0x" + "a" * 40


# ============================================================================
# P1 - UnifiedPayResult shape (TS types/adapter.ts:232-288)
# ============================================================================


class TestUnifiedPayResultShape:
    def test_has_all_ts_fields(self) -> None:
        result = UnifiedPayResult(
            tx_id="0x" + "1" * 64,
            escrow_id="0x" + "1" * 64,
            adapter="basic",
            state="COMMITTED",
            success=True,
            amount="100.00",
            release_required=True,
            provider=PROVIDER,
            requester=REQUESTER,
            deadline="2026-01-01T00:00:00Z",
        )
        # Every TS UnifiedPayResult field is present.
        for field in (
            "tx_id",
            "escrow_id",
            "adapter",
            "state",
            "success",
            "amount",
            "response",
            "error",
            "release_required",
            "provider",
            "requester",
            "deadline",
            "erc8004_agent_id",
            "fee_breakdown",
        ):
            assert hasattr(result, field), field

    def test_optional_defaults(self) -> None:
        result = UnifiedPayResult(
            tx_id="0x1",
            escrow_id=None,
            adapter="x402",
            state="COMMITTED",
            success=True,
            amount="1.00",
            release_required=False,
            provider=PROVIDER,
            requester=REQUESTER,
            deadline="2026-01-01T00:00:00Z",
        )
        assert result.response is None
        assert result.error is None
        assert result.erc8004_agent_id is None
        assert result.fee_breakdown is None


# ============================================================================
# P1 - BasicAdapter.pay returns UnifiedPayResult (+ backward compat)
# ============================================================================


class TestBasicPayUnifiedResult:
    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(mode="mock", requester_address=REQUESTER)

    @pytest.mark.asyncio
    async def test_pay_returns_unified_result_instance(self, client) -> None:
        result = await client.basic.pay({"to": PROVIDER, "amount": 100})
        assert isinstance(result, UnifiedPayResult)

    @pytest.mark.asyncio
    async def test_unified_fields_populated(self, client) -> None:
        result = await client.basic.pay({"to": PROVIDER, "amount": 100})
        assert result.adapter == "basic"
        assert result.state == "COMMITTED"
        assert result.success is True
        assert result.release_required is True
        assert result.provider == PROVIDER.lower()
        assert result.requester == REQUESTER.lower()
        # TS-spec formatted amount + ISO deadline live alongside legacy fields.
        assert result.amount_formatted == "100.00"
        assert result.deadline_iso.endswith("Z")

    @pytest.mark.asyncio
    async def test_backward_compat_legacy_fields_unchanged(self, client) -> None:
        """Legacy amount (wei str) and deadline (int) MUST be preserved."""
        result = await client.basic.pay({"to": PROVIDER, "amount": 100})
        assert result.amount == "100000000"  # raw wei string (legacy)
        assert isinstance(result.deadline, int)  # unix timestamp (legacy)
        assert result.tx_id.startswith("0x")
        assert result.escrow_id is not None
        assert result.state == "COMMITTED"

    @pytest.mark.asyncio
    async def test_erc8004_agent_id_echoed(self, client) -> None:
        params = UnifiedPayParams(to=PROVIDER, amount=100, erc8004_agent_id="42")
        result = await client.basic.pay(params)
        assert result.erc8004_agent_id == "42"

    @pytest.mark.asyncio
    async def test_dispute_window_threaded(self, client) -> None:
        """A custom dispute_window from UnifiedPayParams reaches the tx."""
        params = UnifiedPayParams(to=PROVIDER, amount=100, dispute_window=7200)
        result = await client.basic.pay(params)
        tx = await client.runtime.get_transaction(result.tx_id)
        assert tx.dispute_window == 7200


# ============================================================================
# P1 - StandardAdapter.pay returns UnifiedPayResult (+ backward compat)
# ============================================================================


class TestStandardPayUnifiedResult:
    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(mode="mock", requester_address=REQUESTER)

    @pytest.mark.asyncio
    async def test_pay_returns_unified_result(self, client) -> None:
        result = await client.standard.pay(UnifiedPayParams(to=PROVIDER, amount=100))
        assert isinstance(result, UnifiedPayResult)
        assert result.adapter == "standard"
        assert result.state == "COMMITTED"
        assert result.success is True
        assert result.release_required is True
        # TS-spec formatted amount + ISO deadline available alongside legacy.
        assert result.amount_formatted == "100.00"
        assert result.deadline_iso.endswith("Z")
        assert result.provider == PROVIDER.lower()
        assert result.requester == REQUESTER.lower()

    @pytest.mark.asyncio
    async def test_backward_compat_attribute_access(self, client) -> None:
        """Old callers read .tx_id / .escrow_id / .state / wei amount / int
        deadline — all preserved (the standard pay() used to return a dict with
        those exact semantics)."""
        result = await client.standard.pay(UnifiedPayParams(to=PROVIDER, amount=100))
        assert result.tx_id.startswith("0x")
        assert result.escrow_id is not None
        assert result.state == "COMMITTED"
        assert result.amount == "100000000"  # legacy wei string
        assert isinstance(result.deadline, int)  # legacy unix int

    @pytest.mark.asyncio
    async def test_dispute_window_threaded(self, client) -> None:
        params = UnifiedPayParams(to=PROVIDER, amount=100, dispute_window=10800)
        result = await client.standard.pay(params)
        tx = await client.runtime.get_transaction(result.tx_id)
        assert tx.dispute_window == 10800

    @pytest.mark.asyncio
    async def test_erc8004_agent_id_echoed(self, client) -> None:
        params = UnifiedPayParams(to=PROVIDER, amount=100, erc8004_agent_id="7")
        result = await client.standard.pay(params)
        assert result.erc8004_agent_id == "7"

    @pytest.mark.asyncio
    async def test_missing_amount_raises(self, client) -> None:
        with pytest.raises(ValidationError, match="amount is required"):
            await client.standard.pay(UnifiedPayParams(to=PROVIDER, amount=None))


# ============================================================================
# P1 - UnifiedPayParams / BasicPayParams new fields + dispute_window bounds
# ============================================================================


class TestUnifiedPayParamsFields:
    def test_new_fields_present_with_defaults(self) -> None:
        p = UnifiedPayParams(to=PROVIDER, amount="100")
        assert p.dispute_window is None
        assert p.http_method is None
        assert p.http_body is None
        assert p.http_headers is None

    def test_amount_now_optional(self) -> None:
        # x402 URL targets omit amount; UnifiedPayParams allows it.
        p = UnifiedPayParams(to="https://api.example.com/pay")
        assert p.amount is None

    def test_http_fields_roundtrip(self) -> None:
        p = UnifiedPayParams(
            to="https://api.example.com/pay",
            http_method="POST",
            http_body="hello",
            http_headers={"X-Test": "1"},
        )
        assert p.http_method == "POST"
        assert p.http_body == "hello"
        assert p.http_headers == {"X-Test": "1"}

    def test_dispute_window_valid(self) -> None:
        p = UnifiedPayParams(to=PROVIDER, amount="100", dispute_window=7200)
        assert p.dispute_window == 7200

    def test_dispute_window_min_boundary_ok(self) -> None:
        assert (
            UnifiedPayParams(
                to=PROVIDER, amount="100", dispute_window=MIN_DISPUTE_WINDOW
            ).dispute_window
            == MIN_DISPUTE_WINDOW
        )

    def test_dispute_window_max_boundary_ok(self) -> None:
        assert (
            UnifiedPayParams(
                to=PROVIDER, amount="100", dispute_window=MAX_DISPUTE_WINDOW
            ).dispute_window
            == MAX_DISPUTE_WINDOW
        )

    def test_dispute_window_below_min_raises(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            UnifiedPayParams(to=PROVIDER, amount="100", dispute_window=3599)

    def test_dispute_window_above_max_raises(self) -> None:
        with pytest.raises(ValueError, match="at most"):
            UnifiedPayParams(
                to=PROVIDER, amount="100", dispute_window=MAX_DISPUTE_WINDOW + 1
            )

    def test_dispute_window_bool_rejected(self) -> None:
        with pytest.raises(ValueError, match="integer"):
            UnifiedPayParams(to=PROVIDER, amount="100", dispute_window=True)


class TestBasicPayParamsFields:
    def test_new_fields_present(self) -> None:
        p = BasicPayParams(to=PROVIDER, amount="100")
        assert p.dispute_window is None
        assert p.http_method is None
        assert p.http_body is None
        assert p.http_headers is None


# ============================================================================
# P2 - AdapterMetadata TS-parity fields
# ============================================================================


class TestAdapterMetadataFields:
    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(mode="mock", requester_address=REQUESTER)

    def test_metadata_has_ts_parity_fields(self) -> None:
        m = AdapterMetadata(
            id="x",
            priority=50,
            uses_escrow=True,
            supports_disputes=True,
            release_required=True,
        )
        assert m.name == ""
        assert m.requires_identity is False
        assert m.settlement_mode == "explicit"
        assert m.supported_identity_types is None

    @pytest.mark.asyncio
    async def test_basic_metadata_populated(self, client) -> None:
        m = client.basic.metadata
        assert m.name == "Basic Adapter"
        assert m.requires_identity is False
        assert m.settlement_mode == "explicit"

    @pytest.mark.asyncio
    async def test_standard_metadata_populated(self, client) -> None:
        m = client.standard.metadata
        assert m.name == "Standard Adapter"
        assert m.requires_identity is False
        assert m.settlement_mode == "explicit"


# ============================================================================
# P2 - IAdapter Protocol declares lifecycle methods
# ============================================================================


class TestIAdapterProtocol:
    @pytest.fixture
    async def client(self):
        return await ACTPClient.create(mode="mock", requester_address=REQUESTER)

    @pytest.mark.asyncio
    async def test_basic_is_iadapter(self, client) -> None:
        assert isinstance(client.basic, IAdapter)

    @pytest.mark.asyncio
    async def test_standard_is_iadapter(self, client) -> None:
        assert isinstance(client.standard, IAdapter)

    def test_protocol_declares_lifecycle_methods(self) -> None:
        # runtime_checkable Protocol must expose all lifecycle members.
        members = set(dir(IAdapter))
        for member in ("get_status", "start_work", "deliver", "release"):
            assert member in members

    @pytest.mark.asyncio
    async def test_incomplete_adapter_is_not_iadapter(self, client) -> None:
        class Incomplete:
            metadata = client.basic.metadata

            def can_handle(self, params):  # noqa: ANN001
                return True

            def validate(self, params):  # noqa: ANN001
                return None

            async def pay(self, params):  # noqa: ANN001
                return None

        # Missing get_status/start_work/deliver/release -> not an IAdapter.
        assert not isinstance(Incomplete(), IAdapter)


# ============================================================================
# P2 - AdapterRouter strict amount validation
# ============================================================================


class _RouterMockAdapter:
    def __init__(self, adapter_id: str, priority: int = 50) -> None:
        self._metadata = AdapterMetadata(
            id=adapter_id,
            priority=priority,
            uses_escrow=True,
            supports_disputes=True,
            release_required=True,
        )

    @property
    def metadata(self) -> AdapterMetadata:
        return self._metadata

    def can_handle(self, params: UnifiedPayParams) -> bool:
        return True

    def validate(self, params: UnifiedPayParams) -> None:
        return None

    async def pay(self, params: UnifiedPayParams):  # noqa: ANN201
        return {"tx_id": "0x" + "1" * 64}


def _make_router(*adapter_ids: str) -> AdapterRouter:
    reg = AdapterRegistry()
    for aid in adapter_ids:
        reg.register(_RouterMockAdapter(aid))
    return AdapterRouter(reg)


class TestRouterAmountValidation:
    def test_positive_string_amount_ok(self) -> None:
        router = _make_router("basic", "standard")
        adapter = router.select(UnifiedPayParams(to=PROVIDER, amount="100"))
        assert adapter is not None

    def test_positive_number_amount_ok(self) -> None:
        router = _make_router("basic", "standard")
        adapter = router.select(UnifiedPayParams(to=PROVIDER, amount=100))
        assert adapter is not None

    def test_none_amount_allowed(self) -> None:
        """amount optional (x402 URL targets); router must not reject None."""
        router = _make_router("basic", "standard")
        adapter = router.select(UnifiedPayParams(to=PROVIDER, amount=None))
        assert adapter is not None

    def test_empty_string_amount_rejected(self) -> None:
        router = _make_router("basic", "standard")
        with pytest.raises(ValidationError, match="empty"):
            router.select(UnifiedPayParams(to=PROVIDER, amount=""))

    def test_zero_amount_rejected(self) -> None:
        router = _make_router("basic", "standard")
        with pytest.raises(ValidationError, match="positive"):
            router.select(UnifiedPayParams(to=PROVIDER, amount=0))

    def test_negative_amount_rejected(self) -> None:
        router = _make_router("basic", "standard")
        with pytest.raises(ValidationError, match="positive"):
            router.select(UnifiedPayParams(to=PROVIDER, amount=-5))

    def test_bool_amount_rejected(self) -> None:
        router = _make_router("basic", "standard")
        with pytest.raises(ValidationError, match="positive number"):
            router.select(UnifiedPayParams(to=PROVIDER, amount=True))


# ============================================================================
# P2 - AdapterRouter ERC-8004 identity branch (dict + dataclass shapes)
# ============================================================================


class TestRouterIdentityBranch:
    def test_dict_shaped_identity_selects_erc8004(self) -> None:
        router = _make_router("basic", "standard", "erc8004")
        params = UnifiedPayParams(
            to=PROVIDER,
            amount="100",
            metadata={"identity": {"type": "erc8004", "value": "5"}},
        )
        adapter = router.select(params)
        assert adapter.metadata.id == "erc8004"

    def test_dataclass_shaped_identity_selects_erc8004(self) -> None:
        from agirails.adapters.types import PaymentIdentity

        router = _make_router("basic", "standard", "erc8004")
        params = UnifiedPayParams(
            to=PROVIDER,
            amount="100",
            metadata={"identity": PaymentIdentity(type="erc8004", value="5")},
        )
        adapter = router.select(params)
        assert adapter.metadata.id == "erc8004"

    def test_non_erc8004_identity_does_not_select_erc8004(self) -> None:
        router = _make_router("basic", "standard", "erc8004")
        params = UnifiedPayParams(
            to=PROVIDER,
            amount="100",
            metadata={"identity": {"type": "ens", "value": "alice.eth"}},
        )
        adapter = router.select(params)
        # Falls through to priority selection (standard, priority 50 here).
        assert adapter.metadata.id != "erc8004"

    def test_identity_branch_skipped_when_erc8004_unregistered(self) -> None:
        router = _make_router("basic", "standard")
        params = UnifiedPayParams(
            to=PROVIDER,
            amount="100",
            metadata={"identity": {"type": "erc8004", "value": "5"}},
        )
        adapter = router.select(params)
        assert adapter.metadata.id in ("basic", "standard")
