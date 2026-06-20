"""
X402Adapter — native x402 v2 protocol support (EIP-3009 / Permit2).

1:1 port of sdk-js/src/adapters/X402Adapter.ts (@agirails/sdk@4.8.0).

The buyer signs an EIP-3009 ``transferWithAuthorization`` (EOA) or a Permit2
``PermitWitnessTransferFrom`` witness (Smart Wallet) OFF-CHAIN; a facilitator
(server-configured) submits the on-chain tx and pays gas, so the buyer is always
gasless by protocol design. Settlement is proven by the decoded ``payment-response``
header (X402SettlementProofMissingError when absent), with a payer-replay check,
canonical-USDC asset allowlist, per-tx dollar cap, MEV authorization cap, and an
opt-in safety gate (allowedHosts / metadata.paymentMethod) so the adapter NEVER
auto-pays an arbitrary HTTPS URL.

Wire layout (X-PAYMENT header):
    base64(JSON({x402Version: 2, scheme: 'exact', network, payload}))
where payload = {authorization, signature} (EIP-3009) — byte-identical to TS,
proven by the cross-SDK oracle in tests/fixtures/cross_sdk/wave3_x402.json.

Backward compatibility
----------------------
The legacy custom ``x-payment-*`` HTTP flow (transfer_fn / X402Relay) is NOT the
canonical path. It is preserved as ``LegacyX402Adapter`` + ``LegacyX402AdapterConfig``
for existing callers. ``X402Adapter`` accepts EITHER config shape: a v2
``X402AdapterConfig`` (wallet_provider) routes through the native x402 v2 flow;
a legacy ``LegacyX402AdapterConfig`` (transfer_fn) transparently delegates to the
legacy adapter so old code keeps working unchanged.

@module adapters/x402_adapter
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Union,
)
from urllib.parse import urlparse

import httpx

from agirails.adapters.types import AdapterMetadata, UnifiedPayParams
from agirails.adapters.x402.eip3009 import (
    PaymentRequirements as _EIP3009Requirements,
)
from agirails.adapters.x402.eip3009 import (
    build_eip3009_payload,
    encode_x_payment_header,
    network_name_for_caip2,
)
from agirails.adapters.x402.permit2 import (
    PaymentRequirementsPermit2,
    build_permit2_payload,
    create_permit2_approval_tx,
)
from agirails.types.x402 import (
    DEFAULT_EVM_NETWORKS,
    DEFAULT_USDC_BY_NETWORK,
    X402_HEADERS,
    X402_PROOF_HEADERS,
    X402AmountExceededError,
    X402ApprovalFailedError,
    X402ConfigError,
    X402Error,
    X402ErrorCode,
    X402FeeBreakdown,
    X402HttpMethod,
    X402NetworkNotAllowedError,
    X402PaymentFailedError,
    X402PaymentHeaders,
    X402PublishRequiredError,
    X402SettlementProofMissingError,
    is_paymaster_gate_error,
    is_valid_x402_network,
)

# ============================================================================
# Type Aliases (legacy)
# ============================================================================

TransferFunction = Callable[[str, str], Awaitable[str]]
"""(to, amount) -> tx_hash. Direct atomic USDC transfer. LEGACY."""

ApproveFunction = Callable[[str, str], Awaitable[str]]
"""(spender, amount) -> tx_hash. USDC approval for relay contract. LEGACY."""

RelayPayFunction = Callable[[str, str, str], Awaitable[str]]
"""(provider, grossAmount, serviceId) -> tx_hash. Relay payWithFee. LEGACY."""

FetchFunction = Callable[..., Awaitable[httpx.Response]]
"""Custom fetch function signature for testing."""


# ============================================================================
# Local helpers (port of X402Adapter.ts local helpers)
# ============================================================================


def parse_usdc_amount(usd: str) -> int:
    """Parse human USD ("10", "0.50") to USDC 6-decimal int. (TS parseUsdcAmount)."""
    trimmed = usd.strip().lstrip("$")
    if not re.match(r"^\d+(\.\d{1,6})?$", trimmed):
        raise X402ConfigError(
            f'Invalid maxAmountPerTx "{usd}" — must be a non-negative decimal '
            f"with at most 6 digits after the point."
        )
    whole, _, frac = trimmed.partition(".")
    frac_padded = (frac + "000000")[:6]
    return int(whole + frac_padded)


def format_usdc_amount(amount: int) -> str:
    """Format USDC 6-decimal int back to human USD string. (TS formatUsdcAmount)."""
    whole = amount // 1_000_000
    frac = amount % 1_000_000
    if frac == 0:
        return str(whole)
    frac_str = f"{frac:06d}".rstrip("0")
    return f"{whole}.{frac_str}"


def resolve_allowed_networks(
    allowed: Optional[Sequence[str]],
) -> Sequence[str]:
    """Resolve effective allowed-network list (TS resolveAllowedNetworks)."""
    if allowed and len(allowed) > 0:
        return list(allowed)
    return list(DEFAULT_EVM_NETWORKS)


def safe_big_int(v: Any) -> int:
    """Parse any reasonable amount representation to USDC 6-decimal int.

    1:1 with TS ``safeBigInt``: bare-int string => raw; decimal string => USD.
    """
    try:
        if isinstance(v, bool):
            return 0
        if isinstance(v, int):
            return v if v >= 0 else 0
        if isinstance(v, float):
            import math

            if math.isnan(v) or v < 0:  # NaN or negative (TS !Number.isFinite)
                return 0
            if v.is_integer():
                return int(v)
            return parse_usdc_amount(str(v))
        if isinstance(v, str):
            trimmed = v.strip().lstrip("$")
            if re.match(r"^\d+$", trimmed):
                return int(trimmed)
            if re.match(r"^\d+\.\d{1,6}$", trimmed):
                return parse_usdc_amount(trimmed)
    except Exception:
        pass
    return 0


# ============================================================================
# Configuration
# ============================================================================


@dataclass
class X402AdapterConfig:
    """Configuration for the native x402 v2 X402Adapter.

    Mirrors the TS ``X402AdapterConfig`` interface (X402Adapter.ts:70-147).

    Attributes:
        wallet_provider: Wallet provider for signing payment authorizations.
            Must expose ``sign_typed_data`` (EOA Tier-2 or Auto Tier-1 Smart Wallet),
            ``get_address`` and ``get_wallet_info``.
        allowed_networks: Optional CAIP-2 network allowlist. None => all
            DEFAULT_EVM_NETWORKS (maximal interop).
        max_amount_per_tx: Per-tx safety cap in human USD (default "1").
        auto_approve_permit2: One-time Permit2 approve on first Smart Wallet x402
            payment (default True).
        max_authorization_valid_sec: MEV cap on signed authorization validity
            window (default 300s).
        allowed_assets: Token-address allowlist. None => canonical USDC per
            network; empty list => any asset (sentinel, NOT recommended).
        allowed_hosts: HTTPS hosts allowed without explicit opt-in. Empty
            (default) => always require opt-in.
        fetch_fn: Optional fetch override for tests.

    Backward compatibility: the legacy ``expected_network`` / ``transfer_fn`` /
    relay fields are accepted here too (all optional) so existing callers that
    construct ``X402AdapterConfig(expected_network=..., transfer_fn=...)`` keep
    working — ``X402Adapter.__new__`` routes such a config to the legacy adapter.
    New code should use :class:`LegacyX402AdapterConfig` explicitly for the
    legacy path, or supply ``wallet_provider`` for the canonical x402 v2 path.
    """

    wallet_provider: Any = None
    allowed_networks: Optional[Sequence[str]] = None
    max_amount_per_tx: Optional[str] = None
    auto_approve_permit2: bool = True
    max_authorization_valid_sec: Optional[int] = None
    allowed_assets: Optional[Sequence[str]] = None
    allowed_hosts: Optional[Sequence[str]] = None
    fetch_fn: Optional[FetchFunction] = None

    # --- legacy compat fields (optional; route to LegacyX402Adapter) ---------
    expected_network: Optional[str] = None
    transfer_fn: Optional[TransferFunction] = None
    request_timeout: float = 30.0
    default_headers: Optional[Dict[str, str]] = None
    relay_address: Optional[str] = None
    approve_fn: Optional[ApproveFunction] = None
    relay_pay_fn: Optional[RelayPayFunction] = None
    platform_fee_bps: int = 100


@dataclass
class LegacyX402AdapterConfig:
    """LEGACY configuration: custom ``x-payment-*`` HTTP flow (transfer_fn / relay).

    Preserved for backward compatibility. NOT the canonical x402 path. New code
    should use :class:`X402AdapterConfig` (wallet_provider, native x402 v2).
    """

    expected_network: str  # X402Network
    transfer_fn: TransferFunction
    request_timeout: float = 30.0
    fetch_fn: Optional[FetchFunction] = None
    default_headers: Optional[Dict[str, str]] = None
    relay_address: Optional[str] = None
    approve_fn: Optional[ApproveFunction] = None
    relay_pay_fn: Optional[RelayPayFunction] = None
    platform_fee_bps: int = 100


# ============================================================================
# Pay Parameters / Result
# ============================================================================


@dataclass
class X402PayParams(UnifiedPayParams):
    """Extended payment parameters for x402 with full HTTP support.

    Attributes:
        method: HTTP method (default: GET).
        headers: Custom request headers.
        body: Request body (string or dict, JSON-serialized if dict).
        content_type: Content-Type header.
    """

    method: X402HttpMethod = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Union[str, Dict[str, Any]]] = None
    content_type: Optional[str] = None


@dataclass
class X402PayResult:
    """Result from an x402 payment (both v2 and legacy)."""

    tx_id: str
    escrow_id: Optional[str]
    adapter: str
    state: str
    success: bool
    amount: str
    response: Optional[httpx.Response]
    release_required: bool
    provider: str
    requester: str
    deadline: str
    fee_breakdown: Optional[X402FeeBreakdown] = None
    erc8004_agent_id: Optional[str] = None


# ============================================================================
# Internal records
# ============================================================================


@dataclass
class _X402PaymentRecord:
    """Internal record of a completed x402 v2 payment for get_status lookups."""

    tx_id: str
    amount: int
    network: str
    payer: str
    pay_to: str
    settled_at: int


@dataclass
class _AtomicPaymentRecord:
    """LEGACY internal record for status lookups."""

    tx_hash: str
    provider: str
    requester: str
    amount: str
    timestamp: int
    endpoint: str
    fee_breakdown: Optional[X402FeeBreakdown] = None


# ============================================================================
# Address validation (legacy helpers)
# ============================================================================

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + "0" * 40
_TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$", re.IGNORECASE)
_ADDR_LOWER_RE = re.compile(r"^0x[0-9a-f]{40}$", re.IGNORECASE)


def _validate_address(address: str, field_name: str = "address") -> str:
    if not address or not _ADDRESS_RE.match(address):
        raise ValueError(f"Invalid {field_name}: must be 0x followed by 40 hex characters")
    normalized = address.lower()
    if normalized == _ZERO_ADDRESS:
        raise ValueError(f"{field_name} cannot be zero address")
    return normalized


def _format_amount(wei: Union[int, str]) -> str:
    """LEGACY: Format USDC wei to '<n>.<frac> USDC'."""
    wei_int = int(wei)
    whole = wei_int // 1_000_000
    frac = wei_int % 1_000_000
    if frac == 0:
        return f"{whole}.00 USDC"
    frac_str = f"{frac:06d}".rstrip("0")
    return f"{whole}.{frac_str} USDC"


# ============================================================================
# X402Adapter (native x402 v2; dispatches to legacy when given legacy config)
# ============================================================================


_MAX_PAYMENT_RECORDS = 10_000


class X402Adapter:
    """Native x402 v2 adapter (EIP-3009 / Permit2).

    Constructor accepts EITHER:
      * ``X402AdapterConfig`` (wallet_provider) — native x402 v2 (canonical), or
      * ``LegacyX402AdapterConfig`` (transfer_fn) — backward-compatible legacy
        ``x-payment-*`` flow (transparently delegates to :class:`LegacyX402Adapter`).
    """

    metadata: AdapterMetadata = AdapterMetadata(
        id="x402",
        priority=70,
        uses_escrow=False,
        supports_disputes=False,
        release_required=False,
    )

    def __new__(cls, requester_address: str, config: Any) -> Any:
        # Backward compat: a legacy config routes to the legacy adapter so all
        # existing code/tests keep working unchanged.
        if isinstance(config, LegacyX402AdapterConfig):
            return LegacyX402Adapter(requester_address, config)
        if _looks_like_legacy_config(config):
            return LegacyX402Adapter(requester_address, _coerce_legacy_config(config))
        return super().__new__(cls)

    def __init__(self, requester_address: str, config: X402AdapterConfig) -> None:
        # If __new__ returned a LegacyX402Adapter, __init__ won't be called on
        # this class (different type) — guard anyway.
        if isinstance(self, LegacyX402Adapter):  # pragma: no cover
            return

        self._requester_address = requester_address.lower() if requester_address else ""
        self._config = config

        wp = config.wallet_provider
        if not callable(getattr(wp, "sign_typed_data", None)):
            raise X402ConfigError(
                "X402Adapter requires a wallet_provider with sign_typed_data() "
                "support. Both EOAWalletProvider and AutoWalletProvider implement "
                "this in @agirails/sdk."
            )

        # I1: resolve + cache allowed networks once.
        self._allowed_networks: Sequence[str] = resolve_allowed_networks(
            config.allowed_networks
        )

        # P1-1: resolve allowed assets (lowercase). None => canonical USDC per
        # network; empty list => None sentinel ("any asset", explicit opt-out).
        if config.allowed_assets is None:
            defaults = [
                DEFAULT_USDC_BY_NETWORK[n]
                for n in self._allowed_networks
                if n in DEFAULT_USDC_BY_NETWORK
            ]
            self._allowed_assets_lc: Optional[Set[str]] = {a.lower() for a in defaults}
        elif len(config.allowed_assets) == 0:
            self._allowed_assets_lc = None
        else:
            self._allowed_assets_lc = {a.lower() for a in config.allowed_assets}

        # P1-3: resolve allowed hosts (lowercase). Default empty = always opt-in.
        self._allowed_hosts_lc: Set[str] = {
            h.lower() for h in (config.allowed_hosts or [])
        }

        # P1-3: default cap $1.
        self._max_amount_per_tx: int = parse_usdc_amount(config.max_amount_per_tx or "1")
        self._max_authorization_valid_sec: int = (
            config.max_authorization_valid_sec
            if config.max_authorization_valid_sec is not None
            else 300
        )

        self._permit2_approved_cache: Set[str] = set()
        self._payments: Dict[str, _X402PaymentRecord] = {}

    # ------------------------------------------------------------------
    # IAdapter
    # ------------------------------------------------------------------

    def can_handle(self, params: UnifiedPayParams) -> bool:
        """STRICT HTTPS ONLY (TS canHandle). validate() enforces opt-in later."""
        to = params.to
        if not isinstance(to, str):
            return False
        return bool(re.match(r"^https://", to, re.IGNORECASE))

    def validate(self, params: UnifiedPayParams) -> None:
        """Validate + enforce the opt-in safety gate (TS validate)."""
        if not params.to or not isinstance(params.to, str):
            raise X402ConfigError("x402: params.to must be a non-empty string URL")
        if not self.can_handle(params):
            raise X402ConfigError(
                f"x402: refusing non-HTTPS target {params.to}. Only https:// URLs "
                f"are supported to prevent MITM interception of signed payment payloads."
            )

        # P1-3: explicit opt-in gate.
        explicit_opt_in = bool(
            params.metadata and params.metadata.get("payment_method") == "x402"
        )
        host_allowed = False
        if len(self._allowed_hosts_lc) > 0:
            try:
                host = urlparse(params.to).hostname
                if host:
                    host_allowed = host.lower() in self._allowed_hosts_lc
            except Exception:
                pass

        if not explicit_opt_in and not host_allowed:
            raise X402ConfigError(
                f"x402: refusing to auto-pay {params.to}. HTTPS URLs trigger x402 "
                f"payments only when the caller explicitly opts in. Either:\n"
                f"  (a) pass metadata={{'payment_method': 'x402'}} to client.pay(), or\n"
                f"  (b) add the host to X402AdapterConfig.allowed_hosts.\n"
                f"This safeguard prevents accidental charges from unrelated HTTPS calls."
            )

    async def pay(
        self, params: Union[UnifiedPayParams, X402PayParams]
    ) -> X402PayResult:
        """Execute the native x402 v2 payment flow.

        1. Request endpoint -> get 402 with payment requirements
        2. Select requirement (scheme=exact + network + asset allowlist, cap, MEV)
        3. Smart-Wallet Permit2 approve (lazy/one-time) if needed
        4. Sign EIP-3009 (EOA) or Permit2 (Smart Wallet) authorization off-chain
        5. Retry with X-PAYMENT header (facilitator submits on-chain, pays gas)
        6. Validate `payment-response` settlement proof + payer-replay check
        """
        self.validate(params)

        method, request_headers, request_body, content_type = _extract_http_options(params)

        # Step 1: initial request
        initial = await self._make_request(
            params.to, method, request_headers, request_body, content_type
        )

        # Free service: 200 on initial request, no payment.
        if initial.status_code != 402:
            if 200 <= initial.status_code < 300:
                return self._free_service_result(params, initial)
            raise X402PaymentFailedError(
                f"x402: expected 402 Payment Required, got {initial.status_code}"
            )

        # Step 2: parse + select requirements.
        requirements = self._parse_payment_requirements(initial)
        chosen = self._select_requirements(requirements)

        # Step 3 + 4: build a signed payment payload.
        scheme_payload, network_name = await self._build_payment_payload(chosen)
        x_payment = encode_x_payment_header(scheme_payload, network_name)

        # Step 5: retry with the X-PAYMENT header (facilitator settles on-chain).
        retry_headers = dict(request_headers)
        retry_headers["X-PAYMENT"] = x_payment
        try:
            res = await self._make_request(
                params.to, method, retry_headers, request_body, content_type
            )
        except Exception as exc:
            raise X402PaymentFailedError(
                f"x402 payment failed: {exc}"
            )

        if res.status_code < 200 or res.status_code >= 300:
            raise X402PaymentFailedError(
                f"x402 payment returned HTTP {res.status_code} {res.reason_phrase}"
            )

        return self._map_to_pay_result(res, params, chosen)

    async def get_status(self, tx_id: str) -> Dict[str, Any]:
        record = self._payments.get(tx_id)
        if record is None:
            raise ValueError(
                f"x402 payment {tx_id} not found. x402 payments are atomic and "
                f"stateless; only payments made through this adapter instance are tracked."
            )
        # B4: pay() returns COMMITTED; get_status mirrors it.
        return {
            "state": "COMMITTED",
            "can_start_work": False,
            "can_deliver": False,
            "can_release": False,
            "can_dispute": False,
            "amount": format_usdc_amount(record.amount),
            "provider": record.pay_to,
            "requester": record.payer,
        }

    async def start_work(self, tx_id: str) -> None:
        raise RuntimeError(
            "x402 is stateless — no lifecycle methods. The HTTP response IS the "
            "delivery. Use ACTP adapters for stateful transactions."
        )

    async def deliver(self, tx_id: str, proof: Optional[str] = None) -> None:
        raise RuntimeError(
            "x402 is stateless — no lifecycle methods. The HTTP response IS the "
            "delivery. Use ACTP adapters for stateful transactions."
        )

    async def release(self, escrow_id: str, attestation_uid: Optional[str] = None) -> None:
        raise RuntimeError(
            "x402 has no escrow to release — payment settles instantly via the "
            "facilitator. Use ACTP adapters for escrow-based transactions."
        )

    # ------------------------------------------------------------------
    # Requirement parsing + selection
    # ------------------------------------------------------------------

    def _parse_payment_requirements(
        self, response: httpx.Response
    ) -> List[Dict[str, Any]]:
        """Parse the server's 402 ``accepts[]`` payment requirements.

        x402 v2 servers return JSON ``{x402Version, accepts: [PaymentRequirements]}``.
        """
        try:
            body = response.json()
        except Exception as exc:
            raise X402PaymentFailedError(
                f"x402: 402 response body is not valid JSON: {exc}"
            )
        accepts = body.get("accepts") if isinstance(body, dict) else None
        if not isinstance(accepts, list) or len(accepts) == 0:
            raise X402PaymentFailedError(
                "x402: 402 response has no `accepts` payment requirements array."
            )
        return accepts

    def _select_requirements(
        self, requirements: Sequence[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Pick the best requirement (TS selectRequirements).

        Filter: scheme=='exact' AND network in allowlist AND asset allowed.
        Order: Smart Wallet prefers Permit2; EOA prefers EIP-3009.
        Enforce maxAmountPerTx; clamp maxTimeoutSeconds to the MEV cap.
        """
        allowed = self._allowed_networks

        def _passes(r: Dict[str, Any]) -> bool:
            if r.get("scheme") != "exact":
                return False
            if r.get("network") not in allowed:
                return False
            if self._allowed_assets_lc is not None:
                asset = r.get("asset")
                if not isinstance(asset, str) or asset.lower() not in self._allowed_assets_lc:
                    return False
            return True

        candidates = [r for r in requirements if _passes(r)]

        if len(candidates) == 0:
            seen = ", ".join(
                f"{r.get('scheme')}@{r.get('network')}({str(r.get('asset') or '')[:10]}...)"
                for r in requirements
            )
            asset_info = ""
            if self._allowed_assets_lc is not None:
                asset_info = (
                    ", allowed assets: ["
                    + ", ".join(a[:10] + "..." for a in self._allowed_assets_lc)
                    + "]"
                )
            raise X402NetworkNotAllowedError(
                f"x402: no accepted requirement. Server offered [{seen}], "
                f"allowed networks: [{', '.join(allowed)}]{asset_info}."
            )

        def _is_permit2(r: Dict[str, Any]) -> bool:
            extra = r.get("extra")
            return isinstance(extra, dict) and extra.get("assetTransferMethod") == "permit2"

        tier = self._wallet_tier()
        if tier == "auto":
            prioritized = sorted(candidates, key=lambda r: 0 if _is_permit2(r) else 1)
        else:
            prioritized = sorted(candidates, key=lambda r: 1 if _is_permit2(r) else 0)

        chosen = dict(prioritized[0])
        amount_big = int(chosen["amount"])
        if amount_big > self._max_amount_per_tx:
            raise X402AmountExceededError(
                f"x402: required amount {chosen['amount']} "
                f"({format_usdc_amount(amount_big)} USD) exceeds maxAmountPerTx "
                f"{self._max_amount_per_tx} ({self._config.max_amount_per_tx or '1'} USD)."
            )

        server_timeout = chosen.get("maxTimeoutSeconds")
        if server_timeout is None:
            server_timeout = self._max_authorization_valid_sec
        chosen["maxTimeoutSeconds"] = min(
            int(server_timeout), self._max_authorization_valid_sec
        )
        return chosen

    # ------------------------------------------------------------------
    # Payload building (EIP-3009 / Permit2)
    # ------------------------------------------------------------------

    async def _build_payment_payload(
        self, chosen: Dict[str, Any]
    ) -> "tuple[Dict[str, Any], str]":
        """Build the inner x402 payload + the network name for the header.

        Smart Wallet => Permit2; EOA => EIP-3009 (TS scheme client auto-selects
        by signer type; Python selects by wallet tier + advertised method).
        """
        extra = chosen.get("extra") or {}
        advertised_permit2 = extra.get("assetTransferMethod") == "permit2"
        tier = self._wallet_tier()
        use_permit2 = advertised_permit2 or tier == "auto"

        network = chosen["network"]
        network_name = network_name_for_caip2(network)

        signer = self._signer_for_eth_account()

        if use_permit2:
            if self._config.auto_approve_permit2 and tier == "auto":
                await self._ensure_permit2_approved(network, chosen["asset"])
            payload = build_permit2_payload(
                account=signer,
                requirements=PaymentRequirementsPermit2(
                    pay_to=chosen["payTo"],
                    amount=str(chosen["amount"]),
                    asset=chosen["asset"],
                    network=network,
                ),
                max_timeout_seconds=int(chosen["maxTimeoutSeconds"]),
            )
            return payload["payload"], network_name

        # EIP-3009 path (common case)
        if not extra.get("name") or not extra.get("version"):
            raise X402ConfigError(
                f"x402: EIP-712 domain parameters (name, version) are required in "
                f"payment requirements for asset {chosen.get('asset')}."
            )
        payload = build_eip3009_payload(
            account=signer,
            requirements=_EIP3009Requirements(
                pay_to=chosen["payTo"],
                amount=str(chosen["amount"]),
                asset=chosen["asset"],
                network=network,
                max_timeout_seconds=int(chosen["maxTimeoutSeconds"]),
                extra_name=extra["name"],
                extra_version=extra["version"],
            ),
        )
        return payload["payload"], network_name

    def _signer_for_eth_account(self) -> Any:
        """Return an object usable by the x402 signing primitives.

        The primitives call ``account.address`` and ``account.sign_message``.
        We adapt the wallet provider's ``sign_typed_data`` into that shape so a
        custom provider (EOA or Smart Wallet) drives the signature, matching the
        TS ``walletProviderToClientEvmSigner`` bridge.
        """
        return _WalletProviderSigner(self._config.wallet_provider)

    # ------------------------------------------------------------------
    # Permit2 approve (lazy, one-time)
    # ------------------------------------------------------------------

    async def _ensure_permit2_approved(self, network: str, token: str) -> None:
        key = f"{network}:{token.lower()}"
        if key in self._permit2_approved_cache:
            return

        wp = self._config.wallet_provider
        if not callable(getattr(wp, "send_transaction", None)):
            # No send capability — cannot approve. Caller (facilitator/ERC-6492)
            # may still settle; mark approved to avoid retry loops.
            self._permit2_approved_cache.add(key)
            return

        approval = create_permit2_approval_tx(token)
        try:
            from agirails.wallet.auto_wallet_provider import TransactionRequest

            receipt = await wp.send_transaction(
                TransactionRequest(to=approval.to, data=approval.data, value="0")
            )
            if receipt is not None and getattr(receipt, "success", True) is False:
                raise X402ApprovalFailedError(
                    f"Permit2 approve transaction reverted on-chain for {network}:{token}"
                )
            self._permit2_approved_cache.add(key)
        except X402ApprovalFailedError:
            raise
        except Exception as exc:
            if is_paymaster_gate_error(exc):
                raise X402PublishRequiredError()
            raise X402ApprovalFailedError(
                f"Permit2 approve failed for {network}:{token}: {exc}"
            )

    # ------------------------------------------------------------------
    # Response mapping + settlement proof
    # ------------------------------------------------------------------

    def _map_to_pay_result(
        self,
        res: httpx.Response,
        params: UnifiedPayParams,
        chosen: Dict[str, Any],
    ) -> X402PayResult:
        # FIX v4.1: missing payment-response header is NOT silent success.
        header = res.headers.get("payment-response")
        if not header:
            raise X402SettlementProofMissingError()

        try:
            decoded = _decode_payment_response_header(header)
        except Exception as exc:
            raise X402SettlementProofMissingError(
                f"Failed to decode payment-response header: {exc}"
            )

        raw_tx_hash = decoded.get("transaction")
        raw_network = decoded.get("network")
        raw_payer = decoded.get("payer")
        pay_to = decoded.get("payTo")
        amount = decoded.get("amount")

        missing: List[str] = []
        if not raw_tx_hash or not _TX_HASH_RE.match(str(raw_tx_hash)):
            missing.append("transaction")
        if not raw_network:
            missing.append("network")
        if not raw_payer or not _ADDR_LOWER_RE.match(str(raw_payer)):
            missing.append("payer")
        if missing:
            raise X402SettlementProofMissingError(
                f"payment-response header decoded but missing/invalid fields: "
                f"{', '.join(missing)}. Decoded values: transaction="
                f"{raw_tx_hash or 'undefined'}, network={raw_network or 'undefined'}, "
                f"payer={raw_payer or 'undefined'}. Do not treat as settled."
            )

        tx_hash = str(raw_tx_hash)
        network = str(raw_network)
        payer = str(raw_payer)

        # Replay detection: payer must match our wallet address.
        our_address = self._config.wallet_provider.get_address().lower()
        if payer.lower() != our_address:
            raise X402SettlementProofMissingError(
                f"payment-response payer {payer} does not match our wallet "
                f"{our_address}. Possible replay of another client's settlement."
            )

        amount_big = safe_big_int(amount if amount is not None else "0")
        self._payments[tx_hash] = _X402PaymentRecord(
            tx_id=tx_hash,
            amount=amount_big,
            network=network,
            payer=payer,
            pay_to=pay_to or "",
            settled_at=int(time.time() * 1000),
        )
        if len(self._payments) > _MAX_PAYMENT_RECORDS:
            oldest = next(iter(self._payments))
            del self._payments[oldest]

        return X402PayResult(
            tx_id=tx_hash,
            escrow_id=None,
            adapter="x402",
            state="COMMITTED",
            success=True,
            amount=format_usdc_amount(amount_big),
            response=res,
            release_required=False,
            provider=pay_to or params.to,
            requester=payer,
            deadline=datetime.now(timezone.utc).isoformat(),
            erc8004_agent_id=getattr(params, "erc8004_agent_id", None),
        )

    def _free_service_result(
        self, params: UnifiedPayParams, response: httpx.Response
    ) -> X402PayResult:
        deadline_iso = datetime.fromtimestamp(
            time.time() + 86400, tz=timezone.utc
        ).isoformat()
        return X402PayResult(
            tx_id="0x" + "0" * 64,
            escrow_id=None,
            adapter="x402",
            state="COMMITTED",
            success=True,
            amount="0",
            response=response,
            release_required=False,
            provider="0x" + "0" * 40,
            requester=self._requester_address or self._config.wallet_provider.get_address().lower(),
            deadline=deadline_iso,
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _make_request(
        self,
        url: str,
        method: X402HttpMethod = "GET",
        custom_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> httpx.Response:
        headers: Dict[str, str] = {"accept": "application/json"}
        if custom_headers:
            headers.update(custom_headers)
        if body and content_type and "content-type" not in {k.lower() for k in headers}:
            headers["content-type"] = content_type
        elif body and method not in ("GET", "DELETE") and "content-type" not in {
            k.lower() for k in headers
        }:
            headers["content-type"] = "application/json"

        if self._config.fetch_fn is not None:
            return await self._config.fetch_fn(
                url,
                method=method,
                headers=headers,
                content=body.encode() if body and method not in ("GET", "DELETE") else None,
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            kwargs: Dict[str, Any] = {"method": method, "url": url, "headers": headers}
            if body and method not in ("GET", "DELETE"):
                kwargs["content"] = body.encode()
            return await client.request(**kwargs)

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    def _wallet_tier(self) -> str:
        try:
            return self._config.wallet_provider.get_wallet_info().tier
        except Exception:
            return "eoa"


# ============================================================================
# Wallet-provider signer bridge
# ============================================================================


class _WalletProviderSigner:
    """Adapt an IWalletProvider to the shape the x402 signing primitives need.

    The signing primitives detect ``sign_typed_data`` (the TS
    ``walletProviderToClientEvmSigner`` bridge) and hand it the full typed-data
    dict — exactly what the wallet provider expects. We expose ``address`` and
    ``sign_typed_data`` delegating to the provider. The result is wrapped in
    X402SignatureFailedError-compatible flow at the provider boundary.
    """

    def __init__(self, wallet_provider: Any) -> None:
        self._wp = wallet_provider

    @property
    def address(self) -> str:
        return self._wp.get_address()

    def _x402_sign_typed_data(self, typed_data: Any) -> Any:
        """Sentinel-named hook the signing primitives dispatch to for providers."""
        return self._wp.sign_typed_data(typed_data)


# ============================================================================
# payment-response header decoding (TS decodePaymentResponseHeader)
# ============================================================================


def _decode_payment_response_header(header: str) -> Dict[str, Any]:
    """Decode the base64-JSON `payment-response` header into a dict.

    x402 v2 facilitators set this header (base64 of a JSON settlement object)
    ONLY after on-chain settlement. Mirrors @x402/fetch decodePaymentResponseHeader.
    """
    # Tolerate missing padding.
    padded = header + "=" * (-len(header) % 4)
    raw = base64.b64decode(padded)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("payment-response is not a JSON object")
    return obj


# ============================================================================
# Shared param extraction
# ============================================================================


def _extract_http_options(
    params: Union[UnifiedPayParams, X402PayParams]
) -> "tuple[X402HttpMethod, Dict[str, str], Optional[str], Optional[str]]":
    method: X402HttpMethod = "GET"
    request_headers: Dict[str, str] = {}
    request_body: Optional[str] = None
    content_type: Optional[str] = None
    if isinstance(params, X402PayParams):
        method = params.method or "GET"
        request_headers = dict(params.headers or {})
        request_body = _serialize_body(params.body, params.content_type)
        content_type = params.content_type
        if content_type is None and params.body and method != "GET":
            content_type = "application/json"
    return method, request_headers, request_body, content_type


def _serialize_body(
    body: Optional[Union[str, Dict[str, Any]]],
    content_type: Optional[str] = None,
) -> Optional[str]:
    if body is None:
        return None
    if isinstance(body, str):
        return body
    return json.dumps(body)


def _looks_like_legacy_config(config: Any) -> bool:
    """True if ``config`` is (or carries) the legacy transfer_fn-based shape.

    Covers two cases:
      * a :class:`LegacyX402AdapterConfig` instance (no wallet_provider attr), and
      * a v2 :class:`X402AdapterConfig` that was populated with the legacy
        compat fields (``transfer_fn`` set, ``wallet_provider`` unset) — e.g. the
        pre-v2 auto-registration call.
    """
    # Bare legacy config: has transfer_fn + expected_network, no wallet_provider.
    if (
        hasattr(config, "transfer_fn")
        and hasattr(config, "expected_network")
        and not hasattr(config, "wallet_provider")
    ):
        return True
    # v2 config carrying legacy fields and no wallet provider.
    return (
        getattr(config, "wallet_provider", None) is None
        and getattr(config, "transfer_fn", None) is not None
    )


def _coerce_legacy_config(config: Any) -> LegacyX402AdapterConfig:
    """Build a :class:`LegacyX402AdapterConfig` from a v2 config carrying legacy
    fields (the backward-compat path used by pre-v2 auto-registration)."""
    if isinstance(config, LegacyX402AdapterConfig):
        return config
    return LegacyX402AdapterConfig(
        expected_network=getattr(config, "expected_network", "") or "",
        transfer_fn=config.transfer_fn,
        request_timeout=getattr(config, "request_timeout", 30.0),
        fetch_fn=getattr(config, "fetch_fn", None),
        default_headers=getattr(config, "default_headers", None),
        relay_address=getattr(config, "relay_address", None),
        approve_fn=getattr(config, "approve_fn", None),
        relay_pay_fn=getattr(config, "relay_pay_fn", None),
        platform_fee_bps=getattr(config, "platform_fee_bps", 100),
    )


# ============================================================================
# LegacyX402Adapter — preserved custom `x-payment-*` flow (NOT canonical)
# ============================================================================


class LegacyX402Adapter:
    """LEGACY x402 adapter: custom ``x-payment-*`` HTTP scheme + X402Relay.

    Preserved verbatim for backward compatibility. This is NOT real x402 v2 and
    is wire-incompatible with x402 v2 sellers. New code must use
    :class:`X402Adapter` with :class:`X402AdapterConfig`.
    """

    metadata: AdapterMetadata = AdapterMetadata(
        id="x402",
        priority=70,
        uses_escrow=False,
        supports_disputes=False,
        release_required=False,
    )

    def __init__(self, requester_address: str, config: LegacyX402AdapterConfig) -> None:
        self._requester_address = requester_address.lower()
        self._config = config
        self._timeout = config.request_timeout
        self._default_headers = config.default_headers or {}
        self._transfer_fn = config.transfer_fn
        self._payments: Dict[str, _AtomicPaymentRecord] = {}

    def can_handle(self, params: UnifiedPayParams) -> bool:
        to = params.to
        if not isinstance(to, str):
            return False
        try:
            parsed = urlparse(to)
            return parsed.scheme == "https"
        except Exception:
            return False

    def validate(self, params: UnifiedPayParams) -> None:
        if not self.can_handle(params):
            raise X402Error(
                f'X402 requires HTTPS URL, got: "{params.to}". '
                f"HTTP endpoints are not supported for security reasons.",
                X402ErrorCode.INSECURE_PROTOCOL,
            )
        parsed = urlparse(params.to)
        if parsed.username or parsed.password:
            raise X402Error(
                "URL cannot contain embedded credentials (username:password).",
                X402ErrorCode.MISSING_HEADERS,
            )

    async def pay(
        self, params: Union[UnifiedPayParams, X402PayParams]
    ) -> X402PayResult:
        self.validate(params)
        endpoint = params.to

        method: X402HttpMethod = "GET"
        request_headers: Dict[str, str] = {}
        request_body: Optional[str] = None
        content_type: Optional[str] = None
        if isinstance(params, X402PayParams):
            method = params.method or "GET"
            request_headers = params.headers or {}
            request_body = self._serialize_body(params.body, params.content_type)
            content_type = params.content_type
            if content_type is None and params.body and method != "GET":
                content_type = "application/json"

        initial_response = await self._make_request(
            endpoint, method, request_headers, request_body, content_type
        )

        if initial_response.status_code != 402:
            if 200 <= initial_response.status_code < 300:
                return self._create_free_service_result(params, initial_response)
            raise X402Error(
                f"Expected 402 Payment Required, got {initial_response.status_code}",
                X402ErrorCode.NOT_402_RESPONSE,
                initial_response,
            )

        payment_headers = self._parse_payment_headers(initial_response)

        if payment_headers.network != self._config.expected_network:
            raise X402Error(
                f"Network mismatch: expected {self._config.expected_network}, "
                f"got {payment_headers.network}",
                X402ErrorCode.NETWORK_MISMATCH,
                initial_response,
            )

        now = int(time.time())
        if payment_headers.deadline <= now:
            deadline_str = datetime.fromtimestamp(
                payment_headers.deadline, tz=timezone.utc
            ).isoformat()
            raise X402Error(
                f"Payment deadline has passed: {deadline_str}",
                X402ErrorCode.DEADLINE_PASSED,
                initial_response,
            )

        tx_hash, fee_breakdown = await self._execute_atomic_payment(payment_headers)

        service_response = await self._retry_with_proof(
            endpoint, tx_hash, method, request_headers, request_body, content_type
        )

        self._payments[tx_hash] = _AtomicPaymentRecord(
            tx_hash=tx_hash,
            provider=payment_headers.payment_address.lower(),
            requester=self._requester_address,
            amount=payment_headers.amount,
            timestamp=now,
            endpoint=endpoint,
            fee_breakdown=fee_breakdown,
        )

        deadline_iso = datetime.fromtimestamp(
            payment_headers.deadline, tz=timezone.utc
        ).isoformat()

        return X402PayResult(
            tx_id=tx_hash,
            escrow_id=None,
            adapter=self.metadata.id,
            state="COMMITTED",
            success=True,
            amount=_format_amount(payment_headers.amount),
            response=service_response,
            release_required=False,
            provider=payment_headers.payment_address.lower(),
            requester=self._requester_address,
            deadline=deadline_iso,
            fee_breakdown=fee_breakdown,
        )

    async def get_status(self, tx_id: str) -> Dict[str, Any]:
        record = self._payments.get(tx_id)
        if record is None:
            raise ValueError(
                f"Payment {tx_id} not found. X402 payments are atomic and stateless."
            )
        return {
            "state": "SETTLED",
            "can_start_work": False,
            "can_deliver": False,
            "can_release": False,
            "can_dispute": False,
            "amount": _format_amount(record.amount),
            "provider": record.provider,
            "requester": record.requester,
        }

    async def start_work(self, tx_id: str) -> None:
        raise RuntimeError(
            "X402 is atomic - no lifecycle methods. "
            "Payment and delivery happen atomically. Use ACTP for stateful transactions."
        )

    async def deliver(self, tx_id: str, proof: Optional[str] = None) -> None:
        raise RuntimeError(
            "X402 is atomic - no lifecycle methods. "
            "The HTTP response IS the delivery. Use ACTP for stateful transactions."
        )

    async def release(self, escrow_id: str, attestation_uid: Optional[str] = None) -> None:
        raise RuntimeError(
            "X402 is atomic - no escrow to release. "
            "Payment settled instantly. Use ACTP for escrow-based transactions."
        )

    async def _make_request(
        self,
        url: str,
        method: X402HttpMethod = "GET",
        custom_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
        proof_headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        headers: Dict[str, str] = dict(self._default_headers)
        if custom_headers:
            headers.update(custom_headers)
        if content_type:
            headers["content-type"] = content_type
        if proof_headers:
            headers.update(proof_headers)

        if self._config.fetch_fn is not None:
            return await self._config.fetch_fn(
                url,
                method=method,
                headers=headers,
                content=body.encode() if body and method != "GET" else None,
            )

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            kwargs: Dict[str, Any] = {"method": method, "url": url, "headers": headers}
            if body and method != "GET":
                kwargs["content"] = body.encode()
            return await client.request(**kwargs)

    def _parse_payment_headers(self, response: httpx.Response) -> X402PaymentHeaders:
        h = response.headers
        required_val = h.get(X402_HEADERS["REQUIRED"])
        if not required_val or required_val.lower() != "true":
            raise X402Error(
                f"Missing or invalid {X402_HEADERS['REQUIRED']} header",
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        address = h.get(X402_HEADERS["ADDRESS"])
        amount = h.get(X402_HEADERS["AMOUNT"])
        network = h.get(X402_HEADERS["NETWORK"])
        token = h.get(X402_HEADERS["TOKEN"])
        deadline = h.get(X402_HEADERS["DEADLINE"])

        if not address:
            raise X402Error(f"Missing {X402_HEADERS['ADDRESS']}", X402ErrorCode.MISSING_HEADERS, response)
        if not amount:
            raise X402Error(f"Missing {X402_HEADERS['AMOUNT']}", X402ErrorCode.MISSING_HEADERS, response)
        if not network:
            raise X402Error(f"Missing {X402_HEADERS['NETWORK']}", X402ErrorCode.MISSING_HEADERS, response)
        if not token:
            raise X402Error(f"Missing {X402_HEADERS['TOKEN']}", X402ErrorCode.MISSING_HEADERS, response)
        if not deadline:
            raise X402Error(f"Missing {X402_HEADERS['DEADLINE']}", X402ErrorCode.MISSING_HEADERS, response)

        validated_address = self._validate_payment_address(address, response)

        if not re.match(r"^\d+$", amount):
            raise X402Error(f'Invalid {X402_HEADERS["AMOUNT"]}: "{amount}"', X402ErrorCode.INVALID_AMOUNT, response)
        if not is_valid_x402_network(network):
            raise X402Error(f'Invalid {X402_HEADERS["NETWORK"]}: "{network}"', X402ErrorCode.INVALID_NETWORK, response)
        if token.upper() != "USDC":
            raise X402Error(
                f'Unsupported token: "{token}". Only USDC supported.',
                X402ErrorCode.MISSING_HEADERS,
                response,
            )
        try:
            deadline_num = int(deadline)
        except ValueError:
            deadline_num = 0
        if deadline_num <= 0:
            raise X402Error(f'Invalid {X402_HEADERS["DEADLINE"]}: "{deadline}"', X402ErrorCode.MISSING_HEADERS, response)

        return X402PaymentHeaders(
            required=True,
            payment_address=validated_address,
            amount=amount,
            network=network,
            token="USDC",
            deadline=deadline_num,
            service_id=h.get(X402_HEADERS["SERVICE_ID"]) or None,
        )

    def _validate_payment_address(self, address: str, response: httpx.Response) -> str:
        try:
            return _validate_address(address, X402_HEADERS["ADDRESS"])
        except ValueError:
            raise X402Error(
                f'Invalid {X402_HEADERS["ADDRESS"]}: "{address}"',
                X402ErrorCode.INVALID_ADDRESS,
                response,
            )

    async def _execute_atomic_payment(
        self, headers: X402PaymentHeaders
    ) -> "tuple[str, Optional[X402FeeBreakdown]]":
        try:
            if (
                self._config.relay_address
                and self._config.approve_fn
                and self._config.relay_pay_fn
            ):
                gross_amount = headers.amount
                fee_bps = self._config.platform_fee_bps
                MIN_FEE = 50_000
                gross_big = int(gross_amount)
                bps_fee = (gross_big * fee_bps) // 10_000
                fee = bps_fee if bps_fee > MIN_FEE else MIN_FEE
                provider_net = gross_big - fee

                await self._config.approve_fn(self._config.relay_address, gross_amount)
                service_id = headers.service_id or ("0x" + "0" * 64)
                tx_hash = await self._config.relay_pay_fn(
                    headers.payment_address, gross_amount, service_id
                )
                breakdown = X402FeeBreakdown(
                    gross_amount=gross_amount,
                    provider_net=str(provider_net),
                    platform_fee=str(fee),
                    fee_bps=fee_bps,
                    estimated=True,
                )
                return tx_hash, breakdown

            tx_hash = await self._transfer_fn(headers.payment_address, headers.amount)
            return tx_hash, None
        except X402Error:
            raise
        except Exception as exc:
            raise X402Error(f"Atomic payment failed: {exc}", X402ErrorCode.PAYMENT_FAILED)

    async def _retry_with_proof(
        self,
        endpoint: str,
        tx_hash: str,
        method: X402HttpMethod = "GET",
        custom_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> httpx.Response:
        proof_headers = {X402_PROOF_HEADERS["TX_ID"]: tx_hash}
        response = await self._make_request(
            endpoint, method, custom_headers, body, content_type, proof_headers
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise X402Error(
                f"Retry failed: {response.status_code} {response.reason_phrase}",
                X402ErrorCode.RETRY_FAILED,
                response,
            )
        return response

    @staticmethod
    def _serialize_body(
        body: Optional[Union[str, Dict[str, Any]]],
        content_type: Optional[str] = None,
    ) -> Optional[str]:
        if body is None:
            return None
        if isinstance(body, str):
            return body
        return json.dumps(body)

    def _create_free_service_result(
        self, params: UnifiedPayParams, response: httpx.Response
    ) -> X402PayResult:
        deadline_iso = datetime.fromtimestamp(
            time.time() + 86400, tz=timezone.utc
        ).isoformat()
        return X402PayResult(
            tx_id="0x" + "0" * 64,
            escrow_id=None,
            adapter=self.metadata.id,
            state="COMMITTED",
            success=True,
            amount="0.00 USDC",
            response=response,
            release_required=False,
            provider="0x" + "0" * 40,
            requester=self._requester_address,
            deadline=deadline_iso,
        )
