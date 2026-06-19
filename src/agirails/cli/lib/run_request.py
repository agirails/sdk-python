"""``run_request`` — Python port of sdk-js/src/cli/lib/runRequest.ts.

Level 1 requester flow. Distinct from ``agirails.level0.request``:
that function is the Level 0 simple API with one monolithic delivery
timeout; ``run_request`` splits the lifecycle into a **quote phase**
(capped by ``quote_timeout_ms``, default 30s) and a **delivery phase**
(capped by ``delivery_timeout_ms``, default 5min), and reports each
state transition through an ``on_transition`` callback so the CLI can
print a live progress log.

**Scope (4.0.0): poll-only, auto-accept-friendly path + AIP-16 delivery.**

Polls ``runtime.get_transaction(tx_id)`` to observe state transitions
and relies on a provider whose ``Agent.provide()`` handler links
escrow + delivers on its own side. Multi-round counter-offer
negotiation (which BuyerOrchestrator would handle) is out of scope.

The AIP-16 delivery surface (``delivery_channel`` + ``expected_kernel_address``
+ ``expected_chain_id``) is opt-in and STRICTLY additive: when omitted,
``run_request`` behaves exactly as the legacy poll-only path (payload from
``tx.delivery_proof``). When supplied (and a ``private_key`` is available for
the EIP-712 signer), ``run_request`` signs + POSTs a ``DeliverySetupWireV1``,
subscribes to the response envelope, and decodes the (public / encrypted)
body. Failures are non-fatal — settlement is never blocked by the channel.

**Protocol invariants (PRD §5.6):**

  - On-chain ``service_description`` is the bytes32 routing key
    ``keccak256(serviceName.strip())``. Never JSON.
  - Requester immediately settles after DELIVERED (kernel allows
    this without waiting for the dispute window).
  - Quote-timeout → :class:`QuoteTimeoutError`; CLI surfaces this as
    exit code 2 so scripts can distinguish "provider offline" from
    other failure modes.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from eth_account import Account
from eth_hash.auto import keccak

from agirails.client import ACTPClient
from agirails.utils.logging import get_logger
from agirails.wallet.keystore import (
    ResolvePrivateKeyOptions,
    resolve_private_key,
)

_logger = get_logger(__name__)

# Type aliases
TransitionCallback = Callable[[str, str, float], None]
RequestNetwork = str  # Literal["mock", "testnet", "mainnet"] at runtime

# DeliveryPrivacy ∈ {"public", "encrypted"} — kept as a plain str alias so the
# delivery package stays a lazy import (the legacy poll-only path must not pull
# in cryptography / X25519 deps when no channel is wired).
DeliveryPrivacy = str


# ============================================================================
# Result + errors
# ============================================================================


@dataclass(frozen=True)
class RunRequestResult:
    tx_id: str
    final_state: str
    elapsed_ms: int
    settled: bool
    payload: Optional[Any] = None
    #: Absolute public receipt URL (https://agirails.app/r/r_...) when the
    #: buyer-side V2 push to the AGIRAILS Platform succeeded after SETTLED.
    #: None when settle did not complete, the push failed, or network='mock'.
    receipt_url: Optional[str] = None
    #: Structured non-fatal delivery error if any AIP-16 step failed
    #: (``setup_post_failed`` / ``envelope_missing`` / ``envelope_decrypt_failed``
    #: / ``crypto_keygen_failed``). NEVER set when the channel was not provided.
    delivery_error: Optional[Dict[str, Any]] = None


class QuoteTimeoutError(RuntimeError):
    """No state movement off INITIATED within ``quote_timeout_ms``.

    The transaction remains on-chain INITIATED; the caller can either
    retry (provider may come back) or cancel via ``actp tx cancel``.
    """

    def __init__(self, tx_id: str, timeout_ms: int) -> None:
        super().__init__(
            f"No quote received within {timeout_ms}ms. Provider may be "
            f"offline. TX {tx_id} remains on-chain INITIATED — cancel "
            f"with 'actp tx cancel {tx_id}' or retry."
        )
        self.tx_id = tx_id
        self.timeout_ms = timeout_ms


class DeliveryTimeoutError(RuntimeError):
    def __init__(
        self, tx_id: str, timeout_ms: int, last_state: str
    ) -> None:
        super().__init__(
            f"No delivery within {timeout_ms}ms (last state: {last_state}). "
            f"TX {tx_id} may still be in flight; check 'actp tx status "
            f"{tx_id}'."
        )
        self.tx_id = tx_id
        self.timeout_ms = timeout_ms
        self.last_state = last_state


# ============================================================================
# Public API
# ============================================================================


_TERMINAL_FAILURE = {"CANCELLED", "DISPUTED"}
_POLL_INTERVAL_S = 1.0

# Non-blocking setup POST timeout (TS runRequest.ts:453).
_SETUP_POST_TIMEOUT_S = 3.0
# Envelope grace-period poll cadence after DELIVERED (TS runRequest.ts:617).
_ENVELOPE_POLL_S = 0.25
# Default envelope grace window after DELIVERED (TS runRequest.ts:616).
_DEFAULT_ENVELOPE_WAIT_MS = 30_000


async def run_request(
    *,
    provider: str,
    amount: str,
    service: str,
    deadline: Optional[Any] = None,
    network: RequestNetwork = "testnet",
    quote_timeout_ms: int = 30_000,
    delivery_timeout_ms: int = 300_000,
    auto_accept: bool = True,
    private_key: Optional[str] = None,
    rpc_url: Optional[str] = None,
    state_directory: Optional[str] = None,
    on_transition: Optional[TransitionCallback] = None,
    # ------------------------------------------------------------------
    # AIP-16 Phase 2e — Delivery Surface (opt-in, all optional)
    # ------------------------------------------------------------------
    delivery_channel: Optional[Any] = None,
    expected_kernel_address: Optional[str] = None,
    expected_chain_id: Optional[int] = None,
    envelope_wait_ms: Optional[int] = None,
    delivery_privacy: Optional[DeliveryPrivacy] = None,
    smart_wallet_nonce: Optional[int] = None,
) -> RunRequestResult:
    """Execute a Level 1 negotiated request end-to-end."""
    # 1. Validate provider address.
    if not _is_evm_address(provider):
        raise ValueError(f"Invalid provider address: {provider}")
    provider_address = provider

    # 2. Resolve requester key + address.
    if private_key is None and network in ("testnet", "mainnet"):
        private_key = await resolve_private_key(
            state_directory=state_directory,
            options=ResolvePrivateKeyOptions(network=network),
        )
    requester_address = (
        Account.from_key(private_key).address
        if private_key
        else _deterministic_mock_address()
    )

    # 3. Resolve RPC URL.
    if not rpc_url and network in ("testnet", "mainnet"):
        from agirails.config.networks import get_network

        net_name = "base-sepolia" if network == "testnet" else "base-mainnet"
        rpc_url = get_network(net_name).rpc_url

    # 4. Build client.
    client = await ACTPClient.create(
        mode=network if network in ("mock", "testnet", "mainnet") else "mock",
        requester_address=requester_address,
        state_directory=state_directory,
        private_key=private_key,
        rpc_url=rpc_url,
    )

    # 5. Routing key = keccak256(toUtf8Bytes(serviceName.strip())).
    normalized = service.strip()
    if not normalized:
        raise ValueError("run_request: `service` must be a non-empty name.")
    service_hash = "0x" + keccak(normalized.encode("utf-8")).hex()

    # 6. Mock-mode top-up (mirrors level0/request convenience).
    runtime = client.runtime
    amount_wei = _usdc_to_wei(amount)
    if hasattr(runtime, "mint_tokens") and hasattr(runtime, "get_balance"):
        balance_str = await runtime.get_balance(requester_address)
        balance = int(balance_str)
        if balance < amount_wei:
            top_up = str(amount_wei - balance + 10_000_000)
            await runtime.mint_tokens(requester_address, top_up)

    # 7. createTransaction → INITIATED.
    from agirails.adapters.standard import StandardTransactionParams

    deadline_value = _resolve_deadline(deadline)
    started_at = time.monotonic()
    tx_id = await client.standard.create_transaction(
        StandardTransactionParams(
            provider=provider_address,
            amount=amount,
            deadline=deadline_value,
            dispute_window=172_800,  # 2 days
            service_hash=service_hash,
        )
    )
    _emit(on_transition, "INITIATED", tx_id, started_at)

    # ----------------------------------------------------------------------
    # 7a. AIP-16 Phase 2e — Delivery surface: setup POST + envelope subscribe
    # ----------------------------------------------------------------------
    #
    # Activation requires: delivery_channel + expected_kernel_address +
    # expected_chain_id + a raw private_key (needed for the EIP-712 setup
    # signature — Smart Wallet signing is not wired here yet).
    #
    # Failure of either the setup POST OR the envelope subscription is
    # STRICTLY non-fatal: settlement always proceeds. Errors are captured
    # into ``delivery_error`` for caller visibility.
    delivery_enabled = (
        delivery_channel is not None
        and bool(expected_kernel_address)
        and isinstance(expected_chain_id, int)
        and bool(private_key)
    )

    delivery_error: Optional[Dict[str, Any]] = None
    envelope_state = _EnvelopeState()
    envelope_subscription: Optional[Any] = None
    buyer_ephemeral_priv_key: Optional[bytes] = None
    delivery_scheme: Optional[str] = None

    if delivery_enabled:
        (
            delivery_error,
            envelope_subscription,
            buyer_ephemeral_priv_key,
            delivery_scheme,
        ) = await _setup_delivery(
            tx_id=tx_id,
            client=client,
            private_key=private_key,  # type: ignore[arg-type]
            delivery_channel=delivery_channel,
            kernel_address=expected_kernel_address,  # type: ignore[arg-type]
            chain_id=expected_chain_id,  # type: ignore[arg-type]
            privacy=delivery_privacy or "public",
            smart_wallet_nonce=smart_wallet_nonce or 0,
            envelope_state=envelope_state,
        )

    # 7b. linkEscrow → COMMITTED (kernel requires msg.sender == requester).
    if network in ("testnet", "mainnet"):
        await client.standard.link_escrow(tx_id)
        _emit(on_transition, "COMMITTED", tx_id, started_at)

    # 8. Quote phase — wait for state to advance off INITIATED.
    last_state = "INITIATED"

    def _track(state: str) -> None:
        nonlocal last_state
        if state != last_state:
            last_state = state
            _emit(on_transition, state, tx_id, started_at)

    passed_quote = await _wait_for_state_change(
        client, tx_id, "INITIATED", quote_timeout_ms / 1000.0, _track
    )
    if not passed_quote:
        await _close_subscription(envelope_subscription, tx_id)
        raise QuoteTimeoutError(tx_id, quote_timeout_ms)
    if last_state in _TERMINAL_FAILURE:
        await _close_subscription(envelope_subscription, tx_id)
        raise RuntimeError(
            f"Transaction {last_state.lower()} before delivery"
        )

    # 9. Delivery phase.
    reached = await _wait_for_target_state(
        client, tx_id, {"DELIVERED", "SETTLED"},
        delivery_timeout_ms / 1000.0, _track,
    )
    if not reached:
        await _close_subscription(envelope_subscription, tx_id)
        if last_state in _TERMINAL_FAILURE:
            raise RuntimeError(
                f"Transaction {last_state.lower()} before delivery"
            )
        raise DeliveryTimeoutError(tx_id, delivery_timeout_ms, last_state)

    # 10. Decode delivery payload.
    #
    # Precedence (DELIVERED → "what bytes does the buyer surface?"):
    #   1. AIP-16 envelope payload (when delivery surface was active and an
    #      envelope landed within the grace period). Preferred.
    #   2. Legacy ``tx.delivery_proof`` parse. Backward-compat path.
    tx = await runtime.get_transaction(tx_id)
    payload: Optional[Any] = None

    if delivery_enabled:
        wait_ms = (
            envelope_wait_ms
            if envelope_wait_ms is not None
            else _DEFAULT_ENVELOPE_WAIT_MS
        )
        # Bounded grace period after DELIVERED to let the channel deliver the
        # envelope. NEVER blocks settlement.
        grace_start = time.monotonic()
        while (
            not envelope_state.resolved
            and (time.monotonic() - grace_start) * 1000.0 < wait_ms
        ):
            getter = getattr(delivery_channel, "get_envelopes", None)
            if getter is not None:
                try:
                    snap = await getter(tx_id)
                    if snap and not envelope_state.resolved:
                        envelope_state.resolved = True
                        envelope_state.wire = snap[0]
                        break
                except Exception:
                    # Ignore — subscription path is still active.
                    pass
            await asyncio.sleep(_ENVELOPE_POLL_S)

        if envelope_state.resolved and envelope_state.wire is not None:
            payload, decode_err = _decode_envelope(
                envelope_state.wire,
                buyer_ephemeral_priv_key,
                tx_id,
                delivery_scheme,
            )
            if decode_err is not None:
                delivery_error = decode_err
        elif delivery_error is None:
            # Grace period elapsed with no envelope and no prior error.
            delivery_error = {
                "code": "envelope_missing",
                "message": (
                    f"No envelope received within {wait_ms}ms grace period"
                ),
                "details": {"txId": tx_id, "waitedMs": wait_ms},
            }

    # Legacy fallback: only consult ``tx.delivery_proof`` when the AIP-16 path
    # did NOT produce a payload.
    if payload is None:
        payload = _safe_parse(getattr(tx, "delivery_proof", None))

    # 11. Requester-immediate settle. ACTPKernel allows DELIVERED →
    # SETTLED by the requester without waiting for the dispute window.
    final_state = _state_str(getattr(tx, "state", last_state))
    settled = final_state == "SETTLED"
    if not settled and tx is not None and final_state == "DELIVERED":
        escrow_id = getattr(tx, "escrow_id", None) or tx_id
        try:
            await client.standard.release_escrow(escrow_id)
            settled = True
            final_state = "SETTLED"
            _emit(on_transition, "SETTLED", tx_id, started_at)
        except Exception as err:
            _logger.warning(
                "Requester settle failed; settlement will fall back to "
                "dispute-window auto-settle",
                extra={"tx_id": tx_id, "error": str(err)},
            )

    # 12. Buyer-visible settlement receipt push — the wow flow.
    #
    # On SETTLED with a real on-chain network and a real signer, post the
    # requester-side receipt to the AGIRAILS Platform. Failure is non-fatal:
    # settlement already happened on-chain and the indexer cron backfills.
    receipt_url: Optional[str] = None
    if settled and private_key and network in ("testnet", "mainnet"):
        receipt_url = await _push_receipt(
            client=client,
            private_key=private_key,
            network=network,
            provider_address=provider_address,
            tx_id=tx_id,
            amount_wei=amount_wei,
            service_hash=service_hash,
            normalized_service=normalized,
            started_at=started_at,
        )

    # Close the envelope subscription before returning. Idempotent.
    await _close_subscription(envelope_subscription, tx_id)

    return RunRequestResult(
        tx_id=tx_id,
        final_state=final_state,
        elapsed_ms=int((time.monotonic() - started_at) * 1000),
        payload=payload,
        settled=settled,
        receipt_url=receipt_url,
        delivery_error=delivery_error,
    )


# ============================================================================
# AIP-16 delivery helpers
# ============================================================================


@dataclass
class _EnvelopeState:
    """Closure-shared holder for the first envelope wire seen.

    The buyer ephemeral private key is held in ``run_request``'s local scope
    only (never on this holder) so it is never logged / returned / persisted.
    """

    resolved: bool = False
    wire: Optional[Any] = None


async def _setup_delivery(
    *,
    tx_id: str,
    client: ACTPClient,
    private_key: str,
    delivery_channel: Any,
    kernel_address: str,
    chain_id: int,
    privacy: str,
    smart_wallet_nonce: int,
    envelope_state: _EnvelopeState,
):
    """Sign + POST the DeliverySetupWireV1 and subscribe to envelopes.

    Mirrors TS runRequest.ts:402-535. Returns a 4-tuple of
    ``(delivery_error, subscription, buyer_ephemeral_priv_key, scheme)``.
    Every failure here is non-fatal; the caller proceeds with settlement.
    """
    # Lazy import — keeps the crypto deps off the legacy poll-only path.
    from agirails.delivery import (
        CANONICAL_EMPTY_BYTES32,
        BuildSetupParams,
        DeliverySetupBuilder,
        generate_ephemeral_key_pair,
        pubkey_to_hex,
    )

    delivery_error: Optional[Dict[str, Any]] = None
    buyer_ephemeral_priv_key: Optional[bytes] = None
    buyer_ephemeral_pubkey = CANONICAL_EMPTY_BYTES32

    # Generate ephemeral keypair only for encrypted privacy. Public uses
    # CANONICAL_EMPTY_BYTES32 (EIP-712 has no "absent field" notion).
    if privacy == "encrypted":
        try:
            kp = generate_ephemeral_key_pair()
            buyer_ephemeral_pubkey = pubkey_to_hex(kp.public_key)
            buyer_ephemeral_priv_key = kp.secret_key
        except Exception as err:
            delivery_error = {
                "code": "crypto_keygen_failed",
                "message": str(err),
            }

    # Proceed with setup only if keygen (if attempted) succeeded.
    if delivery_error is None:
        try:
            signer = Account.from_key(private_key)
            signer_address = signer.address
            # ``client.info.address`` puts the on-chain participant address
            # (smart wallet when AutoWallet is active, EOA otherwise) into the
            # signed payload.
            requester_on_chain = client.info.address

            builder = DeliverySetupBuilder(signer)
            result = builder.build(
                BuildSetupParams(
                    tx_id=tx_id,
                    chain_id=chain_id,
                    kernel_address=kernel_address,
                    requester_address=requester_on_chain,
                    signer_address=signer_address,
                    buyer_ephemeral_pubkey=buyer_ephemeral_pubkey,
                    expected_privacy=privacy,
                    # H4 (AIP-16 Phase 3): thread caller-supplied Smart Wallet
                    # factory nonce; defaults to 0 to preserve byte-identical
                    # signing for the common nonce=0 case.
                    smart_wallet_nonce=smart_wallet_nonce,
                )
            )
            setup_wire = result["wire"]

            # Non-blocking POST: race against a 3s timeout. Timeout means we
            # proceed with state polling and let the subscription catch up.
            try:
                await asyncio.wait_for(
                    delivery_channel.publish_setup(setup_wire),
                    timeout=_SETUP_POST_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                delivery_error = {
                    "code": "setup_post_failed",
                    "message": (
                        f"Delivery setup POST exceeded "
                        f"{int(_SETUP_POST_TIMEOUT_S * 1000)}ms; proceeding "
                        f"without setup."
                    ),
                    "details": {"txId": tx_id},
                }
                _logger.warning(
                    "Delivery setup POST timed out; proceeding",
                    extra={"tx_id": tx_id},
                )
            except Exception as err:
                delivery_error = {
                    "code": "setup_post_failed",
                    "message": str(err),
                    "details": {"txId": tx_id},
                }
                _logger.warning(
                    "Delivery setup POST failed; proceeding",
                    extra={"tx_id": tx_id, "error": str(err)},
                )
        except Exception as err:
            # Builder-side failure (signer/address mismatch, canonical-empty
            # rule violation, etc.). Treat as setup_post_failed semantically.
            delivery_error = {
                "code": "setup_post_failed",
                "message": str(err),
                "details": {"txId": tx_id, "stage": "build"},
            }
            _logger.warning(
                "Delivery setup build failed; proceeding",
                extra={"tx_id": tx_id, "error": str(err)},
            )

    # Envelope subscription: parallel to the state-polling loop. The callback
    # stores only the FIRST envelope seen. Subscription errors are tolerated —
    # we fall through to the legacy ``tx.delivery_proof`` path.
    subscription: Optional[Any] = None

    def _on_envelope(env: Any) -> None:
        if envelope_state.resolved:
            return
        envelope_state.resolved = True
        # Stash the wire object; decoded later (after DELIVERED) so we don't
        # burn cycles for a tx that aborts mid-flight.
        envelope_state.wire = env

    try:
        subscription = await delivery_channel.subscribe_envelopes(
            tx_id, _on_envelope
        )
    except Exception as err:
        _logger.warning(
            "Delivery envelope subscription failed; proceeding",
            extra={"tx_id": tx_id, "error": str(err)},
        )

    return delivery_error, subscription, buyer_ephemeral_priv_key, privacy


def _decode_envelope(
    wire: Any,
    buyer_ephemeral_priv_key: Optional[bytes],
    tx_id: str,
    scheme: Optional[str],
):
    """Decode an envelope wire into a payload (TS runRequest.ts:641-679).

    Returns ``(payload, delivery_error)``. ``delivery_error`` is non-None
    only on a decode/decrypt failure (non-fatal).
    """
    try:
        signed = wire.get("signed") if isinstance(wire, dict) else None
        wire_scheme = signed.get("scheme") if isinstance(signed, dict) else None
        if (
            wire_scheme == "x25519-aes256gcm-v1"
            and buyer_ephemeral_priv_key is not None
        ):
            from agirails.delivery import DeliveryEnvelopeBuilder

            payload = DeliveryEnvelopeBuilder.decrypt_payload(
                wire, buyer_ephemeral_priv_key
            )
            return payload, None

        # public-v1: body is hex-encoded UTF-8 JSON OR plaintext JSON
        # (depending on relay vs mock channel). Try parsing as JSON directly
        # first; if the body is hex-prefixed, decode then parse.
        body = wire.get("body") if isinstance(wire, dict) else None
        if isinstance(body, str) and body.startswith("0x"):
            from agirails.delivery import bytes_from_hex

            raw = bytes_from_hex(body)
            payload = json.loads(raw.decode("utf-8"))
        elif isinstance(body, str):
            payload = json.loads(body)
        else:
            payload = body
        return payload, None
    except Exception as err:
        _logger.warning(
            "Delivery envelope decode failed; proceeding",
            extra={"tx_id": tx_id, "error": str(err)},
        )
        return None, {
            "code": "envelope_decrypt_failed",
            "message": str(err),
            "details": {"txId": tx_id, "scheme": scheme},
        }


async def _push_receipt(
    *,
    client: ACTPClient,
    private_key: str,
    network: str,
    provider_address: str,
    tx_id: str,
    amount_wei: int,
    service_hash: str,
    normalized_service: str,
    started_at: float,
) -> Optional[str]:
    """Push the requester-side V2 receipt on SETTLED (TS runRequest.ts:732-775).

    Lazy imports ``receipts.push`` (shipped Wave 5). Non-fatal — returns None
    on any failure (the Platform indexer cron is the backstop).
    """
    try:
        from agirails.receipts import (
            PushReceiptArgs,
            push_receipt_on_settled,
        )
        from agirails.cli.commands.receipt import compute_display_fee
        from agirails.config.networks import get_network

        net_name = "base-sepolia" if network == "testnet" else "base-mainnet"
        kernel_address = get_network(net_name).contracts.actp_kernel
        fee_wei = compute_display_fee(amount_wei)
        # Clamp net to zero for dust amounts where fee >= amount.
        net_wei = amount_wei - fee_wei if amount_wei > fee_wei else 0

        # The on-chain requester is ``client.info.address`` — the smart wallet
        # when AutoWallet is active, or the EOA in Tier 2/3.
        push = await push_receipt_on_settled(
            PushReceiptArgs(
                signer=Account.from_key(private_key),
                participant_role="requester",
                provider_address=provider_address,
                requester_address=client.info.address,
                kernel_address=kernel_address,
                tx_id=tx_id,
                network=net_name,
                amount_wei=str(amount_wei),
                fee_wei=str(fee_wei),
                net_wei=str(net_wei),
                service_hash=service_hash,
                service=normalized_service,
                duration_ms=int((time.monotonic() - started_at) * 1000),
            )
        )
        return push.receipt_url
    except Exception as err:
        _logger.warning(
            "Buyer-side receipt push failed; indexer will backfill",
            extra={"tx_id": tx_id, "error": str(err)},
        )
        return None


async def _close_subscription(subscription: Optional[Any], tx_id: str) -> None:
    """Close a DeliverySubscription, awaiting if it returns an awaitable."""
    if subscription is None:
        return
    try:
        ret = subscription.close()
        if inspect.isawaitable(ret):
            await ret
    except Exception as err:
        _logger.warning(
            "Delivery envelope subscription close failed",
            extra={"tx_id": tx_id, "error": str(err)},
        )


# ============================================================================
# Internals
# ============================================================================


_HEX_ADDR_LEN = 42


def _is_evm_address(s: str) -> bool:
    return (
        isinstance(s, str)
        and len(s) == _HEX_ADDR_LEN
        and s.startswith("0x")
        and all(c in "0123456789abcdefABCDEF" for c in s[2:])
    )


def _deterministic_mock_address() -> str:
    """Stable address for mock-mode callers without a private key."""
    return "0x" + "1" * 40


def _usdc_to_wei(amount: str) -> int:
    """Parse a human-readable USDC amount ("1.5") to base units (6 decimals)."""
    # Reuse the SDK helper if available, otherwise simple split.
    from agirails.utils.helpers import USDC

    return int(USDC.to_wei(amount))


def _resolve_deadline(deadline: Any) -> Any:
    """Pass-through: StandardAdapter accepts ISO / unix-int / duration-string."""
    if deadline is None:
        return "1h"
    return deadline


def _emit(
    cb: Optional[TransitionCallback], state: str, tx_id: str, started_at: float
) -> None:
    if cb is not None:
        cb(state, tx_id, time.monotonic() - started_at)


def _state_str(state: Any) -> str:
    if hasattr(state, "value"):
        return str(state.value)
    return str(state) if state else "INITIATED"


def _safe_parse(raw: Any) -> Optional[Any]:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


async def _wait_for_state_change(
    client: ACTPClient,
    tx_id: str,
    from_state: str,
    timeout_s: float,
    on_state: Callable[[str], None],
) -> bool:
    """Poll until state moves OFF ``from_state`` or timeout elapses."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tx = await client.runtime.get_transaction(tx_id)
        state = _state_str(getattr(tx, "state", None))
        on_state(state)
        if state != from_state:
            return True
        await asyncio.sleep(_POLL_INTERVAL_S)
    return False


async def _wait_for_target_state(
    client: ACTPClient,
    tx_id: str,
    targets: set,
    timeout_s: float,
    on_state: Callable[[str], None],
) -> bool:
    """Poll until ``state`` ∈ ``targets`` or timeout elapses.

    Returns ``False`` on timeout OR when the state hits a terminal
    failure (CANCELLED / DISPUTED) before reaching ``targets``.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tx = await client.runtime.get_transaction(tx_id)
        state = _state_str(getattr(tx, "state", None))
        on_state(state)
        if state in targets:
            return True
        if state in _TERMINAL_FAILURE:
            return False
        await asyncio.sleep(_POLL_INTERVAL_S)
    return False


# ============================================================================
# V3 framed receipt render — buyer perspective (the wow artifact)
# ============================================================================


def render_request_receipt(
    *,
    result: RunRequestResult,
    network: str,
    amount: str,
    service: str,
    provider: str,
    counterparty: Optional[str] = None,
    reflection: Optional[str] = None,
    now_fn: Optional[Any] = None,
) -> Optional[str]:
    """Render the ceremonial V3 framed receipt for a settled request.

    Python port of the render call in TS ``request.ts``
    (cli/commands/request.ts:198-237): always renders the buyer-perspective
    ceremonial receipt for a settled, non-mock request — in ``actp request`` the
    local agent is by definition the requester paying the provider. Returns the
    receipt string, or ``None`` when the V3 frame is suppressed (mock network or
    unsettled outcome) so the caller falls back to the legacy success line.

    Uses :func:`agirails.receipts.push.render_receipt_v3` (the framed V3
    renderer ported in this subsystem); the legacy
    ``cli.commands.receipt.render_receipt`` box (V1) remains available unchanged.
    """
    # Suppress the frame for mock / unsettled outcomes (TS request.ts:204).
    if network == "mock" or not result.settled:
        return None

    from agirails.receipts.push import (
        ReceiptDataV3,
        ReceiptTimingV3,
        render_receipt_v3,
    )

    network_label = "base-sepolia" if network == "testnet" else "base-mainnet"
    # ``amount`` is the human USDC string ("0.05", "10"); convert to 6-decimal
    # wei. Strip a leading $ if a user passed "$10" (TS request.ts:209-212).
    try:
        amount_num = float(amount.lstrip("$"))
        amount_wei = int(round(amount_num * 1_000_000))
    except (TypeError, ValueError):
        amount_wei = 0

    return render_receipt_v3(
        ReceiptDataV3(
            agent="your-agent",
            # Only pass ``counterparty`` when we have a human-readable slug — a
            # raw 42-char hex address overflows the inner card width. When
            # unset, the renderer falls back to short_addr(requester) which
            # always fits (TS request.ts:216-220).
            counterparty=counterparty,
            perspective="buyer",
            service=service,
            amount_wei=amount_wei,
            network=network_label,
            tx_id=result.tx_id,
            timing=ReceiptTimingV3(total_ms=result.elapsed_ms),
            reflection=reflection,
            receipt_url=result.receipt_url,
            # ``requester`` feeds short_addr — for buyer perspective the
            # counterparty IS the provider we paid (TS request.ts:229-233).
            requester=provider,
            now_fn=now_fn,
        )
    )


__all__ = [
    "DeliveryTimeoutError",
    "QuoteTimeoutError",
    "RunRequestResult",
    "run_request",
    "render_request_receipt",
]
