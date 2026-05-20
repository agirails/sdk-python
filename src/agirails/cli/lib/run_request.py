"""``run_request`` — Python port of sdk-js/src/cli/lib/runRequest.ts.

Level 1 requester flow. Distinct from ``agirails.level0.request``:
that function is the Level 0 simple API with one monolithic delivery
timeout; ``run_request`` splits the lifecycle into a **quote phase**
(capped by ``quote_timeout_ms``, default 30s) and a **delivery phase**
(capped by ``delivery_timeout_ms``, default 5min), and reports each
state transition through an ``on_transition`` callback so the CLI can
print a live progress log.

**Scope (3.0.0): poll-only, auto-accept-friendly path.**

Polls ``runtime.get_transaction(tx_id)`` to observe state transitions
and relies on a provider whose ``Agent.provide()`` handler links
escrow + delivers on its own side. Multi-round counter-offer
negotiation (which BuyerOrchestrator would handle) is out of scope.

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
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List, Optional

from eth_account import Account
from eth_hash.auto import keccak

from agirails.client import ACTPClient
from agirails.wallet.keystore import (
    ResolvePrivateKeyOptions,
    resolve_private_key,
)

# Type aliases
TransitionCallback = Callable[[str, str, float], None]
RequestNetwork = str  # Literal["mock", "testnet", "mainnet"] at runtime


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
    if hasattr(runtime, "mint_tokens") and hasattr(runtime, "get_balance"):
        amount_wei = _usdc_to_wei(amount)
        balance_str = await runtime.get_balance(requester_address)
        balance = int(balance_str)
        if balance < amount_wei:
            top_up = str(amount_wei - balance + 10_000_000)
            await runtime.mint_tokens(requester_address, top_up)

    # 7. createTransaction → INITIATED.
    from agirails.adapters.standard import StandardTransactionParams

    deadline_value = _resolve_deadline(deadline)
    started_at = time.time()
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
        raise QuoteTimeoutError(tx_id, quote_timeout_ms)
    if last_state in _TERMINAL_FAILURE:
        raise RuntimeError(
            f"Transaction {last_state.lower()} before delivery"
        )

    # 9. Delivery phase.
    reached = await _wait_for_target_state(
        client, tx_id, {"DELIVERED", "SETTLED"},
        delivery_timeout_ms / 1000.0, _track,
    )
    if not reached:
        if last_state in _TERMINAL_FAILURE:
            raise RuntimeError(
                f"Transaction {last_state.lower()} before delivery"
            )
        raise DeliveryTimeoutError(tx_id, delivery_timeout_ms, last_state)

    # 10. Decode delivery payload.
    tx = await runtime.get_transaction(tx_id)
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
        except Exception:
            # Best-effort: leave DELIVERED-final; caller can settle later.
            pass

    return RunRequestResult(
        tx_id=tx_id,
        final_state=final_state,
        elapsed_ms=int((time.time() - started_at) * 1000),
        payload=payload,
        settled=settled,
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
        cb(state, tx_id, time.time() - started_at)


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
    deadline = time.time() + timeout_s
    while time.time() < deadline:
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
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        tx = await client.runtime.get_transaction(tx_id)
        state = _state_str(getattr(tx, "state", None))
        on_state(state)
        if state in targets:
            return True
        if state in _TERMINAL_FAILURE:
            return False
        await asyncio.sleep(_POLL_INTERVAL_S)
    return False


__all__ = [
    "DeliveryTimeoutError",
    "QuoteTimeoutError",
    "RunRequestResult",
    "run_request",
]
