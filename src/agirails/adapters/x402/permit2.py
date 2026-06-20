"""
Permit2 ``PermitWitnessTransferFrom`` signing for x402 v2 (exact scheme).

Structural 1:1 port of the @x402/evm Permit2 path
(node_modules/@x402/evm/dist/cjs/exact/client/index.js — createPermit2Payload /
createPermit2PayloadForProxy / signPermit2Authorization / createPermit2Nonce /
createPermit2ApprovalTx). This is the path Smart-Wallet (contract) buyers use,
because USDC ``transferWithAuthorization`` (EIP-3009) requires the signer to be
the token holder and does NOT delegate to ERC-1271 for contract wallets.

The EIP-3009 path is the common case (EOA) and is fully exercised by the
cross-SDK oracle. The Permit2 path mirrors the exact typed-data structs and
domain so a Smart-Wallet signer (ERC-1271/ERC-6492 via the wallet provider)
produces a wire-compatible payload.

@module adapters/x402/permit2
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address

from agirails.adapters.x402.eip3009 import chain_id_for_network

# ============================================================================
# Constants (mirror @x402/evm constants.ts)
# ============================================================================

# Canonical Permit2 contract (same address on every chain).
PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# x402 exact-scheme Permit2 proxy (spender in the witness transfer).
X402_EXACT_PERMIT2_PROXY_ADDRESS = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"

MAX_UINT256 = (1 << 256) - 1

# permit2WitnessTypes — IMMUTABLE field order/types (must match TS exactly).
PERMIT2_WITNESS_TYPES: Dict[str, Any] = {
    "PermitWitnessTransferFrom": [
        {"name": "permitted", "type": "TokenPermissions"},
        {"name": "spender", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
        {"name": "witness", "type": "Witness"},
    ],
    "TokenPermissions": [
        {"name": "token", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ],
    "Witness": [
        {"name": "to", "type": "address"},
        {"name": "validAfter", "type": "uint256"},
    ],
}

# Permit2 domain has NO version field (matches @x402/evm signPermit2Authorization
# which passes `{ name: "Permit2", chainId, verifyingContract }`).
_PERMIT2_EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

# ERC-20 approve(spender, amount) selector for the one-time Permit2 approve tx.
# keccak256("approve(address,uint256)")[:4] = 0x095ea7b3
_APPROVE_SELECTOR = keccak(text="approve(address,uint256)")[:4]

# ERC-20 allowance(address owner, address spender) selector for the pre-approve
# on-chain read. keccak256("allowance(address,address)")[:4] = 0xdd62ed3e.
_ALLOWANCE_SELECTOR = keccak(text="allowance(address,address)")[:4]

# Permit2 approve is typically MAX_UINT256. Treat any value at/above half-max as
# "already approved" (tolerates partial-spend scenarios). 1:1 with TS
# X402Adapter.readPermit2AllowanceIsSet THRESHOLD = (1n << 255n).
_ALLOWANCE_APPROVED_THRESHOLD = 1 << 255


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class _TokenPermissions:
    token: str
    amount: str  # uint256 base-units string


@dataclass
class _Witness:
    to: str
    valid_after: str  # uint256 string


@dataclass
class Permit2Authorization:
    """A Permit2 ``PermitWitnessTransferFrom`` authorization (x402 wire shape)."""

    from_address: str
    permitted: _TokenPermissions
    spender: str
    nonce: str  # uint256 string
    deadline: str  # uint256 string
    witness: _Witness

    def to_wire(self) -> Dict[str, Any]:
        return {
            "from": self.from_address,
            "permitted": {
                "token": self.permitted.token,
                "amount": self.permitted.amount,
            },
            "spender": self.spender,
            "nonce": self.nonce,
            "deadline": self.deadline,
            "witness": {
                "to": self.witness.to,
                "validAfter": self.witness.valid_after,
            },
        }


@dataclass
class PaymentRequirementsPermit2:
    """Subset of PaymentRequirements needed for the Permit2 path."""

    pay_to: str  # witness.to (recipient)
    amount: str  # permitted.amount (base units)
    asset: str  # permitted.token (USDC)
    network: str  # CAIP-2 or alias


# ============================================================================
# Nonce
# ============================================================================


def create_permit2_nonce() -> str:
    """Random Permit2 nonce as a decimal uint256 string.

    1:1 with @x402/evm ``createPermit2Nonce`` =
    ``BigInt(toHex(randomValues(32))).toString()``.
    """
    return str(int.from_bytes(os.urandom(32), "big"))


# ============================================================================
# Signing
# ============================================================================


def sign_permit2_authorization(
    account: Any,
    authorization: Permit2Authorization,
    network: str,
) -> str:
    """Sign a Permit2 ``PermitWitnessTransferFrom`` over EIP-712.

    1:1 with @x402/evm ``signPermit2Authorization``: domain is
    ``{ name: "Permit2", chainId, verifyingContract: PERMIT2_ADDRESS }`` and
    the message uses ``BigInt`` (int) for all uint256 fields.

    Args:
        account: eth_account LocalAccount or any signer exposing sign_message.
                 (For Smart Wallets, the wallet provider's sign_typed_data is
                 used by the adapter instead — see X402Adapter.)
        authorization: The Permit2 authorization to sign.
        network: CAIP-2 or alias network (resolved to chainId).

    Returns:
        0x-prefixed signature hex string.
    """
    chain_id = chain_id_for_network(network)
    domain = {
        "name": "Permit2",
        "chainId": chain_id,
        "verifyingContract": to_checksum_address(PERMIT2_ADDRESS),
    }
    message = {
        "permitted": {
            "token": to_checksum_address(authorization.permitted.token),
            "amount": int(authorization.permitted.amount),
        },
        "spender": to_checksum_address(authorization.spender),
        "nonce": int(authorization.nonce),
        "deadline": int(authorization.deadline),
        "witness": {
            "to": to_checksum_address(authorization.witness.to),
            "validAfter": int(authorization.witness.valid_after),
        },
    }
    full_message = {
        "domain": domain,
        "types": dict(PERMIT2_WITNESS_TYPES, EIP712Domain=_PERMIT2_EIP712_DOMAIN_TYPE),
        "primaryType": "PermitWitnessTransferFrom",
        "message": message,
    }

    # Wallet-provider path: hand the typed-data dict to the provider's signer
    # (TS bridge). Gated on a sentinel so plain eth_account accounts stay on the
    # byte-exact sign_message path.
    typed_signer = getattr(account, "_x402_sign_typed_data", None)
    if callable(typed_signer):
        sig = typed_signer(full_message)
        if isinstance(sig, str):
            return sig if sig.startswith("0x") else "0x" + sig
        return "0x" + bytes(sig).hex()

    signable = encode_typed_data(full_message=full_message)
    signed = account.sign_message(signable)
    sig = signed.signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def build_permit2_payload(
    account: Any,
    requirements: PaymentRequirementsPermit2,
    max_timeout_seconds: int,
    x402_version: int = 2,
    proxy_address: str = X402_EXACT_PERMIT2_PROXY_ADDRESS,
    now: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a signed x402 Permit2 payment payload.

    1:1 with @x402/evm ``createPermit2PayloadForProxy``:
      validAfter = now - 600; deadline = now + maxTimeoutSeconds;
      nonce = random uint256; spender = proxy; witness.to = payTo.

    Returns:
        ``{"x402Version": <int>, "payload": {"signature": "0x...", "permit2Authorization": {...}}}``
    """
    import time

    if now is None:
        now = int(time.time())
    if nonce is None:
        nonce = create_permit2_nonce()

    authorization = Permit2Authorization(
        from_address=account.address,
        permitted=_TokenPermissions(
            token=to_checksum_address(requirements.asset),
            amount=requirements.amount,
        ),
        spender=proxy_address,
        nonce=nonce,
        deadline=str(now + max_timeout_seconds),
        witness=_Witness(
            to=to_checksum_address(requirements.pay_to),
            valid_after=str(now - 600),
        ),
    )
    signature = sign_permit2_authorization(account, authorization, requirements.network)
    return {
        "x402Version": x402_version,
        "payload": {
            "signature": signature,
            "permit2Authorization": authorization.to_wire(),
        },
    }


# ============================================================================
# On-chain allowance read (pre-approve check)
# ============================================================================


def read_permit2_allowance_is_set(
    read_provider: Any,
    owner: str,
    token: str,
    spender: str = PERMIT2_ADDRESS,
) -> bool:
    """Return True if ``token.allowance(owner, PERMIT2)`` is already set.

    P2 / P1-2 parity with TS ``X402Adapter.readPermit2AllowanceIsSet``
    (X402Adapter.ts:680-712): read the on-chain ERC-20 allowance BEFORE sending
    a Permit2 approve. The in-memory approved-cache is only a fast path — after a
    process restart or horizontal scale the cache is empty but the on-chain
    allowance may already be set from a prior run. Without this check we'd pay
    (sponsor gas) for a redundant approve.

    Uses a raw ``eth_call`` with the ERC-20 ``allowance(address,address)``
    selector (0xdd62ed3e) to avoid pulling in a full contract ABI. Returns
    ``True`` only when the allowance is at/above half of ``MAX_UINT256`` (Permit2
    approves are typically ``MAX_UINT256``).

    Fail-open-to-submit semantics (matches TS): returns ``False`` (i.e. "submit
    the approve") if no usable read provider is available or the call fails, so
    we never skip a needed approve — the worst case is a redundant (sponsored)
    approve, never a missing one.

    Args:
        read_provider: A Web3 instance (``.eth.call``) or an ethers-style object
            exposing ``call({"to", "data"}) -> hex|bytes``. ``None`` => False.
        owner: The Smart Wallet / token holder address.
        token: The ERC-20 (USDC) token contract address.
        spender: Allowance spender (defaults to the canonical Permit2 address).

    Returns:
        True if already approved (>= half MAX_UINT256); False otherwise.
    """
    if read_provider is None:
        return False

    owner_word = bytes.fromhex(
        to_checksum_address(owner)[2:].lower()
    ).rjust(32, b"\x00")
    spender_word = bytes.fromhex(
        to_checksum_address(spender)[2:].lower()
    ).rjust(32, b"\x00")
    data = "0x" + (_ALLOWANCE_SELECTOR + owner_word + spender_word).hex()
    to_addr = to_checksum_address(token)

    try:
        result = _eth_call(read_provider, to_addr, data)
    except Exception:
        return False

    if result is None:
        return False
    # Normalize to an int.
    if isinstance(result, (bytes, bytearray)):
        if len(result) == 0:
            return False
        allowance = int.from_bytes(bytes(result), "big")
    else:
        text = str(result)
        if not text or text == "0x":
            return False
        try:
            allowance = int(text, 16)
        except ValueError:
            return False

    return allowance >= _ALLOWANCE_APPROVED_THRESHOLD


def _eth_call(read_provider: Any, to_addr: str, data: str) -> Any:
    """Perform a read-only ``eth_call`` across web3 / ethers-style providers.

    Web3.py: ``read_provider.eth.call({"to", "data"})`` -> bytes.
    Ethers-style duck type: ``read_provider.call({"to", "data"})`` -> hex str.
    """
    eth = getattr(read_provider, "eth", None)
    if eth is not None and callable(getattr(eth, "call", None)):
        return eth.call({"to": to_addr, "data": data})
    call = getattr(read_provider, "call", None)
    if callable(call):
        return call({"to": to_addr, "data": data})
    return None


# ============================================================================
# One-time Permit2 approve tx
# ============================================================================


@dataclass
class Permit2ApprovalTx:
    """A ready-to-send ERC-20 approve(PERMIT2, MAX_UINT256) transaction."""

    to: str  # token contract
    data: str  # calldata (0x-hex)
    value: str = "0"


def create_permit2_approval_tx(token_address: str) -> Permit2ApprovalTx:
    """Build the one-time ERC-20 ``approve(PERMIT2_ADDRESS, MAX_UINT256)`` tx.

    1:1 with @x402/evm ``createPermit2ApprovalTx``.
    """
    spender_word = bytes.fromhex(PERMIT2_ADDRESS[2:].lower()).rjust(32, b"\x00")
    amount_word = MAX_UINT256.to_bytes(32, "big")
    data = "0x" + (_APPROVE_SELECTOR + spender_word + amount_word).hex()
    return Permit2ApprovalTx(to=to_checksum_address(token_address), data=data)
