"""
AIP-16 Delivery Surface — EIP-712 domain, types, sign & recover (Python port).

Byte-exact parity with sdk-js/src/delivery/eip712.ts. The delivery domain
(``"AGIRAILS Delivery"`` / version ``"1"``) is deliberately distinct from the
negotiation domain (``"AGIRAILS"``) and the receipts domain
(``"AGIRAILS Receipts"``) to prevent cross-feature signature replay.

Field order in the type schemas is IMMUTABLE — it is part of the EIP-712 type
hash and MUST be byte-for-byte identical to the TS signer / every verifier.
"""

from __future__ import annotations

from typing import Any, Dict, List

from eth_account import Account
from eth_account.messages import encode_typed_data

# ============================================================================
# Domain constants
# ============================================================================

DELIVERY_DOMAIN_NAME = "AGIRAILS Delivery"
DELIVERY_DOMAIN_VERSION = "1"

_EIP712_DOMAIN_TYPE: List[Dict[str, str]] = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

# IMMUTABLE field order — see module docstring.
DELIVERY_SETUP_TYPES_V1: Dict[str, List[Dict[str, str]]] = {
    "DeliverySetupSignedV1": [
        {"name": "version", "type": "uint8"},
        {"name": "txId", "type": "bytes32"},
        {"name": "chainId", "type": "uint256"},
        {"name": "kernelAddress", "type": "address"},
        {"name": "requesterAddress", "type": "address"},
        {"name": "signerAddress", "type": "address"},
        {"name": "buyerEphemeralPubkey", "type": "bytes32"},
        {"name": "acceptedChannels", "type": "string[]"},
        {"name": "expectedPrivacy", "type": "string"},
        {"name": "createdAt", "type": "uint64"},
        {"name": "expiresAt", "type": "uint64"},
        # H4 fix: appended at END so existing field indices stay stable.
        {"name": "smartWalletNonce", "type": "uint256"},
    ]
}

DELIVERY_ENVELOPE_TYPES_V1: Dict[str, List[Dict[str, str]]] = {
    "DeliveryEnvelopeSignedV1": [
        {"name": "version", "type": "uint8"},
        {"name": "txId", "type": "bytes32"},
        {"name": "chainId", "type": "uint256"},
        {"name": "kernelAddress", "type": "address"},
        {"name": "providerAddress", "type": "address"},
        {"name": "signerAddress", "type": "address"},
        {"name": "scheme", "type": "string"},
        {"name": "providerEphemeralPubkey", "type": "bytes32"},
        {"name": "nonce", "type": "bytes12"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "tag", "type": "bytes16"},
        {"name": "createdAt", "type": "uint64"},
        # H4 fix: appended at END so existing field indices stay stable.
        {"name": "smartWalletNonce", "type": "uint256"},
    ]
}

_SETUP_FIELDS = [f["name"] for f in DELIVERY_SETUP_TYPES_V1["DeliverySetupSignedV1"]]
_ENVELOPE_FIELDS = [f["name"] for f in DELIVERY_ENVELOPE_TYPES_V1["DeliveryEnvelopeSignedV1"]]


class DeliveryEip712Error(Exception):
    """Malformed delivery EIP-712 input (unknown network, bad kernel, etc.)."""

    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def chain_id_for_network(network: str) -> int:
    """Resolve an EVM chainId from a delivery network name."""
    if network == "base-sepolia":
        return 84532
    if network == "base-mainnet":
        return 8453
    if network == "mock":
        raise DeliveryEip712Error(
            "MOCK_NETWORK_NOT_SUPPORTED",
            "Delivery EIP-712 signatures are not defined for the mock network.",
            {"network": network},
        )
    raise DeliveryEip712Error("UNKNOWN_NETWORK", f"Unknown delivery network: {network}", {"network": network})


def build_delivery_domain(chain_id: int, kernel_address: str) -> Dict[str, Any]:
    """Construct the EIP-712 domain for a delivery signature (anchored to kernel)."""
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise DeliveryEip712Error("INVALID_CHAIN_ID", f"chainId must be a positive integer, got {chain_id}")
    if not isinstance(kernel_address, str) or not kernel_address.startswith("0x") or len(kernel_address) != 42:
        raise DeliveryEip712Error("INVALID_KERNEL_ADDRESS", f"kernelAddress is not a valid address: {kernel_address}")
    return {
        "name": DELIVERY_DOMAIN_NAME,
        "version": DELIVERY_DOMAIN_VERSION,
        "chainId": chain_id,
        "verifyingContract": kernel_address,
    }


def _normalize(payload: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    """Project to the signed fields and normalize H4 smartWalletNonce None->0."""
    msg = {}
    for name in fields:
        val = payload.get(name)
        if name == "smartWalletNonce" and val is None:
            val = 0
        msg[name] = val
    return msg


def _typed_data(primary_type: str, types: Dict[str, Any], domain: Dict[str, Any], message: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "types": {"EIP712Domain": _EIP712_DOMAIN_TYPE, **types},
        "primaryType": primary_type,
        "domain": domain,
        "message": message,
    }


def _sign(account: Any, primary_type: str, types: Dict[str, Any], payload: Dict[str, Any], fields: List[str], kernel_address: str) -> str:
    domain = build_delivery_domain(payload["chainId"], kernel_address)
    message = _normalize(payload, fields)
    signable = encode_typed_data(full_message=_typed_data(primary_type, types, domain, message))
    sig = account.sign_message(signable).signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def _recover(payload: Dict[str, Any], signature: str, primary_type: str, types: Dict[str, Any], fields: List[str], kernel_address: str) -> str:
    _assert_signature_shape(signature)
    domain = build_delivery_domain(payload["chainId"], kernel_address)
    message = _normalize(payload, fields)
    signable = encode_typed_data(full_message=_typed_data(primary_type, types, domain, message))
    return Account.recover_message(signable, signature=signature)


def _assert_signature_shape(signature: str) -> None:
    if not isinstance(signature, str) or not signature.startswith("0x"):
        raise DeliveryEip712Error("INVALID_SIGNATURE", "signature must be a 0x-prefixed hex string")
    hex_len = len(signature) - 2
    if hex_len not in (128, 130):
        raise DeliveryEip712Error("INVALID_SIGNATURE", f"signature has unexpected length {hex_len} (expected 128 or 130)")


def sign_setup(account: Any, payload: Dict[str, Any], kernel_address: str) -> str:
    """EIP-712 sign a DeliverySetupSignedV1 payload with an eth_account account."""
    return _sign(account, "DeliverySetupSignedV1", DELIVERY_SETUP_TYPES_V1, payload, _SETUP_FIELDS, kernel_address)


def sign_envelope(account: Any, payload: Dict[str, Any], kernel_address: str) -> str:
    """EIP-712 sign a DeliveryEnvelopeSignedV1 payload with an eth_account account."""
    return _sign(account, "DeliveryEnvelopeSignedV1", DELIVERY_ENVELOPE_TYPES_V1, payload, _ENVELOPE_FIELDS, kernel_address)


def recover_setup_signer(payload: Dict[str, Any], signature: str, kernel_address: str) -> str:
    """Recover the EOA that signed a DeliverySetupSignedV1 payload (checksummed)."""
    return _recover(payload, signature, "DeliverySetupSignedV1", DELIVERY_SETUP_TYPES_V1, _SETUP_FIELDS, kernel_address)


def recover_envelope_signer(payload: Dict[str, Any], signature: str, kernel_address: str) -> str:
    """Recover the EOA that signed a DeliveryEnvelopeSignedV1 payload (checksummed)."""
    return _recover(payload, signature, "DeliveryEnvelopeSignedV1", DELIVERY_ENVELOPE_TYPES_V1, _ENVELOPE_FIELDS, kernel_address)


__all__ = [
    "DELIVERY_DOMAIN_NAME",
    "DELIVERY_DOMAIN_VERSION",
    "DELIVERY_SETUP_TYPES_V1",
    "DELIVERY_ENVELOPE_TYPES_V1",
    "DeliveryEip712Error",
    "chain_id_for_network",
    "build_delivery_domain",
    "sign_setup",
    "sign_envelope",
    "recover_setup_signer",
    "recover_envelope_signer",
]
