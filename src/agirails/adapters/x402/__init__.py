"""
Native x402 v2 signing primitives (EIP-3009 / Permit2).

1:1 port of the @x402/evm exact-scheme client signing logic
(node_modules/@x402/evm/dist/cjs/exact/client/index.js) so a Python buyer
produces byte-identical EIP-712 signatures and X-PAYMENT headers as the
TypeScript SDK (@agirails/sdk@4.8.0).

Modules:
- eip3009: EIP-3009 ``transferWithAuthorization`` path (common case, EOA buyers)
- permit2: Permit2 ``PermitWitnessTransferFrom`` path (Smart Wallet buyers)

@module adapters/x402
"""

from __future__ import annotations

from agirails.adapters.x402.eip3009 import (
    AUTHORIZATION_TYPES,
    EIP3009Authorization,
    EIP3009Domain,
    build_eip3009_payload,
    chain_id_for_network,
    create_nonce,
    encode_x_payment_header,
    network_name_for_caip2,
    sign_eip3009_authorization,
)
from agirails.adapters.x402.permit2 import (
    PERMIT2_ADDRESS,
    PERMIT2_WITNESS_TYPES,
    X402_EXACT_PERMIT2_PROXY_ADDRESS,
    Permit2Authorization,
    build_permit2_payload,
    create_permit2_approval_tx,
    create_permit2_nonce,
    sign_permit2_authorization,
)

__all__ = [
    # EIP-3009
    "AUTHORIZATION_TYPES",
    "EIP3009Authorization",
    "EIP3009Domain",
    "build_eip3009_payload",
    "chain_id_for_network",
    "create_nonce",
    "encode_x_payment_header",
    "network_name_for_caip2",
    "sign_eip3009_authorization",
    # Permit2
    "PERMIT2_ADDRESS",
    "PERMIT2_WITNESS_TYPES",
    "X402_EXACT_PERMIT2_PROXY_ADDRESS",
    "Permit2Authorization",
    "build_permit2_payload",
    "create_permit2_approval_tx",
    "create_permit2_nonce",
    "sign_permit2_authorization",
]
