"""
UserOpBuilder -- Constructs ERC-4337 v0.6 UserOperations.

Builds UserOps for CoinbaseSmartWallet:
- Encodes executeBatch(Call[]) as callData
- Adds initCode for first-time wallet deployment
- Signs with owner's private key (raw ECDSA over UserOp hash)

Uses web3.py + eth_account + eth_abi for encoding.

This is a 1:1 port of sdk-js/src/wallet/aa/UserOpBuilder.ts.
"""

from __future__ import annotations

from typing import List, Dict

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from agirails.wallet.aa.constants import (
    ENTRYPOINT_V06,
    SMART_WALLET_FACTORY,
    DEFAULT_WALLET_NONCE,
    SmartWalletCall,
    UserOperationV06,
)

# ============================================================================
# ABI fragments (function selectors)
# ============================================================================

# CoinbaseSmartWallet.executeBatch((address,uint256,bytes)[])
# selector = keccak256("executeBatch((address,uint256,bytes)[])")[:4]
_EXECUTE_BATCH_SELECTOR = Web3.keccak(
    text="executeBatch((address,uint256,bytes)[])"
)[:4].hex()

# CoinbaseSmartWalletFactory.createAccount(bytes[],uint256)
_CREATE_ACCOUNT_SELECTOR = Web3.keccak(
    text="createAccount(bytes[],uint256)"
)[:4].hex()

# CoinbaseSmartWalletFactory.getAddress(bytes[],uint256)
_GET_ADDRESS_SELECTOR = Web3.keccak(
    text="getAddress(bytes[],uint256)"
)[:4].hex()


# ============================================================================
# Public API
# ============================================================================


async def compute_smart_wallet_address(
    signer_address: str,
    w3: Web3,
    nonce: int = DEFAULT_WALLET_NONCE,
) -> str:
    """Compute the counterfactual Smart Wallet address for a given signer.

    This address is deterministic (CREATE2) and can be computed off-chain
    without deploying the wallet.

    Args:
        signer_address: EOA address that owns the Smart Wallet.
        w3: Web3 instance connected to the target chain.
        nonce: Wallet nonce (default 0 for first wallet per owner).

    Returns:
        Checksummed Smart Wallet address.
    """
    factory_abi = [
        {
            "inputs": [
                {"name": "owners", "type": "bytes[]"},
                {"name": "nonce", "type": "uint256"},
            ],
            "name": "getAddress",
            "outputs": [{"name": "", "type": "address"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    factory = w3.eth.contract(
        address=Web3.to_checksum_address(SMART_WALLET_FACTORY),
        abi=factory_abi,
    )
    # CoinbaseSmartWallet encodes owners as bytes[] -- EOA address is abi.encode(address)
    owner_bytes = abi_encode(["address"], [Web3.to_checksum_address(signer_address)])
    result = factory.functions.getAddress([owner_bytes], nonce).call()
    return Web3.to_checksum_address(result)


def build_init_code(
    signer_address: str,
    nonce: int = DEFAULT_WALLET_NONCE,
) -> str:
    """Build initCode for first-time wallet deployment.

    initCode = factory address + createAccount calldata.
    When the wallet already exists, pass '0x' as initCode.

    Args:
        signer_address: EOA address that owns the Smart Wallet.
        nonce: Wallet nonce (default 0).

    Returns:
        Hex-encoded initCode string.
    """
    owner_bytes = abi_encode(["address"], [Web3.to_checksum_address(signer_address)])

    # Encode createAccount(bytes[] owners, uint256 nonce)
    # Dynamic array encoding: offset, length, element(s)
    calldata = abi_encode(
        ["bytes[]", "uint256"],
        [[owner_bytes], nonce],
    )

    # initCode = factory address (20 bytes) + selector + calldata
    factory_addr = SMART_WALLET_FACTORY.lower().replace("0x", "")
    return "0x" + factory_addr + _CREATE_ACCOUNT_SELECTOR + calldata.hex()


def encode_execute_batch(calls: List[SmartWalletCall]) -> str:
    """Encode executeBatch calldata from an array of calls.

    Args:
        calls: List of SmartWalletCall to batch.

    Returns:
        Hex-encoded calldata for executeBatch((address,uint256,bytes)[]).
    """
    # Encode the tuple array: (address target, uint256 value, bytes data)[]
    tuples = [
        (Web3.to_checksum_address(c.target), c.value, bytes.fromhex(c.data.replace("0x", "")))
        for c in calls
    ]

    encoded_params = abi_encode(
        ["(address,uint256,bytes)[]"],
        [tuples],
    )

    return "0x" + _EXECUTE_BATCH_SELECTOR + encoded_params.hex()


def build_user_op(
    sender: str,
    nonce: int,
    calls: List[SmartWalletCall],
    is_first_deploy: bool,
    signer_address: str,
) -> UserOperationV06:
    """Build a full UserOperation (unsigned).

    Gas limits and paymasterAndData must be filled by the caller
    (via BundlerClient.estimate_gas and PaymasterClient.sponsor).

    Args:
        sender: Smart Wallet address.
        nonce: EntryPoint nonce.
        calls: List of calls to batch.
        is_first_deploy: Whether this is the first UserOp (needs initCode).
        signer_address: EOA signer address (for initCode).

    Returns:
        Unsigned UserOperationV06 with placeholder gas values.
    """
    call_data = encode_execute_batch(calls)
    init_code = build_init_code(signer_address) if is_first_deploy else "0x"

    return UserOperationV06(
        sender=sender,
        nonce=nonce,
        init_code=init_code,
        call_data=call_data,
        call_gas_limit=0,
        verification_gas_limit=0,
        pre_verification_gas=0,
        max_fee_per_gas=0,
        max_priority_fee_per_gas=0,
        paymaster_and_data="0x",
        signature="0x",
    )


def get_user_op_hash(user_op: UserOperationV06, chain_id: int) -> str:
    """Compute the UserOperation hash for signing (v0.6).

    hash = keccak256(abi.encode(
        keccak256(pack(userOp)),
        entryPoint,
        chainId
    ))

    Args:
        user_op: The UserOperation to hash.
        chain_id: Chain ID (8453 for Base Mainnet, 84532 for Sepolia).

    Returns:
        Hex-encoded hash string (0x-prefixed).
    """
    # Pack all fields except signature
    packed = abi_encode(
        [
            "address",    # sender
            "uint256",    # nonce
            "bytes32",    # keccak256(initCode)
            "bytes32",    # keccak256(callData)
            "uint256",    # callGasLimit
            "uint256",    # verificationGasLimit
            "uint256",    # preVerificationGas
            "uint256",    # maxFeePerGas
            "uint256",    # maxPriorityFeePerGas
            "bytes32",    # keccak256(paymasterAndData)
        ],
        [
            Web3.to_checksum_address(user_op.sender),
            user_op.nonce,
            Web3.keccak(hexstr=user_op.init_code),
            Web3.keccak(hexstr=user_op.call_data),
            user_op.call_gas_limit,
            user_op.verification_gas_limit,
            user_op.pre_verification_gas,
            user_op.max_fee_per_gas,
            user_op.max_priority_fee_per_gas,
            Web3.keccak(hexstr=user_op.paymaster_and_data),
        ],
    )

    packed_hash = Web3.keccak(packed)

    final = abi_encode(
        ["bytes32", "address", "uint256"],
        [packed_hash, Web3.to_checksum_address(ENTRYPOINT_V06), chain_id],
    )

    return "0x" + Web3.keccak(final).hex()


def sign_user_op(
    user_op: UserOperationV06,
    private_key: str,
    chain_id: int,
) -> str:
    """Sign a UserOperation with the owner's private key.

    CoinbaseSmartWallet expects the signature to be:
        abi.encode(SignatureWrapper(0, abi.encodePacked(r,s,v)))

    where ownerIndex=0 for single-owner wallets.

    Uses raw ECDSA signing (no EIP-191 prefix) -- CoinbaseSmartWallet
    expects raw signature over the hash bytes.

    Args:
        user_op: The UserOperation to sign.
        private_key: Private key (0x-prefixed hex).
        chain_id: Chain ID.

    Returns:
        Hex-encoded signature in SignatureWrapper format.
    """
    op_hash = get_user_op_hash(user_op, chain_id)
    op_hash_bytes = bytes.fromhex(op_hash.replace("0x", ""))

    # Raw ECDSA sign (no EIP-191 prefix)
    account = Account.from_key(private_key)
    signed = account.unsafe_sign_hash(op_hash_bytes)

    # Pack r + s + v as raw 65 bytes
    r_bytes = signed.r.to_bytes(32, "big")
    s_bytes = signed.s.to_bytes(32, "big")
    v_byte = signed.v.to_bytes(1, "big")
    raw_sig = r_bytes + s_bytes + v_byte

    # CoinbaseSmartWallet SignatureWrapper: abi.encode(uint256 ownerIndex, bytes signatureData)
    wrapper = abi_encode(
        ["uint256", "bytes"],
        [0, raw_sig],
    )

    return "0x" + wrapper.hex()


def serialize_user_op(user_op: UserOperationV06) -> Dict[str, str]:
    """Serialize UserOp for JSON-RPC (bundler API).

    Converts ints to hex strings.

    Args:
        user_op: The UserOperation to serialize.

    Returns:
        Dict with all fields as hex strings.
    """
    return {
        "sender": user_op.sender,
        "nonce": _to_hex(user_op.nonce),
        "initCode": user_op.init_code,
        "callData": user_op.call_data,
        "callGasLimit": _to_hex(user_op.call_gas_limit),
        "verificationGasLimit": _to_hex(user_op.verification_gas_limit),
        "preVerificationGas": _to_hex(user_op.pre_verification_gas),
        "maxFeePerGas": _to_hex(user_op.max_fee_per_gas),
        "maxPriorityFeePerGas": _to_hex(user_op.max_priority_fee_per_gas),
        "paymasterAndData": user_op.paymaster_and_data,
        "signature": user_op.signature,
    }


def dummy_signature() -> str:
    """Generate a dummy signature for gas estimation.

    CoinbaseSmartWallet expects abi.encode(uint256 ownerIndex, bytes sig)
    where sig is 65 bytes (r,s,v).

    Returns:
        Hex-encoded dummy signature in SignatureWrapper format.
    """
    dummy_sig = b"\xff" * 65
    wrapper = abi_encode(
        ["uint256", "bytes"],
        [0, dummy_sig],
    )
    return "0x" + wrapper.hex()


# ============================================================================
# CoinbaseSmartWallet SignatureWrapper + ERC-1271/ERC-6492 (x402 v2 path)
# ============================================================================
#
# 1:1 port of viem's `wrapSignature` / `toReplaySafeTypedData` /
# `serializeErc6492Signature` (sdk-js/node_modules/viem/account-abstraction/
# accounts/implementations/toCoinbaseSmartAccount.ts:330-443 and
# utils/signature/serializeErc6492Signature.ts). The TS AutoWalletProvider
# (AutoWalletProvider.ts:211-358) delegates to viem's `toCoinbaseSmartAccount`
# for these — this is the byte-exact Python equivalent so a Smart-Wallet
# (Tier-1) buyer produces an ERC-1271 / ERC-6492-valid x402 signature instead
# of a raw owner EOA sig.

# ERC-6492 magic suffix (viem constants/bytes.ts: erc6492MagicBytes).
ERC6492_MAGIC_BYTES = bytes.fromhex(
    "6492649264926492649264926492649264926492649264926492649264926492"
)


def wrap_signature(owner_index: int, signature: bytes) -> str:
    """CoinbaseSmartWallet ``SignatureWrapper(ownerIndex, signatureData)``.

    1:1 with viem ``wrapSignature`` (toCoinbaseSmartAccount.ts:407-443):
      * If ``signature`` is exactly 65 bytes (r,s,v), it is re-packed as
        ``encodePacked(bytes32 r, bytes32 s, uint8 v)`` with ``v`` normalized
        to 27/28 (``yParity === 0 ? 27 : 28``).
      * Otherwise ``signature`` is used verbatim (e.g. WebAuthn — not used here).
    Then ABI-encoded as a single ``(uint8 ownerIndex, bytes signatureData)``
    tuple.

    ``abi_encode(["(uint8,bytes)"], ...)`` is byte-identical to viem's
    ``encodeAbiParameters`` of the same tuple, and (for ownerIndex=0) also
    byte-identical to the ``(uint256,bytes)`` SignatureWrapper used in
    ``sign_user_op`` — a uint8 0 and uint256 0 both occupy one zero word.

    Args:
        owner_index: Index of the owner in the Smart Wallet owner set (0).
        signature: Raw signature bytes (65 for ECDSA r,s,v).

    Returns:
        0x-prefixed hex SignatureWrapper.
    """
    if len(signature) == 65:
        r = signature[0:32]
        s = signature[32:64]
        v = signature[64]
        # viem parseSignature: 27 -> yParity 0, 28 -> yParity 1; 0/1 stay as-is.
        # eth_account / unsafe_sign_hash already returns v in {27, 28}.
        if v in (0, 27):
            packed_v = 27
        elif v in (1, 28):
            packed_v = 28
        else:
            raise ValueError(f"Invalid signature v value: {v}")
        signature_data = r + s + bytes([packed_v])
    else:
        signature_data = signature

    wrapped = abi_encode(["(uint8,bytes)"], [(owner_index, signature_data)])
    return "0x" + wrapped.hex()


def build_replay_safe_typed_data(
    smart_wallet_address: str,
    chain_id: int,
    inner_hash: bytes,
) -> Dict[str, object]:
    """Build the CoinbaseSmartWallet replay-safe ``full_message`` typed data.

    1:1 with viem ``toReplaySafeTypedData`` (toCoinbaseSmartAccount.ts:330-359):
    a single-field ``CoinbaseSmartWalletMessage(bytes32 hash)`` struct under a
    domain of ``{name: "Coinbase Smart Wallet", version: "1", chainId,
    verifyingContract: smartWallet}``. ``inner_hash`` is the EIP-712 hash of the
    payload the caller actually wants signed (e.g. the Permit2 witness).

    The returned dict is an ``eth_account`` ``encode_typed_data(full_message=...)``
    shape (domain + types + primaryType + message). ``EIP712Domain`` is omitted;
    ``encode_typed_data`` derives it from the domain keys, matching viem.

    Args:
        smart_wallet_address: The Smart Wallet (verifyingContract).
        chain_id: Chain ID.
        inner_hash: 32-byte EIP-712 hash of the inner payload.

    Returns:
        ``full_message`` dict for ``encode_typed_data``.
    """
    return {
        "domain": {
            "name": "Coinbase Smart Wallet",
            "version": "1",
            "chainId": chain_id,
            "verifyingContract": Web3.to_checksum_address(smart_wallet_address),
        },
        "types": {
            "CoinbaseSmartWalletMessage": [{"name": "hash", "type": "bytes32"}],
        },
        "primaryType": "CoinbaseSmartWalletMessage",
        "message": {"hash": inner_hash},
    }


def build_create_account_factory_data(
    signer_address: str,
    nonce: int = DEFAULT_WALLET_NONCE,
) -> bytes:
    """ABI-encode ``createAccount(bytes[] owners, uint256 nonce)`` calldata.

    Mirrors viem ``getFactoryArgs`` (toCoinbaseSmartAccount.ts:170-177) =
    ``encodeFunctionData(createAccount, [owners_bytes, nonce])`` where
    ``owners_bytes = [pad(owner.address)]`` (the owner address left-padded to
    32 bytes — identical to ``abi_encode(["address"], [addr])``). This is the
    ``factoryData`` portion of the ERC-6492 envelope. Equivalent in bytes to
    ``build_init_code`` minus the leading factory address.

    Returns:
        Raw calldata bytes (selector + ABI-encoded args).
    """
    owner_bytes = abi_encode(["address"], [Web3.to_checksum_address(signer_address)])
    calldata = abi_encode(["bytes[]", "uint256"], [[owner_bytes], nonce])
    return bytes.fromhex(_CREATE_ACCOUNT_SELECTOR) + calldata


def serialize_erc6492_signature(
    factory_address: str,
    factory_data: bytes,
    signature: str,
) -> str:
    """Wrap a signature in an ERC-6492 envelope for counterfactual verification.

    1:1 with viem ``serializeErc6492Signature``
    (utils/signature/serializeErc6492Signature.ts):
    ``abi.encode(address factory, bytes factoryData, bytes signature)`` followed
    by the 32-byte ERC-6492 magic suffix. Lets a facilitator deploy the Smart
    Wallet via simulation and validate the signature before the first UserOp.

    Args:
        factory_address: Account factory address (SMART_WALLET_FACTORY).
        factory_data: ``createAccount`` calldata (build_create_account_factory_data).
        signature: 0x-prefixed inner signature (the SignatureWrapper).

    Returns:
        0x-prefixed ERC-6492 signature.
    """
    sig_bytes = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
    encoded = abi_encode(
        ["address", "bytes", "bytes"],
        [Web3.to_checksum_address(factory_address), factory_data, sig_bytes],
    )
    return "0x" + (encoded + ERC6492_MAGIC_BYTES).hex()


# ============================================================================
# Helpers
# ============================================================================


def _to_hex(n: int) -> str:
    """Convert an integer to 0x-prefixed hex string."""
    return hex(n)
