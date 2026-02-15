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
# Helpers
# ============================================================================


def _to_hex(n: int) -> str:
    """Convert an integer to 0x-prefixed hex string."""
    return hex(n)
