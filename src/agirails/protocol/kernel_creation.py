"""Creation ABI selection for the locally pinned legacy deployment descriptor."""
from typing import Any, List
from eth_abi import encode
from web3 import Web3

LEGACY_KERNEL = "0x048c811352e8a3fecd5b0ec4aa2c2b94083cc842"
CREATE_TYPES = ["address", "address", "uint256", "uint256", "uint256", "bytes32", "bytes32", "uint256", "uint256"]


def is_legacy_creation_kernel(address: Any) -> bool:
    return isinstance(address, str) and address.lower() == LEGACY_KERNEL


def kernel_creation_arguments(address: str, args: List[Any], agreement_hash: bytes) -> List[Any]:
    if len(args) != 9:
        raise ValueError("Expected canonical nine creation arguments")
    if not is_legacy_creation_kernel(address):
        return args
    if agreement_hash != bytes(32):
        raise ValueError("Legacy kernel does not support agreement_hash; refusing to discard binding")
    return args[:6] + args[7:]


def encode_kernel_creation(address: str, args: List[Any], agreement_hash: bytes) -> str:
    values = kernel_creation_arguments(address, args, agreement_hash)
    types = CREATE_TYPES[:6] + CREATE_TYPES[7:] if is_legacy_creation_kernel(address) else CREATE_TYPES
    signature = "createTransaction(" + ",".join(types) + ")"
    return Web3.to_hex(Web3.keccak(text=signature)[:4] + encode(types, values))


def kernel_creation_abi(address: str, abi: List[Any]) -> List[Any]:
    if not is_legacy_creation_kernel(address):
        return abi
    result = []
    for item in abi:
        if item.get("name") == "createTransaction":
            result.append({**item, "inputs": [field for field in item["inputs"] if field["name"] != "agreementHash"]})
        elif item.get("name") == "TransactionCreated":
            result.append({**item, "inputs": [field for field in item["inputs"] if field["name"] != "agreementHash"]})
        else:
            result.append(item)
    return result
