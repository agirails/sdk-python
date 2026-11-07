"""In-memory JSON-RPC boundary; real AsyncWeb3 ABI coding and local signing."""

from eth_abi import decode, encode
from hexbytes import HexBytes
import rlp
from web3 import Web3
from web3.providers import AsyncBaseProvider


def abi_type(item):
    if not item["type"].startswith("tuple"):
        return item["type"]
    return "(" + ",".join(abi_type(x) for x in item["components"]) + ")" + item["type"][5:]


class ContractRPC(AsyncBaseProvider):
    def __init__(self):
        super().__init__()
        self.nonce = 3
        self.block = 10
        self.methods = {}
        self.results = {}
        self.calls = []
        self.sent = []
        self.logs = []
        self.status = 1
        self.chain_id = 84532
        self.timestamp = 1700001000

    def register(self, abi):
        for item in abi:
            if item.get("type") == "function":
                signature = item["name"] + "(" + ",".join(abi_type(x) for x in item["inputs"]) + ")"
                self.methods[Web3.keccak(text=signature)[:4].hex()] = item

    def reply(self, name, *values):
        self.results[name] = values

    async def make_request(self, method, params):
        if method == "eth_chainId":
            result = hex(self.chain_id)
        elif method == "eth_getTransactionCount":
            result = hex(self.nonce)
        elif method == "eth_blockNumber":
            result = hex(self.block)
        elif method == "eth_getBlockByNumber":
            result = {"number": hex(self.block), "baseFeePerGas": hex(10**9), "timestamp": hex(self.timestamp)}
        elif method == "eth_gasPrice":
            result = hex(10**9)
        elif method == "eth_estimateGas":
            result = hex(50_000)
        elif method == "eth_call":
            call = params[0]
            data = HexBytes(call.get("data", call.get("input")))
            abi = self.methods[data[:4].hex()]
            arguments = decode([abi_type(x) for x in abi["inputs"]], data[4:])
            self.calls.append((abi["name"], arguments, call["to"]))
            result = Web3.to_hex(encode([abi_type(x) for x in abi["outputs"]], self.results[abi["name"]]))
        elif method == "eth_sendRawTransaction":
            raw = HexBytes(params[0])
            fields = rlp.decode(raw[1:]) if raw[0] == 2 else rlp.decode(raw)
            data = fields[7] if raw[0] == 2 else fields[5]
            abi = self.methods[data[:4].hex()]
            arguments = decode([abi_type(x) for x in abi["inputs"]], data[4:])
            self.sent.append((abi["name"], arguments, raw))
            self.nonce += 1
            result = Web3.to_hex(Web3.keccak(raw))
        elif method == "eth_getTransactionReceipt":
            result = {
                "transactionHash": params[0], "transactionIndex": "0x0",
                "blockHash": "0x" + "bb" * 32, "blockNumber": hex(self.block),
                "from": "0x" + "11" * 20, "to": "0x" + "22" * 20,
                "cumulativeGasUsed": "0xc350", "gasUsed": "0xc350",
                "contractAddress": None, "logs": self.logs, "status": hex(self.status),
                "effectiveGasPrice": hex(10**9), "type": "0x2",
            }
        else:
            raise AssertionError(f"Unexpected JSON-RPC method: {method}")
        return {"jsonrpc": "2.0", "id": 1, "result": result}
