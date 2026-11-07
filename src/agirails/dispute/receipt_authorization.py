"""Explicit quote-bound paid-receipt authorization and unverified HTTP transport."""
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol
import asyncio
import re
from urllib.parse import urlparse
import httpx
from web3 import Web3


@dataclass(frozen=True)
class ReceiptAuthorizationInput:
    chain_id: int
    verifying_contract: str
    quote_hash: str
    dispute_nonce: str
    tx_hash: str
    payer: str


class ReceiptAuthorizer(Protocol):
    def get_address(self) -> str: ...
    def sign_typed_data(self, data: Dict[str, Any]) -> str: ...


def receipt_authorization_typed_data(value: ReceiptAuthorizationInput) -> Dict[str, Any]:
    if isinstance(value.chain_id, bool) or not isinstance(value.chain_id, int) or not 0 < value.chain_id <= 9007199254740991:
        raise ValueError("Invalid receipt authorization chain_id")
    if not all(re.fullmatch(r"0x[0-9a-fA-F]{64}", item) for item in [value.quote_hash, value.tx_hash]):
        raise ValueError("Invalid receipt authorization hash")
    if not value.dispute_nonce or len(value.dispute_nonce) > 1024:
        raise ValueError("Invalid receipt authorization nonce")
    return {
        "domain": {"name": "AGIRAILS Evaluator Receipt", "version": "1", "chainId": value.chain_id,
                   "verifyingContract": Web3.to_checksum_address(value.verifying_contract)},
        "primaryType": "ReceiptAuthorization",
        "types": {"ReceiptAuthorization": [
            {"name": "quoteHash", "type": "bytes32"}, {"name": "disputeNonce", "type": "string"},
            {"name": "txHash", "type": "bytes32"}, {"name": "payer", "type": "address"}]},
        "message": {"quoteHash": value.quote_hash, "disputeNonce": value.dispute_nonce,
                    "txHash": value.tx_hash, "payer": Web3.to_checksum_address(value.payer)},
    }


async def authorize_payment_receipt(receipt: Dict[str, Any], value: ReceiptAuthorizationInput, signer: ReceiptAuthorizer) -> Dict[str, Any]:
    if Web3.to_checksum_address(signer.get_address()) != Web3.to_checksum_address(value.payer):
        raise ValueError("Receipt authorizer is not payer")
    if receipt["txHash"].lower() != value.tx_hash.lower():
        raise ValueError("Receipt authorization tx_hash mismatch")
    signature = await asyncio.to_thread(signer.sign_typed_data, receipt_authorization_typed_data(value))
    if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", signature):
        raise ValueError("Invalid receipt authorization signature")
    if signature.lower().endswith("6492" * 16):
        raise ValueError("Counterfactual ERC-6492 receipt signatures unsupported; deploy wallet first")
    return {**receipt, "authorization": {"version": "1", "signature": signature}}


async def post_paid_evaluation(base_url: str, body: Dict[str, Any], client: Optional[httpx.AsyncClient] = None) -> httpx.Response:
    """Explicit receipt POST only; result and v2 ruling signatures are unverified."""
    url = urlparse(base_url)
    if url.scheme != "https" and not (url.scheme == "http" and url.hostname in ["127.0.0.1", "::1", "localhost"]):
        raise ValueError("Paid evaluation requires HTTPS or loopback")
    if client is not None:
        return await client.post(base_url.rstrip("/") + "/evaluate", json=body, follow_redirects=False)
    async with httpx.AsyncClient(timeout=12, trust_env=False) as owned:
        return await owned.post(base_url.rstrip("/") + "/evaluate", json=body, follow_redirects=False)


def _validate_quote_transport(quote: Dict[str, Any], chain_id: int) -> None:
    from agirails.dispute.evaluator_client import EvaluateResponseError
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise EvaluateResponseError("Invalid dispute chain_id")
    x402 = quote.get("x402") or {}
    if not isinstance(x402, dict):
        raise ValueError("Invalid x402 quote")
    if "receiptAuthorization" in x402:
        raise EvaluateResponseError("Server requires signed paid receipts; use explicit receipt transport before payment")
    economics = quote.get("quote") or {}
    if not isinstance(economics, dict):
        raise EvaluateResponseError("Invalid quote economics")
    for value in [economics.get("chainId"), x402.get("chainId")]:
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value != chain_id):
            raise EvaluateResponseError("Quote chainId conflicts with dispute chain_id")
    network = x402.get("network")
    aliases = {"base-mainnet": 8453, "base-sepolia": 84532}
    if network is not None and (not isinstance(network, str) or not network or
            (network in aliases and aliases[network] != chain_id) or
            (network not in aliases and network != "base" and not network.startswith("eip155:"))):
        raise EvaluateResponseError("Quote network conflicts with dispute chain_id")
    if isinstance(network, str) and network.startswith("eip155:") and network != f"eip155:{chain_id}":
        raise EvaluateResponseError("Quote network conflicts with dispute chain_id")
