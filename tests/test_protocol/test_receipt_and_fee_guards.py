import pytest
from unittest.mock import MagicMock, AsyncMock
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_abi import encode
from agirails.protocol.kernel import ACTPKernel
from agirails.protocol.kernel_creation import encode_kernel_creation, LEGACY_KERNEL
from agirails.dispute.composite_mediator import decode_resolution_proof
from agirails.reputation.dispute_split_indexer import DisputeOutcome, DisputeSplitIndexer
from agirails.dispute.receipt_authorization import ReceiptAuthorizationInput, receipt_authorization_typed_data, authorize_payment_receipt


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['Tx missing', 'Vault not approved'])
async def test_retry_estimation_revert_never_signs_or_broadcasts(reason):
    fn = MagicMock(estimate_gas=AsyncMock(side_effect=Exception(reason)))
    contract = MagicMock(); contract.functions.retryPlatformFee.return_value = fn
    account = MagicMock(); account.address = '0x' + '11' * 20
    w3 = MagicMock(); w3.eth.send_raw_transaction = AsyncMock()
    kernel = ACTPKernel(contract, account, w3, 31337)
    with pytest.raises(Exception, match=reason):
        await kernel.retry_platform_fee('0x' + '99' * 32)
    account.sign_transaction.assert_not_called()
    w3.eth.send_raw_transaction.assert_not_awaited()
    fn.build_transaction.assert_not_called()


def test_fee_only_debt_principal_snapshot_suppresses_sentinel():
    proof = '0x' + encode(['uint256', 'uint256', 'bool'], [1, 0, True]).hex()
    result = decode_resolution_proof(proof, 0)
    assert result.phantom_sentinel and result.requester_amount == result.provider_amount == 0
    outcome = DisputeOutcome(provider='p', requester='r', kind='settled', remaining=50000, escrow_principal=0, proof=proof)
    assert DisputeSplitIndexer().classify_payout(outcome).phantom_sentinel
    assert decode_resolution_proof(proof, remaining=50000, escrow_principal=0).phantom_sentinel
    assert decode_resolution_proof(proof, remaining=50000).requester_amount == 1


def test_legacy_creation_encoding_keeps_agent_ids_and_rejects_lost_binding():
    args = ['0x' + '11' * 20, '0x' + '22' * 20, 100000, 999999, 3600, bytes(32), bytes(32), 42, 43]
    old = encode_kernel_creation(LEGACY_KERNEL, args, bytes(32))
    new = encode_kernel_creation('0x' + '33' * 20, args, bytes(32))
    assert len(bytes.fromhex(old[2:])) == 4 + 8 * 32
    assert len(bytes.fromhex(new[2:])) == 4 + 9 * 32
    assert old[:10] != new[:10]
    assert old[-128:] == new[-128:]
    with pytest.raises(ValueError, match='refusing to discard'):
        encode_kernel_creation(LEGACY_KERNEL, args, bytes([1]) * 32)


@pytest.mark.asyncio
async def test_authorize_paid_receipt_has_recoverable_domain_bound_signature():
    account = Account.from_key(bytes([1]) * 32)
    value = ReceiptAuthorizationInput(84532, '0x' + '33' * 20, '0x' + '44' * 32, 'dn_non_bytes32', '0x' + '55' * 32, account.address)
    class Signer:
        def get_address(self): return account.address
        def sign_typed_data(self, data): return '0x' + account.sign_message(encode_typed_data(full_message=data)).signature.hex()
    receipt = await authorize_payment_receipt({'scheme': 'exact', 'network': 'eip155:84532', 'txHash': value.tx_hash, 'payload': '{}'}, value, Signer())
    import json
    from pathlib import Path
    from web3 import Web3
    vector = json.loads((Path(__file__).resolve().parents[2] / 'test-vectors/dispute/receipt-authorization-v1.json').read_text())
    signed = account.sign_message(encode_typed_data(full_message=receipt_authorization_typed_data(value)))
    assert Web3.to_hex(signed.message_hash) == vector['digest']
    assert receipt['authorization']['signature'] == vector['signature']
    assert Account.recover_message(encode_typed_data(full_message=receipt_authorization_typed_data(value)), signature=receipt['authorization']['signature']) == account.address


def test_python_legacy_client_capability_and_chain_guards():
    from agirails.dispute.receipt_authorization import _validate_quote_transport
    from agirails.dispute.evaluator_client import EvaluateResponseError
    with pytest.raises(EvaluateResponseError, match='signed paid receipts'):
        _validate_quote_transport({'x402': {'receiptAuthorization': {'version': '1'}}}, 84532)
    for quote in [{'quote': {'chainId': 8453}}, {'x402': {'chainId': 8453}}, {'x402': {'network': 'eip155:8453'}}]:
        with pytest.raises(EvaluateResponseError, match='conflicts'):
            _validate_quote_transport(quote, 84532)
    _validate_quote_transport({'quote': {'chainId': 84532}, 'x402': {'network': 'base'}}, 84532)
