"""Actual-adapter regression tests for accepted evaluator payment terms."""
from __future__ import annotations

import asyncio
import base64
import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from agirails.adapters.x402_adapter import X402Adapter, X402AdapterConfig, X402PayParams, LegacyX402AdapterConfig
from agirails.dispute.evaluator_client import EvaluatorClient, EvaluatorClientConfig
from tests.test_adapters.test_x402_v2_adapter import MockWalletProvider, _requirements, _resp, _payment_response_header, SIGNER_ADDR, USDC_SEPOLIA
from tests.test_dispute.test_evaluator_client import _base_params, _make_quote_fetch, EXAMPLE_A_HASH

NONCE = 'opaque-evaluator-quote'
PAY_TO = '0x90F79bf6EB2c4f870365E785982E1f101E93b906'


class Wallet(MockWalletProvider):
    def __init__(self, tier='eoa'):
        super().__init__(tier)
        self.signatures = []

    def get_wallet_info(self):
        info = super().get_wallet_info()
        info.chain_id = 84532
        return info

    def sign_typed_data(self, typed):
        self.signatures.append(copy.deepcopy(typed))
        return super().sign_typed_data(typed)


def terms(**updates):
    return dict(amount='10000', asset=USDC_SEPOLIA, pay_to=PAY_TO, network='eip155:84532', nonce=NONCE, **updates)


def params(quote=None, path='paid'):
    return X402PayParams(to='https://evaluator.test/' + path, method='POST', body=json.dumps({'disputeNonce': NONCE}), metadata={'payment_method': 'x402'}) if quote is None else SimpleNamespace(to='https://evaluator.test/' + path, method='POST', body=json.dumps({'disputeNonce': NONCE}), headers={}, content_type=None, metadata={'payment_method': 'x402'}, accepted_quote=quote)


def completed():
    return _resp(200, json_body={'outcome': 'proposeDirectly', 'bundleHash': EXAMPLE_A_HASH, 'recommendation': {'ruling': 1, 'splitBps': 0, 'confidence': 8000, 'rationale': 'local fixture'}}, headers={'payment-response': _payment_response_header()})


def adapter_for(offers, tier='eoa'):
    wallet = Wallet(tier)
    calls = []
    async def fetch(url='', **kwargs):
        calls.append(kwargs)
        return completed() if kwargs['headers'].get('X-PAYMENT') else _resp(402, json_body={'x402Version': 2, 'accepts': offers})
    return X402Adapter(wallet.get_address(), X402AdapterConfig(wallet_provider=wallet, fetch_fn=fetch)), wallet, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('tier', ['eoa', 'auto'])
@pytest.mark.parametrize('change', [
    {'network': 'eip155:8453', 'asset': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'},
    {'amount': '9000'}, {'asset': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'},
    {'payTo': '0x' + '33' * 20}, {'disputeNonce': 'other'},
    {'extra': {'name': 'USDC', 'version': '2', 'commit': {'disputeNonce': 'other'}}},
])
async def test_rebound_offer_rejected_before_signing_or_approval(change, tier):
    offer = _requirements(); offer.update(change)
    adapter, wallet, calls = adapter_for([offer], tier)
    p = params(); p.accepted_quote = terms()
    with pytest.raises(Exception) as caught:
        await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert wallet.signatures == [] and wallet.sent == []
    assert len(calls) == 1 and 'X-PAYMENT' not in calls[0]['headers']


@pytest.mark.asyncio
@pytest.mark.parametrize('tier', ['eoa', 'auto'])
async def test_matching_quote_preserves_post_and_random_payment_nonce(tier):
    offer = _requirements(permit2=tier == 'auto')
    offer['extra']['commit'] = {'disputeNonce': NONCE}
    adapter, wallet, calls = adapter_for([offer], tier)
    p = params(); p.accepted_quote = terms()
    assert (await adapter.pay(p)).success
    assert len(wallet.signatures) == 1 and len(wallet.sent) == (1 if tier == 'auto' else 0)
    for call in calls:
        assert call['method'] == 'POST' and json.loads(call['content'])['disputeNonce'] == NONCE
    payload = json.loads(base64.b64decode(calls[1]['headers']['X-PAYMENT']))['payload']
    auth = payload['permit2Authorization' if tier == 'auto' else 'authorization']
    assert auth['nonce'] != NONCE
    assert str(auth['nonce']).isdigit() if tier == 'auto' else len(auth['nonce']) == 66


@pytest.mark.asyncio
async def test_mixed_offers_choose_matching_terms_and_address_case():
    offers = [_requirements(amount='9000'), _requirements()]
    adapter, wallet, _ = adapter_for(offers)
    p = params(); p.accepted_quote = {**terms(), 'amount': '010000', 'asset': USDC_SEPOLIA.upper().replace('0X', '0x')}
    assert (await adapter.pay(p)).success
    assert int(wallet.signatures[0]['message']['value']) == 10000


@pytest.mark.asyncio
async def test_quote_and_params_mutation_during_fetch_cannot_rebind_payment():
    quote = terms(); p = params(); p.accepted_quote = quote
    adapter, wallet, calls = adapter_for([])
    async def fetch(url='', **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            quote['network'] = 'eip155:8453'; p.accepted_quote = None
            return _resp(402, json_body={'accepts': [_requirements(network='eip155:8453', asset='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913')]})
        return completed()
    adapter._config.fetch_fn = fetch
    with pytest.raises(Exception) as caught:
        await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert not wallet.signatures and len(calls) == 1


@pytest.mark.asyncio
async def test_overlapping_unquoted_pay_cannot_clear_another_calls_quote():
    entered, release = asyncio.Event(), asyncio.Event()
    adapter, wallet, calls = adapter_for([])
    async def fetch(url='', **kwargs):
        calls.append(kwargs)
        if kwargs['headers'].get('X-PAYMENT'): return completed()
        if url.endswith('/quoted'):
            entered.set(); await release.wait()
        return _resp(402, json_body={'accepts': [_requirements(amount='9000')]})
    adapter._config.fetch_fn = fetch
    p = params(path='quoted'); p.accepted_quote = terms()
    quoted = asyncio.create_task(adapter.pay(p)); await entered.wait()
    assert (await adapter.pay(params(path='unquoted'))).success
    release.set()
    with pytest.raises(Exception) as caught: await quoted
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert len(wallet.signatures) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [('amount', ''), ('amount', '-1'), ('amount', 'nan'), ('network', None), ('pay_to', 42)])
async def test_malformed_defined_binding_fails_before_http(field, value):
    adapter, wallet, calls = adapter_for([_requirements()])
    p = params(); p.accepted_quote = {**terms(), field: value}
    with pytest.raises(Exception) as caught: await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert not calls and not wallet.signatures and not wallet.sent


@pytest.mark.asyncio
async def test_request_nonce_conflict_fails_before_http():
    adapter, wallet, calls = adapter_for([_requirements()])
    p = params(); p.body = json.dumps({'disputeNonce': 'other'}); p.accepted_quote = terms()
    with pytest.raises(Exception) as caught: await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert not calls and not wallet.signatures


@pytest.mark.asyncio
async def test_quoted_legacy_adapter_fails_before_transfer_or_http():
    calls = []
    async def transfer(*args): calls.append(args); return '0x' + 'aa' * 32
    adapter = X402Adapter(SIGNER_ADDR, LegacyX402AdapterConfig(expected_network='base-sepolia', transfer_fn=transfer))
    from unittest.mock import AsyncMock
    adapter._make_request = AsyncMock()
    p = params(); p.accepted_quote = terms()
    with pytest.raises(Exception) as caught: await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    adapter._make_request.assert_not_awaited()
    assert not calls


@pytest.mark.asyncio
@pytest.mark.parametrize('rebound', [True, False])
async def test_public_evaluator_uses_actual_adapter_with_chain_pin_and_post(rebound):
    quote = {'disputeNonce': NONCE, 'quote': {'chainId': 84532, 'amount': '10000', 'asset': USDC_SEPOLIA}, 'x402': {'network': 'base', 'chainId': 84532, 'payTo': PAY_TO}}
    fetch_quote, _ = _make_quote_fetch(quote)
    offer = _requirements(network='eip155:8453', asset='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913') if rebound else _requirements()
    adapter, wallet, calls = adapter_for([offer])
    client = EvaluatorClient(EvaluatorClientConfig(base_url='https://evaluator.test', payment_client=adapter, fetch_impl=fetch_quote))
    request = replace(_base_params(), chain_id=84532, payer=SIGNER_ADDR)
    if rebound:
        with pytest.raises(Exception) as caught: await client.request_evaluation(request)
        assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
        assert not wallet.signatures and len(calls) == 1
    else:
        assert (await client.request_evaluation(request)).outcome == 'proposeDirectly'
        assert len(wallet.signatures) == 1
    assert calls[0]['method'] == 'POST' and json.loads(calls[0]['content'])['disputeNonce'] == NONCE


@pytest.mark.asyncio
@pytest.mark.parametrize('bad', [
    {'quote': {'amount': '10000'}, 'x402': {'amount': '20000'}},
    {'quote': {'asset': USDC_SEPOLIA}, 'x402': {'asset': '0x' + '22' * 20}},
    {'x402': {'payTo': PAY_TO, 'recipient': '0x' + '22' * 20}},
    {'x402': {'commit': {'disputeNonce': 'other'}}},
    {'x402': {'network': 'base-mainnet'}},
    {'quote': {'amount': True}}, {'quote': {'amount': '-1'}},
    {'quote': {'asset': 'invalid'}}, {'quote': []},
])
async def test_public_client_rejects_conflicting_or_invalid_quote_before_payment(bad):
    quote = {'disputeNonce': NONCE, **bad}
    fetch_quote, _ = _make_quote_fetch(quote)
    adapter, wallet, calls = adapter_for([_requirements()])
    client = EvaluatorClient(EvaluatorClientConfig(base_url='https://evaluator.test', payment_client=adapter, fetch_impl=fetch_quote))
    with pytest.raises(Exception):
        await client.request_evaluation(replace(_base_params(), chain_id=84532, payer=SIGNER_ADDR))
    assert not calls and not wallet.signatures and not wallet.sent


@pytest.mark.asyncio
async def test_unified_http_fields_and_quote_nonce_reach_native_adapter():
    from agirails.adapters.types import UnifiedPayParams
    p = UnifiedPayParams(to='https://evaluator.test/evaluate', http_method='POST', http_body=json.dumps({'disputeNonce': NONCE}).encode(), http_headers={'X-Context': 'preserved'}, metadata={'payment_method': 'x402'}, accepted_quote=terms())
    adapter, wallet, calls = adapter_for([_requirements()])
    assert (await adapter.pay(p)).success
    assert calls[0]['method'] == 'POST' and calls[0]['headers']['X-Context'] == 'preserved'
    assert json.loads(calls[0]['content'])['disputeNonce'] == NONCE
    assert len(wallet.signatures) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('chain_id', [8453, None, True, '84532'])
async def test_quoted_wallet_chain_must_match_before_side_effects(chain_id):
    adapter, wallet, calls = adapter_for([_requirements(permit2=True)], 'auto')
    wallet.get_wallet_info = lambda: SimpleNamespace(tier='auto', chain_id=chain_id)
    p = params(); p.accepted_quote = terms()
    with pytest.raises(Exception) as caught: await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert not calls and not wallet.sent and not wallet.signatures


@pytest.mark.asyncio
async def test_wallet_chain_change_during_fetch_is_rechecked_before_approval():
    adapter, wallet, calls = adapter_for([_requirements(permit2=True)], 'auto')
    chain = [84532]
    wallet.get_wallet_info = lambda: SimpleNamespace(tier='auto', chain_id=chain[0])
    fetch = adapter._config.fetch_fn
    async def changing_fetch(*args, **kwargs):
        result = await fetch(*args, **kwargs)
        chain[0] = 8453
        return result
    adapter._config.fetch_fn = changing_fetch
    p = params(); p.accepted_quote = terms()
    with pytest.raises(Exception) as caught: await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert len(calls) == 1 and not wallet.sent and not wallet.signatures


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['GET', 'DELETE'])
@pytest.mark.parametrize('native', [True, False])
async def test_nonce_binding_requires_body_that_is_actually_sent(method, native):
    from agirails.adapters.types import UnifiedPayParams
    adapter, wallet, calls = adapter_for([_requirements()])
    if native:
        p = params(); p.method = method; p.accepted_quote = terms()
    else:
        p = UnifiedPayParams(to='https://evaluator.test/evaluate', http_method=method,
                             http_body=json.dumps({'disputeNonce': NONCE}),
                             metadata={'payment_method': 'x402'}, accepted_quote=terms())
    with pytest.raises(Exception) as caught:
        await adapter.pay(p)
    assert getattr(caught.value, 'code', None) == 'X402_QUOTE_MISMATCH'
    assert not calls and not wallet.signatures and not wallet.sent
