"""Real signatures, resolver cache lifetimes, and terminal output contracts."""
import asyncio
import json
from io import StringIO

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
import pytest
from rich.console import Console

from agirails.protocol.did import DIDManager, DIDResolver, VerificationMethod, ServiceEndpoint
from agirails.cli.utils import output
from agirails.utils.semaphore import Semaphore, RateLimiter

KEY = '0x' + '13' * 32

@pytest.mark.parametrize('network,chain', [('base-sepolia','84532'), ('local','31337'), ('mock','0'), ('unknown','0')])
def test_did_document_and_real_owner_signature(network, chain):
    manager = DIDManager(KEY, network=network)
    did = str(manager.did)
    message = 'prove ownership without authorizing payment'
    signature = manager.sign_for_did(message)
    assert Account.recover_message(encode_defunct(text=message), signature=signature) == manager.address
    assert manager.verify_did_ownership(did, signature, message)
    assert not manager.verify_did_ownership(did, signature, message + '!')
    assert not manager.verify_did_ownership(did.replace(manager.address, '0x' + '22'*20), signature, message)
    assert not manager.verify_did_ownership('invalid', signature, message)
    assert not manager.verify_did_ownership(did, '0xzz', message)
    doc = manager.create_did_document(endpoint='https://example.invalid', service_types=['echo'], metadata={'version':1})
    method = doc.verification_method[0]
    assert method['blockchainAccountId'] == f'eip155:{chain}:{manager.did.identifier}'
    assert method['publicKeyHex'] == keys.PrivateKey(bytes.fromhex(KEY[2:])).public_key.to_hex()
    assert doc.service[1]['serviceEndpoint'] == 'https://example.invalid/services/echo'
    assert doc.metadata == {'version':1}
    assert manager.create_did_document(service_types=['echo']).service[0]['serviceEndpoint'] == ''

@pytest.mark.asyncio
@pytest.mark.parametrize('method,network,identifier', [('agirails','base-sepolia','0x'+'ab'*20), ('eth','mainnet','0x'+'cd'*20), ('key','local','zPublicKey')])
async def test_resolver_cache_bypass_and_expiry(method, network, identifier, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr('agirails.protocol.did.time.time', lambda: now[0])
    resolver = DIDResolver(cache_ttl=10)
    manager = DIDManager(resolver=resolver)
    assert manager.resolver is resolver
    did = f'did:{method}:{network}:{identifier}'
    first = await manager.resolve(did)
    assert first is not None and first.authentication == [f'{did}#key-1']
    assert await resolver.resolve(did) is first
    bypass = await resolver.resolve(did, use_cache=False)
    assert bypass is not first
    assert await resolver.resolve(did) is first
    now[0] = 1011
    renewed = await resolver.resolve(did)
    assert renewed is not first
    resolver.clear_cache()
    assert await resolver.resolve(did) is not renewed
    assert await resolver.resolve('garbage') is None

@pytest.mark.parametrize('with_keys', [False, True])
def test_verification_and_endpoint_optional_wire_fields(with_keys):
    method = VerificationMethod('id', 'type', 'controller', '0xabc' if with_keys else '', 'zkey' if with_keys else '')
    wire = method.to_dict()
    assert ('publicKeyHex' in wire) is with_keys
    assert ('publicKeyMultibase' in wire) is with_keys
    endpoint = ServiceEndpoint('id', 'type', {'url':'https://example.invalid'}, 'description' if with_keys else '')
    assert ('description' in endpoint.to_dict()) is with_keys

@pytest.mark.parametrize('rich', [False, True])
def test_terminal_output_contracts(rich, monkeypatch, capsys):
    buffer = StringIO()
    monkeypatch.setattr(output, 'HAS_RICH', rich)
    monkeypatch.setattr(output, '_console', Console(file=buffer, color_system=None))
    output.print_success('Completed', {'id':42})
    output.print_success('Empty')
    output.print_warning('Warning')
    output.print_info('Information')
    output.print_table(['id','value'], [[1,'long value'], [2,'ok']], title='Results')
    output.print_table(['id'], [], title=None)
    output.print_transaction({'id':'tx-1', 'state':'SETTLED'})
    rendered = buffer.getvalue() if rich else capsys.readouterr().out
    for expected in ('Completed','42','Empty','Warning','Information','Results','long value','tx-1','SETTLED'):
        assert expected in rendered
    output.print_error('Failed', details='reason')
    assert 'reason' in capsys.readouterr().out
    output.print_transaction({'id':'tx-2'}, output.OutputFormat.JSON)
    assert json.loads(capsys.readouterr().out) == {'id':'tx-2'}
    output.print_transaction({'tx_id':'tx-3'}, output.OutputFormat.QUIET)
    assert capsys.readouterr().out.strip() == 'tx-3'
    assert output.format_state('settled') == ('[green]settled[/green]' if rich else 'settled')
    assert output.format_state('unknown') == ('[white]unknown[/white]' if rich else 'unknown')

@pytest.mark.parametrize('data,expected', [({'txId':'a'},'a'), ({'escrow_id':'b'},'b'), ({'other':4},'4'), ({},'{}'), (12,'12')])
def test_quiet_output_fallback_priority(data, expected):
    assert output.format_output(data, output.OutputFormat.QUIET) == expected
    assert output.format_output(data, output.OutputFormat.QUIET, quiet_value='override') == 'override'
    assert json.loads(output.format_output(data, output.OutputFormat.JSON)) == data
    assert isinstance(output.format_output(data), str)

@pytest.mark.asyncio
async def test_semaphore_fifo_timeout_and_context_release():
    semaphore = Semaphore(1)
    assert await semaphore.acquire()
    timeout = asyncio.create_task(semaphore.acquire(timeout_ms=1))
    assert not await timeout
    assert semaphore.queue_length == 0 and semaphore.available_permits == 0
    waiting = asyncio.create_task(semaphore.acquire())
    await asyncio.sleep(0)
    assert semaphore.queue_length == 1
    semaphore.release()
    assert await waiting
    semaphore.release()
    assert semaphore.available_permits == 1
    with pytest.raises(ValueError, match='inside'):
        async with semaphore:
            assert semaphore.available_permits == 0
            raise ValueError('inside')
    assert semaphore.available_permits == 1

@pytest.mark.asyncio
async def test_rate_limiter_window_reset_and_wait(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr('agirails.utils.semaphore.time.time', lambda: now[0])
    limiter = RateLimiter(2, 10)
    assert limiter.available == 2 and limiter.time_until_available == 0
    assert await limiter.acquire() and await limiter.acquire()
    assert not await limiter.acquire()
    assert limiter.available == 0 and limiter.time_until_available == 10
    async def advance(_): now[0] += 0.01
    monkeypatch.setattr('agirails.utils.semaphore.asyncio.sleep', advance)
    assert not await limiter.wait_and_acquire(timeout_ms=20)
    now[0] = 1011
    assert await limiter.wait_and_acquire(timeout_ms=20)
    limiter.reset()
    assert limiter.available == 2

@pytest.mark.parametrize('args', [(0, 1), (1, 0), (-1, 1)])
def test_invalid_rate_limits(args):
    with pytest.raises(ValueError): RateLimiter(*args)
