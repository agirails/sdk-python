"""Client commitments, settlement ordering and read-only startup drift checks."""

import json
from functools import partial
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from web3 import Web3

from agirails.client import ACTPClient, ACTPClientConfig, ACTPClientInfo
from agirails.config.pending_publish import PendingPublishData, ServiceDescriptorData
from agirails.protocol.agent_registry import _load_agent_registry_abi

ADDRESS='0x'+'12'*20
REGISTRY='0x'+'23'*20
HASH='0x'+'34'*32
TX='0x'+'45'*32


@pytest.mark.parametrize('value',[bytes.fromhex(HASH[2:]),bytearray.fromhex(HASH[2:]),HASH,HASH[2:],'0X'+HASH[2:]])
def test_explicit_result_commitment_has_priority_over_payload_and_stored_data(value):
    tx=SimpleNamespace(delivery_proof=json.dumps({'resultHash':'0x'+'99'*32}))
    assert ACTPClient._resolve_result_hash(TX,tx,result={'a':1},result_hash=value)==bytes.fromhex(HASH[2:])


def test_payload_hash_uses_actual_canonical_commitment():
    tx=SimpleNamespace(delivery_proof=json.dumps({'resultHash':HASH}))
    assert ACTPClient._resolve_result_hash(TX,tx,result={'a':1})==Web3.keccak(text='{"a":1}')


@pytest.mark.parametrize('key',['resultHash','result_hash'])
def test_stored_proof_binds_the_existing_delivery_commitment(key):
    tx=SimpleNamespace(delivery_proof=json.dumps({key:HASH}))
    assert ACTPClient._resolve_result_hash(TX,tx)==bytes.fromhex(HASH[2:])


@pytest.mark.parametrize('stored',[None,'bad','[]','{}',json.dumps({'resultHash':'short'}),json.dumps({'result_hash':'0x12'})])
def test_missing_or_malformed_commitments_fail_without_a_synthetic_result(stored):
    with pytest.raises(ValueError,match='requires a real deliverable'):
        ACTPClient._resolve_result_hash(TX,SimpleNamespace(delivery_proof=stored))


@pytest.mark.parametrize('value',[b'',b'1'*31,b'1'*33,'0x12'])
def test_explicit_wrong_length_result_hash_is_rejected(value):
    with pytest.raises(ValueError,match='32 bytes'):
        ACTPClient._resolve_result_hash(TX,SimpleNamespace(),result_hash=value)


@pytest.mark.asyncio
@pytest.mark.parametrize('state',['DELIVERED','SETTLED'])
@pytest.mark.parametrize('route',[False,True])
@pytest.mark.parametrize('report',['none','success','failure'])
async def test_settlement_routes_once_and_reputation_failure_does_not_undo_it(state,route,report):
    trace=[]
    async def record(name,*args):trace.append((name,args))
    runtime=SimpleNamespace(get_transaction=AsyncMock(return_value=SimpleNamespace(state=state,agent_id=42)),release_escrow=AsyncMock(side_effect=partial(record,'runtime')))
    router=SimpleNamespace(should_route=lambda:route,validate_release_preconditions=AsyncMock(side_effect=partial(record,'validate')),verify_release_attestation=AsyncMock(side_effect=partial(record,'attestation')),send_settle=AsyncMock(side_effect=partial(record,'settle')))
    client=ACTPClient(runtime,ADDRESS,ACTPClientInfo(mode='mock',address=ADDRESS))
    client._smart_wallet_router=router
    if report!='none':
        async def reporter(**kw):
            trace.append(('report',kw))
            if report=='failure':raise RuntimeError('reporter unavailable after settlement')
            return SimpleNamespace(tx_hash=HASH)
        client._reputation_reporter=SimpleNamespace(report_settlement=AsyncMock(side_effect=reporter))
    await client.release(TX,HASH)
    names=[entry[0] for entry in trace]
    expected=[] if state=='SETTLED' else ['validate','attestation','settle'] if route else ['runtime']
    if report!='none':expected+=['report']
    assert names==expected
    if state!='SETTLED' and route:
        router.verify_release_attestation.assert_awaited_once_with(TX,HASH)
        router.send_settle.assert_awaited_once_with(TX)
    elif state!='SETTLED':runtime.release_escrow.assert_awaited_once_with(TX,HASH)


@pytest.mark.asyncio
async def test_attestation_failure_stops_settlement_and_reputation():
    runtime=SimpleNamespace(get_transaction=AsyncMock(return_value=SimpleNamespace(state='DELIVERED',agent_id=42)),release_escrow=AsyncMock())
    router=SimpleNamespace(should_route=lambda:True,validate_release_preconditions=AsyncMock(),verify_release_attestation=AsyncMock(side_effect=ValueError('invalid attestation')),send_settle=AsyncMock())
    client=ACTPClient(runtime,ADDRESS,ACTPClientInfo(mode='mock',address=ADDRESS))
    client._smart_wallet_router=router
    reporter=AsyncMock();client._reputation_reporter=SimpleNamespace(report_settlement=reporter)
    with pytest.raises(ValueError,match='invalid attestation'):await client.release(TX,HASH)
    router.send_settle.assert_not_awaited();runtime.release_escrow.assert_not_awaited();reporter.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('scenario,expected',[('A',['registerAgent','publishConfig','setListed']),('B1',['publishConfig','setListed']),('B2',['publishConfig'])])
@pytest.mark.parametrize('cleanup_failure',[False,True])
async def test_activation_call_data_and_success_callback_do_not_repeat_registration(tmp_path,monkeypatch,scenario,expected,cleanup_failure):
    pending=PendingPublishData(config_hash=HASH,cid='bafy-config',endpoint='https://agent.invalid',service_descriptors=[ServiceDescriptorData(HASH,'echo',min_price='50000',max_price='1000000')])
    runtime=SimpleNamespace()
    client=ACTPClient(runtime,ADDRESS,ACTPClientInfo(mode='mock',address=ADDRESS),lazy_scenario=scenario,pending_publish=pending,agent_registry_address=REGISTRY,network_id='base-sepolia')
    removed=[]
    def remove(**kw):
        removed.append(kw)
        if cleanup_failure:raise OSError('local deletion unavailable')
    monkeypatch.setattr('agirails.config.pending_publish.delete_pending_publish',remove)
    batch=client.get_activation_calls()
    decoder=Web3().eth.contract(abi=_load_agent_registry_abi())
    decoded=[decoder.decode_function_input(call.data) for call in batch['calls']]
    assert [fn.fn_name for fn,_ in decoded]==expected
    assert all(call.target==REGISTRY and call.value==0 for call in batch['calls'])
    if scenario=='A':
        assert 'https://agent.invalid' in decoded[0][1].values()
    batch['on_success']()
    assert removed==[{'network':'base-sepolia'}]
    assert client.get_activation_calls()['calls']==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('case',['missing','template','published','different','identity','broken_pointer','pay','nested_pay','reader_failure','invalid'])
async def test_startup_drift_never_writes_identity_or_submits_calls(tmp_path,monkeypatch,case):
    monkeypatch.chdir(tmp_path);monkeypatch.setenv('ACTP_DIR',str(tmp_path/'.actp'))
    client=await ACTPClient.create(mode='mock',requester_address=ADDRESS,state_directory=str(tmp_path/'state'))
    cfg=ACTPClientConfig(mode='testnet',requester_address=ADDRESS)
    text='---\nname: local\nintent: earn\n'+('config_hash: stored\n' if case=='published' else '')+'---\n# local\n'
    if case=='pay':text=text.replace('intent: earn','intent: pay')
    if case=='nested_pay':text=text.replace('intent: earn','agent:\n  intent: pay')
    if case=='invalid':text='not a frontmatter file'
    identity=tmp_path/('identity.md' if case=='identity' else 'AGIRAILS.md')
    if case!='missing':identity.write_text(text)
    if case in ('identity','broken_pointer'):
        path=tmp_path/'.actp';path.mkdir(exist_ok=True)
        (path/'config.json').write_text(json.dumps({'identity':'identity.md'}) if case=='identity' else 'invalid json')
    reads=[]
    def chain(*args):
        reads.append(args)
        if case=='reader_failure':raise ConnectionError('RPC unavailable')
        return SimpleNamespace(config_hash='0x'+('ab' if case=='different' else '00')*32)
    monkeypatch.setattr('agirails.config.on_chain_state.get_on_chain_config_state',chain)
    await client.check_config_drift(cfg)
    if case in ('missing','pay','nested_pay','invalid'):assert reads==[]
    else:assert len(reads)==1 and reads[0][:2]==(ADDRESS,'base-sepolia')
    if case!='missing':assert identity.read_text()==text


@pytest.mark.asyncio
@pytest.mark.parametrize('amount',['50000','1000000','123456789'])
async def test_x402_wallet_transfer_encodes_exact_token_principal_and_real_signature(amount):
    import rlp
    from eth_abi import decode
    from eth_account import Account
    from agirails.wallet.eoa_wallet_provider import EOAWalletProvider
    from tests.test_wallet.test_wallet_wire_boundaries import LocalEOARPC,KEY
    rpc=LocalEOARPC()
    wallet=EOAWalletProvider(KEY,Web3(rpc),84532)
    transfer=ACTPClient._build_x402_transfer_fn(wallet,REGISTRY,'http://offline.invalid')
    tx_hash=await transfer(ADDRESS,amount)
    raw=rpc.sent[0][0]
    assert Account.recover_transaction(raw)==wallet.get_address()
    assert tx_hash==Web3.keccak(raw).hex()
    fields=rlp.decode(raw[1:])
    assert fields[5].hex()==REGISTRY[2:]
    assert int.from_bytes(fields[6],'big')==0
    calldata=fields[7]
    assert calldata[:4].hex()=='a9059cbb'
    assert decode(['address','uint256'],calldata[4:])==(ADDRESS,int(amount))


@pytest.mark.asyncio
async def test_x402_wallet_failure_or_fractional_base_units_cannot_return_a_proof():
    wallet=SimpleNamespace(send_transaction=AsyncMock(side_effect=RuntimeError('wallet unavailable')))
    transfer=ACTPClient._build_x402_transfer_fn(wallet,REGISTRY,'http://offline.invalid')
    with pytest.raises(ValueError):await transfer(ADDRESS,'0.5')
    wallet.send_transaction.assert_not_awaited()
    with pytest.raises(RuntimeError,match='wallet unavailable'):await transfer(ADDRESS,'1000000')
    wallet.send_transaction.assert_awaited_once()
