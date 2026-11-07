"""CLI reads/writes against isolated real runtime/config and policy boundaries."""

import asyncio
import importlib
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner
import typer

from agirails.cli.main import app
from agirails.client import ACTPClient
from agirails.cli.utils.client import init_directory, load_config
from agirails.cli.utils import validation
from agirails.runtime.base import CreateTransactionParams
from agirails.server.policy import load_policy_from_file, load_policy_from_dict

runner=CliRunner()
REQUESTER='0x'+'11'*20
PROVIDER='0x'+'22'*20
MISSING='0x'+'ff'*32


@pytest.fixture
def operator(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_directory(tmp_path,mode='mock',address=REQUESTER)
    async def create():
        client=await ACTPClient.create(mode='mock',requester_address=REQUESTER,state_directory=str(tmp_path/'.actp'))
        tx1=await client.runtime.create_transaction(CreateTransactionParams(PROVIDER,REQUESTER,'1000000',client.runtime.time.now()+3600))
        tx2=await client.runtime.create_transaction(CreateTransactionParams(PROVIDER,REQUESTER,'2000000',client.runtime.time.now()+7200))
        await client.runtime.transition_state(tx1,'QUOTED')
        return client,tx1,tx2
    client,tx1,tx2=asyncio.run(create())
    module=importlib.import_module('agirails.cli.commands.tx')
    monkeypatch.setattr(module,'get_client',AsyncMock(return_value=client))
    return client,tx1,tx2,tmp_path,module


@pytest.mark.parametrize('flags',[[],['--json'],['--quiet']])
def test_tx_status_list_filter_limit_and_transition_actual_state(operator,flags):
    client,tx1,tx2,_,_=operator
    status=runner.invoke(app,[*flags,'tx','status',tx1])
    assert status.exit_code==0,status.output
    assert 'QUOTED' in status.stdout
    if '--json' in flags:
        data=json.loads(status.stdout)
        assert data['id']==tx1 and data['amount']=='1000000'
        assert data['requester']==REQUESTER and data['provider']==PROVIDER
    listing=runner.invoke(app,[*flags,'tx','list','--state','QUOTED','--limit','1'])
    assert listing.exit_code==0,listing.output
    if '--json' in flags:
        data=json.loads(listing.stdout)
        assert data['count']==1 and data['transactions'][0]['id']==tx1
    else:
        assert tx2 not in listing.stdout
    transition=runner.invoke(app,[*flags,'tx','transition',tx2,'QUOTED'])
    assert transition.exit_code==0,transition.output
    actual=asyncio.run(client.runtime.get_transaction(tx2))
    assert actual.state=='QUOTED'
    listing=runner.invoke(app,[*flags,'tx','list','--state','SETTLED'])
    assert listing.exit_code==0,listing.output
    if '--json' in flags:assert json.loads(listing.stdout)['transactions']==[]


@pytest.mark.parametrize('flags',[[],['--json'],['--quiet']])
@pytest.mark.parametrize('command',[['status','bad'],['status',MISSING],['list','--state','bad'],['transition',MISSING,'QUOTED'],['transition',MISSING,'bad']])
def test_tx_invalid_input_and_missing_transactions_fail_with_no_state_change(operator,flags,command):
    client,tx1,tx2,_,_=operator
    result=runner.invoke(app,[*flags,'tx',*command])
    assert result.exit_code==1,result.output
    if '--json' in flags:assert json.loads(result.stdout)['error']
    assert asyncio.run(client.runtime.get_transaction(tx1)).state=='QUOTED'
    assert asyncio.run(client.runtime.get_transaction(tx2)).state=='INITIATED'


@pytest.mark.parametrize('flags',[[],['--json']])
@pytest.mark.parametrize('command',[['status',MISSING],['list'],['transition',MISSING,'QUOTED']])
@pytest.mark.parametrize('failure',['uninitialized','unavailable'])
def test_tx_operator_failures_surface_without_success(operator,flags,command,failure,monkeypatch):
    _,_,_,_,module=operator
    if failure=='uninitialized':monkeypatch.setattr(module,'ensure_initialized',lambda directory:False)
    else:monkeypatch.setattr(module,'get_client',AsyncMock(side_effect=ConnectionError('local unavailable')))
    result=runner.invoke(app,[*flags,'tx',*command])
    assert result.exit_code==1,result.output
    if '--json' in flags:assert json.loads(result.stdout)['error']


@pytest.mark.parametrize('flags',[[],['--json'],['--quiet']])
@pytest.mark.parametrize('key,value',[('mode','testnet'),('address',PROVIDER),('rpc_url','https://rpc.example.invalid')])
def test_config_round_trip_uses_real_local_storage(operator,flags,key,value):
    _,_,_,directory,_=operator
    changed=runner.invoke(app,[*flags,'config','set',key,value])
    assert changed.exit_code==0,changed.output
    assert load_config(directory)[key]==value
    result=runner.invoke(app,[*flags,'config','get',key])
    assert result.exit_code==0,result.output
    if '--json' in flags:
        data=json.loads(result.stdout);assert data['value']==value and data['exists'] is True
    else:assert value in result.stdout
    show=runner.invoke(app,[*flags,'config','show'])
    assert show.exit_code==0,show.output
    if '--json' in flags:assert json.loads(show.stdout)['config'][key]==value
    missing=runner.invoke(app,[*flags,'config','get','not_set'])
    assert missing.exit_code==0
    if '--json' in flags:assert json.loads(missing.stdout)['exists'] is False


@pytest.mark.parametrize('flags',[[],['--json']])
@pytest.mark.parametrize('key,value',[('private_key','never-store-this'),('unknown','x'),('mode','bad'),('address','invalid')])
def test_config_rejects_secrets_unknown_keys_and_invalid_values(operator,flags,key,value):
    _,_,_,directory,_=operator
    before=load_config(directory)
    result=runner.invoke(app,[*flags,'config','set',key,value])
    assert result.exit_code==1,result.output
    assert load_config(directory)==before
    assert value not in json.dumps(load_config(directory)) or value in json.dumps(before)


def policy_data():
    return {'pricing':{'min_acceptable':{'amount':'50000'},'ideal_price':{'amount':'100000'}},'services':['echo']}


@pytest.mark.parametrize('duration,seconds',[('15m',900),('1h',3600),('2d',172800),('900',900),(60,60),(None,900)])
def test_policy_file_preserves_duration_and_pricing_constraints(tmp_path,duration,seconds):
    data=policy_data();data['quote_ttl']=duration
    path=tmp_path/'policy.json';path.write_text(json.dumps(data))
    policy=load_policy_from_file(path)
    assert policy.quote_ttl_seconds==seconds
    assert policy.pricing.min_acceptable_amount==50000
    assert policy.pricing.ideal_amount==100000
    assert policy.services==['echo']


@pytest.mark.parametrize('change,message',[
    ({'pricing':{'min_acceptable':{'amount':'1'},'ideal_price':{'amount':'100000'}}},'below platform'),
    ({'pricing':{'min_acceptable':{'amount':'100000'},'ideal_price':{'amount':'50000'}}},'ideal_amount'),
    ({'pricing':{'min_acceptable':{'amount':'50000','currency':'EUR'},'ideal_price':{'amount':'100000'}}},'Only USDC'),
    ({'counter_strategy':'invalid'},'counter_strategy'),({'concede_pct':0},'concede_pct'),
    ({'concede_pct':100},'concede_pct'),({'max_requotes':-1},'max_requotes'),
    ({'min_deadline_seconds':-1},'min_deadline_seconds'),({'quote_ttl':'bad'},'Invalid duration'),
    ({'quote_ttl':[]},'Invalid duration type'),
])
def test_invalid_policy_rejected_at_load(change,message):
    data=policy_data();data.update(change)
    with pytest.raises(ValueError,match=message):load_policy_from_dict(data)


@pytest.mark.parametrize('fn,value,valid',[
    (validation.validate_seconds,0,True),(validation.validate_seconds,31536000,True),
    (validation.validate_seconds,-1,False),(validation.validate_seconds,31536001,False),
    (validation.validate_timestamp,1577836800,True),(validation.validate_timestamp,4102444800,True),
    (validation.validate_timestamp,-1,False),(validation.validate_timestamp,1,False),(validation.validate_timestamp,4102444801,False),
    (validation.validate_amount,'1.000001',True),(validation.validate_amount,'1.0000001',False),
    (validation.validate_amount,'-1',False),(validation.validate_amount,'0',False),(validation.validate_amount,'bad',False),
])
def test_validation_numeric_boundaries(fn,value,valid):
    if valid:assert fn(value)==value
    else:
        with pytest.raises(typer.BadParameter):fn(value)


def test_path_validation_resolves_and_enforces_existence(tmp_path):
    target=tmp_path/'file.txt';target.write_text('test')
    assert validation.validate_path(target,must_exist=True)==target.resolve()
    with pytest.raises(typer.BadParameter,match='does not exist'):
        validation.validate_path(tmp_path/'missing',must_exist=True)
