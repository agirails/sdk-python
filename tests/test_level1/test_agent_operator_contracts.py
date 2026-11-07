"""Agent terminal states, timeout/error propagation and handler cleanup."""

import asyncio
import importlib
from datetime import datetime,timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agirails.level1.agent import Agent
from agirails.level1.config import AgentConfig,ServiceConfig,AgentBehavior
from agirails.level1.job import Job,JobResult
from agirails.errors import NoProviderFoundError
from tests.test_level1.test_agent_delivery_hook import _agent_with_delivery,_job

TX='0x'+'ab'*32
PROVIDER='0x'+'22'*20


@pytest.mark.asyncio
@pytest.mark.parametrize('states,expected', [(['SETTLED'],'completed'),(['COMMITTED','SETTLED'],'completed'),(['CANCELLED'],'cancelled'),([None],'not found')])
async def test_agent_request_reports_only_terminal_success_and_funds_once(states,expected,monkeypatch):
    agent=Agent(AgentConfig(name='buyer',network='mock'))
    standard=SimpleNamespace(create_transaction=AsyncMock(return_value=TX),link_escrow=AsyncMock(),get_transaction=AsyncMock(side_effect=[None if state is None else SimpleNamespace(state=state) for state in states]))
    agent._client=SimpleNamespace(standard=standard)
    original=asyncio.sleep
    async def tick(_):await original(0)
    monkeypatch.setattr('agirails.level1.agent.asyncio.sleep',tick)
    if expected=='completed':
        result=await agent.request('echo',{'message':'hello'},provider=PROVIDER,budget=1.25,timeout=1)
        assert result['tx_id']==TX and result['status']=='completed'
    else:
        with pytest.raises(RuntimeError,match=expected):
            await agent.request('echo',{},provider=PROVIDER,budget=1.25,timeout=1)
    standard.create_transaction.assert_awaited_once()
    payload=standard.create_transaction.await_args.args[0]
    assert payload['provider']==PROVIDER and payload['amount']==1.25
    standard.link_escrow.assert_awaited_once_with(TX)
    assert standard.get_transaction.await_count==len(states)


@pytest.mark.asyncio
async def test_agent_request_requires_started_client_and_handles_lookup_and_timeout(monkeypatch):
    agent=Agent(AgentConfig(name='buyer',network='mock'))
    with pytest.raises(RuntimeError,match='not started'):await agent.request('echo',{},budget=1)
    standard=SimpleNamespace(create_transaction=AsyncMock(return_value=TX),link_escrow=AsyncMock(),get_transaction=AsyncMock())
    agent._client=SimpleNamespace(standard=standard)
    directory_module=importlib.import_module('agirails.level0.directory')
    directory=directory_module.ServiceDirectory()
    monkeypatch.setattr(directory_module,'_global_directory',directory)
    with pytest.raises(NoProviderFoundError):await agent.request('echo',{},budget=1)
    standard.create_transaction.assert_not_awaited()
    directory.register('echo')
    with pytest.raises(NoProviderFoundError):await agent.request('echo',{},budget=1)
    standard.create_transaction.assert_not_awaited()
    directory.unregister('echo')
    directory.register('echo',provider_address=PROVIDER)
    standard.get_transaction.return_value=SimpleNamespace(state='COMMITTED')
    with pytest.raises(TimeoutError,match='timed out'):await agent.request('echo',{},budget=1,timeout=1)
    standard.create_transaction.assert_awaited_once()
    standard.get_transaction.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('state',['COMMITTED','IN_PROGRESS','CANCELLED','DISPUTED'])
@pytest.mark.parametrize('result',['plain','success','failure','exception'])
async def test_execute_handler_respects_state_and_always_cleans_active_job(state,result,monkeypatch):
    agent=Agent(AgentConfig(name='provider',network='mock'))
    async def handler(job,ctx):
        if result=='exception':raise RuntimeError('handler unavailable')
        if result=='success':return JobResult.ok({'output':42})
        if result=='failure':return JobResult.fail('handler declined')
        return {'output':42}
    agent.provide('echo',handler=handler)
    agent._client=SimpleNamespace(runtime=SimpleNamespace(get_transaction=AsyncMock(return_value=SimpleNamespace(state=state))),standard=SimpleNamespace(transition_state=AsyncMock()))
    complete=AsyncMock();fail=AsyncMock()
    monkeypatch.setattr(agent,'_complete_job',complete);monkeypatch.setattr(agent,'_fail_job',fail)
    job=_job();agent._active_jobs.set(job.id,job)
    await agent._execute_job(job,agent._services['echo'])
    assert agent.jobs==[]
    if state in ('CANCELLED','DISPUTED'):
        complete.assert_not_awaited();fail.assert_not_awaited()
        agent._client.standard.transition_state.assert_not_awaited()
    else:
        if state=='COMMITTED':agent._client.standard.transition_state.assert_awaited_once_with(job.id,'IN_PROGRESS')
        else:agent._client.standard.transition_state.assert_not_awaited()
        if result in ('plain','success'):
            complete.assert_awaited_once_with(job,{'output':42},agent._services['echo']);fail.assert_not_awaited()
        else:
            fail.assert_awaited_once();complete.assert_not_awaited()
            assert fail.await_args.args[0] is job


@pytest.mark.asyncio
async def test_execute_timeout_and_state_read_failure_keep_cleanup_bounded(monkeypatch):
    agent=Agent(AgentConfig(name='provider',network='mock'))
    async def handler(job,ctx):await asyncio.Event().wait()
    agent.provide(ServiceConfig(name='echo',timeout=0),handler=handler)
    agent._client=SimpleNamespace(runtime=SimpleNamespace(get_transaction=AsyncMock(side_effect=ConnectionError('RPC unavailable'))),standard=SimpleNamespace(transition_state=AsyncMock(side_effect=ValueError('already in progress'))))
    fail=AsyncMock();monkeypatch.setattr(agent,'_fail_job',fail)
    job=_job();agent._active_jobs.set(job.id,job)
    await agent._execute_job(job,agent._services['echo'])
    assert agent.jobs==[]
    fail.assert_awaited_once()
    assert 'timed out' in fail.await_args.args[1]


@pytest.mark.asyncio
@pytest.mark.parametrize('description,expected', [(None,None),('invalid',None),('service:echo;input:{"a":1}',{'a':1}),('service:echo;input:raw','raw'),(123,None)])
async def test_job_input_legacy_parsing_is_bounded(description,expected):
    agent=Agent(AgentConfig(name='provider',network='mock'))
    assert agent._extract_job_input(SimpleNamespace(service_description=description))==expected


@pytest.mark.asyncio
@pytest.mark.parametrize('reason',['processed','locked','no_handler','declined'])
async def test_rejected_or_duplicate_transaction_does_not_spawn_work(reason):
    agent=Agent(AgentConfig(name='provider',network='mock',behavior=AgentBehavior(auto_accept=False)))
    tx=SimpleNamespace(id=TX,amount='1000000',deadline=int((datetime.now()+timedelta(hours=1)).timestamp()),requester=PROVIDER,service_description='0x'+'00'*32)
    if reason=='processed':agent._processed_jobs.set(TX,True)
    if reason=='locked':agent._processing_locks.add(TX)
    if reason=='declined':
        async def handler(job,ctx):pytest.fail('declined job executed')
        agent.provide('echo',handler=handler)
    await agent._process_transaction(tx)
    assert agent.stats.jobs_received==0 and agent.jobs==[]
    if reason!='locked':assert TX not in agent._processing_locks


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['state_read','signer_address','provider_address','missing_setups','setups_unavailable','malformed_setup'])
async def test_delivery_hook_dependency_errors_skip_publish_without_raising(fault,monkeypatch):
    monkeypatch.setenv('ACTP_DELIVERY_CHANNEL','v1')
    channel=SimpleNamespace(publish_envelope=AsyncMock())
    agent,_=_agent_with_delivery(channel)
    if fault=='state_read':agent._client.runtime.get_transaction=AsyncMock(side_effect=ConnectionError('read unavailable'))
    elif fault=='signer_address':
        class BrokenSigner:
            @property
            def address(self):raise RuntimeError('signer unavailable')
        agent._delivery_signer=BrokenSigner()
    elif fault=='provider_address':agent._address='invalid'
    else:
        from agirails.level1.config import DeliveryServiceConfig
        agent._services['echo'].config.delivery=DeliveryServiceConfig(privacy='encrypted')
        if fault=='setups_unavailable':channel.get_setups=AsyncMock(side_effect=ConnectionError('relay unavailable'))
        if fault=='malformed_setup':channel.get_setups=AsyncMock(return_value=[{'signed':[]}])
    await agent._maybe_publish_delivery_envelope(_job(),{'output':'private'})
    channel.publish_envelope.assert_not_awaited()
