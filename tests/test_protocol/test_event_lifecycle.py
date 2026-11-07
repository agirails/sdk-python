"""Public event streams, filters, recovery cursors and cancellable subscriptions."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agirails.config.networks import BASE_SEPOLIA
from agirails.protocol.events import EventFilter, EventType
from tests.test_protocol.test_event_monitor_layouts import setup_monitor, add_logs, TX_ID, REQUESTER, PROVIDER


def advance_blocks(provider, monkeypatch):
    original=provider.make_request
    count=[0]
    async def rpc(method,params):
        if method == 'eth_blockNumber':
            count[0]+=1
            return {'jsonrpc':'2.0','id':1,'result':hex(9 if count[0]==1 else 12)}
        return await original(method,params)
    monkeypatch.setattr(provider,'make_request',rpc)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,expected', [('watch_transactions',EventType.TRANSACTION_CREATED),('watch_escrows',EventType.ESCROW_CREATED)])
async def test_public_stream_reads_actual_abi_logs_and_closes(kind,expected,monkeypatch):
    monitor,provider,_=setup_monitor(BASE_SEPOLIA,'config')
    add_logs(provider,False)
    advance_blocks(provider,monkeypatch)
    stream=getattr(monitor,kind)(requester=REQUESTER.lower(),provider=PROVIDER.lower(),poll_interval=0.001)
    try:
        event=await asyncio.wait_for(stream.__anext__(),timeout=1)
        assert event.event_type == expected and event.amount == 50000
        assert event.requester == REQUESTER and event.provider == PROVIDER
    finally:
        await stream.aclose()
    assert all(query['fromBlock']=='0xa' for query,_,_ in provider.filters.values())


@pytest.mark.asyncio
async def test_subscription_callback_receives_ordered_logs_and_cancellation_stops_reads(monkeypatch):
    monitor,provider,_=setup_monitor(BASE_SEPOLIA,'config')
    add_logs(provider,False)
    advance_blocks(provider,monkeypatch)
    seen=[];ready=asyncio.Event()
    def receive(event):
        seen.append(event)
        if len(seen)==3:ready.set()
    task=await monitor.subscribe(receive,poll_interval=0.001)
    try:
        await asyncio.wait_for(ready.wait(),1)
    finally:
        task.cancel();await task
    before=len(provider.requests)
    await asyncio.sleep(0.003)
    assert len(provider.requests)==before
    assert [event.event_type for event in seen]==[EventType.TRANSACTION_CREATED,EventType.STATE_TRANSITIONED,EventType.ESCROW_CREATED]
    assert [event.block_number for event in seen]==[10,11,12]


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value,expected', [
    ('transaction_id','0x'+TX_ID.hex(),3),('transaction_id','0x'+'ff'*32,1),
    ('escrow_id','0x'+'88'*32,3),('escrow_id','0x'+'ff'*32,2),
    ('requester',REQUESTER.lower(),3),('requester','0x'+'ff'*20,1),
    ('provider',PROVIDER.lower(),3),('provider','0x'+'ff'*20,1),
    ('event_types',[EventType.ESCROW_CREATED],1),
])
async def test_event_filters_reject_nonmatching_fields_without_dropping_unrelated_shapes(field,value,expected):
    monitor,provider,_=setup_monitor(BASE_SEPOLIA,'config')
    add_logs(provider,False)
    events=await monitor.get_events(EventFilter(**{field:value}),from_block=10,to_block=12)
    assert len(events)==expected
    for event in events:
        wire=event.to_dict()
        assert wire['eventType']==event.event_type.value
        assert wire['blockNumber'] in (10,11,12)


class AdvancingEth:
    def __init__(self):self.height=9
    @property
    def block_number(self):
        async def read():
            self.height+=1
            return self.height
        return read()


@pytest.mark.asyncio
@pytest.mark.parametrize('method,kind', [('on_dispute_split_recorded','split'),('on_uma_dispute_escalated','uma'),('on_disputed_to_cancelled','state')])
async def test_dispute_subscriptions_recover_failed_read_and_do_not_advance_cursor(method,kind,monkeypatch):
    monitor,_,_=setup_monitor(BASE_SEPOLIA,'config')
    monitor.w3=SimpleNamespace(eth=AdvancingEth())
    monitor.mediator_contract=SimpleNamespace(events=SimpleNamespace(DisputeSplitRecorded=object()))
    monitor.bond_escalation_contract=SimpleNamespace(events=SimpleNamespace(UMADisputeEscalated=object()))
    args={'txId':bytes.fromhex('44'*32),'requester':REQUESTER,'provider':PROVIDER,'splitBps':4500} if kind=='split' else {'disputeId':bytes.fromhex('44'*32),'assertionId':bytes.fromhex('55'*32)} if kind=='uma' else {'transactionId':TX_ID,'oldState':6,'newState':7,'triggeredBy':PROVIDER}
    log={'address':PROVIDER,'blockNumber':12,'transactionHash':bytes.fromhex('66'*32),'logIndex':0,'args':args}
    query=AsyncMock(side_effect=[ConnectionError('temporary'),[log]])
    monkeypatch.setattr(monitor,'_query_event_logs',query)
    ready=asyncio.Event();seen=[]
    def receive(event):seen.append(event);ready.set()
    task=await getattr(monitor,method)(receive,poll_interval=0.001)
    try:
        await asyncio.wait_for(ready.wait(),1)
    finally:
        task.cancel();await task
    assert len(seen)==1
    assert query.await_args_list[0].args[1:]==(11,11)
    assert query.await_args_list[1].args[1:]==(11,12)
    wire=seen[0].to_dict()
    assert wire['blockNumber']==12
    assert wire['eventType']=={'split':'DisputeSplitRecorded','uma':'UMADisputeEscalated','state':'StateTransitioned'}[kind]


@pytest.mark.asyncio
@pytest.mark.parametrize('method',['on_dispute_split_recorded','on_uma_dispute_escalated'])
async def test_dispute_subscription_requires_configured_contract(method):
    monitor,_,_=setup_monitor(BASE_SEPOLIA,'direct')
    with pytest.raises(ValueError,match='without'):
        await getattr(monitor,method)(lambda event:None)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,count',[('watch_transactions',3),('watch_escrows',1)])
async def test_event_stream_retries_failed_read_and_responds_to_cancellation(kind,count,monkeypatch):
    monitor,provider,_=setup_monitor(BASE_SEPOLIA,'config')
    add_logs(provider,False)
    advance_blocks(provider,monkeypatch)
    original=provider.make_request
    failed=[False]
    async def rpc(method,params):
        if method=='eth_getFilterLogs' and not failed[0]:
            failed[0]=True
            raise ConnectionError('transient read failure')
        return await original(method,params)
    monkeypatch.setattr(provider,'make_request',rpc)
    stream=getattr(monitor,kind)(poll_interval=0.001)
    try:
        events=[await asyncio.wait_for(stream.__anext__(),1) for _ in range(count)]
        assert failed[0] and len(events)==count
        next_event=asyncio.create_task(stream.__anext__())
        await asyncio.sleep(0)
        next_event.cancel()
        with pytest.raises(StopAsyncIteration):await next_event
    finally:await stream.aclose()


@pytest.mark.asyncio
async def test_callback_subscription_recovers_before_first_callback(monkeypatch):
    monitor,provider,_=setup_monitor(BASE_SEPOLIA,'config')
    add_logs(provider,False)
    advance_blocks(provider,monkeypatch)
    original=provider.make_request
    failed=[False]
    async def rpc(method,params):
        if method=='eth_getFilterLogs' and not failed[0]:
            failed[0]=True
            raise ConnectionError('transient read failure')
        return await original(method,params)
    monkeypatch.setattr(provider,'make_request',rpc)
    ready=asyncio.Event();seen=[]
    def receive(event):
        seen.append(event)
        if len(seen)==3:ready.set()
    task=await monitor.subscribe(receive,poll_interval=0.001)
    try:await asyncio.wait_for(ready.wait(),1)
    finally:task.cancel();await task
    assert failed[0] and [event.block_number for event in seen]==[10,11,12]
