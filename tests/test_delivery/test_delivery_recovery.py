"""Delivery verification-before-dedup, callback isolation, replay and HTTP recovery."""

import asyncio
import copy
import time
from urllib.parse import parse_qs

import httpx
import pytest

from agirails.delivery import (
    CANONICAL_EMPTY_BYTES32, BuildSetupParams, DeliverySetupBuilder,
    MockDeliveryChannel, MockDeliveryChannelOptions, RelayDeliveryChannel, RelayDeliveryChannelOptions,
)
from tests.test_delivery.test_relay_channel import _make_envelope_wire, PROVIDER, KERNEL, CHAIN, TXID
from tests.test_delivery.test_roundtrip_channel import BUYER


def wire_for(kind):
    if kind=='envelope':return _make_envelope_wire()
    return DeliverySetupBuilder(signer=BUYER).build(BuildSetupParams(tx_id=TXID,chain_id=CHAIN,kernel_address=KERNEL,requester_address=BUYER.address,signer_address=BUYER.address,buyer_ephemeral_pubkey=CANONICAL_EMPTY_BYTES32,expected_privacy='public'))['wire']


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['setup','envelope'])
@pytest.mark.parametrize('async_callback',[False,True])
async def test_mock_verifies_before_dedup_and_isolates_subscribers_and_replay(kind,async_callback):
    logs=[]
    channel=MockDeliveryChannel(MockDeliveryChannelOptions(log=lambda *a:logs.append(a),now=lambda:int(time.time())))
    wire=wire_for(kind)
    publish=getattr(channel,'publish_'+kind)
    subscribe=getattr(channel,'subscribe_'+('setups' if kind=='setup' else 'envelopes'))
    get=getattr(channel,'get_'+('setups' if kind=='setup' else 'envelopes'))
    get_all=getattr(channel,'get_all_'+('setups' if kind=='setup' else 'envelopes'))
    bad=copy.deepcopy(wire);bad['requesterSig' if kind=='setup' else 'providerSig']='0x'+'00'*65
    with pytest.raises(RuntimeError,match='verify failed'):await publish(bad)
    received=[]
    def broken(_):raise RuntimeError('broken subscriber')
    async def async_broken(_):
        await asyncio.sleep(0)
        raise RuntimeError('broken async subscriber')
    broken_sub=await subscribe(TXID,async_broken if async_callback else broken)
    good_sub=await subscribe(TXID.upper(),lambda item:received.append(item))
    await publish(wire)
    await publish(wire)
    for _ in range(5):await asyncio.sleep(0)
    assert len(received)==1 and received[0]==wire
    assert channel.active_subscription_count()==2
    assert len(await get(TXID))==1 and len(get_all())==1
    snapshot=get_all(TXID);snapshot.clear()
    assert len(get_all(TXID))==1 and get_all('unknown')==[]
    with pytest.raises(RuntimeError,match='verify failed'):await publish(bad)
    replay=[]
    replay_sub=await subscribe(TXID,lambda item:replay.append(item))
    cancelled=await subscribe(TXID,lambda item:pytest.fail('closed subscriber replayed'))
    cancelled.close();cancelled.close()
    for _ in range(3):await asyncio.sleep(0)
    assert replay==[wire]
    assert any('subscriber threw' in args[1] for args in logs)
    for sub in [good_sub,broken_sub,replay_sub]:sub.close()
    assert channel.active_subscription_count()==0
    await channel.close();await channel.close()
    with pytest.raises(RuntimeError,match='closed'):await publish(wire)
    with pytest.raises(RuntimeError,match='closed'):await subscribe(TXID,lambda _:None)
    channel.clear()
    assert get_all()==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['setup','envelope'])
async def test_relay_poll_recovers_http_failure_verifies_then_deduplicates_and_closes(kind):
    wire=wire_for(kind);bad=copy.deepcopy(wire)
    bad['requesterSig' if kind=='setup' else 'providerSig']='0x'+'00'*65
    requests=[];logs=[];received=[];ready=asyncio.Event();polling=[False];fail_next=[False]
    def handler(request):
        requests.append(request)
        if request.method=='POST':return httpx.Response(200,json={'ok':True})
        if fail_next[0]:
            fail_next[0]=False
            return httpx.Response(503,text='try later')
        if not polling[0]:return httpx.Response(200,json={'items':[{'cursor':'valid','wire':wire}]})
        return httpx.Response(200,json={'items':[{'cursor':'bad','wire':bad},{'cursor':'valid/1','wire':wire},{'cursor':'valid/2','wire':wire}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        channel=RelayDeliveryChannel(RelayDeliveryChannelOptions(base_url='https://relay.invalid',http_client=client,allow_private_hosts=True,poll_interval_ms=1,log=lambda *a:logs.append(a),expected_chain_id=CHAIN,expected_kernel_address=KERNEL,now=lambda:int(time.time())))
        publish=getattr(channel,'publish_'+kind)
        subscribe=getattr(channel,'subscribe_'+('setups' if kind=='setup' else 'envelopes'))
        get=getattr(channel,'get_'+('setups' if kind=='setup' else 'envelopes'))
        assert await get() == []
        await publish(wire)
        assert await get(TXID,after='a/b') == [wire]
        assert parse_qs(requests[-1].url.query.decode()) == {'after':['a/b']}
        requests.clear();polling[0]=True;fail_next[0]=True
        async def receive(item):
            received.append(item)
            ready.set()
            raise RuntimeError('subscriber failure after delivery')
        subscription=await subscribe(TXID,receive)
        try:await asyncio.wait_for(ready.wait(),1)
        finally:
            subscription.close();subscription.close();await channel.close()
        assert received==[wire]
        assert any('poll error' in args[1] for args in logs)
        assert any('dropping unverified' in args[1] for args in logs)
        assert any('subscriber threw' in args[1] for args in logs)
        assert not client.is_closed
        with pytest.raises(RuntimeError,match='closed'):await publish(wire)
        with pytest.raises(RuntimeError,match='closed'):await subscribe(TXID,lambda _:None)


@pytest.mark.asyncio
async def test_relay_reports_transport_failure_and_closes_owned_client(monkeypatch):
    original=httpx.AsyncClient
    def fail(request):raise httpx.ConnectError('offline',request=request)
    monkeypatch.setattr('agirails.delivery.relay_delivery_channel.httpx.AsyncClient',lambda **kw:original(transport=httpx.MockTransport(fail),**kw))
    channel=RelayDeliveryChannel(RelayDeliveryChannelOptions(base_url='https://relay.invalid',allow_private_hosts=True))
    with pytest.raises(RuntimeError,match='POST failed'):await channel.publish_setup(wire_for('setup'))
    await channel.close()
    assert channel._client.is_closed
