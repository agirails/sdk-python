"""Real web3/eth_abi decoding of historical static return layouts; no network."""
import pytest
from eth_abi import encode
from web3 import AsyncWeb3
from web3.providers.async_base import AsyncBaseProvider
from unittest.mock import MagicMock
from agirails.protocol.kernel import ACTPKernel

V3='bytes32,address,address,uint8,uint256,uint256,uint256,uint256,bytes32,address,bytes32,bytes32,uint256,bytes32,uint16,uint16,uint16,uint256,uint256,address,uint256'
A='0x'+'11'*20; Z=b'\0'*32; ID=b'\1'*32
VALUES=[ID,A,A,1,1000000,1,1,2,Z,A,Z,Z,3600,Z,100,500,1000,42,7,A,50000]
class EncodedProvider(AsyncBaseProvider):
    def __init__(self,raw):super().__init__();self.raw=raw
    async def make_request(self,method,params):return {'jsonrpc':'2.0','id':1,'result':'0x'+self.raw.hex() if method=='eth_call' else '0x7a69'}
    async def is_connected(self,show_traceback=False):return True

def kernel(raw):
    w=AsyncWeb3(EncodedProvider(raw));c=w.eth.contract(address=AsyncWeb3.to_checksum_address('0x'+'cc'*20),abi=ACTPKernel._load_abi());a=MagicMock();a.address=A
    return ACTPKernel(c,a,w,31337)

@pytest.mark.parametrize('suffix',[False,True])
async def test_v3_and_candidate_keep_economic_and_identity_fields(suffix):
    raw=encode(['('+V3+(',bytes32,bytes32' if suffix else '')+')'],[VALUES+([Z,Z] if suffix else [])])
    tx=await kernel(raw).get_transaction('0x'+ID.hex())
    assert (tx.agent_id,tx.requester_agent_id,tx.requester_penalty_bps_locked,tx.dispute_bond_bps_locked,tx.dispute_bond)==(42,7,500,1000,50000)

async def test_legacy_keeps_its_actual_agent_id():
    types=V3.split(',')[:15]+['uint256'];values=VALUES[:15]+[42]
    tx=await kernel(encode(['('+','.join(types)+')'],[values])).get_transaction('0x'+ID.hex())
    assert tx.agent_id==42 and tx.dispute_bond==0

@pytest.mark.parametrize('words',[17,19,20,22])
async def test_unknown_historical_layout_fails_loudly(words):
    with pytest.raises(Exception,match='Unsupported getTransaction return size'):
        await kernel(b'\0'*(words*32)).get_transaction('0x'+ID.hex())
