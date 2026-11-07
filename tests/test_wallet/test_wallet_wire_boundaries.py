"""Wire-level wallet sponsorship failover, real EOA signatures, message verification."""

import copy
import json

from eth_account import Account
from hexbytes import HexBytes
import httpx
import pytest
import rlp
from web3 import Web3
from web3.providers import BaseProvider

from agirails.config.networks import BASE_SEPOLIA
from agirails.protocol.messages import MessageSigner, SignatureComponents, SECP256K1_N
from agirails.types.message import ServiceRequest, ServiceResponse, DeliveryProof, DeliveryProofMessage
from agirails.wallet.eoa_wallet_provider import EOAWalletProvider
from agirails.wallet.auto_wallet_provider import TransactionRequest
from agirails.wallet.aa.paymaster_client import PaymasterClient, PaymasterConfig, PaymasterError
from agirails.wallet.aa.constants import UserOperationV06, ENTRYPOINT_V06

KEY = '0x' + '12' * 32
ADDRESS = Web3.to_checksum_address('0x' + '23' * 20)
HASH = '0x' + '34' * 32


class LocalEOARPC(BaseProvider):
    def __init__(self, fail_estimate=False, rewards=True, statuses=(1,)):
        super().__init__()
        self.fail_estimate = fail_estimate
        self.rewards = rewards
        self.statuses = iter(statuses)
        self.sent = []
        self.nonce = 5

    def make_request(self, method, params):
        if method == 'eth_chainId':
            result = hex(84532)
        elif method == 'eth_getTransactionCount':
            result = hex(self.nonce)
        elif method == 'eth_estimateGas':
            if self.fail_estimate: raise ValueError('estimator unavailable')
            result = hex(42000)
        elif method == 'eth_feeHistory':
            result = {'oldestBlock':'0x1','baseFeePerGas':['0x64','0x64'], 'gasUsedRatio':[0.5]}
            if self.rewards: result['reward'] = [['0x2']]
        elif method == 'eth_sendRawTransaction':
            raw = HexBytes(params[0])
            self.sent.append((raw, next(self.statuses)))
            self.nonce += 1
            result = Web3.to_hex(Web3.keccak(raw))
        elif method == 'eth_getTransactionReceipt':
            result = {'transactionHash': params[0], 'status':hex(self.sent[-1][1]),
                'transactionIndex':'0x0','blockNumber':'0x1','blockHash':HASH,
                'from':Account.from_key(KEY).address,'to':ADDRESS,'gasUsed':'0xa410',
                'cumulativeGasUsed':'0xa410','contractAddress':None,'logs':[],
                'logsBloom':'0x'+'00'*256,'type':'0x2','effectiveGasPrice':'0x66'}
        else:
            raise AssertionError('Unexpected RPC method: '+method)
        return {'jsonrpc':'2.0','id':1,'result':result}


@pytest.mark.asyncio
@pytest.mark.parametrize('fallback,rewards', [(False,True),(True,True),(False,False)])
async def test_eoa_signs_actual_value_nonce_chain_and_fees(fallback, rewards):
    rpc = LocalEOARPC(fail_estimate=fallback,rewards=rewards)
    provider = EOAWalletProvider(KEY, Web3(rpc), 84532)
    receipt = await provider.send_transaction(TransactionRequest(ADDRESS,'0x1234','123'))
    raw = rpc.sent[0][0]
    assert receipt.success is True
    assert receipt.hash == Web3.keccak(raw).hex()
    assert Account.recover_transaction(raw) == provider.get_address()
    fields = rlp.decode(raw[1:])
    integer = lambda i: int.from_bytes(fields[i], 'big')
    assert integer(0) == 84532 and integer(1) == 5
    assert integer(4) == (500000 if fallback else 42000)
    assert integer(6) == 123 and fields[7] == bytes.fromhex('1234')
    priority = 2 if rewards else 1000000000
    assert integer(2) == priority and integer(3) == 200+priority
    info = provider.get_wallet_info()
    assert info.tier == 'eoa' and info.gas_sponsored is False
    assert info.supports_batching is False and info.chain_id == 84532


@pytest.mark.asyncio
@pytest.mark.parametrize('statuses,count,success', [((1,1),2,True),((0,),1,False),((1,0),2,False)])
async def test_eoa_batch_stops_on_failed_receipt(statuses,count,success):
    rpc = LocalEOARPC(statuses=statuses)
    provider = EOAWalletProvider(KEY, Web3(rpc), 84532)
    receipt = await provider.send_batch_transaction([TransactionRequest(ADDRESS,'0x'),TransactionRequest(ADDRESS,'0x')])
    assert len(rpc.sent) == count and receipt.success is success
    with pytest.raises(ValueError, match='at least one'):
        await provider.send_batch_transaction([])
    assert len(rpc.sent) == count


@pytest.mark.asyncio
@pytest.mark.parametrize('method,wire', [('get_paymaster_stub_data','pm_getPaymasterStubData'),('get_paymaster_data','pm_getPaymasterData')])
@pytest.mark.parametrize('primary_failure', [None,'http','rpc','transport'])
async def test_paymaster_serializes_network_and_uses_backup_only_on_failure(monkeypatch,method,wire,primary_failure):
    seen = []
    original_client = httpx.AsyncClient
    def handler(request):
        body = json.loads(request.content)
        seen.append((request.url.host,body))
        if request.url.host == 'primary.invalid' and primary_failure:
            if primary_failure == 'transport': raise httpx.ConnectError('offline',request=request)
            if primary_failure == 'http': return httpx.Response(503,text='unavailable')
            return httpx.Response(200,json={'error':{'code':-32000,'message':'declined','data':'policy'}})
        return httpx.Response(200,json={'result':{'paymasterAndData':'0xabc123'}})
    monkeypatch.setattr('agirails.wallet.aa.paymaster_client.httpx.AsyncClient',lambda **kw: original_client(transport=httpx.MockTransport(handler),**kw))
    client = PaymasterClient(PaymasterConfig('https://primary.invalid',84532,backup_url='https://backup.invalid'))
    operation = UserOperationV06(sender=ADDRESS,nonce=7,call_gas_limit=120000)
    result = await getattr(client,method)(operation)
    assert result.paymaster_and_data == '0xabc123'
    assert [host for host,_ in seen] == (['primary.invalid','backup.invalid'] if primary_failure else ['primary.invalid'])
    assert [body['id'] for _,body in seen] == list(range(1,len(seen)+1))
    for _,body in seen:
        assert body['method'] == wire
        op,entrypoint,chain,context = body['params']
        assert op['sender'] == ADDRESS and op['nonce'] == '0x7'
        assert op['callGasLimit'] == hex(120000)
        assert (entrypoint,chain,context) == (ENTRYPOINT_V06,hex(84532),{})


@pytest.mark.asyncio
@pytest.mark.parametrize('backup', [False,True])
async def test_unavailable_sponsorship_raises_without_pretending_success(monkeypatch,backup):
    original_client = httpx.AsyncClient
    hosts=[]
    def handler(request):
        hosts.append(request.url.host)
        return httpx.Response(200,json={'error':{'code':-1,'message':'declined'}})
    monkeypatch.setattr('agirails.wallet.aa.paymaster_client.httpx.AsyncClient',lambda **kw: original_client(transport=httpx.MockTransport(handler),**kw))
    client=PaymasterClient(PaymasterConfig('https://primary.invalid',84532,backup_url='https://backup.invalid' if backup else None))
    with pytest.raises(PaymasterError,match='both Coinbase and Pimlico' if backup else 'No backup'):
        await client.get_paymaster_data(UserOperationV06(sender=ADDRESS))
    assert len(hosts) == (2 if backup else 1)


@pytest.mark.parametrize('kind', ['request','response','delivery'])
@pytest.mark.parametrize('with_contract', [False,True])
def test_legacy_typed_messages_recover_owner_and_reject_tampering(kind,with_contract):
    signer = MessageSigner(KEY,chain_id=84532,verifying_contract=ADDRESS if with_contract else '')
    if kind == 'request':
        signed = signer.sign_request(ServiceRequest('echo',HASH,1000000,1700000000,provider=ADDRESS))
        field = 'budget'
    elif kind == 'response':
        signed = signer.sign_response(ServiceResponse(HASH,HASH,1))
        field = 'status'
    else:
        signed = signer.sign_delivery_proof(DeliveryProof(HASH,HASH,attestation_uid=HASH))
        field = 'timestamp'
    assert signer.verify_signature(signed)
    assert signer.verify_signature(signed,expected_signer=signer.address.lower())
    assert not signer.verify_signature(signed,expected_signer=ADDRESS)
    bad = copy.deepcopy(signed)
    bad.message[field] += 1
    assert not signer.verify_signature(bad)
    bad = copy.deepcopy(signed);bad.message_type='unsupported'
    assert not signer.verify_signature(bad)
    bad = copy.deepcopy(signed);bad.signature=''
    assert not signer.verify_signature(bad)
    bad = copy.deepcopy(signed);bad.signature='0xzz'
    assert not signer.verify_signature(bad,reject_malleable=False)
    high = copy.deepcopy(signed)
    parts = SignatureComponents.from_signature(high.signature)
    high.signature=SignatureComponents(27 if parts.v==28 else 28,parts.r,(SECP256K1_N-int.from_bytes(parts.s,'big')).to_bytes(32,'big')).to_hex()
    assert not signer.verify_signature(high)
    assert signer.verify_signature(high,reject_malleable=False)


@pytest.mark.parametrize('kind',['actp_kernel','escrow_vault'])
def test_message_domain_selects_configured_contract(kind):
    signer=MessageSigner.from_config(KEY,BASE_SEPOLIA,contract_type=kind)
    assert signer.domain.verifying_contract == getattr(BASE_SEPOLIA.contracts,kind)
    assert signer.domain.chain_id == 84532
    with pytest.raises(ValueError,match='Unknown contract'):
        MessageSigner.from_config(KEY,BASE_SEPOLIA,contract_type='unknown')


@pytest.mark.parametrize('with_contract',[False,True])
def test_modern_delivery_schema_and_ambiguous_payloads(with_contract):
    signer=MessageSigner(KEY, chain_id=84532,verifying_contract=ADDRESS if with_contract else '')
    proof=DeliveryProofMessage(HASH,'did:ethr:84532:'+signer.address,'did:ethr:84532:'+ADDRESS,'bafy-result',HASH,HASH,1700000000,84532,4)
    signed=signer.sign_delivery_proof_message(proof)
    assert signer.verify_signature(signed)
    tampered=copy.deepcopy(signed);tampered.message['nonce']+=1
    assert not signer.verify_signature(tampered)
    missing=copy.deepcopy(signed);del missing.message['txId']
    assert not signer.verify_signature(missing)
    ambiguous=copy.deepcopy(signed)
    ambiguous.message.update(transactionId=HASH,outputHash=HASH,attestationUid=HASH,timestamp=1700000000)
    assert not signer.verify_signature(ambiguous)
    malformed=copy.deepcopy(signed);malformed.message=None
    assert not signer.verify_signature(malformed)
