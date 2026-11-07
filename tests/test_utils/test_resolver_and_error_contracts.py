"""Real loopback DID resolution and operator-facing storage error contracts."""

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from agirails.protocol.did import DIDResolver
from agirails.errors import storage


@pytest.fixture
def resolver_origin():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.server.calls.append(self.path)
            with self.server.guard:
                self.server.active+=1
                self.server.peak=max(self.server.peak,self.server.active)
            try:
                if self.path.startswith('/slow'):time.sleep(0.01)
                if self.path.startswith('/error'):
                    self.send_error(503);return
                did=unquote(self.path.rsplit('/',1)[-1])
                body={} if self.path.startswith('/missing') else {'didDocument':{'id':'invalid' if self.path.startswith('/invalid') else did,'service':[{'id':did+'#api','type':'AgentAPI','serviceEndpoint':'https://agent.invalid'}]}}
                self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
                self.wfile.write(b'not json' if self.path.startswith('/broken') else json.dumps(body).encode())
            finally:
                with self.server.guard:self.server.active-=1
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.calls=[];server.active=0;server.peak=0;server.guard=threading.Lock()
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    yield f'http://127.0.0.1:{server.server_port}',server
    server.shutdown();server.server_close();worker.join()


@pytest.mark.asyncio
async def test_unknown_did_method_uses_real_http_document_and_cache(resolver_origin):
    url,server=resolver_origin
    resolver=DIDResolver(resolver_url=url+'/ok',http_timeout=1)
    did='did:web:base:node'
    first=await resolver.resolve(did)
    assert str(first.id)==did and first.service[0]['serviceEndpoint']=='https://agent.invalid'
    assert await resolver.resolve(did) is first
    assert len(server.calls)==1
    assert await resolver.resolve(did,use_cache=False) is not first
    assert len(server.calls)==2


@pytest.mark.asyncio
@pytest.mark.parametrize('path',['error','missing','invalid','broken'])
async def test_resolution_failure_returns_none_and_does_not_cache_success(resolver_origin,path):
    url,server=resolver_origin
    resolver=DIDResolver(resolver_url=url+'/'+path,http_timeout=1)
    assert await resolver.resolve('did:web:base:node') is None
    assert await resolver.resolve('did:web:base:node') is None
    assert len(server.calls)==2


@pytest.mark.asyncio
async def test_http_resolution_obeys_concurrency_bound(resolver_origin):
    url,server=resolver_origin
    resolver=DIDResolver(resolver_url=url+'/slow',max_concurrent_requests=1,http_timeout=1)
    documents=await asyncio.gather(*(resolver.resolve(f'did:web:base:node{i}') for i in range(3)))
    assert [str(doc.id) for doc in documents]==[f'did:web:base:node{i}' for i in range(3)]
    assert server.peak==1 and len(server.calls)==3


@pytest.mark.parametrize('kind,args,kwargs,code,attributes',[
    ('InvalidCIDError',('bad-cid',),{'reason':'invalid encoding'},'INVALID_CID',{'cid':'bad-cid','reason':'invalid encoding'}),
    ('UploadTimeoutError',(1500,),{'file_size':100,'gateway':'https://gateway.invalid'},'UPLOAD_TIMEOUT',{'timeout_ms':1500,'file_size':100}),
    ('DownloadTimeoutError',('bafy-cid',1500),{'gateway':'https://gateway.invalid'},'DOWNLOAD_TIMEOUT',{'cid':'bafy-cid','timeout_ms':1500}),
    ('FileSizeLimitExceededError',(100,90),{},'FILE_SIZE_LIMIT_EXCEEDED',{'file_size':100,'max_size':90}),
    ('StorageAuthenticationError',(),{'gateway':'https://gateway.invalid'},'STORAGE_AUTH_ERROR',{'gateway':'https://gateway.invalid'}),
    ('StorageRateLimitError',(500,),{'gateway':'https://gateway.invalid'},'STORAGE_RATE_LIMIT',{'retry_after_ms':500}),
    ('ContentNotFoundError',('bafy-cid',),{},'CONTENT_NOT_FOUND',{'cid':'bafy-cid'}),
    ('FilebaseUploadError',(),{'bucket':'bucket','key':'file'},'FILEBASE_UPLOAD_ERROR',{'bucket':'bucket','key':'file'}),
    ('FilebaseDownloadError',(),{'cid':'bafy-cid','gateway':'https://gateway.invalid'},'FILEBASE_DOWNLOAD_ERROR',{'cid':'bafy-cid','gateway':'https://gateway.invalid'}),
    ('ArweaveUploadError',(),{'node_url':'https://node.invalid','size_bytes':100},'ARWEAVE_UPLOAD_ERROR',{'node_url':'https://node.invalid','size_bytes':100}),
    ('ArweaveDownloadError',(),{'tx_id':'tx1','gateway':'https://gateway.invalid'},'ARWEAVE_DOWNLOAD_ERROR',{'tx_id':'tx1','gateway':'https://gateway.invalid'}),
    ('InsufficientFundsError',(10,50),{'currency':'AR'},'INSUFFICIENT_FUNDS',{'balance':10,'required':50,'currency':'AR'}),
    ('SSRFProtectionError',('http://blocked.invalid',),{'reason':'blocked'},'SSRF_PROTECTION_ERROR',{'url':'http://blocked.invalid','reason':'blocked'}),
    ('FileSizeLimitError',('too large',),{'file_size':100,'max_size':90},'FILE_SIZE_LIMIT',{'file_size':100,'max_size':90}),
    ('CircuitBreakerOpenError',(),{'gateway':'https://gateway.invalid','reset_at':1000},'CIRCUIT_BREAKER_OPEN',{'gateway':'https://gateway.invalid','reset_at':1000}),
])
def test_storage_failures_have_stable_codes_context_and_redacted_credentials(kind,args,kwargs,code,attributes,monkeypatch):
    monkeypatch.setattr('agirails.errors.base.DEBUG_MODE',False)
    error=getattr(storage,kind)(*args,**kwargs,details={'request_id':'r-1','api_key':'dummy-not-a-credential'})
    wire=error.to_dict()
    assert wire['code']==code and wire['message']
    assert wire['details']['request_id']=='r-1'
    assert wire['details']['api_key']=='[REDACTED]'
    assert error.to_dict(include_sensitive=True)['details']['api_key']=='dummy-not-a-credential'
    for name,value in attributes.items():assert getattr(error,name)==value
    assert json.loads(json.dumps(wire))['code']==code
