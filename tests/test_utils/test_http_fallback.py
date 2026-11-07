"""Exercise real stdlib HTTP framing without external network or credentials."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError

import pytest

from agirails.api import agirails_app, discover
from agirails.utils.http import request_http


@pytest.fixture(scope="module")
def http_origin():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", self.path.split("?", 1)[1])
                self.end_headers()
                return
            if self.path.startswith("/error"):
                self.send_error(503)
                return
            body = {
                "path": self.path,
                "method": "GET",
                "agents": [],
                "total": 0,
                "available": True,
                "accept": self.headers.get("Accept"),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"method": "POST", "body": data}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    worker.join()


@pytest.mark.parametrize("url", ["file:///tmp/unused", "data:application/json,{}", "ftp://localhost/a", "relative"])
def test_non_http_schemes_are_rejected_before_open(url):
    with pytest.raises(URLError, match="Only HTTP and HTTPS"):
        request_http(url, timeout=0.1)


@pytest.mark.parametrize("target", ["file:///tmp/unused", "data:text/plain,unused", "ftp://127.0.0.1/a"])
def test_redirects_cannot_switch_to_a_non_http_protocol(http_origin, target):
    with pytest.raises((URLError, HTTPError)):
        request_http(f"{http_origin}/redirect?{target}", timeout=1)


def test_http_redirect_retains_normal_http_response(http_origin):
    with request_http(f"{http_origin}/redirect?{http_origin}/ok", timeout=1) as response:
        assert response.status == 200
        assert json.load(response)["path"] == "/ok"


@pytest.fixture
def stdlib_clients(monkeypatch, http_origin):
    for module in (agirails_app, discover):
        monkeypatch.setattr(module, "_HAS_HTTPX", False)
        monkeypatch.setattr(module, "_HAS_AIOHTTP", False)
        monkeypatch.setattr(module, "AGIRAILS_APP_BASE_URL", http_origin)


@pytest.mark.asyncio
async def test_get_and_post_fallback_preserve_headers_and_json(stdlib_clients, http_origin):
    result = await agirails_app._get(f"{http_origin}/ok", timeout=1)
    assert result["method"] == "GET"
    assert result["accept"] == "application/json"
    result = await agirails_app._post(f"{http_origin}/ok", {"amount": "250000"}, timeout=1)
    assert result == {"method": "POST", "body": {"amount": "250000"}}


@pytest.mark.asyncio
async def test_slug_and_discovery_use_supported_endpoints(stdlib_clients):
    result = await agirails_app.check_slug("test agent")
    assert result["available"] is True
    assert result["path"].endswith("check-slug?slug=test%20agent")
    result = await discover.discover_agents()
    assert result.agents == []
    assert result.total == 0


@pytest.mark.asyncio
async def test_http_error_is_not_reinterpreted_as_success(stdlib_clients, http_origin):
    with pytest.raises(HTTPError) as raised:
        await agirails_app._get(f"{http_origin}/error", timeout=1)
    assert raised.value.code == 503


@pytest.mark.asyncio
async def test_profile_and_claim_payloads_preserve_wire_names(stdlib_clients):
    profile = agirails_app.UpsertAgentParams(
        slug="test", agent_id="42", wallet="0x123", config_cid="bafy-test",
        config_hash="0x456", signature="example-signature", message="claim", timestamp=123,
        network="base-sepolia",
    )
    result = await agirails_app.upsert_agent(profile)
    assert result["body"] == {
        "slug": "test", "agentId": "42", "wallet": "0x123", "configCid": "bafy-test",
        "configHash": "0x456", "signature": "example-signature", "message": "claim",
        "timestamp": 123, "network": "base-sepolia",
    }


def test_ftp_redirect_is_rejected_by_the_explicit_protocol_guard(http_origin):
    with pytest.raises(URLError, match="Only HTTP and HTTPS"):
        request_http(f"{http_origin}/redirect?ftp://127.0.0.1/unused", timeout=1)
