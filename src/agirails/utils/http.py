"""Standard-library HTTP fallback with an explicit protocol boundary."""

from typing import Any, Optional
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    UnknownHandler,
)


def _require_http(url: str) -> None:
    if urlsplit(url).scheme.lower() not in {"http", "https"}:
        raise URLError("Only HTTP and HTTPS URLs are supported")


class _HTTPRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_http(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _HTTPRequest(Request):
    def __init__(self, url, *, data=None, headers=None, method=None):
        _require_http(url)
        super().__init__(url, data=data, headers=headers or {}, method=method)


def request_http(
    url: str,
    *,
    timeout: float,
    headers: Optional[dict[str, str]] = None,
    data: Optional[bytes] = None,
    method: Optional[str] = None,
) -> Any:
    """Open HTTP(S), including redirects, without file/data/FTP handlers."""
    request = _HTTPRequest(url, data=data, headers=headers, method=method)
    opener = OpenerDirector()
    for handler in (
        ProxyHandler(),
        UnknownHandler(),
        HTTPHandler(),
        HTTPDefaultErrorHandler(),
        _HTTPRedirectHandler(),
        HTTPErrorProcessor(),
        HTTPSHandler(),
    ):
        opener.add_handler(handler)
    return opener.open(request, timeout=timeout)
