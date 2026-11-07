"""Snapshot native and unified x402 HTTP options before asynchronous requests."""

import json
from typing import Any, Optional, Union

from agirails.types.x402 import X402HttpMethod


def extract_http_options(
    params: Any, native: bool
) -> tuple[X402HttpMethod, dict[str, str], Optional[str], Optional[str]]:
    method: X402HttpMethod = "GET"
    request_headers: dict[str, str] = {}
    request_body: Optional[str] = None
    content_type: Optional[str] = None
    if native:
        method = params.method or "GET"
        request_headers = dict(params.headers or {})
        request_body = serialize_body(params.body)
        content_type = params.content_type
        if content_type is None and params.body and method != "GET":
            content_type = "application/json"
    else:
        method = getattr(params, "http_method", None) or "GET"
        request_headers = dict(getattr(params, "http_headers", None) or {})
        request_body = serialize_body(getattr(params, "http_body", None))
        if request_body is not None and method != "GET":
            content_type = "application/json"
    return method, request_headers, request_body, content_type


def serialize_body(
    body: Optional[Union[str, dict[str, Any]]],
) -> Optional[str]:
    if body is None:
        return None
    if isinstance(body, str):
        return body
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8")
    return json.dumps(body)
