"""
Tests for the native AWS Signature Version 4 implementation used by FilebaseClient.

These verify the SigV4 canonical-request, signing-key derivation, and final
signature byte-for-byte against AWS's published reference vectors:

  1. "Examples of how to derive a signing key for Signature Version 4"
     (AWS docs worked example) — exercises _derive_signing_key.
  2. The "Signature Version 4 test suite" get-vanilla example — exercises the
     full canonical-request -> string-to-sign -> signature pipeline.

They also assert the Filebase upload path actually attaches an Authorization
header (replacing the old HTTP Basic auth that Filebase S3 rejects with 403).
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agirails.storage.filebase_client import (
    FilebaseClient,
    _derive_signing_key,
    sign_aws_v4,
)
from agirails.storage.types import FilebaseConfig, CircuitBreakerConfig


# =============================================================================
# AWS published reference vectors
# =============================================================================

# AWS docs "derive a signing key" worked example.
# Secret key uses '+' (not '/') — this is the canonical docs value.
DERIVE_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
DERIVE_DATESTAMP = "20150830"
DERIVE_REGION = "us-east-1"
DERIVE_SERVICE = "iam"
DERIVE_EXPECTED_SIGNING_KEY_HEX = (
    "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
)

# AWS "Signature Version 4 test suite" get-vanilla example.
GET_VANILLA_ACCESS_KEY = "AKIDEXAMPLE"
GET_VANILLA_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
GET_VANILLA_REGION = "us-east-1"
GET_VANILLA_SERVICE = "service"
GET_VANILLA_HOST = "example.amazonaws.com"
GET_VANILLA_AMZDATE = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)
GET_VANILLA_EXPECTED_SIGNATURE = (
    "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
)


class TestSigningKeyDerivation:
    """Verify _derive_signing_key against the AWS docs worked example."""

    def test_signing_key_matches_aws_docs_example(self) -> None:
        key = _derive_signing_key(
            DERIVE_SECRET, DERIVE_DATESTAMP, DERIVE_REGION, DERIVE_SERVICE
        )
        assert key.hex() == DERIVE_EXPECTED_SIGNING_KEY_HEX


class TestGetVanillaVector:
    """Verify the full SigV4 pipeline against the AWS get-vanilla test vector."""

    def test_get_vanilla_signature(self) -> None:
        # The get-vanilla request is a bare GET / on the service host with only
        # the Host and X-Amz-Date headers signed (no Content-Type, empty body).
        # The AWS test suite predates x-amz-content-sha256, so it is excluded
        # from the SIGNED header set (sign_content_sha256=False) to reproduce
        # the published signature byte-for-byte.
        url = f"https://{GET_VANILLA_HOST}/"
        headers = sign_aws_v4(
            method="GET",
            url=url,
            region=GET_VANILLA_REGION,
            service=GET_VANILLA_SERVICE,
            access_key=GET_VANILLA_ACCESS_KEY,
            secret_key=GET_VANILLA_SECRET_KEY,
            headers=None,
            payload=b"",
            now=GET_VANILLA_AMZDATE,
            sign_content_sha256=False,
        )

        auth = headers["Authorization"]
        # Algorithm + credential scope must match the suite exactly.
        assert auth.startswith("AWS4-HMAC-SHA256 ")
        assert (
            "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
            in auth
        )
        # For get-vanilla only host;x-amz-date are signed.
        assert "SignedHeaders=host;x-amz-date" in auth
        # The signature itself must be byte-exact.
        assert f"Signature={GET_VANILLA_EXPECTED_SIGNATURE}" in auth

    def test_amz_date_and_content_sha_headers(self) -> None:
        headers = sign_aws_v4(
            method="GET",
            url=f"https://{GET_VANILLA_HOST}/",
            region=GET_VANILLA_REGION,
            service=GET_VANILLA_SERVICE,
            access_key=GET_VANILLA_ACCESS_KEY,
            secret_key=GET_VANILLA_SECRET_KEY,
            now=GET_VANILLA_AMZDATE,
        )
        assert headers["x-amz-date"] == "20150830T123600Z"
        # SHA256 of empty payload.
        assert headers["x-amz-content-sha256"] == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )


class TestSignAwsV4Properties:
    """Property/edge-case tests for the SigV4 signer."""

    def test_content_type_is_signed_when_present(self) -> None:
        # When Content-Type is provided it must appear in SignedHeaders.
        headers = sign_aws_v4(
            method="PUT",
            url="https://s3.filebase.com/bucket/key.json",
            region="us-east-1",
            service="s3",
            access_key="AKID",
            secret_key="SECRET",
            headers={"Content-Type": "application/json"},
            payload=b'{"a":1}',
            now=GET_VANILLA_AMZDATE,
        )
        auth = headers["Authorization"]
        assert "content-type" in auth  # appears in SignedHeaders list
        assert "host" in auth
        assert "x-amz-content-sha256" in auth
        assert "x-amz-date" in auth
        # Original header preserved.
        assert headers["Content-Type"] == "application/json"

    def test_payload_hash_reflects_body(self) -> None:
        import hashlib

        body = b"hello-filebase"
        headers = sign_aws_v4(
            method="PUT",
            url="https://s3.filebase.com/bucket/k",
            region="us-east-1",
            service="s3",
            access_key="AKID",
            secret_key="SECRET",
            payload=body,
            now=GET_VANILLA_AMZDATE,
        )
        assert headers["x-amz-content-sha256"] == hashlib.sha256(body).hexdigest()

    def test_signature_is_deterministic_for_fixed_time(self) -> None:
        kwargs = dict(
            method="PUT",
            url="https://s3.filebase.com/b/k",
            region="us-east-1",
            service="s3",
            access_key="AKID",
            secret_key="SECRET",
            payload=b"data",
            now=GET_VANILLA_AMZDATE,
        )
        a = sign_aws_v4(**kwargs)["Authorization"]
        b = sign_aws_v4(**kwargs)["Authorization"]
        assert a == b

    def test_different_keys_yield_different_signature(self) -> None:
        base = dict(
            method="PUT",
            url="https://s3.filebase.com/b/k",
            region="us-east-1",
            service="s3",
            payload=b"data",
            now=GET_VANILLA_AMZDATE,
        )
        a = sign_aws_v4(access_key="AKID", secret_key="SECRET1", **base)
        b = sign_aws_v4(access_key="AKID", secret_key="SECRET2", **base)
        assert a["Authorization"] != b["Authorization"]


# =============================================================================
# FilebaseClient SigV4 wiring (replaces HTTP Basic auth)
# =============================================================================


@pytest.fixture
def filebase_config() -> FilebaseConfig:
    return FilebaseConfig(
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        bucket="test-bucket",
        endpoint="https://s3.filebase.com",
        gateway_url="https://ipfs.filebase.io/ipfs/",
        timeout=30000,
        circuit_breaker=CircuitBreakerConfig(enabled=False),
    )


class TestFilebaseUploadSigV4:
    """Ensure the upload path uses SigV4 (Authorization header), not Basic auth."""

    @pytest.mark.asyncio
    async def test_upload_attaches_sigv4_authorization(
        self, filebase_config: FilebaseConfig
    ) -> None:
        client = FilebaseClient(filebase_config)

        mock_put_response = MagicMock()
        mock_put_response.status_code = 200
        mock_put_response.headers = {"x-amz-meta-cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await client.upload(b"hello", filename="obj.bin")

            call = mock_client.put.call_args
            sent_headers = call.kwargs["headers"]

            # SigV4 Authorization header is present and correctly scoped.
            assert "Authorization" in sent_headers
            auth = sent_headers["Authorization"]
            assert auth.startswith("AWS4-HMAC-SHA256 ")
            assert (
                f"Credential={filebase_config.access_key}/" in auth
            )
            assert "/us-east-1/s3/aws4_request" in auth
            assert "Signature=" in auth
            # x-amz-* signing headers present.
            assert "x-amz-date" in sent_headers
            assert "x-amz-content-sha256" in sent_headers
            # Content-Type preserved (and signed).
            assert sent_headers["Content-Type"] == "application/octet-stream"
            # NO HTTP Basic auth tuple is passed anymore.
            assert "auth" not in call.kwargs

    @pytest.mark.asyncio
    async def test_upload_head_fallback_is_also_signed(
        self, filebase_config: FilebaseConfig
    ) -> None:
        client = FilebaseClient(filebase_config)

        # PUT returns no CID -> triggers signed HEAD fallback.
        mock_put_response = MagicMock()
        mock_put_response.status_code = 200
        mock_put_response.headers = {}

        mock_head_response = MagicMock()
        mock_head_response.status_code = 200
        mock_head_response.headers = {
            "x-amz-meta-cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_put_response)
            mock_client.head = AsyncMock(return_value=mock_head_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            await client.upload(b"hello", filename="obj.bin")

            head_call = mock_client.head.call_args
            head_headers = head_call.kwargs["headers"]
            assert "Authorization" in head_headers
            assert head_headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")
            # HEAD signs an empty payload.
            assert head_headers["x-amz-content-sha256"] == (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            assert "auth" not in head_call.kwargs
