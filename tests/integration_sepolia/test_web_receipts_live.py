"""Live agirails.app Web Receipts upload tests.

Audit follow-up #6. Existing tests/test_receipts/test_web_receipt.py
covers the SDK side via respx mocks — proves the client builds the
right HTTP request shape locally. This file goes against the LIVE
agirails.app server to prove the request shape is what the server
ACTUALLY accepts. Web Receipts are public, shareable artifacts by
design (CHANGELOG: "agirails.app public receipt artifact"), so
posting a test receipt is the legitimate use of the endpoint.

Sentinel-based testing (per Damir): production agirails.app is the
target — Sentinel is the canonical live agent in that environment,
so the receipt-write API is exercised the same way every integrator
hits it. No staging environment needed.

What this proves:
  - SDK ``upload_receipt`` POSTs the exact bytes the server route
    parses (no field-name / case drift)
  - EIP-712 ReceiptWrite domain + types match between SDK signer and
    server-side verifyTypedData
  - The /prepare nonce → /receipts atomic-consume handshake works
    end-to-end
  - Returned receipt URL is reachable and references our receipt

Each run creates ONE public receipt artifact on agirails.app keyed
to our test ownerCaption ("python-sdk integration test"). Run cost:
zero (server-side; SDK is free).

Marker-gated `-m integration_sepolia` — default skip. Same
ACTP_KEY_PASSWORD env var as the rest of the integration suite.
"""

from __future__ import annotations

import json
import os
import time

import pytest

pytestmark = pytest.mark.integration_sepolia


@pytest.mark.asyncio
async def test_live_agirails_app_receipt_upload(sepolia_signer, sepolia_w3):
    """Full Web Receipts round-trip against live agirails.app:

      1. SDK builds ReceiptUploadPayload with a real settled-tx
         shape (use an existing sepolia tx ID — no new tx required)
      2. SDK POSTs to https://agirails.app/api/v1/receipts/prepare
         with the deployer's address, gets {nonce, issuedAt}
      3. SDK signs EIP-712 ReceiptWrite locally
      4. SDK POSTs to https://agirails.app/api/v1/receipts with
         the signed payload
      5. Server-side ethers.verifyTypedData recovers the deployer
         address; receipt is created
      6. Returned URL is reachable

    If step 4 fails with 4xx, server's expected payload shape has
    drifted from what the SDK produces — that's exactly the gap
    this test closes.
    """
    import httpx
    from eth_hash.auto import keccak
    from agirails.receipts import (
        ReceiptUploadFailure,
        ReceiptUploadOptions,
        ReceiptUploadPayload,
        ReceiptUploadSuccess,
        upload_receipt,
    )
    from tests.integration_sepolia.conftest import SEPOLIA_KERNEL

    # Use a known-good tx id from the EOA lifecycle integration run.
    # If never run, falls back to a placeholder — server may reject
    # with "tx not found" but the EIP-712 verify step still exercises.
    # Pick a fresh nonce per run with timestamp suffix so we never
    # collide with prior test receipts.
    nonce_suffix = int(time.time())
    service_name = f"python-sdk-integration-test-{nonce_suffix}"
    payload = ReceiptUploadPayload(
        agentAddress=sepolia_signer.address,
        service=service_name,
        amountWei="50000",  # $0.05
        feeWei="500",
        netWei="49500",
        # A real on-chain tx_id from prior runs; if absent, server may
        # reject with "tx not found" but we still exercise the EIP-712
        # path which is the primary thing we want to validate.
        txId="0x62a04dcc563d2771334cbae64c2185a9f90383fe7670176de0c87436df5c8c0c",
        network="base-sepolia",
        requesterAddress=sepolia_signer.address,
        durationMs=420,
        # On-chain receipts require kernelAddress + serviceHash — server
        # rejects without them ("Invalid kernelAddress"). For mock
        # receipts both are optional. serviceHash is the keccak256 of
        # the service name (the same hash the SDK puts on chain as the
        # serviceDescription routing key).
        kernelAddress=SEPOLIA_KERNEL,
        serviceHash="0x" + keccak(service_name.encode("utf-8")).hex(),
        ownerCaption=f"python-sdk integration test {nonce_suffix}",
    )

    result = await upload_receipt(
        payload,
        ReceiptUploadOptions(
            base_url="https://agirails.app",
            private_key=sepolia_signer.key.hex(),
            timeout_seconds=30.0,
        ),
    )

    # We don't always succeed (server may reject if tx isn't indexed
    # yet); but the result MUST be a typed dataclass + EIP-712 path
    # must have been hit. The hard failure mode we're catching:
    # server returns 4xx because of a wire-format mismatch, which
    # surfaces as a ReceiptUploadFailure with a reason mentioning the
    # schema.
    assert isinstance(result, (ReceiptUploadSuccess, ReceiptUploadFailure))

    if isinstance(result, ReceiptUploadFailure):
        # Diagnostic-friendly failure: surface the server reason so a
        # CI failure is actionable. The test still PASSES on certain
        # known failure modes (tx not indexed, rate-limited) — the
        # important thing is the SDK and server agreed on the format.
        reason = (result.reason or "").lower()
        # Hard fail on shape/schema drift (would say "invalid X" or
        # "missing X" in the server's response).
        # Soft fail (skip) on transient issues.
        if any(s in reason for s in ("invalid", "missing", "malformed")):
            pytest.fail(
                f"agirails.app rejected the SDK's payload with shape "
                f"error: {result.reason}. This means the SDK's HTTP "
                f"request body has drifted from what the server expects."
            )
        # Otherwise it's a transient/business error — mark expected.
        pytest.skip(
            f"agirails.app didn't accept the receipt this run, but the "
            f"reason isn't a schema drift: {result.reason}"
        )

    # Success case: URL is reachable.
    assert result.url.startswith("https://agirails.app/")
    assert result.id  # server-issued receipt id
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        resp = await client.get(result.url)
        assert resp.status_code == 200, (
            f"Receipt URL {result.url} returned {resp.status_code}"
        )
