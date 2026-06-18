"""Parity tests for the Agent structured delivery proof on completion.

Mirrors TS ``Agent.processJob`` (Agent.ts:1842-1859, 1898-1906): on job
completion the agent builds an authenticated, structured delivery proof
(``ProofGenerator.generateDeliveryProof`` + the ``{...proof, result}``
wrapper) and attaches it to the MockRuntime tx state — NOT just the
ABI-encoded disputeWindow uint256 the kernel needs for the DELIVERED hop.

The on-chain DELIVERED proof param remains the disputeWindow bytes; the
rich JSON is what a buyer reads off ``tx.delivery_proof`` (mock path) and
what the cross-SDK delivery-verification surface expects.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from eth_account import Account
from eth_hash.auto import keccak

from agirails.client import ACTPClient
from agirails.level1.agent import Agent
from agirails.level1.config import AgentConfig
from agirails.level1.job import Job
from agirails.runtime.base import CreateTransactionParams


REQUESTER = Account.create().address
PROVIDER = Account.create().address


async def _committed_in_progress_tx(client: ACTPClient, amount: str) -> str:
    """Create a tx and drive it COMMITTED → IN_PROGRESS via the mock runtime."""
    runtime = client.runtime
    await runtime.mint_tokens(REQUESTER, str(int(amount) * 4))
    tx_id = await runtime.create_transaction(
        CreateTransactionParams(
            provider=PROVIDER,
            requester=REQUESTER,
            amount=amount,
            deadline=runtime.time.now() + 3600,
            dispute_window=172800,
            service_description="echo",
        )
    )
    await runtime.link_escrow(tx_id, amount)  # → COMMITTED
    await runtime.transition_state(tx_id, "IN_PROGRESS")
    return tx_id


def _job(tx_id: str) -> Job:
    return Job(
        id=tx_id,
        service="echo",
        input={},
        budget=10.0,
        deadline=datetime.now() + timedelta(hours=1),
        requester=REQUESTER,
        metadata={"disputeWindow": 172800},
    )


@pytest.mark.asyncio
async def test_structured_proof_attached_to_mock_state():
    """_complete_job attaches the structured proof (not the disputeWindow bytes)."""
    client = await ACTPClient.create(mode="mock", requester_address=REQUESTER)
    tx_id = await _committed_in_progress_tx(client, "10000000")

    agent = Agent(AgentConfig(name="provider", network="mock"))
    agent._client = client

    handler_output = {"reflection": "hello"}
    await agent._complete_job(_job(tx_id), handler_output)

    tx = await client.runtime.get_transaction(tx_id)
    # The DELIVERED transition succeeded.
    assert tx.state.value == "DELIVERED"

    # tx.delivery_proof is the STRUCTURED JSON, not the disputeWindow uint256.
    proof = json.loads(tx.delivery_proof)
    assert proof["type"] == "delivery.proof"
    assert proof["txId"] == tx_id
    # contentHash = keccak256(utf8(JSON.stringify(result))) — TS parity.
    expected_deliverable = json.dumps(
        handler_output, separators=(",", ":"), ensure_ascii=False
    )
    expected_hash = "0x" + keccak(expected_deliverable.encode("utf-8")).hex()
    assert proof["contentHash"] == expected_hash
    # Original result is spread back in for convenience.
    assert proof["result"] == handler_output
    # Enforced metadata fields.
    assert proof["metadata"]["service"] == "echo"
    assert proof["metadata"]["size"] == len(expected_deliverable.encode("utf-8"))
    assert proof["metadata"]["mimeType"] == "application/octet-stream"


@pytest.mark.asyncio
async def test_string_result_hashes_raw_string():
    """A string handler result hashes the raw string (TS deliverable branch)."""
    client = await ACTPClient.create(mode="mock", requester_address=REQUESTER)
    tx_id = await _committed_in_progress_tx(client, "10000000")

    agent = Agent(AgentConfig(name="provider", network="mock"))
    agent._client = client

    await agent._complete_job(_job(tx_id), "plain text output")

    tx = await client.runtime.get_transaction(tx_id)
    proof = json.loads(tx.delivery_proof)
    expected_hash = "0x" + keccak(b"plain text output").hex()
    assert proof["contentHash"] == expected_hash
    assert proof["result"] == "plain text output"


@pytest.mark.asyncio
async def test_blockchain_runtime_path_is_noop_for_attach(monkeypatch):
    """When the runtime has no _state_manager, the attach is a no-op (no raise)."""
    client = await ACTPClient.create(mode="mock", requester_address=REQUESTER)
    tx_id = await _committed_in_progress_tx(client, "10000000")

    agent = Agent(AgentConfig(name="provider", network="mock"))
    agent._client = client

    # Directly exercise the attach helper against a runtime missing the
    # state manager (BlockchainRuntime shape) — MUST NOT raise.
    class _NoStateMgr:
        pass

    client._runtime = _NoStateMgr()
    await agent._attach_mock_delivery_proof(tx_id, '{"type":"delivery.proof"}')
