"""Parity tests for Agent job-decision events, bounded retry, ZeroHash
sole-handler raw-pay routing, the safe-error seam, and the ProviderOrchestrator
(BYO-brain) seam.

Mirrors TS Agent.ts:
  * emitJobDecision (job:declined / job:filtered) — Agent.ts:1402-1609,1651-1691
  * bounded retry + permanent-revert detection — Agent.ts:2020-2087
  * findServiceHandler ZeroHash sole-handler fallback — Agent.ts:1269-1299
  * safeEmitError no-crash-on-unhandled-error — Agent.ts:1029-1035
  * setProviderOrchestrator seam — Agent.ts:972-974

Agent.__init__ constructs asyncio primitives; sync builders are wrapped in
async tests so an event loop exists (same constraint as
test_agent_hash_routing.py).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from eth_hash.auto import keccak

from agirails.level1.agent import Agent
from agirails.level1.config import (
    AgentBehavior,
    AgentConfig,
    ServiceConfig,
    ServiceFilter,
)
from agirails.level1.job import Job
from agirails.level1.pricing import CostModel, PricingStrategy


def _hash(name: str) -> str:
    return "0x" + keccak(name.encode("utf-8")).hex()


def _job(budget: float = 10.0, service: str = "echo") -> Job:
    return Job(
        id="0x" + "ab" * 32,
        service=service,
        input={},
        budget=budget,
        deadline=datetime.now() + timedelta(hours=1),
        requester="0x" + "12" * 20,
    )


def _tx(service_description: str = "", amount: str = "10000000",
        requester: str = "0x" + "12" * 20, tx_id: str = "0x" + "ab" * 32):
    return SimpleNamespace(
        id=tx_id,
        amount=amount,
        requester=requester,
        deadline=int((datetime.now() + timedelta(hours=1)).timestamp()),
        service_description=service_description,
        dispute_window=172800,
    )


def _reg(agent: Agent, name: str):
    return agent._services[name]


# ============================================================================
# job:declined / job:filtered events
# ============================================================================


class TestJobDecisionEvents:
    @pytest.mark.asyncio
    async def test_budget_below_minimum_declines(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide(
            ServiceConfig(name="echo", filter=ServiceFilter(min_budget=5.0)),
            handler=h,
        )
        events = []
        agent.on("job:declined", lambda job, payload: events.append(payload))

        accepted = await agent._should_auto_accept(
            _job(budget=1.0), _reg(agent, "echo"), _tx(amount="1000000")
        )
        assert accepted is False
        assert len(events) == 1
        assert events[0]["reason"] == "budget_below_minimum"
        assert events[0]["minBudget"] == 5.0
        # Payload carries machine-readable jobId/requester/amount.
        assert events[0]["jobId"] == "0x" + "ab" * 32
        assert events[0]["amount"] == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_budget_above_maximum_declines(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide(
            ServiceConfig(name="echo", filter=ServiceFilter(max_budget=5.0)),
            handler=h,
        )
        events = []
        agent.on("job:declined", lambda job, payload: events.append(payload))

        accepted = await agent._should_auto_accept(
            _job(budget=100.0), _reg(agent, "echo"), _tx(amount="100000000")
        )
        assert accepted is False
        assert events[0]["reason"] == "budget_above_maximum"
        assert events[0]["maxBudget"] == 5.0

    @pytest.mark.asyncio
    async def test_custom_filter_emits_job_filtered(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide(
            ServiceConfig(
                name="echo",
                filter=ServiceFilter(custom=lambda job: False),
            ),
            handler=h,
        )
        filtered = []
        agent.on("job:filtered", lambda job, payload: filtered.append(payload))

        accepted = await agent._should_auto_accept(_job(), _reg(agent, "echo"), _tx())
        assert accepted is False
        assert filtered[0]["reason"] == "custom_filter"
        assert filtered[0]["filter"] == "custom"

    @pytest.mark.asyncio
    async def test_pricing_reject_emits_declined(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        # budget below cost; below_cost reject -> declined.
        agent.provide(
            ServiceConfig(
                name="echo",
                pricing=PricingStrategy(
                    cost=CostModel(base=5.0), below_cost="reject"
                ),
            ),
            handler=h,
        )
        declined = []
        agent.on("job:declined", lambda job, payload: declined.append(payload))

        accepted = await agent._should_auto_accept(
            _job(budget=1.0), _reg(agent, "echo"), _tx(amount="1000000")
        )
        assert accepted is False
        assert declined[0]["reason"] == "pricing_rejected"

    @pytest.mark.asyncio
    async def test_counter_offer_does_not_emit_decline(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        # budget above cost but below price; below_price counter-offer.
        agent.provide(
            ServiceConfig(
                name="echo",
                pricing=PricingStrategy(
                    cost=CostModel(base=1.0),
                    margin=0.5,  # price = 1.0/0.5 = 2.00
                    below_price="counter-offer",
                ),
            ),
            handler=h,
        )
        declined = []
        filtered = []
        agent.on("job:declined", lambda job, payload: declined.append(payload))
        agent.on("job:filtered", lambda job, payload: filtered.append(payload))

        # budget 1.50 is above cost 1.00 but below price 2.00 -> counter-offer.
        accepted = await agent._should_auto_accept(
            _job(budget=1.5), _reg(agent, "echo"), _tx(amount="1500000")
        )
        # Counter-offer keeps the job out of the accept pipeline...
        assert accepted is False
        # ...but is NOT a decline/filter (the agent responded with a price).
        assert declined == []
        assert filtered == []

    @pytest.mark.asyncio
    async def test_auto_accept_false_emits_filtered(self):
        agent = Agent(
            AgentConfig(name="agent", behavior=AgentBehavior(auto_accept=False))
        )

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        filtered = []
        agent.on("job:filtered", lambda job, payload: filtered.append(payload))

        accepted = await agent._should_auto_accept(_job(), _reg(agent, "echo"), _tx())
        assert accepted is False
        assert filtered[0]["reason"] == "auto_accept_disabled"

    @pytest.mark.asyncio
    async def test_auto_accept_callback_decline_emits_filtered(self):
        agent = Agent(
            AgentConfig(
                name="agent", behavior=AgentBehavior(auto_accept=lambda job: False)
            )
        )

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        filtered = []
        agent.on("job:filtered", lambda job, payload: filtered.append(payload))

        accepted = await agent._should_auto_accept(_job(), _reg(agent, "echo"), _tx())
        assert accepted is False
        assert filtered[0]["reason"] == "auto_accept_callback"

    @pytest.mark.asyncio
    async def test_listener_exception_does_not_break_decision(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide(
            ServiceConfig(name="echo", filter=ServiceFilter(min_budget=5.0)),
            handler=h,
        )

        def boom(job, payload):
            raise RuntimeError("listener blew up")

        agent.on("job:declined", boom)

        # A throwing listener must NOT propagate — the decision still returns.
        accepted = await agent._should_auto_accept(
            _job(budget=1.0), _reg(agent, "echo"), _tx(amount="1000000")
        )
        assert accepted is False


# ============================================================================
# Bounded retry + permanent-revert detection
# ============================================================================


class TestBoundedRetry:
    @pytest.mark.asyncio
    async def test_transient_failure_retries_until_max_attempts(self):
        agent = Agent(AgentConfig(name="agent"))
        job = _job()

        # First two failures are transient: NOT marked processed -> retryable.
        await agent._fail_job(job, "RPC timeout")
        assert not agent._processed_jobs.has(job.id)
        assert agent._job_attempts.get(job.id) == 1

        await agent._fail_job(job, "RPC timeout")
        assert not agent._processed_jobs.has(job.id)
        assert agent._job_attempts.get(job.id) == 2

        # Third failure hits MAX_JOB_ATTEMPTS -> marked processed (stop retry).
        await agent._fail_job(job, "RPC timeout")
        assert agent._processed_jobs.has(job.id)
        # Attempt counter cleared once we give up.
        assert agent._job_attempts.get(job.id) is None

    @pytest.mark.asyncio
    async def test_permanent_revert_marks_processed_immediately(self):
        agent = Agent(AgentConfig(name="agent"))
        job = _job()

        await agent._fail_job(job, "execution reverted: Invalid transition")
        # Permanent -> processed on the FIRST attempt, no retry.
        assert agent._processed_jobs.has(job.id)
        # No transient attempt counter recorded.
        assert agent._job_attempts.get(job.id) is None

    @pytest.mark.asyncio
    async def test_permanent_revert_hex_encoded_detected(self):
        agent = Agent(AgentConfig(name="agent"))
        job = _job()

        # Bundler simulation reverts surface the reason ABI-hex encoded.
        hex_reason = "Only requester".encode("utf-8").hex()
        await agent._fail_job(job, f"UserOp reverted 0x08c379a0...{hex_reason}...")
        assert agent._processed_jobs.has(job.id)


# ============================================================================
# ZeroHash sole-handler raw-pay routing
# ============================================================================


class TestZeroHashRouting:
    @pytest.mark.asyncio
    async def test_zero_hash_routes_to_sole_handler(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        # Raw pay: serviceHash == ZeroHash, no parsable description.
        tx = _tx(service_description="0x" + "0" * 64)
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "echo"

    @pytest.mark.asyncio
    async def test_missing_hash_routes_to_sole_handler(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        # Some runtimes surface a raw pay with no serviceHash/description at all.
        tx = SimpleNamespace(id="0x" + "cd" * 32)
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "echo"

    @pytest.mark.asyncio
    async def test_zero_hash_two_handlers_is_ambiguous(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        agent.provide("translate", handler=h)
        tx = _tx(service_description="0x" + "0" * 64)
        # 2+ handlers -> ambiguous, NOT routed.
        assert agent._find_service_handler(tx) is None

    @pytest.mark.asyncio
    async def test_unknown_nonzero_hash_not_routed_to_sole_handler(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        # A present-but-unknown bytes32 routing key is NOT a raw-pay case —
        # it must NOT silently route to the sole handler (could be a different
        # service the agent does not provide).
        tx = _tx(service_description="0x" + "f" * 64)
        assert agent._find_service_handler(tx) is None

    @pytest.mark.asyncio
    async def test_known_hash_still_resolves(self):
        agent = Agent(AgentConfig(name="agent"))

        async def h(job, ctx):
            return {}

        agent.provide("echo", handler=h)
        agent.provide("translate", handler=h)
        tx = _tx(service_description=_hash("translate"))
        reg = agent._find_service_handler(tx)
        assert reg is not None
        assert reg.config.name == "translate"


# ============================================================================
# safe_emit_error (no crash on unhandled error)
# ============================================================================


class TestSafeEmitError:
    @pytest.mark.asyncio
    async def test_no_listener_does_not_raise(self):
        agent = Agent(AgentConfig(name="agent"))
        # No 'error' listener attached — must not raise, just log.
        agent.safe_emit_error(RuntimeError("boom"))  # no exception

    @pytest.mark.asyncio
    async def test_listener_receives_error(self):
        agent = Agent(AgentConfig(name="agent"))
        seen = []
        agent.on("error", lambda e: seen.append(e))
        err = RuntimeError("boom")
        agent.safe_emit_error(err)
        assert seen == [err]


# ============================================================================
# ProviderOrchestrator (BYO-brain) seam
# ============================================================================


class TestProviderOrchestratorSeam:
    @pytest.mark.asyncio
    async def test_set_provider_orchestrator_stores_reference(self):
        agent = Agent(AgentConfig(name="agent"))
        sentinel = object()
        agent.set_provider_orchestrator(sentinel)
        assert agent._provider_orchestrator is sentinel
