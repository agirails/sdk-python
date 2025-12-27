#!/usr/bin/env python3
"""
Example: Level 1 API - Agent with Lifecycle

This demonstrates the Agent-based API:
- Agent registration and lifecycle
- Service provision with progress reporting
- Event handling
- Statistics tracking

Run this example:
    python examples/level1_agent.py
"""

import asyncio
import shutil
from pathlib import Path
from agirails.level1 import Agent, AgentConfig, AgentBehavior, Job, JobContext


async def main() -> None:
    print("=" * 60)
    print("AGIRAILS SDK - Level 1 API Example: Agent Lifecycle")
    print("=" * 60)
    print()

    # Clear any previous mock state
    actp_dir = Path(".actp")
    if actp_dir.exists():
        shutil.rmtree(actp_dir)

    # ==========================================================================
    # CREATE AGENT
    # ==========================================================================

    print("[AGENT] Creating agent...")

    agent = Agent(
        AgentConfig(
            name="TranslationBot",
            description="A simple translation service agent",
            network="mock",
            behavior=AgentBehavior(
                auto_accept=True,
                concurrency=5,
            ),
        )
    )

    print(f"[AGENT] Agent name: {agent.name}")
    print(f"[AGENT] Network: {agent.network}")
    print(f"[AGENT] Status: {agent.status.value}")
    print()

    # ==========================================================================
    # REGISTER SERVICE
    # ==========================================================================

    print("[AGENT] Registering translation service...")

    @agent.provide("translation")
    async def handle_translation(job: Job, ctx: JobContext) -> dict:
        print(f"[AGENT] Processing job: {job.id}")
        print(f"[AGENT] Input: {job.input}")

        # Simulate translation work with progress reporting
        ctx.progress(0, "Starting translation...")
        ctx.log.info("Translation started")

        await asyncio.sleep(0.5)
        ctx.progress(50, "Translating...")

        await asyncio.sleep(0.5)
        ctx.progress(100, "Translation complete!")

        # Mock translation result
        text = job.input.get("text", "") if isinstance(job.input, dict) else str(job.input)
        result = {
            "original": text,
            "translated": f"[DE] {text}",
            "from": job.input.get("from", "en") if isinstance(job.input, dict) else "en",
            "to": job.input.get("to", "de") if isinstance(job.input, dict) else "de",
        }

        ctx.log.info("Translation completed successfully", extra=result)
        return result

    print(f"[AGENT] Services registered: {', '.join(agent.service_names)}")
    print()

    # ==========================================================================
    # EVENT LISTENERS
    # ==========================================================================

    print("[AGENT] Registering event listeners...")

    def on_started() -> None:
        print("[EVENT] Agent started successfully")

    def on_stopped() -> None:
        print("[EVENT] Agent stopped")

    def on_error(error: Exception) -> None:
        print(f"[EVENT] Error: {error}")

    def on_job_received(job: Job) -> None:
        print(f"[EVENT] Job received: {job.id}")

    def on_job_completed(job: Job, result: dict) -> None:
        print(f"[EVENT] Job completed: {job.id}")
        print(f"[EVENT] Result: {result}")

    def on_payment(amount: float) -> None:
        print(f"[EVENT] Payment received: ${amount} USDC")

    # Register event handlers
    agent.on("started", on_started)
    agent.on("stopped", on_stopped)
    agent.on("error", on_error)
    agent.on("job:received", on_job_received)
    agent.on("job:completed", on_job_completed)
    agent.on("payment:received", on_payment)

    print()

    # ==========================================================================
    # START AGENT
    # ==========================================================================

    print("[AGENT] Starting agent...")
    await agent.start()

    print(f"[AGENT] Address: {agent.address}")
    print(f"[AGENT] Status: {agent.status.value}")
    print(f"[AGENT] Balance: {agent.balance.usdc} USDC")
    print()

    # Wait for some simulated activity
    print("[AGENT] Agent is now running and listening for jobs...")
    print("[AGENT] (In real usage, jobs would come from requesters)")
    print()

    await asyncio.sleep(2)

    # ==========================================================================
    # LIFECYCLE OPERATIONS
    # ==========================================================================

    print("[AGENT] Testing lifecycle operations...")
    print()

    # Pause
    print("[AGENT] Pausing agent...")
    agent.pause()
    print(f"[AGENT] Status: {agent.status.value}")
    print()

    await asyncio.sleep(1)

    # Resume
    print("[AGENT] Resuming agent...")
    agent.resume()
    print(f"[AGENT] Status: {agent.status.value}")
    print()

    await asyncio.sleep(1)

    # ==========================================================================
    # STATISTICS
    # ==========================================================================

    print("[AGENT] Agent statistics:")
    print(f"  - Jobs received: {agent.stats.jobs_received}")
    print(f"  - Jobs completed: {agent.stats.jobs_completed}")
    print(f"  - Jobs failed: {agent.stats.jobs_failed}")
    print(f"  - Total earned: ${agent.stats.total_earned} USDC")
    print(f"  - Total spent: ${agent.stats.total_spent} USDC")
    print(f"  - Success rate: {agent.stats.success_rate:.2f}%")
    print(f"  - Average job time: {agent.stats.average_job_time}ms")
    print()

    # ==========================================================================
    # STOP AGENT
    # ==========================================================================

    print("[AGENT] Stopping agent...")
    await agent.stop()
    print(f"[AGENT] Status: {agent.status.value}")
    print()

    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
