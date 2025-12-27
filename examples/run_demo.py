#!/usr/bin/env python3
"""
Complete Echo Demo

Demonstrates the full request-provider flow in a single script.
This combines both provider and requester in one process.

Run with: python examples/run_demo.py
"""

import asyncio
import shutil
import os
from pathlib import Path
from agirails import ACTPClient
from agirails.level0 import provide, request, ProgressInfo, set_provider_client, start_provider, stop_provider


# Test addresses
REQUESTER_ADDRESS = "0x1234567890123456789012345678901234567890"
PROVIDER_ADDRESS = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"


async def main() -> None:
    print("=" * 60)
    print("AGIRAILS Level 0 API - Echo Demo")
    print("=" * 60)
    print()

    # Clear any previous mock state
    actp_dir = Path(".actp")
    if actp_dir.exists():
        shutil.rmtree(actp_dir)
        print("  Cleared previous mock state")
        print()

    # Step 1: Register the echo service handler
    print("Step 1: Registering Echo Service...")

    async def echo_handler(job_input: dict) -> dict:
        """Process the echo job."""
        print(f"  [Provider] Job received")
        print(f"  [Provider] Input: {job_input}")

        # Simulate work
        await asyncio.sleep(0.5)

        result = {
            "echo": job_input,
            "processed_at": __import__("datetime").datetime.now().isoformat(),
        }

        return result

    entry = provide(
        "echo",
        echo_handler,
        description="Echo service for demo",
    )

    print(f"  Service registered: {entry.name}")
    print()

    # Step 2: Create a single SDK client (both requester and provider use same mock runtime)
    print("Step 2: Creating SDK client...")

    client = await ACTPClient.create(
        mode="mock",
        requester_address=REQUESTER_ADDRESS,
    )

    # Mint tokens for provider too
    await client.mint_tokens(PROVIDER_ADDRESS, 1_000_000)  # $1M USDC

    # Verify balances
    req_balance = await client.get_balance(REQUESTER_ADDRESS)
    prov_balance = await client.get_balance(PROVIDER_ADDRESS)
    print(f"  Client ready (mock mode)")
    print(f"  Requester: {REQUESTER_ADDRESS} (${req_balance})")
    print(f"  Provider:  {PROVIDER_ADDRESS} (${prov_balance})")
    print()

    # Step 3: Connect provider to client and start polling
    print("Step 3: Starting Provider polling...")
    set_provider_client(client, address=PROVIDER_ADDRESS)
    await start_provider()
    print("  Provider is now listening for jobs")
    print()

    # Step 4: Request the service
    print("Step 4: Requesting Echo Service...")

    try:
        def on_progress(status: ProgressInfo) -> None:
            print(f"  Progress: {status.progress}% - {status.message}")

        result = await request(
            "echo",
            input={
                "message": "Hello from AGIRAILS!",
                "timestamp": __import__("time").time(),
            },
            budget=5,  # $5 USDC
            network="mock",
            timeout=30000,  # 30 seconds
            on_progress=on_progress,
            client=client,
            provider=PROVIDER_ADDRESS,
        )

        print()
        print("=" * 60)
        print("SUCCESS! Service completed")
        print("=" * 60)
        print()
        print("Result:")
        import json
        print(json.dumps(result.result, indent=2, default=str))
        print()
        print("Transaction Details:")
        print(f"  ID:       {result.transaction.id[:20]}...")
        print(f"  Provider: {result.transaction.provider[:20]}...")
        print(f"  Amount:   ${result.transaction.amount}")
        print(f"  Fee:      ${result.transaction.fee}")
        print(f"  Duration: {result.transaction.duration}ms")
        print()

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        raise

    finally:
        # Step 5: Clean up
        print("Step 5: Stopping provider...")
        await stop_provider()
        print("  Demo complete!")
        print()


if __name__ == "__main__":
    asyncio.run(main())
