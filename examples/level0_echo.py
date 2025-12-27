#!/usr/bin/env python3
"""
Example: Level 0 API - Echo Service

This demonstrates the simplest possible AGIRAILS usage:
- Provider: Registers an echo service that returns input
- Requester: Requests the echo service

Run this example:
    python examples/level0_echo.py
"""

import asyncio
import shutil
from pathlib import Path
from agirails import ACTPClient
from agirails.level0 import provide, request, set_provider_client, start_provider, stop_provider


# Test addresses
REQUESTER_ADDRESS = "0x1234567890123456789012345678901234567890"
PROVIDER_ADDRESS = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"


async def main() -> None:
    print("=" * 60)
    print("AGIRAILS SDK - Level 0 API Example: Echo Service")
    print("=" * 60)
    print()

    # Clear any previous mock state
    actp_dir = Path(".actp")
    if actp_dir.exists():
        shutil.rmtree(actp_dir)

    # ==========================================================================
    # PROVIDER SIDE
    # ==========================================================================

    print("[PROVIDER] Starting echo service provider...")

    # Register the echo service handler
    async def echo_handler(data: dict) -> dict:
        """Simple echo: return the input."""
        return {"echoed": data}

    # Register with global provider
    entry = provide("echo", echo_handler, description="Echo service")
    print(f"[PROVIDER] Service registered: {entry.name}")

    # Create client (used by both requester and provider in mock mode)
    client = await ACTPClient.create(
        mode="mock",
        requester_address=REQUESTER_ADDRESS,
    )

    # Mint tokens to provider
    await client.mint_tokens(PROVIDER_ADDRESS, 1_000_000)

    # Connect provider to client and start polling
    set_provider_client(client, address=PROVIDER_ADDRESS)
    await start_provider()

    print(f"[PROVIDER] Provider ready and polling for jobs")
    print()

    # ==========================================================================
    # REQUESTER SIDE
    # ==========================================================================

    print("[REQUESTER] Requesting echo service...")

    try:
        result = await request(
            "echo",
            input="Hello, AGIRAILS!",
            budget=1,  # $1 USDC
            network="mock",
            timeout=30000,  # 30 seconds
            on_progress=lambda status: print(
                f"[REQUESTER] Progress: {status.state} ({status.progress or 0}%)"
            ),
            client=client,
            provider=PROVIDER_ADDRESS,
        )

        print()
        print("[REQUESTER] Request completed!")
        print(f"[REQUESTER] Result: {result.result}")
        print(f"[REQUESTER] Transaction ID: {result.transaction.id}")
        print(f"[REQUESTER] Provider: {result.transaction.provider}")
        print(f"[REQUESTER] Amount paid: {result.transaction.amount}")
        print(f"[REQUESTER] Platform fee: {result.transaction.fee}")
        print(f"[REQUESTER] Duration: {result.transaction.duration} ms")
        print()

        print("=" * 60)
        print("Example completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        raise

    finally:
        # Stop provider
        await stop_provider()


if __name__ == "__main__":
    asyncio.run(main())
