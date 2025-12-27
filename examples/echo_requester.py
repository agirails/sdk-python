#!/usr/bin/env python3
"""
Echo Requester Example

Demonstrates how to request a service using Level 0 API.
This requester calls the "echo" service and displays the result.

Use with echo_provider.py running in another terminal:
  Terminal 1: python examples/echo_provider.py
  Terminal 2: python examples/echo_requester.py

Run with: python examples/echo_requester.py
"""

import asyncio
import os
from agirails import ACTPClient
from agirails.level0 import request, ProgressInfo


# Addresses (use environment variables or defaults for mock mode)
REQUESTER_ADDRESS = os.environ.get(
    "REQUESTER_ADDRESS",
    "0x1234567890123456789012345678901234567890",
)
PROVIDER_ADDRESS = os.environ.get(
    "PROVIDER_ADDRESS",
    "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
)


async def main() -> None:
    print("=" * 60)
    print("AGIRAILS SDK - Echo Requester")
    print("=" * 60)
    print()

    # Create client in mock mode
    client = await ACTPClient.create(
        mode="mock",
        requester_address=REQUESTER_ADDRESS,
    )

    try:
        print(f"Requester address: {REQUESTER_ADDRESS}")
        print(f"Provider address: {PROVIDER_ADDRESS}")
        print()
        print("Requesting echo service...")
        print()

        def on_progress(status: ProgressInfo) -> None:
            print(f"Progress: {status.progress}% - {status.message} ({status.state})")

        result = await request(
            "echo",
            input={"message": "Hello, AGIRAILS!"},
            budget=1,  # $1 USDC
            network="mock",
            timeout=30000,  # 30 seconds
            on_progress=on_progress,
            client=client,
            provider=PROVIDER_ADDRESS,
        )

        print("\nService completed successfully!")
        print(f"\nResult: {result.result}")
        print("\nTransaction Details:")
        print(f"  ID: {result.transaction.id}")
        print(f"  Provider: {result.transaction.provider}")
        print(f"  Amount: ${result.transaction.amount}")
        print(f"  Fee: ${result.transaction.fee}")
        print(f"  Duration: {result.transaction.duration}ms")

    except TimeoutError:
        print("\nRequest timed out")
        raise SystemExit(1)
    except Exception as e:
        print(f"\nRequest failed: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
