#!/usr/bin/env python3
"""
Echo Provider Example

Demonstrates how to create a service provider using Level 0 API.
This provider offers a simple "echo" service that returns the input.

In mock mode, this provider will wait for requests created by the
echo_requester.py example (run them in separate terminals).

Run with: python examples/echo_provider.py
"""

import asyncio
import os
import signal
from agirails import ACTPClient
from agirails.level0 import provide, get_provider, start_provider, stop_provider, set_provider_client


# Provider address (use environment variable or default mock address)
PROVIDER_ADDRESS = os.environ.get(
    "PROVIDER_ADDRESS",
    "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
)


async def main() -> None:
    print("=" * 60)
    print("AGIRAILS SDK - Echo Provider")
    print("=" * 60)
    print()

    # Define the echo handler
    async def echo_handler(job_input: dict) -> dict:
        """Echo handler that returns the input with metadata."""
        print(f"[Provider] Received input: {job_input}")

        # Simulate processing
        await asyncio.sleep(1)

        # Return the input as result
        result = {
            "echo": job_input,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
            "provider": "echo-service-v1",
        }

        print(f"[Provider] Returning result: {result}")
        return result

    # Register the service
    entry = provide(
        "echo",
        echo_handler,
        description="Simple echo service that returns input",
        capabilities=["echo", "test"],
    )

    print(f"Service registered: {entry.name}")
    print(f"Description: {entry.description}")
    print(f"Capabilities: {entry.capabilities}")
    print()

    # Create client in mock mode
    # Note: In testnet/mainnet mode, use private_key and rpc_url
    client = await ACTPClient.create(
        mode="mock",
        requester_address=PROVIDER_ADDRESS,  # Provider uses same address for client
    )

    # Connect provider to client
    set_provider_client(client, address=PROVIDER_ADDRESS)

    print(f"Provider address: {PROVIDER_ADDRESS}")
    print()
    print("Waiting for jobs...")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    # Set up graceful shutdown
    shutdown_event = asyncio.Event()

    def handle_signal(sig: int, frame: object) -> None:
        print("\n\nReceived shutdown signal...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Start the provider
    await start_provider()

    # Wait for shutdown
    await shutdown_event.wait()

    # Stop the provider
    print("Stopping provider...")
    await stop_provider()

    # Get stats from provider
    provider = get_provider()
    print(f"\nProvider stopped. Stats: {provider.stats}")


if __name__ == "__main__":
    asyncio.run(main())
