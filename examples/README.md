# AGIRAILS Python SDK Examples

This directory contains example scripts demonstrating the AGIRAILS SDK APIs.

## Prerequisites

```bash
# Install the SDK
pip install -e ..

# Or if published to PyPI
pip install agirails
```

## Examples

### Level 0 API (Functional)

The simplest possible API - just functions, no classes needed.

| File | Description |
|------|-------------|
| `level0_echo.py` | Complete demo with provider and requester in one script |
| `echo_provider.py` | Standalone provider that offers an echo service |
| `echo_requester.py` | Standalone requester that calls the echo service |
| `run_demo.py` | Step-by-step combined demo with detailed output |

```bash
# Run complete Level 0 demo
python examples/level0_echo.py

# Run provider (in one terminal)
python examples/echo_provider.py

# Run requester (in another terminal)
python examples/echo_requester.py

# Run step-by-step demo
python examples/run_demo.py
```

### Level 1 API (Agent-Based)

Object-oriented API with full lifecycle management.

| File | Description |
|------|-------------|
| `level1_agent.py` | Agent lifecycle: start, provide, pause, resume, stop |

```bash
# Run Agent lifecycle demo
python examples/level1_agent.py
```

## API Comparison

### Level 0 - Functions

```python
from agirails.level0 import provide, request

# Provider side
provide("echo", lambda data: {"echoed": data})

# Requester side
result = await request("echo", input={"msg": "hello"}, budget=1)
print(result.result)
```

### Level 1 - Agent Class

```python
from agirails.level1 import Agent, AgentConfig

agent = Agent(AgentConfig(name="my-agent", network="mock"))

@agent.provide("echo")
async def handle(job, ctx):
    ctx.progress(50, "Working...")
    return {"echo": job.input}

await agent.start()
# ... agent runs and processes jobs ...
await agent.stop()
```

## Network Modes

All examples run in **mock mode** by default (no blockchain needed).

To run against testnet, see the `../test_scripts/` directory.

## Troubleshooting

### "No module named 'agirails'"

Make sure you've installed the SDK:
```bash
pip install -e ..
```

### "Request timed out"

In mock mode, ensure the provider is registered before making requests.
The examples handle this by using a single script or shared runtime.

## See Also

- [SDK README](../README.md) - Full SDK documentation
- [test_scripts/](../test_scripts/) - Testnet integration scripts
- [tests/](../tests/) - Unit and integration tests
