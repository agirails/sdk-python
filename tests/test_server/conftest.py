"""Collection-time gate for server tests.

The ``agirails.server`` package depends on FastAPI + uvicorn, which ship
as the optional ``[server]`` extra. Without those installed, importing
the test module would fail at collection time before any
``pytest.importorskip`` inside the test file gets a chance to run —
which would break the full test suite on a minimal install.

Skipping the whole directory at collection time keeps ``pytest tests/``
green on a no-extras install. Install the extras to run these tests::

    pip install agirails[server]
"""

import pytest

# collect_ignore lets us drop modules at collection time before import.
collect_ignore: list = []

try:  # noqa: SIM105 — explicit two-step keeps intent readable
    import fastapi  # noqa: F401
    import uvicorn  # noqa: F401
except ImportError:
    collect_ignore.append("test_actp_serve.py")
