"""
AGIRAILS CLI Module.

Provides command-line interface for ACTP protocol operations.

Usage:
    $ actp --help
    $ actp init
    $ actp pay <provider> <amount>
    $ actp tx status <tx_id>
"""

from agirails.cli.main import app

__all__ = ["app"]
