"""
AGIRAILS CLI - Command Line Interface for ACTP Protocol.

Usage:
    $ actp --help
    $ actp init
    $ actp pay <provider> <amount>
    $ actp tx status <tx_id>
    $ actp balance
    $ actp mint <address> <amount>
    $ actp time
    $ actp config show
    $ actp watch <tx_id>           # Agent-first: Stream state changes
    $ actp batch <file>            # Agent-first: Execute multiple commands
    $ actp simulate pay <to> <amt> # Agent-first: Dry-run validation
    $ actp publish                 # Publish AGIRAILS.md to IPFS
    $ actp diff                    # Compare local vs on-chain config
    $ actp pull                    # Pull on-chain config to local
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

from agirails.version import __version__
from agirails.cli.utils.output import (
    OutputFormat,
    print_success,
    print_error,
    print_info,
    print_json,
)

# Create main app
app = typer.Typer(
    name="actp",
    help="AGIRAILS CLI - Command Line Interface for ACTP Protocol",
    add_completion=False,
    invoke_without_command=True,
)

# Global options stored in context
class GlobalOptions:
    """Global CLI options."""

    def __init__(self) -> None:
        self.json_output: bool = False
        self.quiet: bool = False
        self.directory: Optional[Path] = None
        self.mode: Optional[str] = None

    @property
    def output_format(self) -> OutputFormat:
        if self.json_output:
            return OutputFormat.JSON
        if self.quiet:
            return OutputFormat.QUIET
        return OutputFormat.PRETTY


# Store global options in typer context
_global_options = GlobalOptions()


def get_global_options() -> GlobalOptions:
    """Get global options."""
    return _global_options


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version and exit"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output as JSON"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Minimal output (IDs only)"
    ),
    directory: Optional[Path] = typer.Option(
        None, "--directory", "-d", help="Working directory"
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="Mode: mock, testnet, mainnet"
    ),
) -> None:
    """AGIRAILS CLI - Command Line Interface for ACTP Protocol."""
    if version:
        typer.echo(f"actp version {__version__}")
        raise typer.Exit()

    # Store global options
    _global_options.json_output = json_output
    _global_options.quiet = quiet
    _global_options.directory = directory
    _global_options.mode = mode

    # Show help if no command provided
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


# Import and register command groups
from agirails.cli.commands import init as init_cmd
from agirails.cli.commands import pay as pay_cmd
from agirails.cli.commands import tx as tx_cmd
from agirails.cli.commands import balance as balance_cmd
from agirails.cli.commands import mint as mint_cmd
from agirails.cli.commands import config as config_cmd
from agirails.cli.commands import time as time_cmd
from agirails.cli.commands import watch as watch_cmd
from agirails.cli.commands import batch as batch_cmd
from agirails.cli.commands import simulate as simulate_cmd
from agirails.cli.commands import deploy_env as deploy_env_cmd
from agirails.cli.commands import deploy_check as deploy_check_cmd
from agirails.cli.commands import publish as publish_cmd
from agirails.cli.commands import diff as diff_cmd
from agirails.cli.commands import pull as pull_cmd

# Register commands
app.command(name="init")(init_cmd.init)
app.command(name="pay")(pay_cmd.pay)
app.add_typer(tx_cmd.tx_app, name="tx")
app.command(name="balance")(balance_cmd.balance)
app.command(name="mint")(mint_cmd.mint)
app.add_typer(config_cmd.config_app, name="config")
app.add_typer(time_cmd.time_app, name="time")
app.command(name="watch")(watch_cmd.watch)
app.command(name="batch")(batch_cmd.batch)
app.add_typer(simulate_cmd.simulate_app, name="simulate")

# Publish/Diff/Pull commands
app.command(name="publish")(publish_cmd.publish)
app.command(name="diff")(diff_cmd.diff)
app.command(name="pull")(pull_cmd.pull)

# Deploy subcommand group
deploy_app = typer.Typer(
    name="deploy",
    help="Deployment commands (env export, security check)",
    no_args_is_help=True,
)
deploy_app.command("env")(deploy_env_cmd.deploy_env)
deploy_app.command("check")(deploy_check_cmd.deploy_check)
app.add_typer(deploy_app, name="deploy")


def run() -> None:
    """Run the CLI application."""
    app()


if __name__ == "__main__":
    run()
