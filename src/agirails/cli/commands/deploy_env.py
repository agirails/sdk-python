"""
Deploy Env Command - Export keystore as environment variables for deployment.

Usage:
    $ actp deploy env
    $ actp deploy env --format docker
    $ actp deploy env --format json
    $ actp deploy env --quiet
"""

from __future__ import annotations

import base64
import json
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_warning,
    print_json as output_json,
)


class EnvFormat(str, Enum):
    """Output format for deploy-env."""

    SHELL = "shell"
    DOCKER = "docker"
    JSON = "json"


def deploy_env(
    format: EnvFormat = typer.Option(
        EnvFormat.SHELL,
        "--format",
        "-f",
        help="Output format: shell, docker, json",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Shorthand for --format json",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Output only the base64 string",
    ),
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Working directory (default: current)",
    ),
) -> None:
    """Export keystore as base64 environment variable for deployment."""
    work_dir = directory or Path.cwd()
    keystore_path = work_dir / ".actp" / "keystore.json"

    if not keystore_path.exists():
        print_error(
            "No keystore found",
            f"Expected at {keystore_path}\nRun 'actp init' first to create a keystore.",
        )
        raise typer.Exit(1)

    # Read and validate JSON
    try:
        raw = keystore_path.read_text(encoding="utf-8")
        json.loads(raw)  # validate
    except json.JSONDecodeError:
        print_error(
            "Invalid keystore",
            f"{keystore_path} is not valid JSON.",
        )
        raise typer.Exit(1)
    except OSError as e:
        print_error("Cannot read keystore", str(e))
        raise typer.Exit(1)

    # Base64 encode
    keystore_b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")

    # Resolve effective format
    effective_format = EnvFormat.JSON if json_output else format

    if quiet:
        typer.echo(keystore_b64)
        return

    if effective_format == EnvFormat.JSON:
        output_json({
            "keystoreBase64": keystore_b64,
            "passwordVar": "ACTP_KEY_PASSWORD",
        })
        return

    if effective_format == EnvFormat.DOCKER:
        print_warning(
            "SECURITY: Do NOT commit Dockerfiles with embedded secrets. "
            "Use Docker secrets or build args instead."
        )
        typer.echo("")
        typer.echo(f'ENV ACTP_KEYSTORE_BASE64="{keystore_b64}"')
        typer.echo('ENV ACTP_KEY_PASSWORD="<your password>"')
        typer.echo("")
        print_info("Recommended: use --mount=type=secret or docker-compose secrets")
        return

    # Default: shell format
    typer.echo(f'export ACTP_KEYSTORE_BASE64="{keystore_b64}"')
    typer.echo('export ACTP_KEY_PASSWORD="<your password>"')
    typer.echo("")
    print_info("Platform examples:")
    typer.echo("  # Railway / Render / Vercel")
    typer.echo(f"  ACTP_KEYSTORE_BASE64={keystore_b64}")
    typer.echo("")
    typer.echo("  # GitHub Actions")
    typer.echo('  gh secret set ACTP_KEYSTORE_BASE64 --body "$ACTP_KEYSTORE_BASE64"')
    typer.echo("")
    typer.echo("  # .env file (DO NOT commit!)")
    typer.echo(f"  echo 'ACTP_KEYSTORE_BASE64={keystore_b64}' >> .env")
