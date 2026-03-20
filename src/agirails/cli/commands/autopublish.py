"""Autopublish Command - Watch AGIRAILS.md and auto-publish on changes.

Usage:
    $ actp autopublish                    # watch ./AGIRAILS.md
    $ actp autopublish /path/to/AGIRAILS.md
    $ actp autopublish --no-publish       # validate only, don't publish
    $ actp autopublish --debounce 2000    # 2s debounce
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.output import (
    OutputFormat,
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
)
from agirails.config.agirailsmd import compute_config_hash

# Minimum debounce to avoid excessive publishes
MIN_DEBOUNCE_MS = 500


def autopublish(
    path: Optional[str] = typer.Argument(
        None,
        help="Path to AGIRAILS.md (default: ./AGIRAILS.md)",
    ),
    publish: bool = typer.Option(
        True, "--publish/--no-publish", help="Auto-publish on change (default: true)"
    ),
    debounce: int = typer.Option(
        1000, "--debounce", help="Debounce delay in milliseconds"
    ),
    network: str = typer.Option(
        "base-mainnet",
        "--network",
        "-n",
        help="Network for publish (base-sepolia, base-mainnet)",
    ),
) -> None:
    """Watch AGIRAILS.md for changes and auto-publish."""
    opts = get_global_options()

    # Enforce minimum debounce
    if debounce < MIN_DEBOUNCE_MS:
        debounce = MIN_DEBOUNCE_MS

    # Resolve file path
    if path:
        md_path = Path(path)
    else:
        md_path = Path(opts.directory or Path.cwd()) / "AGIRAILS.md"

    if not md_path.exists():
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"File not found: {md_path}"})
        else:
            print_error("File not found", str(md_path))
        raise typer.Exit(1)

    # Compute initial hash
    content = md_path.read_text(encoding="utf-8")
    last_hash = compute_config_hash(content).config_hash
    last_mtime = md_path.stat().st_mtime

    if opts.output_format == OutputFormat.JSON:
        print_json({
            "status": "watching",
            "path": str(md_path),
            "configHash": last_hash,
            "publish": publish,
            "debounceMs": debounce,
        })
    elif opts.output_format != OutputFormat.QUIET:
        print_info(f"Watching {md_path}")
        print_info(f"Initial hash: {last_hash}")
        if not publish:
            print_warning("--no-publish: changes will be validated only")

    # Stop event for clean shutdown
    stop_event = threading.Event()
    debounce_timer: Optional[threading.Timer] = None

    def _on_sigint(signum: int, frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, _on_sigint)

    def _handle_change() -> None:
        nonlocal last_hash
        try:
            new_content = md_path.read_text(encoding="utf-8")
        except OSError:
            return

        new_hash = compute_config_hash(new_content).config_hash
        if new_hash == last_hash:
            return

        last_hash = new_hash

        if not publish:
            if opts.output_format == OutputFormat.JSON:
                print_json({"event": "validated", "configHash": new_hash})
            elif opts.output_format != OutputFormat.QUIET:
                print_success(f"Validated — hash: {new_hash}")
            return

        # Run publish as subprocess
        if opts.output_format != OutputFormat.QUIET:
            print_info("Change detected — publishing...")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "agirails.cli.main", "publish",
                 "--path", str(md_path), "--network", network, "--quiet"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                pub_hash = result.stdout.strip()
                if opts.output_format == OutputFormat.JSON:
                    print_json({"event": "published", "configHash": pub_hash or new_hash})
                elif opts.output_format != OutputFormat.QUIET:
                    print_success(f"Published — hash: {pub_hash or new_hash}")
            else:
                err_msg = result.stderr.strip() or result.stdout.strip() or "unknown error"
                if opts.output_format == OutputFormat.JSON:
                    print_json({"event": "publish_failed", "error": err_msg})
                elif opts.output_format != OutputFormat.QUIET:
                    print_error("Publish failed", err_msg)
        except subprocess.TimeoutExpired:
            if opts.output_format == OutputFormat.JSON:
                print_json({"event": "publish_failed", "error": "timeout"})
            elif opts.output_format != OutputFormat.QUIET:
                print_error("Publish timed out", "60s limit exceeded")

    # Poll loop (matching TS fs.watchFile interval: 500ms)
    debounce_s = debounce / 1000.0
    poll_interval = 0.5

    while not stop_event.is_set():
        try:
            current_mtime = md_path.stat().st_mtime
        except OSError:
            stop_event.wait(poll_interval)
            continue

        if current_mtime != last_mtime:
            last_mtime = current_mtime
            # Cancel previous debounce timer if still pending
            if debounce_timer is not None:
                debounce_timer.cancel()
            debounce_timer = threading.Timer(debounce_s, _handle_change)
            debounce_timer.daemon = True
            debounce_timer.start()

        stop_event.wait(poll_interval)

    # Clean shutdown
    if debounce_timer is not None:
        debounce_timer.cancel()

    if opts.output_format == OutputFormat.JSON:
        print_json({"status": "stopped"})
    elif opts.output_format != OutputFormat.QUIET:
        print_info("Stopped watching.")
