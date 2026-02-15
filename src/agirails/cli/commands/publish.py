"""Publish Command - Publish AGIRAILS.md to IPFS and prepare on-chain activation.

Usage:
    $ actp publish                    # publish from current directory
    $ actp publish --dry-run          # compute hash only
    $ actp publish --network base-sepolia
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
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
from agirails.config.agirailsmd import compute_config_hash, parse_agirails_md
from agirails.config.pending_publish import (
    PendingPublishData,
    ServiceDescriptorData,
    save_pending_publish,
)
from agirails.config.publish_pipeline import (
    FilebaseCredentials,
    extract_registration_params,
    publish_config,
    update_frontmatter_after_publish,
)


def publish(
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Compute hash only, skip upload"
    ),
    network: str = typer.Option(
        "base-mainnet",
        "--network",
        "-n",
        help="Target network (base-sepolia, base-mainnet)",
    ),
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        "-p",
        help="Path to AGIRAILS.md (default: ./AGIRAILS.md)",
    ),
) -> None:
    """Publish AGIRAILS.md to IPFS and prepare lazy on-chain activation."""
    opts = get_global_options()
    md_path = path or Path(opts.directory or Path.cwd()) / "AGIRAILS.md"

    if not md_path.exists():
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": f"AGIRAILS.md not found at {md_path}"})
        else:
            print_error(
                "AGIRAILS.md not found",
                f"Expected at: {md_path}\nRun from your agent directory or use --path.",
            )
        raise typer.Exit(1)

    # Read and parse
    content = md_path.read_text(encoding="utf-8")
    try:
        parsed = parse_agirails_md(content)
    except ValueError as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Failed to parse AGIRAILS.md", str(e))
        raise typer.Exit(1)

    # Compute hash
    hash_result = compute_config_hash(content)

    if not dry_run:
        print_info(f"Config hash: {hash_result.config_hash}")

    # Detect Filebase credentials
    filebase_creds = None
    fb_key = os.environ.get("FILEBASE_ACCESS_KEY")
    fb_secret = os.environ.get("FILEBASE_SECRET_KEY")
    fb_bucket = os.environ.get("FILEBASE_BUCKET", "agirails-configs")
    if fb_key and fb_secret:
        filebase_creds = FilebaseCredentials(
            access_key=fb_key,
            secret_key=fb_secret,
            bucket=fb_bucket,
        )

    # Publish (upload to IPFS)
    try:
        result = publish_config(
            content=content,
            filebase_credentials=filebase_creds,
            dry_run=dry_run,
        )
    except Exception as e:
        if opts.output_format == OutputFormat.JSON:
            print_json({"error": str(e)})
        else:
            print_error("Publish failed", str(e))
        raise typer.Exit(1)

    # Save pending-publish for lazy activation (mainnet or specified network)
    if not dry_run:
        try:
            endpoint, descriptors = extract_registration_params(parsed.frontmatter)
        except ValueError:
            endpoint = "https://pending.agirails.io"
            descriptors = []

        pending = PendingPublishData(
            version=1,
            config_hash=result.config_hash,
            cid=result.cid,
            endpoint=endpoint,
            service_descriptors=[
                ServiceDescriptorData(
                    service_type_hash=sd.service_type_hash,
                    service_type=sd.service_type,
                    schema_uri=sd.schema_uri,
                    min_price=str(sd.min_price),
                    max_price=str(sd.max_price),
                    avg_completion_time=sd.avg_completion_time,
                    metadata_cid=sd.metadata_cid,
                )
                for sd in descriptors
            ],
            created_at=datetime.now(timezone.utc).isoformat(),
            network=network,
        )

        save_pending_publish(pending, network=network)

        # Update AGIRAILS.md frontmatter
        updated_content = update_frontmatter_after_publish(
            content, result.config_hash, result.cid
        )
        md_path.write_text(updated_content, encoding="utf-8")

    # Output
    if opts.output_format == OutputFormat.JSON:
        print_json(
            {
                "configHash": result.config_hash,
                "cid": result.cid,
                "dryRun": result.dry_run,
                "network": network,
                "path": str(md_path),
            }
        )
    elif opts.output_format == OutputFormat.QUIET:
        typer.echo(result.config_hash)
    else:
        if dry_run:
            print_info("Dry run -- no upload performed")
            print_success(
                "Config hash computed",
                {
                    "Hash": result.config_hash,
                    "Path": str(md_path),
                },
            )
        else:
            print_success(
                "Published to IPFS",
                {
                    "CID": result.cid,
                    "Hash": result.config_hash,
                    "Network": network,
                    "Pending": f".actp/pending-publish.{network}.json",
                },
            )
            print_info(
                "Lazy publish: on-chain activation will happen on first payment."
            )
