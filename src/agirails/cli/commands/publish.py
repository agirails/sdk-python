"""Publish Command - Publish AGIRAILS.md to IPFS and prepare on-chain activation.

Usage:
    $ actp publish                    # publish from current directory
    $ actp publish --dry-run          # compute hash only
    $ actp publish --network base-sepolia
"""

from __future__ import annotations

import asyncio
import logging
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
from agirails.config.agirailsmd import (
    compute_config_hash,
    parse_agirails_md,
    serialize_agirails_md,
)
from agirails.config.on_chain_state import OnChainAgentState, OnChainStateError, get_on_chain_agent_state
from agirails.config.pending_publish import (
    PendingPublishData,
    ServiceDescriptorData,
    save_pending_publish,
)
from agirails.config.publish_pipeline import (
    PENDING_ENDPOINT,
    FilebaseCredentials,
    extract_registration_params,
    publish_config,
    update_frontmatter_after_publish,
)
from agirails.wallet.aa.transaction_batcher import ActivationScenario

logger = logging.getLogger("agirails.cli.publish")


# ============================================================================
# Scenario Detection
# ============================================================================


def detect_lazy_publish_scenario(
    on_chain: OnChainAgentState,
    pending: Optional[PendingPublishData],
) -> ActivationScenario:
    """Detect the lazy-publish activation scenario.

    Args:
        on_chain: On-chain agent state (registeredAt, configHash, listed).
        pending: Pending publish data (or None if no pending publish).

    Returns:
        ActivationScenario literal: 'A', 'B1', 'B2', 'C', or 'none'.
    """
    if pending is None:
        return "none"

    if not on_chain.is_registered:
        return "A"

    if pending.config_hash != on_chain.config_hash:
        return "B1" if not on_chain.listed else "B2"

    # Hash matches — stale pending
    return "C"


# ============================================================================
# Testnet Activation
# ============================================================================


async def _resolve_sign_and_upsert(
    *,
    slug: str,
    agent_id: str,
    wallet: str,
    config_cid: str,
    config_hash: str,
    network: str,
) -> bool:
    """Resolve private key, sign upsert message, and call agirails.app API.

    Combines resolve_private_key + sign + upsert_agent in a single event loop
    to avoid multiple asyncio.run() calls with stale locks (P-10 / P-8).

    Returns True if upsert succeeded, False if skipped (no key).
    """
    import time as _time

    from agirails.api.agirails_app import UpsertAgentParams, upsert_agent
    from agirails.wallet.keystore import ResolvePrivateKeyOptions, resolve_private_key

    priv_key = await resolve_private_key(
        options=ResolvePrivateKeyOptions(network=network)
    )
    if not priv_key:
        return False

    from eth_account import Account
    from eth_account.messages import encode_defunct

    publish_ts = int(_time.time())
    # C-2 fix: include network in signed message to prevent cross-network replay
    message = f"agirails-publish:{slug}:{config_hash}:{network}:{publish_ts}"
    acct = Account.from_key(priv_key)
    sig = acct.sign_message(encode_defunct(text=message)).signature.hex()

    await upsert_agent(
        UpsertAgentParams(
            slug=slug,
            agent_id=agent_id,
            wallet=wallet,
            config_cid=config_cid,
            config_hash=config_hash,
            signature=f"0x{sig}" if not sig.startswith("0x") else sig,
            message=message,
            timestamp=publish_ts,
            network=network,
        )
    )
    return True


async def _activate_on_testnet(
    config_hash: str,
    cid: str,
    endpoint: str,
    service_descriptors: list,
    network: str = "base-sepolia",
) -> Optional[dict]:
    """Activate agent on testnet via Smart Wallet UserOp.

    Returns dict with tx_hash, wallet_address, agent_id on success, or None.
    """
    from agirails.config.networks import get_network
    from agirails.wallet.keystore import ResolvePrivateKeyOptions, resolve_private_key

    private_key = await resolve_private_key(
        options=ResolvePrivateKeyOptions(network=network)
    )
    if not private_key:
        raise RuntimeError("No wallet found. Cannot activate on testnet.")

    net = get_network(network)
    if not net.aa or not net.contracts.agent_registry:
        raise RuntimeError("Testnet AA or AgentRegistry not configured.")

    aa = net.aa

    bundler_primary = aa.bundler_urls.get("coinbase") or aa.bundler_urls.get("pimlico")
    bundler_backup = (
        aa.bundler_urls.get("pimlico")
        if aa.bundler_urls.get("coinbase") and aa.bundler_urls.get("pimlico")
        else None
    )
    paymaster_primary = aa.paymaster_urls.get("coinbase") or aa.paymaster_urls.get(
        "pimlico"
    )
    paymaster_backup = (
        aa.paymaster_urls.get("pimlico")
        if aa.paymaster_urls.get("coinbase") and aa.paymaster_urls.get("pimlico")
        else None
    )

    if not bundler_primary or not paymaster_primary:
        raise RuntimeError(
            "Testnet AA bundler/paymaster endpoints not configured.\n"
            "Set CDP_API_KEY or PIMLICO_API_KEY."
        )

    from web3 import Web3

    from agirails.wallet.auto_wallet_provider import AutoWalletConfig, AutoWalletProvider

    w3 = Web3(Web3.HTTPProvider(net.rpc_url))

    auto_wallet = await AutoWalletProvider.create(
        AutoWalletConfig(
            private_key=private_key,
            w3=w3,
            chain_id=net.chain_id,
            actp_kernel_address=net.contracts.actp_kernel,
            bundler_primary_url=bundler_primary,
            bundler_backup_url=bundler_backup,
            paymaster_primary_url=paymaster_primary,
            paymaster_backup_url=paymaster_backup,
        )
    )

    wallet_address = auto_wallet.get_address()
    logger.info("Smart Wallet: %s", wallet_address)

    # Check on-chain state
    try:
        on_chain = get_on_chain_agent_state(wallet_address, network)
    except OnChainStateError as e:
        logger.warning("On-chain state read failed: %s", e)
        return {"tx_hash": None, "wallet_address": wallet_address, "agent_id": None}

    # Build a synthetic pending for scenario detection
    scenario = detect_lazy_publish_scenario(
        on_chain,
        PendingPublishData(
            version=1,
            config_hash=config_hash,
            cid=cid,
            endpoint=endpoint,
            service_descriptors=[],
            created_at=datetime.now(timezone.utc).isoformat(),
            network=network,
        ),
    )

    if scenario in ("C", "none"):
        return {"tx_hash": None, "wallet_address": wallet_address, "agent_id": None}

    from agirails.wallet.aa.transaction_batcher import (
        ActivationBatchParams,
        ServiceDescriptor,
        build_activation_batch,
        build_testnet_mint_batch,
    )
    from agirails.wallet.auto_wallet_provider import TransactionRequest

    activation_calls = build_activation_batch(
        ActivationBatchParams(
            scenario=scenario,
            agent_registry_address=net.contracts.agent_registry,
            cid=cid,
            config_hash=config_hash,
            listed=True,
            endpoint=endpoint if scenario == "A" else None,
            service_descriptors=(
                [
                    ServiceDescriptor(
                        service_type_hash=sd.service_type_hash,
                        service_type=sd.service_type,
                        schema_uri=sd.schema_uri,
                        min_price=int(sd.min_price) if isinstance(sd.min_price, str) else sd.min_price,
                        max_price=int(sd.max_price) if isinstance(sd.max_price, str) else sd.max_price,
                        avg_completion_time=sd.avg_completion_time,
                        metadata_cid=sd.metadata_cid,
                    )
                    for sd in service_descriptors
                ]
                if scenario == "A"
                else None
            ),
        )
    )

    # Always mint 1000 test USDC
    mint_calls = build_testnet_mint_batch(
        net.contracts.usdc, wallet_address, "1000000000"  # 1000 USDC (6 decimals)
    )

    all_calls = activation_calls + mint_calls
    tx_requests = [
        TransactionRequest(to=c.target, data=c.data, value=str(c.value))
        for c in all_calls
    ]

    logger.info("Submitting %d-call UserOp...", len(all_calls))
    receipt = await auto_wallet.send_batch_transaction(tx_requests)

    if not receipt.success:
        raise RuntimeError(f"Testnet activation UserOp failed: {receipt.hash}")

    # Derive agent_id = uint256(uint160(walletAddress))
    agent_id = str(int(wallet_address, 16))

    return {
        "tx_hash": receipt.hash,
        "wallet_address": wallet_address,
        "agent_id": agent_id,
    }


# ============================================================================
# Publish Command
# ============================================================================


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

    frontmatter = parsed.frontmatter
    slug = frontmatter.get("slug")
    agent_id = frontmatter.get("agent_id")

    # ── Slug check (first publish only) ──────────────────────────────────
    if slug and not agent_id:
        try:
            from agirails.api.agirails_app import check_slug

            slug_result = asyncio.run(check_slug(slug))
            if not slug_result.get("available"):
                suggestion = slug_result.get("suggestion") or slug_result.get(
                    "suggestions", [None]
                )[0]
                if suggestion:
                    old_slug = slug
                    slug = suggestion
                    print_warning(
                        f'Slug "{old_slug}" was taken. Renamed to "{slug}".'
                    )
                    # Update frontmatter and rewrite
                    frontmatter["slug"] = slug
                    content = serialize_agirails_md(frontmatter, parsed.body)
                    md_path.write_text(content, encoding="utf-8")
                else:
                    print_error(
                        "Slug taken",
                        f'Slug "{slug}" is already taken. Choose a different name.',
                    )
                    raise typer.Exit(1)
            else:
                if opts.output_format != OutputFormat.QUIET:
                    print_info(f'Slug "{slug}" is available.')
        except typer.Exit:
            raise
        except Exception as e:
            # Non-fatal: slug check API failure doesn't block publish
            if opts.output_format != OutputFormat.QUIET:
                print_warning(f"Slug check failed: {e}. Proceeding.")

    # Compute hash
    hash_result = compute_config_hash(content)

    if not dry_run and opts.output_format not in (OutputFormat.JSON, OutputFormat.QUIET):
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

    # Tracking vars for output
    testnet_result = None
    wallet_address = None
    is_testnet = "sepolia" in network

    # Save pending-publish for lazy activation
    if not dry_run:
        try:
            endpoint, descriptors = extract_registration_params(frontmatter)
        except ValueError:
            endpoint = PENDING_ENDPOINT
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

        # ── Testnet activation ───────────────────────────────────────────
        if is_testnet:
            try:
                testnet_result = asyncio.run(
                    _activate_on_testnet(
                        config_hash=result.config_hash,
                        cid=result.cid,
                        endpoint=endpoint,
                        service_descriptors=descriptors,
                        network=network,
                    )
                )
                if testnet_result:
                    wallet_address = testnet_result.get("wallet_address")
                    activation_agent_id = testnet_result.get("agent_id")
                    tx_hash = testnet_result.get("tx_hash")
                    if tx_hash:
                        print_success(f"Testnet activation: {tx_hash}")
                        print_success("Minted 1,000 test USDC to Smart Wallet")
            except Exception as e:
                # Non-fatal: activation failure doesn't block publish
                print_warning(f"Testnet activation failed: {e}")
                testnet_result = None

        # ── Update AGIRAILS.md frontmatter ───────────────────────────────
        updated_content = update_frontmatter_after_publish(
            content, result.config_hash, result.cid
        )

        # Write-back wallet/agent_id/did after testnet activation
        if testnet_result and wallet_address:
            write_back = parse_agirails_md(updated_content)
            wb_fm = {**write_back.frontmatter}
            wb_fm["wallet"] = wallet_address
            if testnet_result.get("agent_id"):
                wb_fm["agent_id"] = testnet_result["agent_id"]
            chain_id = 84532 if "sepolia" in network else 8453
            wb_fm["did"] = f"did:ethr:{chain_id}:{wallet_address}"
            updated_content = serialize_agirails_md(wb_fm, write_back.body)

        md_path.write_text(updated_content, encoding="utf-8")

        # ── agirails.app sync (re-publish with agent_id) ────────────────
        effective_agent_id = (
            testnet_result.get("agent_id") if testnet_result else None
        ) or agent_id
        effective_wallet = wallet_address

        if slug and effective_agent_id and effective_wallet:
            try:
                synced = asyncio.run(
                    _resolve_sign_and_upsert(
                        slug=slug,
                        agent_id=effective_agent_id,
                        wallet=effective_wallet,
                        config_cid=result.cid,
                        config_hash=result.config_hash,
                        network=network,
                    )
                )
                if synced and opts.output_format not in (OutputFormat.JSON, OutputFormat.QUIET):
                    print_success(
                        f"Profile live at: agirails.app/a/{slug}"
                    )
            except Exception as e:
                # Non-blocking: agent is already on-chain
                print_warning(f"agirails.app sync failed: {e}")
        elif slug and not effective_agent_id:
            if opts.output_format not in (OutputFormat.JSON, OutputFormat.QUIET):
                print_info(
                    "First publish — agirails.app sync will happen on re-publish."
                )

    # Output
    if opts.output_format == OutputFormat.JSON:
        json_data: dict = {
            "configHash": result.config_hash,
            "cid": result.cid,
            "dryRun": result.dry_run,
            "network": network,
            "path": str(md_path),
        }
        if testnet_result and testnet_result.get("tx_hash"):
            json_data["testnetTxHash"] = testnet_result["tx_hash"]
            json_data["walletAddress"] = testnet_result.get("wallet_address")
            json_data["agentId"] = testnet_result.get("agent_id")
        print_json(json_data)
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
            typer.echo("")
            typer.echo(
                "Mainnet: on-chain activation will happen on your first payment."
            )

            # Context-aware next steps
            has_endpoint = endpoint and endpoint != PENDING_ENDPOINT
            typer.echo("")
            typer.echo("Next steps:")
            if not has_endpoint:
                typer.echo(
                    '  1. Set your endpoint:    Add "endpoint: https://..." to AGIRAILS.md'
                )
                typer.echo("  2. Check endpoint:       actp health")
                typer.echo("  3. Check your balance:   actp balance")
                typer.echo("  4. Verify config match:  actp diff")
            else:
                typer.echo("  1. Check endpoint:       actp health")
                typer.echo("  2. Check your balance:   actp balance")
                typer.echo("  3. Verify config match:  actp diff")

            # Test payment suggestion
            if is_testnet and testnet_result and testnet_result.get("tx_hash") and slug:
                typer.echo("")
                typer.echo(
                    f"  Try a test payment: actp pay agirails.app/a/{slug} 5"
                )

            # Warn if placeholder endpoint
            if not has_endpoint:
                typer.echo("")
                print_warning(
                    "No endpoint set — your agent can't receive jobs yet."
                )
                typer.echo(
                    '  Add "endpoint: https://your-agent.com/webhook" to AGIRAILS.md, then: actp publish'
                )

            # Profile URL hint
            if slug:
                typer.echo("")
                print_info(f"Your agent profile: https://agirails.app/a/{slug}")
