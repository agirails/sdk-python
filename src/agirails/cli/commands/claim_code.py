"""``actp claim-code`` — Regenerate a claim code for dashboard linking.

Reads AGIRAILS.md, resolves the agent's keystore, signs the
``agirails-claim-code:{agentId}:{chainName}:{timestamp}`` challenge with
EIP-191 personal_sign, and exchanges it at
``agirails.app/api/v1/agents/claim-code`` for a fresh 24h claim code.

Usage::

    actp claim-code                    # use AGIRAILS.md in cwd
    actp claim-code ./path/to/AGIRAILS.md
    actp claim-code --json
    actp claim-code --quiet            # emit only the code (pipe-friendly)

Python port of ``sdk-js/src/cli/commands/claim-code.ts``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from eth_account import Account
from eth_account.messages import encode_defunct

from agirails.api.agirails_app import (
    AgirailsAppError,
    RequestClaimCodeParams,
    request_claim_code,
)
from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_json,
    print_success,
)
from agirails.config.agirailsmd import parse_agirails_md
from agirails.wallet.keystore import ResolvePrivateKeyOptions, resolve_private_key


def claim_code(
    path: Optional[Path] = typer.Argument(
        None,
        help="Path to AGIRAILS.md (defaults to ./AGIRAILS.md).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
    quiet: bool = typer.Option(
        False, "-q", "--quiet", help="Emit only the claim code (pipe-friendly)."
    ),
) -> None:
    """Get a claim code to link your agent to your dashboard account."""
    try:
        asyncio.run(_run(path, json_output=json_output, quiet=quiet))
    except typer.Exit:
        raise
    except Exception as exc:  # narrow at the I/O boundary
        if json_output:
            print_json({"ok": False, "error": str(exc)})
        else:
            print_error(f"claim-code failed: {exc}")
        raise typer.Exit(code=1)


async def _run(
    path: Optional[Path], *, json_output: bool, quiet: bool
) -> None:
    # 1. Resolve AGIRAILS.md path (CLI arg → cwd default).
    md_path = (path or Path("AGIRAILS.md")).resolve()
    if not md_path.exists():
        msg = (
            f"AGIRAILS.md not found at {md_path}. Run from your agent "
            "directory or pass an explicit path."
        )
        if json_output:
            print_json({"ok": False, "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=2)

    content = md_path.read_text(encoding="utf-8")
    parsed = parse_agirails_md(content)
    fm = parsed.frontmatter or {}

    agent_id = fm.get("agent_id")
    if not agent_id:
        msg = (
            "No agent_id in AGIRAILS.md frontmatter. Run `actp publish` "
            "first to register your agent on-chain."
        )
        if json_output:
            print_json({"ok": False, "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=2)
    agent_id_str = str(agent_id)

    # 2. Resolve keystore. Default to testnet; mainnet keystore is
    # selected when the project config explicitly says mode=mainnet.
    project_root = md_path.parent
    network_mode = _detect_network_mode(project_root)
    chain_name = (
        "base-mainnet" if network_mode == "mainnet" else "base-sepolia"
    )

    private_key = await resolve_private_key(
        state_directory=str(project_root),
        options=ResolvePrivateKeyOptions(network=network_mode),
    )
    if not private_key:
        raise RuntimeError(
            "No wallet credentials found. Set ACTP_KEY_PASSWORD or "
            "ACTP_PRIVATE_KEY environment variable."
        )

    account = Account.from_key(private_key)
    signer_address = account.address

    # If the agent's Smart Wallet differs from the EOA signer, the
    # server needs both: ``wallet`` is the on-chain agent owner;
    # ``signer`` is the address recovered from the signature.
    fm_wallet = fm.get("wallet")
    effective_wallet = (
        str(fm_wallet) if isinstance(fm_wallet, str) and fm_wallet else signer_address
    )

    # 3. Sign EIP-191 challenge.
    timestamp = int(time.time())
    message = f"agirails-claim-code:{agent_id_str}:{chain_name}:{timestamp}"
    signable = encode_defunct(text=message)
    signed = account.sign_message(signable)
    sig_hex = signed.signature.hex()
    if not sig_hex.startswith("0x"):
        sig_hex = "0x" + sig_hex

    # 4. Exchange at agirails.app/api/v1/agents/claim-code.
    signer_field = (
        signer_address
        if effective_wallet.lower() != signer_address.lower()
        else None
    )
    try:
        result = await request_claim_code(
            RequestClaimCodeParams(
                agent_id=agent_id_str,
                wallet=effective_wallet,
                signer=signer_field,
                signature=sig_hex,
                message=message,
                network=chain_name,
            )
        )
    except AgirailsAppError as exc:
        if json_output:
            print_json({"ok": False, "error": str(exc)})
        else:
            print_error(f"claim-code API error: {exc}")
        raise typer.Exit(code=1)

    code = result.get("claimCode")
    if not isinstance(code, str) or not code:
        raise RuntimeError(
            f"claim-code response missing claimCode field: {result!r}"
        )

    claim_url = f"https://agirails.app/claim?code={code}"

    if quiet:
        # Pipe-friendly: only the code, no spinner/banner output.
        sys.stdout.write(code + "\n")
        return

    if json_output:
        print_json(
            {
                "ok": True,
                "claimCode": code,
                "claimUrl": claim_url,
                "agentId": agent_id_str,
            }
        )
        return

    print_success(f"Claim code: {code}")
    print_info(f"  Claim link: {claim_url}")
    print_info("  (enter this code in your dashboard to link the agent)")
    print_info("")
    print_info(
        "  Code expires in 24 hours. Run `actp claim-code` to get a new one."
    )


def _detect_network_mode(project_root: Path) -> str:
    """Best-effort: read ``mode`` from a project config if present."""
    for candidate in ("actp.config.json", "agirails.config.json"):
        cfg_path = project_root / candidate
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                mode = str(data.get("mode", "")).lower()
                if mode in ("mainnet", "testnet", "mock"):
                    return mode
            except (json.JSONDecodeError, OSError):
                pass
    env_mode = os.environ.get("ACTP_NETWORK", "").lower()
    if env_mode in ("mainnet", "testnet", "mock"):
        return env_mode
    return "testnet"
