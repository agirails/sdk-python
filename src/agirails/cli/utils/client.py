"""
CLI Client Utilities.

Provides client initialization and configuration management.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, cast

from agirails.client import ACTPClient, ACTPClientConfig, ACTPClientMode


# Default config file name
CONFIG_FILE = "config.json"

# Default state directory name
STATE_DIR = ".actp"

# Valid client modes
VALID_MODES = frozenset(["mock", "testnet", "mainnet"])


def validate_mode(mode: str) -> ACTPClientMode:
    """
    Validate and return mode as ACTPClientMode.

    Args:
        mode: Mode string to validate

    Returns:
        Validated mode cast to ACTPClientMode

    Raises:
        ValueError: If mode is not valid
    """
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(VALID_MODES))}")
    return cast(ACTPClientMode, mode)


def get_state_directory(directory: Optional[Path] = None) -> Path:
    """
    Get the state directory path.

    Args:
        directory: Base directory (defaults to current directory)

    Returns:
        Path to .actp directory

    Raises:
        ValueError: If path traversal attempt detected
    """
    base = (directory or Path.cwd()).resolve()
    state_path = (base / STATE_DIR).resolve()

    # Security: Ensure state_path is within base directory
    try:
        state_path.relative_to(base)
    except ValueError:
        raise ValueError(f"Path traversal detected: {STATE_DIR} escapes base directory")

    return state_path


def get_config_path(directory: Optional[Path] = None) -> Path:
    """
    Get the config file path.

    Args:
        directory: Base directory (defaults to current directory)

    Returns:
        Path to config.json
    """
    return get_state_directory(directory) / CONFIG_FILE


def load_config(directory: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load configuration from .actp/config.json.

    Args:
        directory: Base directory (defaults to current directory)

    Returns:
        Configuration dictionary (empty if not found)
    """
    config_path = get_config_path(directory)

    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_config(config: Dict[str, Any], directory: Optional[Path] = None) -> None:
    """
    Save configuration to .actp/config.json.

    Args:
        config: Configuration dictionary
        directory: Base directory (defaults to current directory)
    """
    state_dir = get_state_directory(directory)
    state_dir.mkdir(parents=True, exist_ok=True)

    config_path = state_dir / CONFIG_FILE

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


def get_default_address() -> str:
    """
    Get a default address for mock mode.

    Returns:
        A deterministic default address
    """
    return "0x" + "1" * 40


async def get_client(
    mode: Optional[str] = None,
    address: Optional[str] = None,
    private_key: Optional[str] = None,
    rpc_url: Optional[str] = None,
    directory: Optional[Path] = None,
) -> ACTPClient:
    """
    Get an initialized ACTPClient.

    Priority for settings:
    1. Function arguments
    2. Environment variables
    3. Config file
    4. Defaults

    Args:
        mode: Client mode ('mock', 'testnet', 'mainnet')
        address: Requester address
        private_key: Private key (for testnet/mainnet)
        rpc_url: RPC URL (for testnet/mainnet)
        directory: Base directory for state

    Returns:
        Initialized ACTPClient
    """
    # Load config
    config = load_config(directory)

    # Determine and validate mode
    mode_str = (
        mode
        or os.environ.get("ACTP_MODE")
        or config.get("mode")
        or "mock"
    )
    validated_mode = validate_mode(mode_str)

    # Determine address
    final_address = (
        address
        or os.environ.get("ACTP_ADDRESS")
        or config.get("address")
        or get_default_address()
    )

    # Determine private key (for non-mock modes)
    # Note: private_key in config is deprecated for security
    final_private_key = (
        private_key
        or os.environ.get("ACTP_PRIVATE_KEY")
    )

    # Determine RPC URL
    final_rpc_url = (
        rpc_url
        or os.environ.get("ACTP_RPC_URL")
        or config.get("rpc_url")
    )

    # Get state directory
    state_dir = get_state_directory(directory)

    # Build client config
    client_config = ACTPClientConfig(
        mode=validated_mode,
        requester_address=final_address,
        state_directory=state_dir,
        private_key=final_private_key,
        rpc_url=final_rpc_url,
    )

    return await ACTPClient.create(config=client_config)


def get_client_sync(
    mode: Optional[str] = None,
    address: Optional[str] = None,
    private_key: Optional[str] = None,
    rpc_url: Optional[str] = None,
    directory: Optional[Path] = None,
) -> ACTPClient:
    """
    Get an initialized ACTPClient (synchronous wrapper).

    See get_client() for argument details.
    """
    return asyncio.run(
        get_client(mode, address, private_key, rpc_url, directory)
    )


def ensure_initialized(directory: Optional[Path] = None) -> bool:
    """
    Check if ACTP is initialized in the directory.

    Args:
        directory: Base directory (defaults to current directory)

    Returns:
        True if .actp directory exists
    """
    state_dir = get_state_directory(directory)
    return state_dir.exists()


def init_directory(
    directory: Optional[Path] = None,
    mode: str = "mock",
    address: Optional[str] = None,
) -> Path:
    """
    Initialize ACTP in a directory.

    Creates .actp directory with default config.

    Args:
        directory: Base directory (defaults to current directory)
        mode: Default mode
        address: Default address

    Returns:
        Path to created .actp directory
    """
    state_dir = get_state_directory(directory)
    state_dir.mkdir(parents=True, exist_ok=True)

    # Create default config
    config: Dict[str, Any] = {
        "mode": mode,
        "address": address or get_default_address(),
    }

    save_config(config, directory)

    return state_dir


__all__ = [
    "get_client",
    "get_client_sync",
    "load_config",
    "save_config",
    "get_config_path",
    "get_state_directory",
    "ensure_initialized",
    "init_directory",
    "get_default_address",
    "validate_mode",
    "VALID_MODES",
]
