"""CLI utility modules."""

from agirails.cli.utils.client import (
    get_client,
    get_client_sync,
    get_config_path,
    get_state_directory,
    load_config,
    save_config,
)
from agirails.cli.utils.identity import resolve_identity_path
from agirails.cli.utils.output import (
    OutputFormat,
    format_output,
    print_error,
    print_info,
    print_json,
    print_success,
    print_table,
    print_warning,
)

__all__ = [
    # Output
    "OutputFormat",
    "format_output",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_table",
    "print_json",
    # Client
    "get_client",
    "get_client_sync",
    "load_config",
    "save_config",
    "get_config_path",
    "get_state_directory",
    # Identity pointer
    "resolve_identity_path",
]
