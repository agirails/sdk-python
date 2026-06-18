"""Identity File Resolution (CLI).

Resolves the absolute path to an agent's ``{slug}.md`` identity file so the
buyer-aware ``actp diff`` / ``actp pull`` paths see no false drift. Mirrors TS
``resolveIdentityPath`` (cli/utils/config.ts:442-492):

  1. Primary: read the ``identity`` pointer from ``.actp/config.json``. If set
     and the pointed-to file exists, return it.
  2. Fallback: scan the project root for ``{slug}.md`` identity files (any
     ``.md`` that parses as a V4 config with a name + services/servicesNeeded or
     a pay/both intent), skipping the well-known non-identity docs.

This is pure read-only path resolution — no file is written. ``ACTP_DIR`` is
honored for the ``.actp`` directory so a buyer's marker/pointer is read from the
same place ``actp publish`` wrote it.

@module cli/utils/identity
"""

from __future__ import annotations

import json
import os
from typing import Optional, Set


# Well-known docs that are never agent identity files (mirror TS skip set).
_SKIP_MD_FILES: Set[str] = {
    "AGIRAILS.md",
    "README.md",
    "CHANGELOG.md",
    "SCRATCHPAD.md",
    "NOTES.md",
}


def _get_actp_dir(project_root: str) -> str:
    """Resolve the ``.actp`` directory, honoring ``ACTP_DIR`` (mirror TS getActpDir)."""
    env_dir = os.environ.get("ACTP_DIR")
    if env_dir:
        return env_dir
    return os.path.join(project_root, ".actp")


def resolve_identity_path(project_root: Optional[str] = None) -> Optional[str]:
    """Resolve the absolute path to the agent's ``{slug}.md`` identity file.

    Reads the ``identity`` pointer from ``config.json``. Returns None if no
    pointer is set or the file doesn't exist; then falls back to scanning the
    project root for a parseable V4 identity file.

    Mirrors TS ``resolveIdentityPath`` (cli/utils/config.ts:442-492).

    Args:
        project_root: Project root directory (defaults to cwd).

    Returns:
        Absolute path to the identity file, or None.
    """
    root = project_root if project_root is not None else os.getcwd()

    # Primary: read the identity pointer from config.json.
    try:
        config_path = os.path.join(_get_actp_dir(root), "config.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            identity = config.get("identity")
            if identity:
                identity_path = os.path.join(root, identity)
                if os.path.exists(identity_path):
                    return identity_path
    except Exception:
        # fall through to auto-detect
        pass

    # Fallback: scan project root for {slug}.md identity files. Handles cases
    # where init ran before the identity file was created, or where the user
    # manually wrote a .md file after init.
    try:
        # Lazy import to avoid a circular import (config → agirailsmd V4).
        from agirails.config.agirailsmd import parse_agirails_md_v4

        for entry in sorted(os.listdir(root)):
            if not entry.endswith(".md") or entry in _SKIP_MD_FILES:
                continue
            md_path = os.path.join(root, entry)
            try:
                with open(md_path, "r", encoding="utf-8") as f:
                    content = f.read()
                v4 = parse_agirails_md_v4(content)
                # Accept provider files (services), buyer files (servicesNeeded),
                # and any pay/both agent. Requiring services > 0 used to skip
                # buyer {slug}.md (AIP-18 §1).
                is_identity = bool(v4.name) and (
                    len(v4.services) > 0
                    or len(v4.services_needed) > 0
                    or v4.intent == "pay"
                    or v4.intent == "both"
                )
                if is_identity:
                    return md_path
            except Exception:
                continue
    except Exception:
        # ignore
        pass

    return None
