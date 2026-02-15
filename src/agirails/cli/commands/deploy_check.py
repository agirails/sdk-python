"""
Deploy Check Command - Pre-deployment security audit.

Usage:
    $ actp deploy check
    $ actp deploy check --quiet
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import typer

try:
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# Status constants
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

# Directories to skip during recursive scan
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}

# Max recursion depth
MAX_DEPTH = 5

# Required entries for ignore files
GITIGNORE_REQUIRED = [".actp/", "*.key"]
DOCKERIGNORE_REQUIRED = [".actp/"]
RAILWAYIGNORE_REQUIRED = [".actp/"]


def _print_status(status: str, message: str, quiet: bool = False) -> None:
    """Print a status line with color."""
    if quiet and status != FAIL:
        return

    if HAS_RICH:
        console = Console()
        color_map = {PASS: "green", WARN: "yellow", FAIL: "red"}
        color = color_map.get(status, "white")
        console.print(f"[{color}][{status}][/{color}] {message}")
    else:
        print(f"[{status}] {message}")


def _file_contains_pattern(filepath: Path, pattern: str) -> bool:
    """Check if a file contains a regex pattern."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        return bool(re.search(pattern, content))
    except OSError:
        return False


def _ignore_file_has_entry(filepath: Path, entry: str) -> bool:
    """Check if an ignore file contains the given entry (line-based, exact match)."""
    if not filepath.exists():
        return False
    try:
        lines = filepath.read_text(encoding="utf-8").splitlines()
        return any(line.strip() == entry for line in lines)
    except OSError:
        return False


def _add_entries_to_ignore_file(filepath: Path, entries: List[str]) -> List[str]:
    """
    Add missing entries to an ignore file (idempotent).
    Returns list of entries that were added.
    """
    added: List[str] = []
    existing_lines: List[str] = []

    if filepath.exists():
        try:
            existing_lines = filepath.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass

    existing_stripped = {line.strip() for line in existing_lines}

    for entry in entries:
        if entry not in existing_stripped:
            existing_lines.append(entry)
            added.append(entry)

    if added:
        # Ensure trailing newline
        content = "\n".join(existing_lines)
        if not content.endswith("\n"):
            content += "\n"
        filepath.write_text(content, encoding="utf-8")

    return added


def _scan_subdirectories(
    root: Path,
    depth: int = 0,
) -> List[Path]:
    """
    Recursively collect non-hidden subdirectories for scanning.
    Skips SKIP_DIRS and hidden directories. Max depth = MAX_DEPTH.
    Returns list of directory paths to check for sensitive files.
    """
    if depth > MAX_DEPTH:
        return []

    results: List[Path] = []

    try:
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name in SKIP_DIRS:
                continue
            if entry.name.startswith("."):
                continue
            results.append(entry)
            results.extend(_scan_subdirectories(entry, depth + 1))
    except PermissionError:
        pass

    return results


def _check_gitignore(project_dir: Path) -> Tuple[str, str]:
    """Check .gitignore contains .actp/ and *.key."""
    gitignore = project_dir / ".gitignore"
    if not gitignore.exists():
        return FAIL, f".gitignore missing at {project_dir}"

    missing = []
    for entry in GITIGNORE_REQUIRED:
        if not _ignore_file_has_entry(gitignore, entry):
            missing.append(entry)

    if missing:
        return FAIL, f".gitignore at {project_dir} missing entries: {', '.join(missing)}"
    return PASS, f".gitignore at {project_dir} OK"


def _check_dockerignore(project_dir: Path) -> Optional[Tuple[str, str]]:
    """Check .dockerignore if Dockerfile exists."""
    dockerfile = project_dir / "Dockerfile"
    if not dockerfile.exists():
        return None  # Not applicable

    dockerignore = project_dir / ".dockerignore"
    if not dockerignore.exists():
        return FAIL, f".dockerignore missing at {project_dir} (Dockerfile exists)"

    missing = []
    for entry in DOCKERIGNORE_REQUIRED:
        if not _ignore_file_has_entry(dockerignore, entry):
            missing.append(entry)

    if missing:
        return FAIL, f".dockerignore at {project_dir} missing entries: {', '.join(missing)}"
    return PASS, f".dockerignore at {project_dir} OK"


def _check_env_files(scan_dir: Path) -> List[Tuple[str, str]]:
    """Check .env files for raw private keys."""
    results: List[Tuple[str, str]] = []
    for env_file in scan_dir.glob(".env*"):
        if env_file.is_file() and _file_contains_pattern(env_file, r"PRIVATE_KEY\s*=\s*0x[0-9a-fA-F]"):
            results.append((FAIL, f"Raw private key found in {env_file}"))
    return results


def _check_docker_files(scan_dir: Path) -> List[Tuple[str, str]]:
    """Check Dockerfile and docker-compose for raw keys."""
    results: List[Tuple[str, str]] = []
    for name in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
        filepath = scan_dir / name
        if filepath.is_file() and _file_contains_pattern(filepath, r"PRIVATE_KEY\s*=?\s*0x[0-9a-fA-F]"):
            results.append((FAIL, f"Raw private key found in {filepath}"))
    return results


def _check_ci_files(project_dir: Path) -> List[Tuple[str, str]]:
    """Check CI files for raw keys."""
    results: List[Tuple[str, str]] = []

    # GitHub Actions
    gh_workflows = project_dir / ".github" / "workflows"
    if gh_workflows.is_dir():
        for yml in gh_workflows.glob("*.yml"):
            if _file_contains_pattern(yml, r"PRIVATE_KEY\s*[:=]\s*0x[0-9a-fA-F]"):
                results.append((FAIL, f"Raw private key found in {yml}"))
        for yaml in gh_workflows.glob("*.yaml"):
            if _file_contains_pattern(yaml, r"PRIVATE_KEY\s*[:=]\s*0x[0-9a-fA-F]"):
                results.append((FAIL, f"Raw private key found in {yaml}"))

    # GitLab CI
    gitlab_ci = project_dir / ".gitlab-ci.yml"
    if gitlab_ci.is_file() and _file_contains_pattern(gitlab_ci, r"PRIVATE_KEY\s*[:=]\s*0x[0-9a-fA-F]"):
        results.append((FAIL, f"Raw private key found in {gitlab_ci}"))

    return results


def _check_symlink(project_dir: Path) -> Optional[Tuple[str, str]]:
    """Check if .actp/ is a symlink (security risk)."""
    actp_dir = project_dir / ".actp"
    if actp_dir.exists() and actp_dir.is_symlink():
        return FAIL, f".actp/ is a symlink at {project_dir} (security risk)"
    return None


def _check_keystore_exists(project_dir: Path) -> Optional[Tuple[str, str]]:
    """Warn if no keystore.json found."""
    keystore = project_dir / ".actp" / "keystore.json"
    if not keystore.exists():
        return WARN, f"No keystore.json found at {project_dir / '.actp'}"
    return None


def _check_keystore_permissions(project_dir: Path) -> Optional[Tuple[str, str]]:
    """Warn if keystore.json permissions are too open (Unix only)."""
    keystore = project_dir / ".actp" / "keystore.json"
    if not keystore.exists():
        return None

    if sys.platform == "win32":
        return None

    try:
        mode = keystore.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            return WARN, f"keystore.json permissions too open at {keystore} (recommend chmod 600)"
    except OSError:
        pass

    return None


def deploy_check(
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Hide PASS and WARN, show only FAIL",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Auto-generate/update .gitignore, .dockerignore, .railwayignore",
    ),
    directory: Optional[Path] = typer.Option(
        None,
        "--directory",
        "-d",
        help="Working directory (default: current)",
    ),
) -> None:
    """Pre-deployment security audit."""
    work_dir = directory or Path.cwd()

    # Collect all check results
    all_results: List[Tuple[str, str]] = []
    has_fail = False

    # Root-level checks (gitignore, dockerignore, symlink, keystore)
    # 1. .gitignore check
    status, msg = _check_gitignore(work_dir)
    all_results.append((status, msg))

    # 2. .dockerignore check (only if Dockerfile exists)
    result = _check_dockerignore(work_dir)
    if result:
        all_results.append(result)

    # 6. Symlink check
    result = _check_symlink(work_dir)
    if result:
        all_results.append(result)

    # 7. Keystore existence
    result = _check_keystore_exists(work_dir)
    if result:
        all_results.append(result)

    # 8. Keystore permissions
    result = _check_keystore_permissions(work_dir)
    if result:
        all_results.append(result)

    # 5. CI files (only at root)
    all_results.extend(_check_ci_files(work_dir))

    # Scan root + subdirectories for sensitive files (.env, Docker files)
    scan_dirs = [work_dir] + _scan_subdirectories(work_dir)

    for scan_dir in scan_dirs:
        # 3. .env files
        all_results.extend(_check_env_files(scan_dir))

        # 4. Docker files with raw keys
        all_results.extend(_check_docker_files(scan_dir))

    # Print results
    for status, msg in all_results:
        if status == FAIL:
            has_fail = True
        _print_status(status, msg, quiet=quiet)

    # Auto-fix if requested
    if fix:
        typer.echo("")
        # .gitignore
        gitignore = work_dir / ".gitignore"
        added = _add_entries_to_ignore_file(gitignore, GITIGNORE_REQUIRED)
        if added:
            _print_status(PASS, f"Updated {gitignore}: added {', '.join(added)}", quiet=False)

        # .dockerignore (only if Dockerfile exists)
        if (work_dir / "Dockerfile").exists():
            dockerignore = work_dir / ".dockerignore"
            added = _add_entries_to_ignore_file(dockerignore, DOCKERIGNORE_REQUIRED)
            if added:
                _print_status(PASS, f"Updated {dockerignore}: added {', '.join(added)}", quiet=False)

        # .railwayignore
        railwayignore = work_dir / ".railwayignore"
        if railwayignore.exists() or (work_dir / "railway.json").exists():
            added = _add_entries_to_ignore_file(railwayignore, RAILWAYIGNORE_REQUIRED)
            if added:
                _print_status(PASS, f"Updated {railwayignore}: added {', '.join(added)}", quiet=False)

    # Summary
    fail_count = sum(1 for s, _ in all_results if s == FAIL)
    warn_count = sum(1 for s, _ in all_results if s == WARN)
    pass_count = sum(1 for s, _ in all_results if s == PASS)

    if not quiet:
        typer.echo("")
        typer.echo(f"Results: {pass_count} pass, {warn_count} warn, {fail_count} fail")

    if has_fail:
        raise typer.Exit(1)
