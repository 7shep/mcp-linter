"""Check that a release tag matches the package version.

Usage: python scripts/check_release_version.py TAG

Exits 0 when TAG matches the version in pyproject.toml and
src/mcp_lint/__init__.py (both must be equal), 1 otherwise, and 2 on a usage
error. Uses only the standard library so it runs on Python 3.10.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_SECTION_HEADER = re.compile(r"^\[.*\]\s*$", re.MULTILINE)
_PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_INIT_VERSION = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_NUMERIC_PART = re.compile(r"[0-9]+")


def tag_matches(tag: str, version: str) -> bool:
    """Return True if a release tag names exactly this package version.

    A single leading "v" is stripped. The tag must have one to three numeric
    dot-separated parts; missing parts are padded with ".0", so "v1.2", "1.2"
    and "v1.2.0" all match "1.2.0". Anything else (including "v1.2.1",
    "v1.3", "v1", "vfoo" or an empty tag) does not match.
    """
    name = tag[1:] if tag.startswith("v") else tag
    parts = name.split(".")
    if not 1 <= len(parts) <= 3:
        return False
    if not all(_NUMERIC_PART.fullmatch(part) for part in parts):
        return False
    padded = parts + ["0"] * (3 - len(parts))
    return ".".join(padded) == version


def _project_table(pyproject_text: str) -> str:
    """Return the body of the [project] table (up to the next table header)."""
    start = re.search(r"^\[project\]\s*$", pyproject_text, re.MULTILINE)
    if start is None:
        raise ValueError("pyproject.toml has no [project] table")
    rest = pyproject_text[start.end():]
    following = _SECTION_HEADER.search(rest)
    return rest[: following.start()] if following else rest


def read_versions(root: Path) -> tuple[str, str]:
    """Return (pyproject version, __init__ version) read from a repo root."""
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = _PYPROJECT_VERSION.search(_project_table(pyproject))
    if match is None:
        raise ValueError("pyproject.toml has no version in the [project] table")
    init = (root / "src" / "mcp_lint" / "__init__.py").read_text(encoding="utf-8")
    init_match = _INIT_VERSION.search(init)
    if init_match is None:
        raise ValueError("src/mcp_lint/__init__.py has no __version__ string")
    return match.group(1), init_match.group(1)


def main(argv: list[str], root: Path = REPO_ROOT) -> int:
    if len(argv) != 2:
        print("usage: check_release_version.py TAG", file=sys.stderr)
        return 2
    tag = argv[1]

    try:
        pyproject_version, init_version = read_versions(root)
    except (OSError, ValueError) as exc:
        print(f"error: could not read package version: {exc}", file=sys.stderr)
        return 1

    if pyproject_version != init_version:
        print(
            "error: version mismatch: pyproject.toml has "
            f"{pyproject_version!r} but src/mcp_lint/__init__.py has {init_version!r}",
            file=sys.stderr,
        )
        return 1

    if not tag_matches(tag, pyproject_version):
        print(
            f"error: tag {tag!r} does not match package version {pyproject_version!r} "
            f"(expected 'v{pyproject_version}' or the same version without a leading 'v')",
            file=sys.stderr,
        )
        return 1

    print(f"ok: tag {tag!r} matches package version {pyproject_version!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
