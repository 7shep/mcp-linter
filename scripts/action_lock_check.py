"""Run `mcp-lint lock --check` for the GitHub Action in action.yml.

The composite action passes every input through environment variables (never
through the script text), so server commands and header names cannot inject
shell code. This script turns those variables into an argv list and runs
mcp-lint with it. It never uses a shell.

Inputs (environment variables):
    MCP_LINT          path to the mcp-lint executable (required)
    INPUT_COMMAND     server launch command, shell-style quoting (or INPUT_URL)
    INPUT_URL         Streamable HTTP endpoint (or INPUT_COMMAND)
    INPUT_LOCK        lockfile path (default mcp-lint.lock)
    INPUT_FAIL_ON     info | warning | error | never (default warning)
    INPUT_JSON        optional path for the JSON report
    INPUT_PASS_ENV    names to pass to a stdio server, split on whitespace, commas or newlines
    INPUT_HEADER_ENV  one Name=VAR per line; the header value comes from env VAR
    GITHUB_STEP_SUMMARY  if set, a markdown section is appended to this file

Exit codes: mcp-lint's own code (0 unchanged, 1 changes at or above --fail-on,
2 usage or connection error). Input validation errors also exit 2.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from collections.abc import Mapping

FAIL_ON_LEVELS = ("info", "warning", "error", "never")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
HEADER_ENV_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+=[A-Za-z_][A-Za-z0-9_]*")
DEFAULT_LOCK = "mcp-lint.lock"
DEFAULT_FAIL_ON = "warning"
CHANGED_MESSAGE = (
    "Tool definitions changed since {lock} was written. Review the changes above; "
    "if they are expected, re-run 'mcp-lint lock' locally and commit the new lock."
)


def _get(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip()


def lock_path(env: Mapping[str, str]) -> str:
    return _get(env, "INPUT_LOCK") or DEFAULT_LOCK


def build_argv(env: Mapping[str, str]) -> list[str]:
    """Return the mcp-lint argv for the given action inputs. Raises ValueError on bad input."""
    mcp_lint = _get(env, "MCP_LINT")
    if not mcp_lint:
        raise ValueError("MCP_LINT is not set; the action must install mcp-lint first")

    command = _get(env, "INPUT_COMMAND")
    url = _get(env, "INPUT_URL")
    if bool(command) == bool(url):
        raise ValueError("set exactly one of 'command' (a stdio server) or 'url' (an HTTP server)")

    fail_on = _get(env, "INPUT_FAIL_ON") or DEFAULT_FAIL_ON
    if fail_on not in FAIL_ON_LEVELS:
        raise ValueError(
            f"fail-on must be one of {', '.join(FAIL_ON_LEVELS)}; got {fail_on!r}")

    json_path = _get(env, "INPUT_JSON")

    pass_names = [n for n in re.split(r"[\s,]+", env.get("INPUT_PASS_ENV") or "") if n]
    for name in pass_names:
        if not ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"pass-env name {name!r} is not a valid environment variable name")
    if pass_names and url:
        raise ValueError("pass-env applies to stdio servers only; it cannot be used with 'url'")

    header_lines = []
    for raw in (env.get("INPUT_HEADER_ENV") or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not HEADER_ENV_RE.fullmatch(line):
            raise ValueError(
                f"header-env line {line!r} must look like Name=VAR "
                "(a header name, '=', then an environment variable name)")
        header_lines.append(line)
    if header_lines and command:
        raise ValueError("header-env applies to 'url' servers only; it cannot be used with 'command'")

    argv = [mcp_lint, "lock", "--check", "--lock", lock_path(env), "--fail-on", fail_on]
    if json_path:
        argv += ["--json", json_path]
    for name in pass_names:
        argv += ["--pass-env", name]
    for line in header_lines:
        argv += ["--header-env", line]

    if url:
        argv += ["--url", url]
    else:
        try:
            parts = shlex.split(command, posix=True)
        except ValueError as exc:
            raise ValueError(f"command could not be parsed ({exc}); check the quoting") from exc
        if not parts or not parts[0]:
            raise ValueError("command is empty after parsing")
        argv += ["--", *parts]
    return argv


def _write_summary(path: str, lock: str, code: int, stdout: str) -> None:
    fence = "```"
    while fence in stdout:
        fence += "`"
    body = stdout if stdout.endswith("\n") else stdout + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("### mcp-lint lock --check\n\n")
        handle.write(f"{fence}text\n{body}{fence}\n\n")
        handle.write(f"Lockfile: `{lock}`. Exit code: {code}.\n\n")


def main() -> int:
    env = os.environ
    try:
        argv = build_argv(env)
    except ValueError as exc:
        print(f"::error::{exc}", flush=True)
        return 2

    child_env = dict(env)
    # Server descriptions can contain non-ASCII text; a Windows pipe would use the
    # locale codec and could crash mcp-lint while printing it.
    child_env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=child_env)
    except OSError as exc:
        print(f"::error::could not start mcp-lint ({exc})", flush=True)
        return 2

    if result.stdout:
        sys.stdout.write(result.stdout if result.stdout.endswith("\n") else result.stdout + "\n")
    if result.stderr:
        sys.stderr.write(result.stderr)
    sys.stdout.flush()
    sys.stderr.flush()

    lock = lock_path(env)
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        _write_summary(summary, lock, result.returncode, result.stdout or "")

    if result.returncode == 1:
        print(f"::error::{CHANGED_MESSAGE.format(lock=lock)}", flush=True)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
