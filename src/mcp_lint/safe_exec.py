"""Run a command with only a minimal environment, passing stdio straight through.

    python -m mcp_lint.safe_exec -- npx -y @modelcontextprotocol/server-filesystem DIR

Claude Code gives MCP servers its whole environment, API keys included. The
eval's baseline condition launches each server through this wrapper instead,
so it gets the same minimal set as ``mcp-lint run`` and the proxy: the SDK's
safe defaults (PATH, TEMP, home folder...) and nothing else.
"""

from __future__ import annotations

import subprocess
import sys

from mcp.client.stdio import get_default_environment

from mcp_lint.client import _resolve_command


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: python -m mcp_lint.safe_exec -- <command> [args...]", file=sys.stderr)
        return 2
    cmd = [_resolve_command(argv[0])] + argv[1:]
    try:
        return subprocess.call(cmd, env=get_default_environment())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
