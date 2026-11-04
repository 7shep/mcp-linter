"""Command-line entry point.

    mcp-lint run -- npx -y @modelcontextprotocol/server-everything
    mcp-lint check tools.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from mcp_lint.models import Severity, ToolDef
from mcp_lint.report import render_text, to_json, write_json
from mcp_lint.rules import run_static

FAIL_ON = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-lint", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--json", metavar="PATH", help="also write a JSON report here")
        sp.add_argument("--min-severity", choices=["info", "warning", "error"], default="info",
                        help="hide terminal findings below this level (default: info)")
        sp.add_argument("--fail-on", choices=["info", "warning", "error", "never"], default="error",
                        help="exit 1 if any finding is at or above this level (default: error)")

    run = sub.add_parser("run", help="start an MCP server over stdio and lint its tools")
    common(run)
    run.add_argument("server", nargs=argparse.REMAINDER,
                     help="server command after '--', e.g. -- npx -y some-server")

    check = sub.add_parser("check", help="lint a saved tools/list JSON file")
    common(check)
    check.add_argument("file", help="JSON file: a tools/list result or a list of tools")
    return p


def _load_tools_file(path: str) -> list[ToolDef]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("tools", data) if isinstance(data, dict) else data
    return [ToolDef.from_dict(t) for t in items]


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "run":
        cmd = [a for a in args.server]
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("mcp-lint: give the server command after '--'", file=sys.stderr)
            return 2
        from mcp_lint.client import fetch_tools  # imported lazily: needs the mcp SDK

        try:
            info = asyncio.run(fetch_tools(cmd[0], cmd[1:]))
        except Exception as exc:  # noqa: BLE001 - surface any connection failure plainly
            print(f"mcp-lint: could not connect to server: {exc!r}", file=sys.stderr)
            return 2
        server = {"name": info.name, "version": info.version, "command": cmd}
        tools = info.tools
    else:
        tools = _load_tools_file(args.file)
        server = {"name": args.file, "version": None}

    findings = run_static(tools)
    print(render_text(server, tools, findings, FAIL_ON[args.min_severity]))
    if args.json:
        write_json(args.json, to_json(server, tools, findings))
        print(f"\nJSON report written to {args.json}")

    if args.fail_on != "never":
        threshold = FAIL_ON[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
