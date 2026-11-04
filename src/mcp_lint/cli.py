"""Command-line entry point.

    mcp-lint run -- npx -y @modelcontextprotocol/server-everything
    mcp-lint run --probe fixtures.json -- <server command>
    mcp-lint check tools.json
    mcp-lint init-fixtures fixtures.json -- <server command>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from mcp_lint.fixtures import FixtureError, load_fixtures, template
from mcp_lint.models import Severity, ToolDef
from mcp_lint.report import render_probes, render_text, to_json, write_json
from mcp_lint.rules import run_static
from mcp_lint.rules.probe import run_probe_rules

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

    def server_cmd(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                        help="forward this environment variable to the server (repeatable); "
                        "by default servers get only a minimal safe set, never your API keys")
        sp.add_argument("server", nargs=argparse.REMAINDER,
                        help="server command after '--', e.g. -- npx -y some-server")

    run = sub.add_parser("run", help="start an MCP server over stdio and lint its tools")
    common(run)
    run.add_argument("--probe", metavar="FIXTURES",
                     help="also call the tools listed in this fixtures file")
    run.add_argument("--error-probes", action="store_true",
                     help="also send generated bad arguments to read-only tools and "
                     "check the error messages (P4); works without a fixtures file")
    run.add_argument("--probe-timeout", type=float, default=30.0, metavar="SECONDS",
                     help="per-call timeout for probes (default: 30)")
    server_cmd(run)

    check = sub.add_parser("check", help="lint a saved tools/list JSON file")
    common(check)
    check.add_argument("file", help="JSON file: a tools/list result or a list of tools")

    init = sub.add_parser("init-fixtures", help="write a starter fixtures file for a server")
    init.add_argument("out", help="path to write, e.g. fixtures.json")
    init.add_argument("--from", dest="from_file", metavar="TOOLS_JSON",
                      help="build from a saved tools/list file instead of a live server")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    server_cmd(init)
    return p


def _load_tools_file(path: str) -> list[ToolDef]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("tools", data) if isinstance(data, dict) else data
    return [ToolDef.from_dict(t) for t in items]


def _server_cmd(raw: list[str]) -> list[str]:
    return raw[1:] if raw and raw[0] == "--" else list(raw)


def _err(msg: str) -> int:
    print(f"mcp-lint: {msg}", file=sys.stderr)
    return 2


def _init_fixtures(args: argparse.Namespace) -> int:
    if os.path.exists(args.out) and not args.force:
        return _err(f"{args.out} already exists (use --force to overwrite)")
    cmd = _server_cmd(args.server)
    if args.from_file:
        tools = _load_tools_file(args.from_file)
    elif cmd:
        from mcp_lint.client import fetch_tools

        try:
            tools = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env)).tools
        except Exception as exc:  # noqa: BLE001
            return _err(f"could not connect to server: {exc!r}")
    else:
        return _err("give a server command after '--' or --from TOOLS_JSON")
    write_json(args.out, template(tools))
    flagged = sum(1 for t in tools if not t.read_only)
    print(f"Wrote {len(tools)} skipped probes to {args.out}.")
    print(f"{flagged} tools are not marked read-only and need \"allow_destructive\": true to run.")
    print("Fill in args and delete \"skip\" for each probe you want to run.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "init-fixtures":
        return _init_fixtures(args)

    probes = None
    if args.command == "run":
        cmd = _server_cmd(args.server)
        if not cmd:
            return _err("give the server command after '--'")
        from mcp_lint.client import fetch_and_probe, fetch_tools  # needs the mcp SDK

        try:
            if args.probe or args.error_probes:
                fixtures = load_fixtures(args.probe) if args.probe else []
                info, probes = asyncio.run(fetch_and_probe(
                    cmd[0], cmd[1:], fixtures, args.probe_timeout, auto_errors=args.error_probes,
                    pass_env=args.pass_env))
            else:
                info = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env))
        except (FixtureError, OSError) as exc:
            return _err(str(exc))
        except Exception as exc:  # noqa: BLE001 - surface any connection failure plainly
            return _err(f"could not connect to server: {exc!r}")
        server = {"name": info.name, "version": info.version, "command": cmd}
        tools = info.tools
    else:
        tools = _load_tools_file(args.file)
        server = {"name": args.file, "version": None}

    findings = run_static(tools)
    if probes is not None:
        findings += run_probe_rules(tools, probes)
    print(render_text(server, tools, findings, FAIL_ON[args.min_severity]))
    if probes is not None:
        print()
        print(render_probes(probes))
    if args.json:
        write_json(args.json, to_json(server, tools, findings, probes))
        print(f"\nJSON report written to {args.json}")

    if args.fail_on != "never":
        threshold = FAIL_ON[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
