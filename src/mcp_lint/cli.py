"""Command-line entry point.

    mcp-lint run -- npx -y @modelcontextprotocol/server-everything
    mcp-lint run --probe fixtures.json -- <server command>
    mcp-lint check tools.json
    mcp-lint init-fixtures fixtures.json -- <server command>
    mcp-lint proxy [--no-paging] [--descriptions FIXES.json] -- <server command>
    mcp-lint eval --setup | --run | --report
    mcp-lint lock [--lock PATH] [--accept] [--from TOOLS_JSON] -- <server command>
    mcp-lint lock --check [--lock PATH] [--fail-on LEVEL] [--json PATH] (--from TOOLS_JSON | -- <server command>)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from mcp_lint.fixtures import FixtureError, load_fixtures, template
from mcp_lint.models import MAX_NESTING, Severity, ToolDef, nesting_depth
from mcp_lint.report import render_probes, render_scores, render_text, to_json, write_json
from mcp_lint.rules import run_static
from mcp_lint.rules.probe import run_probe_rules
from mcp_lint.score import score_server

FAIL_ON = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
DEFAULT_LOCK = "mcp-lint.lock"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-lint", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--json", metavar="PATH", help="also write a JSON report here")
        sp.add_argument("--min-severity", choices=["info", "warning", "error"], default="info",
                        help="hide terminal findings below this level (default: info)")
        sp.add_argument("--fail-on", choices=["info", "warning", "error", "never"], default="error",
                        help="exit 1 if any finding is at or above this level (default: error)")
        sp.add_argument("--fail-under", type=int, metavar="SCORE",
                        help="also exit 1 if the server score is below this (0-100)")

    def server_cmd(sp: argparse.ArgumentParser, after_positional: bool = False) -> None:
        sp.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                        help="forward this environment variable to the server (repeatable); "
                        "by default servers get only a minimal safe set, never your API keys")
        # REMAINDER would swallow options that follow another positional (init-fixtures OUT
        # --from FILE), so that command takes the server command with '*' after '--'.
        sp.add_argument("server", nargs="*" if after_positional else argparse.REMAINDER,
                        help="server command after '--', e.g. -- npx -y some-server")

    run = sub.add_parser("run", help="start an MCP server over stdio and lint its tools")
    common(run)
    run.add_argument("--probe", metavar="FIXTURES",
                     help="also call the tools listed in this fixtures file")
    run.add_argument("--error-probes", action="store_true",
                     help="also send generated bad arguments to read-only tools and "
                     "check the error messages (P4); works without a fixtures file")
    run.add_argument("--include-responses", action="store_true",
                     help="keep full probe response text in the --json report (default: 400-char preview)")
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
    server_cmd(init, after_positional=True)

    proxy = sub.add_parser("proxy", help="serve a server's tools over stdio with fixes applied")
    proxy.add_argument("--no-paging", action="store_true",
                       help="don't cut long responses or add offset/limit parameters")
    proxy.add_argument("--page-tokens", type=int, default=2000, metavar="N",
                       help="page size in estimated tokens (default: 2000)")
    proxy.add_argument("--descriptions", metavar="FIXES_JSON",
                       help='replace tool descriptions from {"descriptions": {tool: text}}')
    proxy.add_argument("--no-errors", action="store_true",
                       help="don't set isError on error text returned as a success")
    proxy.add_argument("--log", metavar="PATH", help="append one JSON line per proxied call")
    server_cmd(proxy)

    lock = sub.add_parser("lock", help="record a server's tools in a lockfile, or check them against it")
    lock.add_argument("--lock", default=DEFAULT_LOCK, metavar="PATH",
                      help=f"lockfile path (default: {DEFAULT_LOCK})")
    lock.add_argument("--check", action="store_true",
                      help="compare the server with the lockfile instead of writing it")
    lock.add_argument("--fail-on", choices=["info", "warning", "error", "never"], default="warning",
                      help="with --check, exit 1 if any change is at or above this level (default: warning)")
    lock.add_argument("--json", metavar="PATH", help="with --check, also write the changes as JSON")
    lock.add_argument("--from", dest="from_file", metavar="TOOLS_JSON",
                      help="use a saved tools/list file instead of a live server")
    lock.add_argument("--accept", action="store_true",
                      help="allow refreshing the lock when the changes include errors "
                      "(review them first)")
    server_cmd(lock)

    from mcp_lint.eval import add_eval_parser

    add_eval_parser(sub)
    return p


def _load_tools_and_instructions(path: str) -> tuple[list[ToolDef], str | None]:
    """Read a tools/list result and its server instructions (None if the file has none).

    Raises ValueError with a short reason if the shape is wrong.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("tools", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError('expected a list of tools, or an object with a "tools" list')
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError(f'tool {i} needs a string "name"')
        for key in ("description", "title"):
            if item.get(key) is not None and not isinstance(item[key], str):
                raise ValueError(f'tool {i} ("{item["name"]}"): "{key}" must be a string')
        for key in ("inputSchema", "input_schema", "annotations", "outputSchema", "output_schema",
                    "_meta", "meta", "execution"):
            if item.get(key) is not None and not isinstance(item[key], dict):
                raise ValueError(f'tool {i} ("{item["name"]}"): "{key}" must be an object')
        if item.get("icons") is not None and not isinstance(item["icons"], list):
            raise ValueError(f'tool {i} ("{item["name"]}"): "icons" must be a list')
        if nesting_depth(item) > MAX_NESTING:
            raise ValueError(f'tool {i} ("{item["name"]}"): {TOO_DEEP}')
    instructions = data.get("instructions") if isinstance(data, dict) else None
    return [ToolDef.from_dict(t) for t in items], instructions if isinstance(instructions, str) else None


TOO_DEEP = f"schema too deeply nested (over {MAX_NESTING} levels)"


def _too_deep(tools: list[ToolDef]) -> str | None:
    """An error message if a live server sent a tool nested deeper than MAX_NESTING."""
    for t in tools:
        if nesting_depth([t.input_schema, t.output_schema, t.annotations, t.meta,
                          t.icons, t.execution]) > MAX_NESTING:  # the list adds one level, like a tool dict
            return f"tool '{t.name}': {TOO_DEEP}"
    return None


def _load_tools_file(path: str) -> list[ToolDef]:
    """Read a tools/list result. Raises ValueError with a short reason if the shape is wrong."""
    return _load_tools_and_instructions(path)[0]


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
        try:
            tools = _load_tools_file(args.from_file)
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            return _err(f"cannot read tools file {args.from_file}: {exc}")
    elif cmd:
        from mcp_lint.client import fetch_tools

        try:
            tools = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env)).tools
        except Exception as exc:  # noqa: BLE001
            return _err(f"could not connect to server: {exc!r}")
        if deep := _too_deep(tools):
            return _err(deep)
    else:
        return _err("give a server command after '--' or --from TOOLS_JSON")
    write_json(args.out, template(tools))
    flagged = sum(1 for t in tools if not t.read_only)
    print(f"Wrote {len(tools)} skipped probes to {args.out}.")
    print(f"{flagged} tools are not marked read-only and need \"allow_destructive\": true to run.")
    print("Fill in args and delete \"skip\" for each probe you want to run.")
    return 0


def _proxy(args: argparse.Namespace) -> int:
    from mcp_lint.proxy import FixOptions, load_descriptions, serve

    cmd = _server_cmd(args.server)
    if not cmd:
        return _err("give the upstream server command after '--'")
    try:
        descriptions = load_descriptions(args.descriptions) if args.descriptions else {}
    except (OSError, ValueError) as exc:
        return _err(str(exc))
    opts = FixOptions(paging=not args.no_paging, page_tokens=args.page_tokens,
                      descriptions=descriptions, errors=not args.no_errors)
    try:
        asyncio.run(serve(cmd[0], cmd[1:], opts, args.pass_env, args.log))
    except KeyboardInterrupt:
        pass
    return 0


def _lock(args: argparse.Namespace) -> int:
    try:
        return _lock_inner(args)
    except RecursionError:
        # A deeply nested schema from an untrusted server or file: fail cleanly, write nothing.
        return _err("schema too deeply nested to lock or check; nothing was written")


def _lock_inner(args: argparse.Namespace) -> int:
    from mcp_lint.lock import (
        LockError, build_lock, command_hash, diff_lock, read_lock, render_changes, write_lock,
    )

    cmd = _server_cmd(args.server)
    if args.from_file:
        try:
            tools, instructions = _load_tools_and_instructions(args.from_file)
        except RecursionError:
            return _err(f"cannot read tools file {args.from_file}: schema too deeply nested")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _err(f"cannot read tools file {args.from_file}: {exc}")
        server = {"name": os.path.basename(args.from_file), "version": None, "command": None,
                  "instructions": instructions}
    elif cmd:
        from mcp_lint.client import fetch_tools

        try:
            info = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env))
        except Exception as exc:  # noqa: BLE001
            return _err(f"could not connect to server: {exc!r}")
        tools = info.tools
        if deep := _too_deep(tools):
            return _err(f"{deep}; nothing was written")
        server = {"name": info.name, "version": info.version, "command": cmd,
                  "instructions": info.instructions}
    else:
        return _err("give a server command after '--' or --from TOOLS_JSON")

    if args.check:
        try:
            locked = read_lock(args.lock)
        except LockError as exc:
            return _err(str(exc))
        changes = diff_lock(locked, server, tools)
        print(render_changes(changes, args.lock, tool_count=len(tools)))
        if args.json:
            # The report never carries the launch command: only its hash.
            summary = {"name": server.get("name"), "version": server.get("version"),
                       "command_sha256": command_hash(server.get("command")),
                       "instructions_known": isinstance(server.get("instructions"), str)}
            try:
                write_json(args.json, {"lock": args.lock, "server": summary,
                                       "changes": [f.to_dict() for f in changes]})
            except OSError as exc:
                return _err(f"cannot write {args.json}: {exc.strerror or exc}")
            print(f"\nJSON report written to {args.json}")
        if args.fail_on != "never":
            threshold = FAIL_ON[args.fail_on].rank
            if any(f.severity.rank >= threshold for f in changes):
                return 1
        return 0

    # Writing: build first, so a refused lock (duplicate names) prints and writes nothing.
    try:
        new_lock = build_lock(server, tools)
    except LockError as exc:
        return _err(str(exc))
    # If a lock already exists, show what is about to be accepted first.
    if os.path.exists(args.lock):
        try:
            previous = read_lock(args.lock)
        except LockError as exc:
            return _err(f"{exc}; fix or delete it before refreshing")
        changes = diff_lock(previous, server, tools)
        print(render_changes(changes, args.lock, tool_count=len(tools)))
        # Unknown instructions (a --from file without them) must not wipe the locked ones.
        if new_lock["server"]["instructions"] is None:
            new_lock["server"]["instructions"] = previous["server"].get("instructions")
        errors = sum(1 for f in changes if f.severity is Severity.ERROR)
        if errors and not args.accept:
            print(f"Refusing to update {args.lock}: {errors} error-level changes. "
                  "Re-run with --accept after reviewing them.", file=sys.stderr)
            return 1
    try:
        write_lock(args.lock, new_lock)
    except OSError as exc:
        return _err(f"cannot write {args.lock}: {exc.strerror or exc}")
    except ValueError:  # json.dumps(allow_nan=False); nothing was written
        return _err("schema contains NaN or Infinity, which isn't valid JSON")
    print(f"Wrote {args.lock} ({len(tools)} tools).")
    return 0


def _safe_console() -> None:
    """Escape characters the console can't encode instead of crashing.

    Findings quote server text (an emoji in a description, say), and a cp1252
    Windows console can't print everything. A crash there would also skip the
    JSON report and the exit code.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    _safe_console()
    args = _build_parser().parse_args(argv)
    if args.command == "init-fixtures":
        return _init_fixtures(args)
    if args.command == "proxy":
        return _proxy(args)
    if args.command == "lock":
        return _lock(args)
    if args.command == "eval":
        from mcp_lint.eval import eval_main

        return eval_main(args)

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
        if deep := _too_deep(tools):
            return _err(deep)
    else:
        try:
            tools = _load_tools_file(args.file)
        except RecursionError:
            return _err(f"cannot read tools file {args.file}: schema too deeply nested")
        except (OSError, ValueError) as exc:
            return _err(f"cannot read tools file {args.file}: {exc}")
        server = {"name": args.file, "version": None}

    findings = run_static(tools)
    if probes is not None:
        findings += run_probe_rules(tools, probes)
    print(render_text(server, tools, findings, FAIL_ON[args.min_severity]))
    if probes is not None:
        print()
        print(render_probes(probes))
    score = score_server(tools, findings, probes)
    print()
    print(render_scores(score))
    if args.json:
        write_json(args.json, to_json(server, tools, findings, probes,
                                      include_responses=getattr(args, "include_responses", False),
                                      score=score))
        print(f"\nJSON report written to {args.json}")

    if args.fail_under is not None and score.score < args.fail_under:
        return 1
    if args.fail_on != "never":
        threshold = FAIL_ON[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
