"""Command-line entry point.

    mcp-lint run -- npx -y @modelcontextprotocol/server-everything
    mcp-lint run --probe fixtures.json -- <server command>
    mcp-lint run --url URL [--header "Name: value"] [--header-env Name=VAR]
    mcp-lint check tools.json
    mcp-lint init-fixtures fixtures.json -- <server command>
    mcp-lint proxy [--no-paging] [--descriptions FIXES.json] [--guard off|warn|block] -- <server command>
    mcp-lint eval --setup | --run | --report
    mcp-lint lock [--lock PATH] [--accept] [--from TOOLS_JSON] -- <server command>
    mcp-lint lock --check [--lock PATH] [--fail-on LEVEL] [--json PATH] (--from TOOLS_JSON | -- <server command>)
    mcp-lint check-config PATH [PATH ...] [--json PATH] [--fail-on LEVEL] [--min-severity LEVEL]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, replace

from mcp_lint.fixtures import FixtureError, load_fixtures, template
from mcp_lint.models import MAX_NESTING, Finding, Severity, ToolDef, nesting_depth
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

    def server_cmd(sp: argparse.ArgumentParser, after_positional: bool = False,
                   http: bool = True) -> None:
        sp.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                        help="forward this environment variable to the server (repeatable); "
                        "by default servers get only a minimal safe set, never your API keys")
        if http:
            sp.add_argument("--url", metavar="URL",
                            help="connect to a Streamable HTTP server instead of launching a command")
            sp.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'",
                            help="with --url, send this literal (non-secret) header (repeatable)")
            sp.add_argument("--header-env", action="append", default=[], metavar="NAME=VAR",
                            help="with --url, send header NAME with the value of environment "
                            "variable VAR, so secrets stay out of the command line (repeatable)")
        # REMAINDER would swallow options that follow another positional (init-fixtures OUT
        # --from FILE), so that command takes the server command with '*' after '--'.
        sp.add_argument("server", nargs="*" if after_positional else argparse.REMAINDER,
                        help="server command after '--', e.g. -- npx -y some-server")

    run = sub.add_parser("run", help="start an MCP server over stdio (or connect with --url) and lint its tools")
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
    proxy.add_argument("--guard", choices=["off", "warn", "block"], default="off",
                       help="refuse (block) or flag (warn) calls to tools that can send data out, "
                            "after a tool that returns untrusted content has been called this session "
                            "(default: off)")
    server_cmd(proxy, http=False)

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

    cfg = sub.add_parser("check-config", help="check how the servers in MCP client config files are launched")
    cfg.add_argument("paths", nargs="+", metavar="PATH",
                     help="client config JSON, e.g. ~/.claude.json or .mcp.json")
    cfg.add_argument("--json", metavar="PATH", help="also write the findings as JSON here")
    cfg.add_argument("--min-severity", choices=["info", "warning", "error"], default="info",
                     help="hide terminal findings below this level (default: info)")
    cfg.add_argument("--fail-on", choices=["info", "warning", "error", "never"], default="warning",
                     help="exit 1 if any finding is at or above this level (default: warning)")

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


def _http_target(args: argparse.Namespace, cmd: list[str]):
    """The HttpTarget for --url, None for stdio, or an int exit code on a usage error.

    Every check runs before any connection, and no message holds a URL or header value.
    """
    from mcp_lint.client import HttpConfigError, HttpTarget, parse_headers

    url = getattr(args, "url", None)
    if url is None:
        if getattr(args, "header", None) or getattr(args, "header_env", None):
            return _err("--header and --header-env need --url")
        return None
    if cmd:
        return _err("give either --url or a server command after '--', not both")
    if args.pass_env:
        return _err("--pass-env only applies to launched servers, not --url")
    if getattr(args, "from_file", None):
        return _err("--url and --from can't be used together")
    try:
        headers = parse_headers(url, args.header, args.header_env)
    except HttpConfigError as exc:
        return _err(str(exc))
    # Only --header-env values are secret; --header is documented as non-secret.
    secret = frozenset(item.partition("=")[0].strip(" ").lower() for item in args.header_env or [])
    return HttpTarget(url, headers, secret_headers=secret)


ECHOED = ("the server echoed a secret header or URL value into its tool definitions; "
          "nothing was written")


def _scrubber(target):
    """text -> text with every secret of an HTTP target removed (identity for stdio).

    A server can echo a header value into errors, descriptions or its name, so all text
    derived from a response is passed through this before it is printed or written.
    """
    if target is None:
        return lambda text: text
    from mcp_lint.client import redact_secrets, secret_strings

    secrets = secret_strings(target.url, target.secret_values())
    return lambda text: redact_secrets(text, secrets)


def _scrub_deep(value, scrub):
    """value with scrub applied to every string inside it (dataclasses, lists, dict keys too)."""
    import dataclasses

    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, (list, tuple)):
        return [_scrub_deep(v, scrub) for v in value]
    if isinstance(value, dict):
        return {_scrub_deep(k, scrub): _scrub_deep(v, scrub) for k, v in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.replace(value, **{f.name: _scrub_deep(getattr(value, f.name), scrub)
                                             for f in dataclasses.fields(value) if f.init})
    return value


def _echoed(target, data) -> bool:
    """True if an HTTP target's secret appears in data once serialised as JSON."""
    if target is None:
        return False
    from mcp_lint.client import contains_secret, secret_strings

    return contains_secret(json.dumps(data), secret_strings(target.url, target.secret_values()))


def _write_json_scrubbed(path: str, data, scrub) -> None:
    """write_json, with secrets removed from the serialised text first."""
    text = scrub(json.dumps(data, indent=2)) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _http_identity(target) -> list[str]:
    """What the lock and reports hash for a URL: scheme, host, port and path only.

    User info and the query string are left out, so a token in the URL can't be
    guessed from a committed lock and rotating it isn't a change. Headers are never hashed.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(target.url)
    netloc = parts.hostname or ""
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if parts.port is not None:
        netloc += f":{parts.port}"
    return ["--url", urlunsplit((parts.scheme, netloc, parts.path, "", ""))]


def _http_hash(target) -> str | None:
    from mcp_lint.lock import command_hash

    return command_hash(_http_identity(target))


def _refuse_known_bad(cmd: list[str]) -> bool:
    """Print to stderr and return True if the launch command runs a known-bad release.

    Called before any connection. Stderr only: the proxy's stdout is the MCP stream.
    """
    from mcp_lint.install import lint_command

    bad = [f for f in lint_command(cmd) if f.kind == "known_bad"]
    for f in bad:
        print(f"mcp-lint: refusing to launch: {f.message}", file=sys.stderr)
        if f.hint:
            print(f"  -> {f.hint}", file=sys.stderr)
    return bool(bad)


def _check_config(args: argparse.Namespace) -> int:
    from mcp_lint.install import lint_command, load_client_config, remote_origin, unreadable_finding
    from mcp_lint.report import _section
    from mcp_lint.rules.security import _escape

    configs = []
    for path in args.paths:
        try:
            configs.append((path, load_client_config(path)))
        except (OSError, ValueError, RecursionError) as exc:
            return _err(f"cannot read config {path}: {exc}")

    def printable(f: Finding) -> Finding:
        # Names and quoted specs come from the config file: escape them for the terminal.
        return replace(f, message=_escape(f.message), hint=_escape(f.hint) if f.hint else None)

    min_rank = FAIL_ON[args.min_severity].rank
    lines: list[str] = []
    entries: list[dict] = []
    all_findings: list[Finding] = []
    checked = remote = unusable = 0
    for _path, servers in configs:
        for server in servers:
            name = _escape(server.name)
            # Only scheme and host of a remote URL are ever printed or written.
            if server.url is not None:
                remote += 1
                origin = _escape(remote_origin(server.url))
                lines.append(f"{name}: remote ({origin}), not checked")
                entries.append({"name": server.name, "remote": True, "checked": False, "findings": []})
            elif server.argv is None:
                unusable += 1
                finding = unreadable_finding(server.name, server.reason or "it can't be read")
                all_findings.append(finding)
                shown = [printable(finding)] if finding.severity.rank >= min_rank else []
                lines += _section(name, shown) if shown else [f"{name}: unreadable entry"]
                entries.append({"name": server.name, "remote": False, "checked": False,
                                "findings": [finding.to_dict()]})
            else:
                checked += 1
                findings = lint_command(server.argv)
                all_findings += findings
                shown = [printable(f) for f in findings if f.severity.rank >= min_rank]
                lines += _section(name, shown) if shown else [f"{name}: no install findings"]
                entries.append({"name": server.name, "remote": False, "checked": True,
                                "findings": [f.to_dict() for f in findings]})

    errors = sum(1 for f in all_findings if f.severity is Severity.ERROR)
    warnings = sum(1 for f in all_findings if f.severity is Severity.WARNING)
    infos = sum(1 for f in all_findings if f.severity is Severity.INFO)
    print("\n".join(lines))
    print(f"{len(entries)} servers: {checked} checked, {remote} remote, {unusable} not checked; "
          f"{errors} errors, {warnings} warnings, {infos} info")
    if args.json:
        try:
            write_json(args.json, {"servers": entries})
        except OSError as exc:
            return _err(f"cannot write {args.json}: {exc.strerror or exc}")
        print(f"\nJSON report written to {args.json}")
    # Exit code counts every finding, including those hidden by --min-severity.
    if args.fail_on != "never":
        threshold = FAIL_ON[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in all_findings):
            return 1
    return 0


def _init_fixtures(args: argparse.Namespace) -> int:
    if os.path.exists(args.out) and not args.force:
        return _err(f"{args.out} already exists (use --force to overwrite)")
    cmd = _server_cmd(args.server)
    target = _http_target(args, cmd)
    if isinstance(target, int):
        return target
    if target is not None:
        from mcp_lint.client import describe_http_error, fetch_tools_http

        try:
            tools = asyncio.run(fetch_tools_http(target)).tools
        except Exception as exc:  # noqa: BLE001
            return _err(describe_http_error(exc, target))
        if deep := _too_deep(tools):
            return _err(_scrubber(target)(deep))
        # Fixtures hold only names and parameters, but refuse on any echo in the definitions too.
        if _echoed(target, [template(tools), [asdict(t) for t in tools]]):
            return _err(ECHOED)
    elif args.from_file:
        try:
            tools = _load_tools_file(args.from_file)
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            return _err(f"cannot read tools file {args.from_file}: {exc}")
    elif cmd:
        if _refuse_known_bad(cmd):
            return 1
        from mcp_lint.client import fetch_tools

        try:
            tools = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env)).tools
        except Exception as exc:  # noqa: BLE001
            return _err(f"could not connect to server: {exc!r}")
        if deep := _too_deep(tools):
            return _err(deep)
    else:
        return _err("give a server command after '--', --url or --from TOOLS_JSON")
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
    if _refuse_known_bad(cmd):
        return 1
    try:
        descriptions = load_descriptions(args.descriptions) if args.descriptions else {}
    except (OSError, ValueError) as exc:
        return _err(str(exc))
    opts = FixOptions(paging=not args.no_paging, page_tokens=args.page_tokens,
                      descriptions=descriptions, errors=not args.no_errors)
    try:
        asyncio.run(serve(cmd[0], cmd[1:], opts, args.pass_env, args.log, guard=args.guard))
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
    target = _http_target(args, cmd)
    if isinstance(target, int):
        return target
    scrub = _scrubber(target)
    if target is not None:
        from mcp_lint.client import describe_http_error, fetch_tools_http

        try:
            info = asyncio.run(fetch_tools_http(target))
        except Exception as exc:  # noqa: BLE001
            return _err(describe_http_error(exc, target))
        tools = info.tools
        if deep := _too_deep(tools):
            return _err(scrub(f"{deep}; nothing was written"))
        # build_lock/diff_lock hash "command"; the lock keeps only that hash, never the URL.
        server = {"name": info.name, "version": info.version, "command": _http_identity(target),
                  "instructions": info.instructions}
    elif args.from_file:
        try:
            tools, instructions = _load_tools_and_instructions(args.from_file)
        except RecursionError:
            return _err(f"cannot read tools file {args.from_file}: schema too deeply nested")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _err(f"cannot read tools file {args.from_file}: {exc}")
        server = {"name": os.path.basename(args.from_file), "version": None, "command": None,
                  "instructions": instructions}
    elif cmd:
        if _refuse_known_bad(cmd):
            return 1
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
        return _err("give a server command after '--', --url or --from TOOLS_JSON")

    if args.check:
        try:
            locked = read_lock(args.lock)
        except LockError as exc:
            return _err(str(exc))
        changes = diff_lock(locked, server, tools)
        print(scrub(render_changes(changes, args.lock, tool_count=len(tools))))
        if args.json:
            # The report never carries the launch command: only its hash.
            summary = {"name": server.get("name"), "version": server.get("version"),
                       "command_sha256": command_hash(server.get("command")),
                       "instructions_known": isinstance(server.get("instructions"), str)}
            try:
                _write_json_scrubbed(args.json, {"lock": args.lock, "server": summary,
                                                 "changes": [f.to_dict() for f in changes]}, scrub)
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
        return _err(scrub(str(exc)))
    if _echoed(target, new_lock):
        return _err(ECHOED)  # no redaction here: it would change the tool hashes
    # If a lock already exists, show what is about to be accepted first.
    if os.path.exists(args.lock):
        try:
            previous = read_lock(args.lock)
        except LockError as exc:
            return _err(f"{exc}; fix or delete it before refreshing")
        changes = diff_lock(previous, server, tools)
        print(scrub(render_changes(changes, args.lock, tool_count=len(tools))))
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
    if args.command == "check-config":
        return _check_config(args)
    if args.command == "eval":
        from mcp_lint.eval import eval_main

        return eval_main(args)

    probes = None
    install_findings: list[Finding] = []
    if args.command == "run":
        cmd = _server_cmd(args.server)
        target = _http_target(args, cmd)
        if isinstance(target, int):
            return target
        scrub = _scrubber(target)
        if target is None:
            if not cmd:
                return _err("give the server command after '--' (or --url)")
            if _refuse_known_bad(cmd):
                return 1
            from mcp_lint.install import lint_command

            install_findings = lint_command(cmd)
        from mcp_lint.client import (
            describe_http_error, fetch_and_probe, fetch_and_probe_http, fetch_tools, fetch_tools_http,
        )  # needs the mcp SDK

        try:
            fixtures = load_fixtures(args.probe) if args.probe else []
        except (FixtureError, OSError) as exc:
            return _err(str(exc))
        try:
            if args.probe or args.error_probes:
                if target is not None:
                    info, probes = asyncio.run(fetch_and_probe_http(
                        target, fixtures, args.probe_timeout, auto_errors=args.error_probes))
                else:
                    info, probes = asyncio.run(fetch_and_probe(
                        cmd[0], cmd[1:], fixtures, args.probe_timeout, auto_errors=args.error_probes,
                        pass_env=args.pass_env))
            elif target is not None:
                info = asyncio.run(fetch_tools_http(target))
            else:
                info = asyncio.run(fetch_tools(cmd[0], cmd[1:], args.pass_env))
        except (FixtureError, OSError) as exc:
            if target is not None:
                return _err(describe_http_error(exc, target))
            return _err(str(exc))
        except Exception as exc:  # noqa: BLE001 - surface any connection failure plainly
            if target is not None:
                return _err(describe_http_error(exc, target))
            return _err(f"could not connect to server: {exc!r}")
        if target is not None:
            # Scrub at the source too: rules cut and reflow server text, and a secret
            # split by a cut would slip past the final scrub of the rendered report.
            info = _scrub_deep(info, scrub)
            probes = _scrub_deep(probes, scrub)
        from mcp_lint.lock import command_hash

        # The report never carries the launch command or URL, only a hash: tokens stay out.
        server = {"name": info.name, "version": info.version,
                  "transport": "stdio" if target is None else "streamable-http",
                  "command_sha256": command_hash(cmd) if target is None else _http_hash(target)}
        tools = info.tools
        if deep := _too_deep(tools):
            return _err(scrub(deep))
    else:
        target = None
        scrub = _scrubber(None)
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
    findings += install_findings  # I1 is server-wide and doesn't affect the score
    print(scrub(render_text(server, tools, findings, FAIL_ON[args.min_severity])))
    if probes is not None:
        print()
        print(scrub(render_probes(probes)))
    score = score_server(tools, findings, probes)
    print()
    print(scrub(render_scores(score)))
    if args.json:
        report = to_json(server, tools, findings, probes,
                         include_responses=getattr(args, "include_responses", False), score=score)
        if target is not None:
            _write_json_scrubbed(args.json, report, scrub)
        else:
            write_json(args.json, report)
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
