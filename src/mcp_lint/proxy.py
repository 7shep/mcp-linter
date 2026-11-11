"""A fixing proxy: an MCP server that wraps another one and fixes what mcp-lint flags.

    mcp-lint proxy --descriptions eval/fixes/mcp-server-git.json -- uvx mcp-server-git

It connects to the upstream server over stdio, re-exposes its tools, and
forwards every call. Three fixes, each switchable so they can be ablated:

- **paging** (P1/P3): text responses over ~2,000 tokens are cut to a page, and
  every tool gains ``offset``/``limit`` parameters (in lines). A one-line note
  says what was shown and how to get more, the pattern Desktop Commander uses:
  ``[showing lines 1-470 of 8000; pass offset=470 for more]``.
- **descriptions** (S1): replace tool descriptions from a hand-written JSON
  file (``{"descriptions": {"tool_name": "new text"}}``).
- **errors** (P4): set ``isError`` on "successful" results whose text is
  really an error message. Results already marked as errors are left alone.

With ``--guard warn|block`` the proxy also runs the trifecta guard
(``mcp_lint.guard``): once a tool that returns untrusted content has been
called in this session, a call to a tool that can send data out is flagged
(warn: the call goes through, with a notice prepended) or refused (block: the
call never reaches the upstream and the agent gets an error). Taint lasts for
the proxy process. See ``mcp_lint.guard`` for the threat model and its limits.

The upstream server gets the same minimal environment as ``mcp-lint run``.
The pure functions here (``rewrite_tool``, ``page_text``, ``fix_result``)
need no server, so they are unit-tested directly. ``ProxyCore`` holds the
call and list logic without any transport, so it is tested with a fake upstream.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import mcp_types as types

from mcp_lint.client import tool_def
from mcp_lint.guard import Decision, GuardMode, TrifectaGuard, Verdict, _listing
from mcp_lint.rules.probe import looks_like_error
from mcp_lint.text import CHARS_PER_TOKEN, estimate_tokens

PAGE_TOKENS = 2_000
# An explicit ``limit`` may ask for more than one page, but never more than this
# many pages' worth, so a single call stays well under Claude Code's 25k cap.
MAX_PAGES_PER_CALL = 5

OFFSET_DOC = ("Line to start from (0-based). Long responses are cut to a page and end "
              "with a note giving the offset of the next page.")
LIMIT_DOC = (f"Maximum number of lines to return. Default: as many as fit in about "
             f"{PAGE_TOKENS:,} tokens.")


@dataclass
class FixOptions:
    paging: bool = True
    page_tokens: int = PAGE_TOKENS
    descriptions: dict[str, str] = field(default_factory=dict)
    errors: bool = True

    @property
    def enabled(self) -> list[str]:
        out = []
        if self.paging:
            out.append("paging")
        if self.descriptions:
            out.append("descriptions")
        if self.errors:
            out.append("errors")
        return out


def load_descriptions(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    descs = data.get("descriptions", data) if isinstance(data, dict) else None
    if not isinstance(descs, dict) or not all(isinstance(v, str) for v in descs.values()):
        raise ValueError(f"{path}: expected {{\"descriptions\": {{tool: text}}}}")
    return {k: v for k, v in descs.items() if not k.startswith("_")}


def paging_param_names(schema: dict[str, Any]) -> tuple[str, str]:
    """``offset``/``limit``, or prefixed names if the tool already uses those."""
    props = schema.get("properties") or {}
    if "offset" in props or "limit" in props:
        return "page_offset", "page_limit"
    return "offset", "limit"


def rewrite_tool(tool: types.Tool, opts: FixOptions) -> types.Tool:
    """The tool definition the proxy advertises."""
    update: dict[str, Any] = {}
    if tool.name in opts.descriptions:
        update["description"] = opts.descriptions[tool.name]
    if opts.paging:
        schema = json.loads(json.dumps(tool.input_schema or {"type": "object"}))
        schema.setdefault("type", "object")
        props = schema.setdefault("properties", {})
        off, lim = paging_param_names(schema)
        props[off] = {"type": "integer", "minimum": 0, "description": OFFSET_DOC}
        props[lim] = {"type": "integer", "minimum": 1, "description": LIMIT_DOC}
        update["input_schema"] = schema
        # Paged results drop structured content (it would repeat the whole
        # response), so the tool can no longer promise an output schema.
        update["output_schema"] = None
    return tool.model_copy(update=update) if update else tool


def split_paging_args(tool: types.Tool | None, args: dict[str, Any]
                      ) -> tuple[dict[str, Any], int, int | None]:
    """Remove the proxy's paging params from the call; return (args, offset, limit)."""
    off_name, lim_name = paging_param_names(tool.input_schema or {} if tool else {})
    args = dict(args)
    offset, limit = args.pop(off_name, None), args.pop(lim_name, None)
    try:
        offset = max(0, int(offset)) if offset is not None else 0
    except (TypeError, ValueError):
        offset = 0
    try:
        limit = max(1, int(limit)) if limit is not None else None
    except (TypeError, ValueError):
        limit = None
    return args, offset, limit


def page_text(text: str, offset: int = 0, limit: int | None = None,
              page_tokens: int = PAGE_TOKENS) -> tuple[str, bool]:
    """Cut ``text`` to one page of lines. Returns (text, paged).

    Text that fits in ``page_tokens`` comes back unchanged unless the caller
    asked for an offset or limit. Otherwise the page starts at line ``offset``
    and holds ``limit`` lines, or as many as fit in the budget; a note at the
    top says which lines are shown and what offset to pass next.
    """
    if offset == 0 and limit is None and estimate_tokens(text) <= page_tokens:
        return text, False
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # a trailing newline isn't a line of its own
    total = len(lines)
    budget = page_tokens * CHARS_PER_TOKEN
    cap = budget * MAX_PAGES_PER_CALL if limit is not None else budget
    want = limit if limit is not None else total
    start = min(offset, total)
    out: list[str] = []
    used = 0
    for line in lines[start:start + want]:
        if out and used + len(line) + 1 > cap:
            break
        if not out and len(line) > cap:
            line = line[:cap] + " ...[line cut: longer than one page]"
        out.append(line)
        used += len(line) + 1
    end = start + len(out)
    if total == 0:
        note = "[empty response]"
    elif start >= total:
        note = f"[offset {offset} is past the end: the response has {total} lines]"
    elif end < total:
        note = f"[showing lines {start + 1}-{end} of {total}; pass offset={end} for more]"
    else:
        note = f"[showing lines {start + 1}-{end} of {total}; end of response]"
    return note + "\n" + "\n".join(out), True


def result_text(result: types.CallToolResult) -> str:
    parts = []
    for block in result.content or []:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts)


@dataclass
class FixReport:
    """What the proxy did to one call (logged for the eval report)."""

    upstream_tokens: int = 0
    returned_tokens: int = 0
    paged: bool = False
    error_flagged: bool = False


def fix_result(result: types.CallToolResult, opts: FixOptions, offset: int = 0,
               limit: int | None = None) -> tuple[types.CallToolResult, FixReport]:
    text = result_text(result)
    report = FixReport(upstream_tokens=estimate_tokens(text))
    update: dict[str, Any] = {}
    if opts.errors and not result.is_error and looks_like_error(text):
        update["is_error"] = True
        report.error_flagged = True
    if opts.paging and text:
        paged, did_page = page_text(text, offset, limit, opts.page_tokens)
        if did_page:
            others = [b for b in result.content or [] if getattr(b, "type", None) != "text"]
            update["content"] = [types.TextContent(type="text", text=paged)] + others
            update["structured_content"] = None
            report.paged = True
            text = paged
    report.returned_tokens = estimate_tokens(text)
    return (result.model_copy(update=update) if update else result), report


class CallLog:
    """Optional JSONL log of each proxied call."""

    def __init__(self, path: str | None):
        self.path = path

    def write(self, tool: str, report: FixReport, latency_ms: int, guard: str | None = None) -> None:
        if not self.path:
            return
        row = {"tool": tool, "latency_ms": latency_ms, **report.__dict__}
        if guard is not None:  # guard-off rows keep their exact pre-guard shape
            row["guard"] = guard
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")


def blocked_result(decision: Decision) -> types.CallToolResult:
    """The error the agent gets for a call the guard refused (the upstream never sees it)."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=decision.message)], is_error=True)


def warn_result(result: types.CallToolResult, decision: Decision) -> types.CallToolResult:
    """The upstream's result with the guard's warning prepended as its own text block."""
    warning = types.TextContent(type="text", text=decision.message)
    return result.model_copy(update={"content": [warning] + list(result.content or [])})


class ProxyCore:
    """The proxy's call and list logic, with no transport in it.

    ``list_page(params=...)`` and ``call_upstream(name, args)`` are the upstream
    session's ``list_tools`` and ``call_tool`` (or fakes in tests).
    """

    def __init__(self, opts: FixOptions,
                 list_page: Callable[..., Awaitable[types.ListToolsResult]],
                 call_upstream: Callable[[str, dict[str, Any]], Awaitable[types.CallToolResult]],
                 guard: TrifectaGuard | None = None,
                 log: CallLog | None = None,
                 errlog=sys.stderr):
        self.opts = opts
        self._list_page = list_page
        self._call_upstream = call_upstream
        # Guard off (no guard, or mode OFF) takes the exact pre-guard code paths.
        self._guard = guard if guard is not None and guard.mode is not GuardMode.OFF else None
        self._log = log or CallLog(None)
        self._errlog = errlog
        self._lock = asyncio.Lock()
        self.by_name: dict[str, types.Tool] = {}
        self.advertised: list[types.Tool] = []
        self.stale = False  # set by tools/list_changed; cleared by a successful refresh

    def _say(self, line: str) -> None:
        # Tool names come from the agent or the upstream: keep each notice on one line.
        line = "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in line)
        print(line, file=self._errlog, flush=True)

    async def refresh(self) -> None:
        if self._guard is not None:
            # Cleared before listing, so a list_changed that arrives mid-refresh
            # leaves the table stale instead of being lost.
            self.stale = False
        raw: list[types.Tool] = []
        cursor = None
        try:
            while True:
                req = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                page = await self._list_page(params=req)
                raw.extend(page.tools)
                cursor = page.next_cursor
                if not cursor:
                    break
        except BaseException:
            if self._guard is not None:
                self.stale = True
            raise
        self.by_name = {t.name: t for t in raw}
        self.advertised = [rewrite_tool(t, self.opts) for t in raw]
        if self._guard is not None:
            self._guard.retag([tool_def(t) for t in raw])

    async def _guarded_refresh(self) -> None:
        """Re-list (caller holds the lock). If it fails, every name becomes unknown
        (all three tags: fail closed) until a later re-list succeeds."""
        try:
            await self.refresh()
        except Exception as exc:  # noqa: BLE001 - any failure fails closed
            self._say(f"mcp-lint guard: could not re-list tools ({type(exc).__name__}); "
                      "treating every tool name as unknown until the next successful list")
            self._guard.retag([])
            self.stale = True

    async def _refresh_for_call(self, name: str) -> None:
        """Re-list once before a call when the table may be out of date."""
        async with self._lock:
            if self.stale or not self._guard.knows(name):
                await self._guarded_refresh()

    async def list_tools(self) -> types.ListToolsResult:
        if self._guard is not None and self.stale:
            async with self._lock:
                if self.stale:
                    await self._guarded_refresh()
        return types.ListToolsResult(tools=self.advertised)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        guard = self._guard
        decision: Decision | None = None
        if guard is not None:
            await self._refresh_for_call(name)
        call_args = dict(arguments or {})
        offset, limit = 0, None
        if self.opts.paging:
            call_args, offset, limit = split_paging_args(self.by_name.get(name), call_args)
        if guard is not None:
            decision = guard.check_call(name, call_args)
            if decision.verdict is Verdict.BLOCK:
                self._log.write(name, FixReport(), 0, guard="block")
                self._say(f"mcp-lint guard: blocked {name} (untrusted content from "
                          f"{_listing(guard.tainted_by)})")
                return blocked_result(decision)
            # Taint at forward time, against the table that was just checked, with no
            # await in between: a re-tag while the call is in flight can't undo it, and
            # a sink called while an untrusted call is still in flight is blocked.
            guard.observe_call(name)
        start = time.perf_counter()
        result = await self._call_upstream(name, call_args)
        fixed, report = fix_result(result, self.opts, offset, limit)
        ms = round((time.perf_counter() - start) * 1000)
        if guard is None:
            self._log.write(name, report, ms)
            return fixed
        if decision.verdict is Verdict.WARN:
            fixed = warn_result(fixed, decision)
            self._say(f"mcp-lint guard: warned about {name} (untrusted content from "
                      f"{_listing(guard.tainted_by)})")
        self._log.write(name, report, ms, guard=decision.verdict.value)
        return fixed

    async def on_upstream_message(self, message: Any) -> None:
        if self._guard is not None and isinstance(message, types.ToolListChangedNotification):
            self.stale = True


async def serve(command: str, args: list[str], opts: FixOptions,
                pass_env: list[str] | None = None, log_path: str | None = None,
                guard: str = "off") -> None:
    """Run the proxy on this process's stdin/stdout until the client disconnects."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    from mcp_lint.client import _resolve_command, server_env

    params = StdioServerParameters(command=_resolve_command(command), args=args,
                                   env=server_env(pass_env))
    trifecta = TrifectaGuard(guard) if guard != "off" else None
    core = ProxyCore(
        opts,
        # ``upstream`` is bound by the ClientSession below, before any of these run.
        list_page=lambda params: upstream.list_tools(params=params),
        call_upstream=lambda name, call_args: upstream.call_tool(name, call_args),
        guard=trifecta, log=CallLog(log_path), errlog=sys.stderr)
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write, message_handler=core.on_upstream_message) as upstream:
            init = await upstream.initialize()
            await core.refresh()

            async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
                return await core.list_tools()

            async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
                return await core.call_tool(params.name, params.arguments)

            info = init.server_info
            server = Server(f"{info.name} (mcp-lint proxy)", version=info.version or "",
                            instructions=getattr(init, "instructions", None),
                            on_list_tools=on_list_tools, on_call_tool=on_call_tool)
            async with stdio_server() as (s_read, s_write):
                await server.run(s_read, s_write, server.create_initialization_options())
