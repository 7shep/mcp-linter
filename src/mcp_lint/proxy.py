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

The upstream server gets the same minimal environment as ``mcp-lint run``.
The pure functions here (``rewrite_tool``, ``page_text``, ``fix_result``)
need no server, so they are unit-tested directly.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import mcp_types as types

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

    def write(self, tool: str, report: FixReport, latency_ms: int) -> None:
        if not self.path:
            return
        row = {"tool": tool, "latency_ms": latency_ms, **report.__dict__}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")


async def serve(command: str, args: list[str], opts: FixOptions,
                pass_env: list[str] | None = None, log_path: str | None = None) -> None:
    """Run the proxy on this process's stdin/stdout until the client disconnects."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    from mcp_lint.client import _resolve_command, server_env

    params = StdioServerParameters(command=_resolve_command(command), args=args,
                                   env=server_env(pass_env))
    log = CallLog(log_path)
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as upstream:
            init = await upstream.initialize()
            raw: list[types.Tool] = []
            cursor = None
            while True:
                req = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                page = await upstream.list_tools(params=req)
                raw.extend(page.tools)
                cursor = page.next_cursor
                if not cursor:
                    break
            by_name = {t.name: t for t in raw}
            advertised = [rewrite_tool(t, opts) for t in raw]

            async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
                return types.ListToolsResult(tools=advertised)

            async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
                tool = by_name.get(params.name)
                call_args = dict(params.arguments or {})
                offset, limit = 0, None
                if opts.paging:
                    call_args, offset, limit = split_paging_args(tool, call_args)
                start = time.perf_counter()
                result = await upstream.call_tool(params.name, call_args)
                fixed, report = fix_result(result, opts, offset, limit)
                log.write(params.name, report, round((time.perf_counter() - start) * 1000))
                return fixed

            info = init.server_info
            server = Server(f"{info.name} (mcp-lint proxy)", version=info.version or "",
                            instructions=getattr(init, "instructions", None),
                            on_list_tools=on_list_tools, on_call_tool=on_call_tool)
            async with stdio_server() as (s_read, s_write):
                await server.run(s_read, s_write, server.create_initialization_options())
