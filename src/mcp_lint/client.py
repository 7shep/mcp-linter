"""Connect to an MCP server over stdio: list its tools and run probe calls."""

from __future__ import annotations

import os
import shutil
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import PaginatedRequestParams

from mcp_lint.fixtures import Probe
from mcp_lint.models import ToolDef
from mcp_lint.probe import ProbeResult, call_probe


@dataclass
class ServerInfo:
    name: str
    version: str
    tools: list[ToolDef]


def _resolve_command(command: str) -> str:
    """Find the executable, including Windows shims like ``npx.cmd``."""
    found = shutil.which(command)
    return found or command


async def _list_tools(session: ClientSession) -> list[ToolDef]:
    tools: list[ToolDef] = []
    cursor: str | None = None
    while True:
        req = PaginatedRequestParams(cursor=cursor) if cursor else None
        result = await session.list_tools(params=req)
        for t in result.tools:
            annotations = t.annotations.model_dump(by_alias=True, exclude_none=True) if t.annotations else {}
            tools.append(
                ToolDef(
                    name=t.name,
                    description=t.description,
                    input_schema=dict(t.input_schema or {}),
                    annotations=annotations,
                )
            )
        cursor = result.next_cursor
        if not cursor:
            return tools


@asynccontextmanager
async def connect(command: str, args: list[str]) -> AsyncIterator[tuple[ClientSession, ServerInfo]]:
    params = StdioServerParameters(
        command=_resolve_command(command),
        args=args,
        env=dict(os.environ),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = await _list_tools(session)
            info = init.server_info
            yield session, ServerInfo(name=info.name, version=info.version, tools=tools)


async def fetch_tools(command: str, args: list[str]) -> ServerInfo:
    async with connect(command, args) as (_, info):
        return info


async def fetch_and_probe(
    command: str, args: list[str], probes: list[Probe], timeout: float
) -> tuple[ServerInfo, list[ProbeResult]]:
    """List tools, then run each runnable probe in order on the same session."""
    async with connect(command, args) as (session, info):
        by_name = {t.name: t for t in info.tools}
        results = [await call_probe(session, p, by_name, timeout) for p in probes]
        return info, results
