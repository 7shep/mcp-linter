"""Connect to an MCP server over stdio and fetch its tool definitions."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import PaginatedRequestParams

from mcp_lint.models import ToolDef


@dataclass
class ServerInfo:
    name: str
    version: str
    tools: list[ToolDef]


def _resolve_command(command: str) -> str:
    """Find the executable, including Windows shims like ``npx.cmd``."""
    found = shutil.which(command)
    return found or command


async def fetch_tools(command: str, args: list[str]) -> ServerInfo:
    params = StdioServerParameters(
        command=_resolve_command(command),
        args=args,
        env=dict(os.environ),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools: list[ToolDef] = []
            cursor: str | None = None
            while True:
                req = PaginatedRequestParams(cursor=cursor) if cursor else None
                result = await session.list_tools(params=req)
                for t in result.tools:
                    tools.append(
                        ToolDef(
                            name=t.name,
                            description=t.description,
                            input_schema=dict(t.input_schema or {}),
                        )
                    )
                cursor = result.next_cursor
                if not cursor:
                    break
            info = init.server_info
            return ServerInfo(name=info.name, version=info.version, tools=tools)
