"""MCP server that reports whether it can see MCP_LINT_TEST_SECRET."""

import os

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("env-server")


@server.tool(description="Report whether the test secret is visible.",
             annotations=ToolAnnotations(read_only_hint=True))
def show_secret() -> str:
    return "secret=" + os.environ.get("MCP_LINT_TEST_SECRET", "<unset>")


if __name__ == "__main__":
    server.run("stdio")
