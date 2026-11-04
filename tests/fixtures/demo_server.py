"""Tiny MCP server with one good tool and one sloppy tool, for integration tests."""

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

server = MCPServer("demo-server")


@server.tool(
    description="Search the team's contacts by name, email, or company. "
    "Returns up to 'limit' matches with name, email, and company, best match first."
)
def search_contacts(
    query: Annotated[str, Field(description="Text to match against name, email, or company.")],
    limit: Annotated[int, Field(description="Maximum results to return (1-50).")] = 10,
) -> str:
    return f"no matches for {query!r}"


@server.tool(description="Gets data.")
def get(id: str) -> str:
    return id


if __name__ == "__main__":
    server.run("stdio")
