"""Tiny MCP server with one good tool and one sloppy tool, for integration tests."""

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

server = MCPServer("demo-server")


@server.tool(
    description="Search the team's contacts by name, email, or company. "
    "Returns up to 'limit' matches with name, email, and company, best match first.",
    annotations=ToolAnnotations(read_only_hint=True),
)
def search_contacts(
    query: Annotated[str, Field(description="Text to match against name, email, or company.")],
    limit: Annotated[int, Field(description="Maximum results to return (1-50).")] = 10,
) -> str:
    if not query.strip():
        # Deliberately a plain ValueError: MCP SDK 2.x hides the message of any
        # exception that isn't ToolError, so the agent only sees
        # "Error executing tool search_contacts". A test case for P4.
        raise ValueError("query must not be empty; pass part of a name, email, or company")
    return f"no matches for {query!r}"


# No annotations, so clients must assume it may change data.
@server.tool(description="Gets data.")
def get(id: str) -> str:
    return id


if __name__ == "__main__":
    server.run("stdio")
