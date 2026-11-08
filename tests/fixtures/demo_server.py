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


def _serve_http(port: int, require_header: str | None) -> None:
    """Streamable HTTP on 127.0.0.1:PORT at /mcp; optionally 401 without NAME=VALUE."""
    import uvicorn
    from starlette.responses import PlainTextResponse

    app = server.streamable_http_app()
    if require_header:
        name, _, value = require_header.partition("=")
        wanted = name.lower().encode("latin-1")
        wanted_value = value.encode("latin-1")

        class RequireHeader:
            def __init__(self, inner):
                self.inner = inner

            async def __call__(self, scope, receive, send):
                if scope["type"] == "http":
                    got = dict(scope["headers"]).get(wanted)
                    if got != wanted_value:
                        await PlainTextResponse("unauthorized", status_code=401)(scope, receive, send)
                        return
                await self.inner(scope, receive, send)

        app = RequireHeader(app)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--http", type=int, metavar="PORT")
    ap.add_argument("--require-header", metavar="NAME=VALUE")
    opts, _unknown = ap.parse_known_args()  # unknown args are ignored (tests pass fake secrets)
    if opts.http is not None:
        _serve_http(opts.http, opts.require_header)
    else:
        server.run("stdio")
