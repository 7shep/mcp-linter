"""MCP stdio bridge to an AgentDojo trial's tools.

    python benchmark/agentdojo_mcp.py --port P --token-file PATH

Claude Code starts this (through mcp_lint.safe_exec) as its only MCP server. It
holds no tools and no data: every tools/list and tools/call is forwarded over a
JSON-lines TCP connection to 127.0.0.1:P, where benchmark/agentdojo_claude.py
runs the real AgentDojo functions against the trial's environment.

Protocol, one connection per request: the first line is the trial's token, the
second a JSON request ({"op": "ping"}, {"op": "list_tools"} or {"op": "call",
"name": ..., "arguments": {...}}), and the reply is one JSON line.

The token comes from a file, not the environment: safe_exec gives its child only
a minimal environment, so a variable would not arrive.

THREAT MODEL
  DEFENDS AGAINST: the bridge reaching any network host but 127.0.0.1:P, starting
    a process, writing a file, or reading outside the interpreter, the benchmark
    folder and the library folders (audit hook, exit 70); another local process
    driving the trial socket (the token); a broken or unauthorised link being served
    as an empty tool list (the bridge pings the socket first and exits nonzero).
  ATTACKER CONTROLS: injected text inside tool results, so the tool names and the
    arguments the model sends.
  MUST FAIL CLOSED WHEN: the token file is unreadable or empty; the socket is
    unreachable or refuses the token (exit 2); a reply is not one JSON object; a
    forward fails mid-run (exit 3, so Claude Code sees the server vanish).
    The bridge also holds a lifeline connection (hello at start, bye on a clean end); the
    trial fails if it ends any other way, so a crash or guard kill is never scored.
  OUT OF SCOPE: a compromised interpreter or MCP SDK; what the model does with results.

Imports only the standard library and the mcp SDK.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # the guard blocks writes; a late import must not try to cache a .pyc

import argparse
import asyncio
import json
import os
import socket
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

HOST = "127.0.0.1"
GUARD_EXIT = 70
CONNECT_TIMEOUT = 5.0
REPLY_TIMEOUT = 120.0
MAX_REPLY = 64 * 1024 * 1024
_BENCH_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- the socket link

class LinkError(RuntimeError):
    """The trial socket is unreachable, refused the token, or replied with garbage."""


def request(port: int, token: str, payload: dict[str, Any], *, reply_timeout: float = REPLY_TIMEOUT) -> dict[str, Any]:
    """One request on a fresh connection. Raises LinkError for anything but one JSON object back."""
    try:
        sock = socket.create_connection((HOST, port), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        raise LinkError(f"cannot reach the trial socket: {exc}") from None
    try:
        sock.settimeout(reply_timeout)
        sock.sendall(token.encode("ascii") + b"\n" + json.dumps(payload).encode("utf-8") + b"\n")
        buf = bytearray()
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REPLY:
                raise LinkError("reply too large")
    except (OSError, UnicodeError) as exc:
        raise LinkError(f"trial socket failed: {exc}") from None
    finally:
        sock.close()
    line = bytes(buf).split(b"\n", 1)[0]
    if not line:
        raise LinkError("the trial socket closed without a reply (wrong token?)")
    try:
        reply = json.loads(line.decode("utf-8"))
    except ValueError:
        raise LinkError("reply was not JSON") from None
    if not isinstance(reply, dict):
        raise LinkError("reply was not a JSON object")
    if "error" in reply and reply.get("ok") is not True and "tools" not in reply and "text" not in reply:
        raise LinkError(f"trial socket error: {str(reply['error'])[:200]}")
    return reply


def open_lifeline(port: int, token: str) -> socket.socket:
    """A long-lived authenticated connection. Its end without a "bye" tells the trial the bridge died."""
    try:
        sock = socket.create_connection((HOST, port), timeout=CONNECT_TIMEOUT)
        sock.sendall(token.encode("ascii") + b"\n" + json.dumps({"op": "hello"}).encode("utf-8") + b"\n")
        reply = sock.recv(4096)
    except OSError as exc:
        raise LinkError(f"cannot open the lifeline: {exc}") from None
    if not reply.startswith(b"{") or b'"ok"' not in reply:
        sock.close()
        raise LinkError("the trial socket refused the lifeline")
    sock.settimeout(None)
    return sock


def say_goodbye(sock: socket.socket) -> None:
    try:
        sock.sendall(json.dumps({"op": "bye"}).encode("utf-8") + b"\n")
    except OSError:
        pass
    finally:
        sock.close()


def tool_list(port: int, token: str) -> list[types.Tool]:
    reply = request(port, token, {"op": "list_tools"})
    items = reply.get("tools")
    if not isinstance(items, list) or not items:
        raise LinkError("the trial socket listed no tools")
    out = []
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not isinstance(item.get("inputSchema"), dict)):
            raise LinkError("malformed tool entry")
        out.append(types.Tool(name=item["name"], description=str(item.get("description") or ""),
                              input_schema=item["inputSchema"]))
    return out


def call_tool(port: int, token: str, name: str, arguments: Any) -> tuple[str, bool]:
    reply = request(port, token, {"op": "call", "name": name, "arguments": arguments})
    text, is_error = reply.get("text"), reply.get("is_error")
    if not isinstance(text, str) or not isinstance(is_error, bool):
        raise LinkError("malformed call reply")
    return text, is_error


# ---------------------------------------------------------------- guard

_DENIED_EVENTS = frozenset({"subprocess.Popen", "os.system", "os.exec", "os.spawn",
                            "os.posix_spawn", "os.startfile"})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
_PATH_EVENTS = frozenset({"os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.link", "os.symlink",
                          "os.truncate", "os.chmod", "os.chown", "shutil.rmtree", "shutil.move",
                          "shutil.copyfile", "shutil.copytree"})
_SOCKET_DENIED = frozenset({"socket.bind", "socket.sendto", "socket.sendmsg"})


def _real(path: Any) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _under(path_real: str, root_real: str) -> bool:
    try:
        return os.path.commonpath([path_real, root_real]) == root_real
    except ValueError:
        return False


def _read_roots() -> list[str]:
    prefixes = {_real(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix) if p}
    roots = set(prefixes) | {_real(_BENCH_DIR)}
    for entry in sys.path:
        if not entry or not os.path.isdir(entry):
            continue
        real = _real(entry)
        lowered = real.casefold()
        if any(_under(real, p) for p in prefixes) or "site-packages" in lowered or "dist-packages" in lowered:
            roots.add(real)
    return sorted(roots)


def _block(event: str, detail: str = "") -> None:
    try:
        suffix = f" {detail}" if detail else ""
        sys.stderr.write(f"agentdojo_mcp guard: blocked {event}{suffix}\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    os._exit(GUARD_EXIT)


def install_guard(port: int) -> None:
    """Exit 70 on a connect to anything but 127.0.0.1:port, a process start, a file write,
    a file change, or a read outside the interpreter, the benchmark folder and the library
    folders. Call after every import, after the token is read and after the event loop exists
    (on Windows an event loop makes a loopback socket pair)."""
    null_real = _real(os.devnull)
    roots = _read_roots()
    allowed_address = (HOST, port)

    def hook(event: str, args: tuple) -> None:
        if event in _DENIED_EVENTS or event in _SOCKET_DENIED or event in _PATH_EVENTS:
            _block(event)
        elif event == "socket.connect":
            address = args[1] if len(args) > 1 else None
            if address != allowed_address:
                _block(event, repr(address))
        elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
            host = args[0] if args else None
            if host != HOST:
                _block(event, repr(host))
        elif event == "open":
            path = args[0] if args else None
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            writing = (any(ch in mode for ch in "wax+") if isinstance(mode, str)
                       else bool(flags & _WRITE_FLAGS) if isinstance(flags, int) else False)
            if isinstance(path, int):
                return  # wrapping an open descriptor (the SDK does this for stdout) reaches no path
            if path is None:
                return
            if writing:
                _block(event, repr(path))
            try:
                target = _real(path)
            except Exception:  # noqa: BLE001
                _block(event)
            if target != null_real and not any(_under(target, root) for root in roots):
                _block(event, repr(path))

    sys.addaudithook(hook)


# ---------------------------------------------------------------- MCP server

async def serve(port: int, token: str) -> None:
    async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        try:
            tools = await asyncio.to_thread(tool_list, port, token)
        except LinkError as exc:
            sys.stderr.write(f"agentdojo_mcp: {exc}\n")
            sys.stderr.flush()
            os._exit(3)
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
        try:
            text, is_error = await asyncio.to_thread(call_tool, port, token, params.name, params.arguments)
        except LinkError as exc:
            sys.stderr.write(f"agentdojo_mcp: {exc}\n")
            sys.stderr.flush()
            os._exit(3)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=is_error)

    server = Server("agentdojo-bridge", version="1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def read_token(path: str) -> str:
    with open(path, encoding="ascii") as fh:
        token = fh.read().strip()
    if not token or not token.isalnum():
        raise ValueError("token file is empty or malformed")
    return token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdojo_mcp.py", description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args(argv)
    if not 0 < args.port < 65536:
        print("agentdojo_mcp: port out of range", file=sys.stderr)
        return 2
    try:
        token = read_token(args.token_file)
    except (OSError, ValueError) as exc:
        print(f"agentdojo_mcp: {exc}", file=sys.stderr)
        return 2
    loop = asyncio.new_event_loop()  # before the guard: on Windows it connects a loopback socket pair
    asyncio.set_event_loop(loop)
    install_guard(args.port)
    try:  # a dead socket or a wrong token must stop the server, not serve an empty tool list
        request(args.port, token, {"op": "ping"})
        lifeline = open_lifeline(args.port, token)
    except LinkError as exc:
        print(f"agentdojo_mcp: {exc}", file=sys.stderr)
        return 2
    loop.run_until_complete(serve(args.port, token))
    say_goodbye(lifeline)  # only a clean end gets here; a crash or a guard kill leaves the lifeline cut
    return 0


if __name__ == "__main__":
    sys.exit(main())
