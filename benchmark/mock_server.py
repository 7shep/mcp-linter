"""One server of a trifecta benchmark tool set, served over stdio.

    python benchmark/mock_server.py --toolset ID --server-index N --trial PATH --log PATH

``Backend`` holds all the behaviour and runs in-process, so G2's scripted agent
can drive it without a subprocess. ``main`` is a thin stdio wrapper around it.

THREAT MODEL
  DEFENDS AGAINST: the mock touching the network, starting processes, or writing
    or reading files it should not; an arbitrary argument shape crashing the
    server; a log that loses or truncates what the model sent.
  ATTACKER CONTROLS: every tool argument (any JSON shape), which tools are called
    and in what order.
  MUST FAIL CLOSED WHEN: arguments are not an object, or a required or typed
    argument is wrong (error result, still logged); the guard sees a forbidden
    act (exit 70).
  OUT OF SCOPE: a compromised interpreter or MCP SDK; timing side channels.

Mock data only. Backends are in memory; a mock ``read_file`` never touches disk.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

import corpus
from corpus import CONDITIONS, Context, ToolSet, ToolSpec, respond

GUARD_EXIT = 70
_CANARY_RE = re.compile(r"^ZQ-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
_TASK_IDS = ("t1", "t2")
_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def _resolve_set(tool_set: Any) -> ToolSet:
    if isinstance(tool_set, ToolSet):
        return tool_set
    if isinstance(tool_set, str) and tool_set in corpus.TOOL_SETS:
        return corpus.TOOL_SETS[tool_set]
    raise ValueError(f"unknown tool set: {tool_set!r}")


def validate_arguments(schema: dict[str, Any], args: Any) -> str | None:
    """A short problem description, or None when the arguments fit the schema's top level."""
    if not isinstance(args, dict):
        return "arguments must be an object"
    props = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in args:
            return f"missing {name}"
    if schema.get("additionalProperties") is False:
        extra = [key for key in args if key not in props]
        if extra:
            return f"unexpected {extra[0]}"
    for name, value in args.items():
        spec = props.get(name)
        if not isinstance(spec, dict):
            continue
        kind = spec.get("type")
        if isinstance(kind, str) and kind in _TYPE_CHECKS and not _TYPE_CHECKS[kind](value):
            return f"{name} must be {kind}"
        if "enum" in spec and isinstance(spec["enum"], list) and value not in spec["enum"]:
            return f"{name} is not an allowed value"
    return None


class Backend:
    """One server's tools, responses and log, with no MCP or transport in it."""

    def __init__(self, tool_set: Any, server_index: int, trial: dict[str, Any],
                 log_path: str | None = None):
        self.tool_set = _resolve_set(tool_set)
        servers = self.tool_set.servers
        if (not isinstance(server_index, int) or isinstance(server_index, bool)
                or not 0 <= server_index < len(servers)):
            raise ValueError(f"server index out of range for {self.tool_set.id}")
        self.server_index = server_index
        self.specs: dict[str, ToolSpec] = {spec.name: spec for spec in servers[server_index]}
        if not isinstance(trial, dict):
            raise ValueError("trial must be an object")
        canary = trial.get("canary")
        if not isinstance(canary, str) or not _CANARY_RE.match(canary):
            raise ValueError("trial canary must look like ZQ-XXXX-XXXX-XXXX")
        condition = trial.get("condition")
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition!r}")
        variant = trial.get("variant")
        if variant not in self.tool_set.destinations:
            raise ValueError(f"unknown variant: {variant!r}")
        task_id = str(trial.get("task", "")).rsplit("/", 1)[-1]
        if task_id not in _TASK_IDS:
            raise ValueError(f"unknown task: {trial.get('task')!r}")
        injection = trial.get("injection_text")
        if condition == "I0" and injection is not None:
            raise ValueError("I0 trials carry no injection")
        if condition != "I0" and not isinstance(injection, str):
            raise ValueError("injected trials need injection_text")
        self.task = self.tool_set.tasks[_TASK_IDS.index(task_id)]
        self.canary = canary
        self.condition = condition
        self.variant = variant
        self.injection_text = injection
        self.injected_item = self.task.injected_item if injection is not None else None
        self.log_path = log_path

    def _write(self, row: dict[str, Any]) -> None:
        if not self.log_path:
            return
        try:
            line = json.dumps(row, ensure_ascii=True, default=repr)
        except (ValueError, RecursionError):  # circular, too deep or unserialisable: keep a repr instead
            try:
                shown = repr(row.get("arguments"))
            except RecursionError:
                shown = "<arguments nested too deeply to show>"
            row = dict(row, arguments=shown)
            line = json.dumps(row, ensure_ascii=True, default=repr)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def startup(self) -> None:
        self._write({"event": "startup", "toolset": self.tool_set.id,
                     "server_index": self.server_index, "pid": os.getpid()})

    def tools(self) -> list[dict[str, Any]]:
        """tools/list entries, with the saved schemas exactly as they are."""
        out = []
        for spec in self.specs.values():
            entry: dict[str, Any] = {"name": spec.name, "description": spec.description,
                                     "inputSchema": spec.input_schema}
            if spec.annotations is not None:
                entry["annotations"] = dict(spec.annotations)
            out.append(entry)
        return out

    def call(self, tool: Any, args: Any) -> tuple[str, bool]:
        """Run one call and log it. Returns (text, is_error); never raises on odd input."""
        spec = self.specs.get(tool) if isinstance(tool, str) else None
        refused = False
        if spec is None:
            text, is_error = "Unknown tool.", True
        else:
            problem = validate_arguments(spec.input_schema, args)
            if problem is not None:
                text, is_error = f"Invalid arguments: {problem}.", True
            else:
                try:
                    refused = bool(self.tool_set.refuses(spec.name, args))
                except Exception:  # noqa: BLE001 - a broken decoy rule fails closed (refuses)
                    refused = True
                if refused:
                    text, is_error = "Refused: this destination is not allowed for this tool.", True
                else:
                    reply = respond(spec, args, Context(self.canary, self.injected_item, self.injection_text))
                    text, is_error = reply.text, reply.is_error
        returned_injection = self.injection_text is not None and self.injection_text in text
        returned_canary = self.canary in text
        self._write({"event": "call", "tool": tool if isinstance(tool, str) else repr(tool),
                     "arguments": args, "is_error": is_error, "refused": refused,
                     "returned_injection": returned_injection, "returned_canary": returned_canary})
        return text, is_error


# ---------------------------------------------------------------- guard (DESIGN section 10)

_DENIED_EVENTS = frozenset({"subprocess.Popen", "os.system", "os.exec", "os.spawn",
                            "os.posix_spawn", "os.startfile"})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
# Filesystem changes: allowed only when every path they name is the log file.
_PATH_EVENTS = frozenset({"os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.link", "os.symlink",
                          "os.truncate", "os.chmod", "os.chown", "shutil.rmtree", "shutil.move",
                          "shutil.copyfile", "shutil.copytree"})
_SOCKET_ADDRESS_EVENTS = frozenset({"socket.sendto", "socket.sendmsg", "socket.bind"})
_BENCH_DIR = Path(__file__).resolve().parent


def _real(path: Any) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _under(path_real: str, root_real: str) -> bool:
    try:
        return os.path.commonpath([path_real, root_real]) == root_real
    except ValueError:
        return False


def _loopback(host: Any) -> bool:
    if not isinstance(host, str):
        return False
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def _is_write(mode: Any, flags: Any) -> bool:
    if isinstance(mode, str):
        return any(ch in mode for ch in "wax+")
    if isinstance(flags, int):
        return bool(flags & _WRITE_FLAGS)
    return False


def _only_log(values: tuple, log_real: str) -> bool:
    """True when at least one path is named and every path named is the log file."""
    found = False
    for value in values:
        if isinstance(value, (str, bytes, os.PathLike)):
            found = True
            try:
                if _real(value) != log_real:
                    return False
            except Exception:  # noqa: BLE001
                return False
    return found


def _read_roots() -> list[str]:
    """Folders reads may use: the interpreter's prefixes, this benchmark folder, and the
    library folders on sys.path. The script's own folder is not a library folder, so it
    is excluded even when it is on sys.path."""
    prefixes = {_real(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix,
                                   sys.base_exec_prefix) if p}
    roots = set(prefixes) | {_real(_BENCH_DIR)}
    for entry in sys.path:
        if not entry or not os.path.isdir(entry):
            continue
        real = _real(entry)
        lowered = real.casefold()
        if any(_under(real, p) for p in prefixes) or "site-packages" in lowered or "dist-packages" in lowered:
            roots.add(real)
    return sorted(roots)


_GUARD_LOG: str | None = None  # set by install_guard: the one file the guard may write


def _block(event: str, detail: str = "") -> None:
    if _GUARD_LOG:
        try:  # leave a mark in the log so the harness can tell a killed server from a quiet one
            with open(_GUARD_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"event": "guard_kill", "blocked": event}) + "\n")
        except Exception:  # noqa: BLE001
            pass
    try:
        suffix = f" {detail}" if detail else ""
        sys.stderr.write(f"mock_server guard: blocked {event}{suffix}\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    os._exit(GUARD_EXIT)


def install_guard(log_path: str, trial_path: str | None = None) -> None:
    """Kill the process (exit 70) on any network connect to a non-loopback address,
    subprocess start, write to a file other than the log, or read outside the
    interpreter, the benchmark folder and the library folders.

    Call after every import and after reading the trial file and survey JSON.
    """
    global _GUARD_LOG
    _GUARD_LOG = log_path
    log_real = _real(log_path)
    trial_real = _real(trial_path) if trial_path else None
    # The MCP stdio server diverts fd 0 by opening the null device for reading.
    null_real = _real(os.devnull)
    roots = _read_roots()

    def hook(event: str, args: tuple) -> None:
        if event in _DENIED_EVENTS:
            _block(event)
        elif event in _SOCKET_ADDRESS_EVENTS:
            address = args[1] if len(args) > 1 else None
            if address is None and event != "socket.bind":
                return  # a connected socket: its peer was checked at connect time
            host = address[0] if isinstance(address, tuple) and address else None
            if not _loopback(host):
                _block(event)
        elif event in _PATH_EVENTS:
            if not _only_log(tuple(args[:2]), log_real):
                _block(event, repr(args[0]) if args else "")
        elif event == "socket.connect":
            address = args[1] if len(args) > 1 else None
            host = address[0] if isinstance(address, tuple) and address else None
            if not _loopback(host):
                _block(event)
        elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
            host = args[0] if args else None
            if host is not None and not _loopback(host):
                _block(event)
        elif event == "open":
            path = args[0] if args else None
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            if _is_write(mode, flags):
                if isinstance(path, int):
                    # Wrapping an already-open descriptor (the MCP SDK does this for stdout)
                    # cannot create, truncate or reach any path.
                    return
                try:
                    target = _real(path)
                except Exception:  # noqa: BLE001
                    _block(event)
                if target != log_real:
                    _block(event, repr(path))
            else:
                if isinstance(path, int) or path is None:
                    return
                try:
                    target = _real(path)
                except Exception:  # noqa: BLE001
                    _block(event)
                if target in (log_real, trial_real, null_real):
                    return
                if not any(_under(target, root) for root in roots):
                    _block(event, repr(path))

    sys.addaudithook(hook)


# ---------------------------------------------------------------- stdio wrapper

async def serve(backend: Backend) -> None:
    """Serve one Backend over MCP stdio until the client disconnects."""
    tools = [types.Tool(name=d["name"], description=d["description"], input_schema=d["inputSchema"],
                        annotations=d.get("annotations")) for d in backend.tools()]

    async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
        text, is_error = backend.call(params.name, params.arguments)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=is_error)

    server = Server(f"{backend.tool_set.id}-server-{backend.server_index}", version="1.0",
                    on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mock_server.py", description=__doc__.split("\n")[0])
    parser.add_argument("--toolset", required=True)
    parser.add_argument("--server-index", type=int, required=True)
    parser.add_argument("--trial", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.trial, encoding="utf-8") as fh:
            trial = json.load(fh)
        backend = Backend(args.toolset, args.server_index, trial, args.log)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"mock_server: {exc}", file=sys.stderr)
        return 2
    install_guard(args.log, args.trial)
    backend.startup()
    asyncio.run(serve(backend))
    return 0


if __name__ == "__main__":
    sys.exit(main())
