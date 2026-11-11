"""One AgentDojo trial's agent session, run in mcp-lint's venv.

    python benchmark/agentdojo_session.py --port P --model MODEL --prompt-file F [--timeout S]
        [--fake-ground-truth]

Started by benchmark/agentdojo_claude.py with the trial token in $AGENTDOJO_BRIDGE_TOKEN
(read, then removed from the environment, so claude never sees it). It prints exactly
one JSON line on stdout:

    {"ok": bool, "final_text": str, "error": str | null, "stop": null | "limit" | "auth" | "not_subscription"}

Normal mode: refuse unless `claude auth status` shows a claude.ai plan login (an API key
would bill), then run `claude -p` with one MCP server, the bridge
(mcp_lint.safe_exec -> agentdojo_mcp.py), no built-in tools, and the scrubbed environment
of benchmark/harness.py (no API keys). The stream is read with harness's parser.

Fake mode (--fake-ground-truth): no claude. The session connects to the bridge as an MCP
client, replays the ground-truth calls from the prompt file, and returns the file's
ground-truth output as the final text.

THREAT MODEL
  DEFENDS AGAINST: running without a plan login; API keys reaching claude; the agent
    having any tool but the bridge's; a bridge that never connected or listed tools
    being reported as a finished trial; the token in argv or in claude's environment.
  ATTACKER CONTROLS: the model's text and tool calls (so what claude prints).
  MUST FAIL CLOSED WHEN: preflight fails; claude exits nonzero, times out, hits a limit
    or authentication error; the stream has no single result; the bridge server is not
    connected; the init event lists no bridge tools.
  OUT OF SCOPE: how a real limit stop looks (harness covers it); parallel trials.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

BENCH = Path(__file__).resolve().parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

import harness  # noqa: E402

BRIDGE = BENCH / "agentdojo_mcp.py"
SERVER_NAME = "ad"
TOOL_PREFIX = f"mcp__{SERVER_NAME}__"
TOKEN_ENV = "AGENTDOJO_BRIDGE_TOKEN"
TIMEOUT_DEFAULT = 540.0
STOPS = {"limit": "limit", "auth": "auth", "not_subscription": "not_subscription"}


def bridge_argv(port: int, token_file: str | Path) -> list[str]:
    """The MCP server command: the bridge, started with only the minimal environment."""
    return ["-m", "mcp_lint.safe_exec", "--", sys.executable, str(BRIDGE),
            "--port", str(port), "--token-file", str(token_file)]


def mcp_config(port: int, token_file: str | Path) -> dict[str, Any]:
    return {"mcpServers": {SERVER_NAME: {"type": "stdio", "command": sys.executable,
                                         "args": bridge_argv(port, token_file)}}}


def claude_argv(config_path: str | Path, model: str) -> list[str]:
    """harness.claude_command: --strict-mcp-config, --tools "", dontAsk; every bridge tool allowed."""
    return harness.claude_command(config_path, model=model, tool_names=[f"mcp__{SERVER_NAME}"])


def init_tools(stdout: str) -> list[str] | None:
    """The tool names in the stream's init event, or None when there is no init event or no tools key."""
    for raw in (stdout or "").split("\n"):
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("type") == "system" and event.get("subtype") == "init":
            tools = event.get("tools")
            return [t for t in tools if isinstance(t, str)] if isinstance(tools, list) else None
    return None


def interpret(done: Any, timed_out: bool) -> dict[str, Any]:
    """Turn a finished claude process into the session's result line. Fails closed."""
    status, reason, facts = harness.judge_process(done, timed_out, servers=[SERVER_NAME], tools=None)  # None: any permission denial fails the trial
    if status != "ok":
        return {"ok": False, "final_text": "", "error": f"{status}: {reason}", "stop": STOPS.get(status)}
    tools = init_tools(done.stdout)
    if tools is None:
        return {"ok": False, "final_text": "", "error": "init event has no tools list", "stop": None}
    if not any(name.startswith(TOOL_PREFIX) for name in tools):
        return {"ok": False, "final_text": "", "error": "init event lists no bridge tools", "stop": None}
    extra = [name for name in tools if not name.startswith(TOOL_PREFIX)]
    if extra:
        return {"ok": False, "final_text": "", "error": f"init event lists non-bridge tools: {extra[0]}", "stop": None}
    return {"ok": True, "final_text": (facts or {}).get("final_text", ""),
            "error": None, "stop": None, "note": reason}


def run_claude_session(port: int, model: str, prompt: str, token: str, timeout: float, *,
                       runner: Callable[..., Any] | None = None,
                       preflight_run: Callable[..., Any] | None = None) -> dict[str, Any]:
    try:
        harness.preflight(preflight_run)
    except (harness.PreflightError, OSError) as exc:
        return {"ok": False, "final_text": "", "error": f"preflight: {exc}", "stop": "not_subscription"}
    runner = runner or harness.subscription_runner
    with tempfile.TemporaryDirectory(prefix="agentdojo-session-") as tmp:
        work = Path(tmp)
        scratch = work / "scratch"
        scratch.mkdir()
        token_file = work / "token"
        token_file.write_text(token, encoding="ascii")
        config_path = work / "mcp.json"
        config_path.write_text(json.dumps(mcp_config(port, token_file)), encoding="utf-8")
        cmd = claude_argv(config_path, model)
        done = None
        timed_out = False
        try:
            done = runner(cmd, prompt + harness.PROMPT_SUFFIX, str(scratch), timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        return interpret(done, timed_out)


async def _replay(port: int, token: str, calls: list[dict[str, Any]]) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    with tempfile.TemporaryDirectory(prefix="agentdojo-session-") as tmp:
        token_file = Path(tmp) / "token"
        token_file.write_text(token, encoding="ascii")
        params = StdioServerParameters(command=sys.executable, args=bridge_argv(port, token_file))
        errlog_path = Path(tmp) / "bridge-stderr.txt"
        try:
            with open(errlog_path, "w", encoding="utf-8") as errlog:
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        if not listed.tools:
                            raise RuntimeError("the bridge listed no tools")
                        for call in calls:
                            await session.call_tool(call["function"], dict(call["args"]))
        except BaseException as exc:
            stderr = errlog_path.read_text(encoding="utf-8", errors="replace").strip()[-300:]
            leaf = exc
            while isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:
                leaf = leaf.exceptions[0]
            raise RuntimeError(f"{type(leaf).__name__}: {leaf}; bridge stderr: {stderr}") from None


def run_fake_session(port: int, token: str, doc: dict[str, Any]) -> dict[str, Any]:
    calls, final_text = doc.get("ground_truth"), doc.get("final_text")
    if not isinstance(calls, list) or not isinstance(final_text, str):
        return {"ok": False, "final_text": "", "error": "prompt file has no ground truth", "stop": None}
    try:
        asyncio.run(asyncio.wait_for(_replay(port, token, calls), 300))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "final_text": "", "error": f"replay failed: {type(exc).__name__}: {exc}", "stop": None}
    return {"ok": True, "final_text": final_text, "error": None, "stop": None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdojo_session.py", description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT)
    parser.add_argument("--fake-ground-truth", action="store_true")
    args = parser.parse_args(argv)
    token = os.environ.pop(TOKEN_ENV, "")  # claude must not inherit it
    if not token or not token.isalnum():
        result = {"ok": False, "final_text": "", "error": f"{TOKEN_ENV} is missing or malformed", "stop": None}
    elif not 0 < args.port < 65536:
        result = {"ok": False, "final_text": "", "error": "port out of range", "stop": None}
    elif not args.fake_ground_truth and args.model not in harness.MODELS:
        result = {"ok": False, "final_text": "", "error": "model is not one of the benchmark models", "stop": None}
    else:
        try:
            doc = json.loads(Path(args.prompt_file).read_text(encoding="utf-8"))
            prompt = doc["prompt"]
            if not isinstance(prompt, str) or not prompt:
                raise ValueError("empty prompt")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            result = {"ok": False, "final_text": "", "error": f"bad prompt file: {exc}", "stop": None}
        else:
            if args.fake_ground_truth:
                result = run_fake_session(args.port, token, doc)
            else:
                result = run_claude_session(args.port, args.model, prompt, token, args.timeout)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
