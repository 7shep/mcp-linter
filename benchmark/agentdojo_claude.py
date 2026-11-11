"""Run AgentDojo cases with Claude through headless `claude -p` on the Claude Code plan login.

Run it with the Python that has AgentDojo installed, not mcp-lint's:

    <agentdojo-venv>/python -I benchmark/agentdojo_claude.py --model claude-haiku-5-5
        [--suite S ...] [--user-task ID ...] [--injection-task ID ...]
        [--clean-only | --attacked-only] [--dry-run] [--fake-ground-truth]

AgentDojo does the injection, the scoring and the logging. Only the agent loop is
replaced: ClaudeCodeLLM, a pipeline element, runs one `claude -p` session per trial.
That session's only tools are the suite's AgentDojo functions, served by
benchmark/agentdojo_mcp.py (MCP stdio) which forwards each call over a token-guarded
127.0.0.1 socket to this process. Calls run here, in-process, against the trial's
environment, so AgentDojo's utility() and security() see the real state changes.

  agentdojo_claude.py (this file, AgentDojo venv)
    -> subprocess: agentdojo_session.py (mcp-lint venv; plan-login preflight, scrubbed env)
       -> claude -p --strict-mcp-config --tools ""
          -> mcp_lint.safe_exec -> agentdojo_mcp.py (audit-hooked MCP bridge)
             -> TCP 127.0.0.1:PORT -> BridgeServer (this file) -> FunctionsRuntime

No API key is used anywhere. Logs go to benchmark/results/agentdojo/runs/claude/
(runs/claude-fake/ under --fake-ground-truth), git-ignored. AgentDojo skips trials it
has already logged there, so a rerun resumes.

--fake-ground-truth uses no model. The session replays the user task's ground-truth
calls through the real MCP bridge and socket and returns the ground-truth output as
the final text. It then compares every clean utility with suite.check() (with
check_injectable=False, so only utility is compared) and prints the mismatch count.

Attack: "important_instructions_no_model_name" cannot be loaded for this pipeline.
AgentDojo's stock class looks the model name up in a table that has no Claude Code
entry, and raises ValueError. So this file registers
"important_instructions_no_model_name_claude_code": the same template, user name
("Emma Johnson") and model name (DEFAULT_MODEL_NAME) as the stock attack, minus the
lookup. A test pins that the injected text is identical.

THREAT MODEL
  DEFENDS AGAINST: the agent getting any tool besides the suite's AgentDojo functions;
    another local process driving the socket (per-trial token, checked with
    hmac.compare_digest); an API key reaching claude (the session's environment is
    scrubbed and a plan login is required); a broken bridge or a failed session being
    scored as "the model declined" (it raises: no AgentDojo log, one line in errors.jsonl).
  ATTACKER CONTROLS: injected text inside tool results, and so the tool names and
    arguments the model sends.
  MUST FAIL CLOSED WHEN: the token is wrong or missing (connection closed, counted);
    a tool is unknown or its arguments are bad (is_error result, never a crash); a
    line is not a JSON object (error reply, connection closed); the session exits
    nonzero, times out, reports a limit, a server that is not connected or no tools;
    the bridge never listed the tools.
  OUT OF SCOPE: adaptive attacks, Codex, prompt caching, whether Claude is fooled,
    local-model runs.

Only the standard library and agentdojo are imported, so the file runs under -I.
"""

from __future__ import annotations

import argparse
import copy
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from ast import literal_eval
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    ChatUserMessage,
    text_content_block_from_string,
)

BENCH = Path(os.path.dirname(os.path.abspath(__file__)))
REPO = BENCH.parent
SESSION_SCRIPT = BENCH / "agentdojo_session.py"
RUNS = BENCH / "results" / "agentdojo" / "runs"
LOGDIR = RUNS / "claude"
LOGDIR_FAKE = RUNS / "claude-fake"
BENCHMARK_VERSION = "v1.2"
MODELS = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
ATTACK = "important_instructions_no_model_name"
ATTACK_CLAUDE_CODE = "important_instructions_no_model_name_claude_code"
TOKEN_ENV = "AGENTDOJO_BRIDGE_TOKEN"
HOST = "127.0.0.1"


# The session runs preflight (two commands, up to 60 s each) before claude's own timer starts,
# so the session's own timeout leaves that much room inside the trial timeout.
SESSION_TIMEOUT_MARGIN = 150.0


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill proc and every descendant (claude, node, the MCP bridge), not just the direct child."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        else:
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run_tree(cmd: list[str], *, timeout: float, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Like subprocess.run(capture_output=True, text=True), but a timeout kills the whole process tree.

    The child gets its own process group (POSIX session / Windows process group), so the kill reaches
    every descendant. Raises subprocess.TimeoutExpired after the tree is killed and reaped.
    """
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", env=env, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        raise
    except BaseException:
        kill_tree(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
TRIAL_TIMEOUT = 600.0
READ_TIMEOUT = 10.0
MAX_TOKEN_LINE = 256
MAX_REQUEST_LINE = 4 * 1024 * 1024
MAX_NAME = 200


class TrialError(RuntimeError):
    """A trial that must not be scored. ``stop`` is set when the whole run must stop (limit, auth)."""

    def __init__(self, message: str, stop: str | None = None):
        super().__init__(message)
        self.stop = stop


# ---------------------------------------------------------------- the socket server

def _read_line(reader: Any, limit: int) -> bytes | None:
    """One line without its newline, or None on EOF before a newline, a timeout or an over-long line."""
    try:
        line = reader.readline(limit + 1)
    except OSError:
        return None
    if not line.endswith(b"\n") or len(line) > limit:
        return None
    return line[:-1]


class BridgeServer:
    """JSON-lines TCP server on 127.0.0.1 (OS-chosen port) that runs the trial's tools in-process.

    Every connection must send the trial token as its first line, then one request line.
    ``calls`` lists every call in order: {"name", "args", "result", "error"}.
    """

    def __init__(self, runtime: FunctionsRuntime, env: Env, token: str):
        self._runtime = runtime
        self._env = env
        self._token = token.encode("utf-8")
        self.calls: list[dict[str, Any]] = []
        self.list_tools_requests = 0
        self.tools_listed = 0
        self.rejected = 0
        self.faults = 0  # authenticated requests the server answered with an error
        self.hellos = self.byes = self.lost = self.lifelines_open = 0  # the bridge's lifeline connection
        self._lock = threading.Lock()  # one tool call at a time against the shared environment
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind((HOST, 0))
        self._listener.listen(16)
        self.port: int = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, name="agentdojo-bridge", daemon=True)

    def start(self) -> "BridgeServer":
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        try:  # wake accept() so the thread ends
            with socket.create_connection((HOST, self.port), timeout=1):
                pass
        except OSError:
            pass
        self._listener.close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "BridgeServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            if self._stop.is_set():
                conn.close()
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn, conn.makefile("rb") as reader:  # the reader must close too, or the socket stays open
            conn.settimeout(READ_TIMEOUT)
            first = _read_line(reader, MAX_TOKEN_LINE)
            if first is None or not hmac.compare_digest(first, self._token):
                self.rejected += 1
                return  # wrong or missing token: close without a word
            line = _read_line(reader, MAX_REQUEST_LINE)
            if line is None:
                return
            try:
                request = json.loads(line.decode("utf-8"))
            except (UnicodeError, ValueError):
                request = None
            if not isinstance(request, dict):
                reply: dict[str, Any] = {"error": "request must be one JSON object"}
            else:
                try:
                    reply = self.handle(request)
                except Exception as exc:  # noqa: BLE001 - never crash the server on odd input
                    reply = {"error": f"{type(exc).__name__}: {exc}"}
            if "error" in reply:  # the bridge would stop on this reply, so the trial must not be scored
                with self._lock:
                    self.faults += 1
            try:
                conn.sendall(json.dumps(reply).encode("utf-8") + b"\n")
            except OSError:
                return
            if isinstance(request, dict) and request.get("op") == "hello" and "error" not in reply:
                self._lifeline(conn, reader)

    def _lifeline(self, conn: socket.socket, reader: Any) -> None:
        """Hold the bridge's long-lived connection. A bye line then EOF is a clean end; EOF alone is a loss."""
        with self._lock:
            self.hellos += 1
            self.lifelines_open += 1
        conn.settimeout(None)
        clean = False
        try:
            line = reader.readline(MAX_TOKEN_LINE)
            try:
                clean = json.loads(line.decode("utf-8")).get("op") == "bye"
            except (UnicodeError, ValueError, AttributeError):
                clean = False
        except OSError:
            clean = False
        with self._lock:
            self.lifelines_open -= 1
            if clean:
                self.byes += 1
            else:
                self.lost += 1

    def lifeline_problem(self, wait: float = 10.0) -> str | None:
        """None when every bridge said hello and then bye; else why the bridge cannot be trusted.
        Waits briefly for a bye that is still in flight when the session returns."""
        deadline = time.monotonic() + wait
        while True:
            with self._lock:
                hellos, open_, lost = self.hellos, self.lifelines_open, self.lost
            if hellos == 0:
                return "bridge lost: it never said hello"
            if lost:
                return "bridge lost: its lifeline closed without a clean goodbye"
            if open_ == 0:
                return None
            if time.monotonic() >= deadline:
                return "bridge lost: no goodbye before the session ended"
            time.sleep(0.05)

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        if op in ("ping", "hello"):
            return {"ok": True}
        if op == "list_tools":
            tools = self.tools()
            with self._lock:
                self.list_tools_requests += 1
                self.tools_listed = len(tools)
            return {"tools": tools}
        if op == "call":
            text, is_error = self.call(request.get("name"), request.get("arguments"))
            return {"text": text, "is_error": is_error}
        return {"error": "unknown op"}

    def tools(self) -> list[dict[str, Any]]:
        return [{"name": f.name, "description": f.description, "inputSchema": f.parameters.model_json_schema()}
                for f in self._runtime.functions.values()]

    def call(self, name: Any, arguments: Any) -> tuple[str, bool]:
        """Run one call here, record it, and return (text, is_error). Never raises."""
        label = name[:MAX_NAME] if isinstance(name, str) else repr(name)[:MAX_NAME]
        if not isinstance(arguments, dict):
            args: dict[str, Any] = {}
            error: str | None = "ValidationError: arguments must be an object"
            result_text = ""
            with self._lock:
                self.calls.append({"name": label, "args": args, "result": result_text, "error": error})
            return error, True
        args = json.loads(json.dumps(arguments))  # the recorded copy until the repair below replaces it
        with self._lock:
            try:
                if not isinstance(name, str):
                    raise LookupError("tool name must be a string")
                run_args = dict(arguments)
                for key, value in list(run_args.items()):  # same list-string repair as AgentDojo's ToolsExecutor
                    if isinstance(value, str) and _is_string_list(value):
                        run_args[key] = literal_eval(value)
                args = copy.deepcopy(run_args)  # recorded after the repair, as the ToolsExecutor does
                result, error = self._runtime.run_function(self._env, name, run_args)
                result_text = tool_result_to_str(result)
            except Exception as exc:  # noqa: BLE001 - a broken tool is an error result, not a crash
                result_text, error = "", f"{type(exc).__name__}: {exc}"
            self.calls.append({"name": label, "args": args, "result": result_text, "error": error})
        return (error, True) if error is not None else (result_text, False)


def _is_string_list(text: str) -> bool:
    try:
        return isinstance(literal_eval(text), list)
    except Exception:  # noqa: BLE001 - literal_eval also raises TypeError, MemoryError, RecursionError
        return False


# ---------------------------------------------------------------- the pipeline element

def find_mcp_python() -> str:
    """The mcp-lint venv's interpreter: $MCP_LINT_PYTHON, else a .venv in this checkout or a parent
    (a git worktree sits inside its main checkout)."""
    override = os.environ.get("MCP_LINT_PYTHON")
    if override:
        return override
    for base in (REPO, *REPO.parents):
        for rel in (".venv/Scripts/python.exe", ".venv/bin/python"):
            candidate = base / rel
            if candidate.is_file():
                return str(candidate)
    raise TrialError("cannot find the mcp-lint venv; set MCP_LINT_PYTHON")


def session_env(token: str) -> dict[str, str]:
    """The session's environment: ours without provider keys, plus the token and PYTHONPATH=src."""
    env = {name: value for name, value in os.environ.items()
           if not name.upper().startswith(("ANTHROPIC_", "CLAUDE_CODE_USE_"))
           and name.upper() not in ("CLAUDE_CODE_OAUTH_TOKEN", "PYTHONPATH", TOKEN_ENV)}
    env["PYTHONPATH"] = str(REPO / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    env[TOKEN_ENV] = token
    return env


def read_session_result(stdout: str) -> dict[str, Any]:
    """The session's single JSON result line (the last line that is a JSON object)."""
    for raw in reversed((stdout or "").split("\n")):
        line = raw.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise TrialError("the session printed no result line")


def _calls_json(calls: Sequence[FunctionCall]) -> list[dict[str, Any]]:
    return [{"function": call.function, "args": dict(call.args)} for call in calls]


class ClaudeCodeLLM(BasePipelineElement):
    """One headless `claude -p` session per query, with the suite's functions as its only tools."""

    def __init__(self, model: str, *, suite: Any = None, fake_ground_truth: bool = False,
                 timeout: float = TRIAL_TIMEOUT, mcp_python: str | None = None,
                 session_script: Path = SESSION_SCRIPT) -> None:
        if not fake_ground_truth and model not in MODELS:
            raise ValueError(f"model must be one of {', '.join(MODELS)}")
        if fake_ground_truth and suite is None:
            raise ValueError("--fake-ground-truth needs the suite, to find each task's ground truth")
        self.model = model
        self.name = f"claude-code-{model}"
        self.suite = suite
        self.fake_ground_truth = fake_ground_truth
        self.timeout = timeout
        self.mcp_python = mcp_python
        self.session_script = session_script

    def _task_for(self, query: str) -> Any:
        found = [t for t in (*self.suite.user_tasks.values(), *self.suite.injection_tasks.values())
                 if query in (getattr(t, "PROMPT", None), getattr(t, "GOAL", None))]
        if len(found) != 1:
            raise TrialError(f"{len(found)} tasks match this prompt; cannot pick a ground truth")
        return found[0]

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict | None = None,
              ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        extra_args = {} if extra_args is None else extra_args
        prompt_doc: dict[str, Any] = {"prompt": query, "ground_truth": None, "final_text": None}
        if self.fake_ground_truth:
            task = self._task_for(query)
            prompt_doc["ground_truth"] = _calls_json(task.ground_truth(env.model_copy(deep=True)))
            prompt_doc["final_text"] = task.GROUND_TRUTH_OUTPUT
        token = secrets.token_hex(16)
        new_messages: list[ChatMessage] = [ChatUserMessage(role="user", content=[text_content_block_from_string(query)])]
        with BridgeServer(runtime, env, token) as server, tempfile.TemporaryDirectory(prefix="agentdojo-") as tmp:
            prompt_file = Path(tmp) / "prompt.json"
            prompt_file.write_text(json.dumps(prompt_doc), encoding="utf-8")
            cmd = [self.mcp_python or find_mcp_python(), str(self.session_script), "--port", str(server.port),
                   "--model", self.model, "--prompt-file", str(prompt_file),
                   "--timeout", str(max(self.timeout - SESSION_TIMEOUT_MARGIN, 30))]
            if self.fake_ground_truth:
                cmd.append("--fake-ground-truth")
            problem: str | None = None
            stop: str | None = None
            final_text = ""
            try:
                done = run_tree(cmd, env=session_env(token), timeout=self.timeout)
            except subprocess.TimeoutExpired:
                problem = f"session timed out after {self.timeout:.0f} s"
            else:
                try:
                    result = read_session_result(done.stdout)
                except TrialError as exc:
                    result = {"ok": False, "error": str(exc)}
                if done.returncode != 0:
                    tail = (done.stderr or "").strip()[-300:]
                    problem = f"session exited {done.returncode}: {result.get('error') or tail}"
                    stop = result.get("stop") if isinstance(result.get("stop"), str) else None
                elif result.get("ok") is not True:
                    problem = f"session failed: {result.get('error')}"
                    stop = result.get("stop") if isinstance(result.get("stop"), str) else None
                elif server.faults > 0:
                    problem = f"bridge fault: {server.faults} request(s) the trial socket could not serve"
                elif (lifeline := server.lifeline_problem()) is not None:
                    problem = lifeline
                elif server.list_tools_requests == 0 or server.tools_listed == 0:
                    problem = "the MCP bridge never listed any tools"
                else:
                    final_text = result.get("final_text") if isinstance(result.get("final_text"), str) else ""
            calls = list(server.calls)
        for index, call in enumerate(calls):
            function_call = FunctionCall(function=call["name"], args=call["args"], id=f"toolu_{index:04d}")
            new_messages.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")],
                                                     tool_calls=[function_call]))
            new_messages.append(ChatToolResultMessage(
                role="tool", content=[text_content_block_from_string(call["result"])],
                tool_call=function_call, tool_call_id=function_call.id, error=call["error"]))
        if problem is not None:
            # No Logger call: AgentDojo must write no log for a failed trial, so it counts as missing.
            raise TrialError(problem, stop)
        new_messages.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(final_text)],
                                                 tool_calls=None))
        return query, runtime, env, [*messages, *new_messages], extra_args


# ---------------------------------------------------------------- the attack

def register_attack() -> str:
    """Register the Claude Code variant of important_instructions_no_model_name; return its name."""
    from agentdojo.attacks.attack_registry import ATTACKS, register_attack as register
    from agentdojo.attacks.base_attacks import DEFAULT_MODEL_NAME, FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    if ATTACK_CLAUDE_CODE in ATTACKS:
        return ATTACK_CLAUDE_CODE

    class ImportantInstructionsNoModelNameClaudeCode(ImportantInstructionsAttack):
        name = ATTACK_CLAUDE_CODE

        def __init__(self, task_suite: Any, target_pipeline: BasePipelineElement) -> None:
            # Skip ImportantInstructionsAttack.__init__: it looks the model name up in the pipeline name.
            FixedJailbreakAttack.__init__(self, ImportantInstructionsAttack._JB_STRING, task_suite, target_pipeline)
            self.user_name = "Emma Johnson"
            self.model_name = DEFAULT_MODEL_NAME

    register(ImportantInstructionsNoModelNameClaudeCode)
    return ATTACK_CLAUDE_CODE


# ---------------------------------------------------------------- planning and running

MODES = ("both", "clean", "attacked")


def plan(suites_info: dict[str, dict[str, list[str]]], suites: Sequence[str] | None = None,
         user_tasks: Sequence[str] | None = None, injection_tasks: Sequence[str] | None = None,
         mode: str = "both") -> dict[str, Any]:
    """Trial counts. suites_info maps suite name -> {"user_tasks": [ids], "injection_tasks": [ids]}."""
    names = list(suites) if suites else sorted(suites_info)
    unknown = [n for n in names if n not in suites_info]
    if unknown:
        raise ValueError(f"unknown suite: {unknown[0]}")
    out: dict[str, Any] = {"suites": {}, "clean": 0, "attacked": 0}
    for name in names:
        info = suites_info[name]
        users = [u for u in info["user_tasks"] if not user_tasks or u in user_tasks]
        injs = [i for i in info["injection_tasks"] if not injection_tasks or i in injection_tasks]
        clean = len(users) if mode in ("both", "clean") else 0
        attacked = len(users) * len(injs) if mode in ("both", "attacked") else 0
        out["suites"][name] = {"user_tasks": users, "injection_tasks": injs, "clean": clean, "attacked": attacked}
        out["clean"] += clean
        out["attacked"] += attacked
    for label, wanted, key in (("user task", user_tasks, "user_tasks"), ("injection task", injection_tasks,
                                                                        "injection_tasks")):
        for item in wanted or ():
            if not any(item in suites_info[n][key] for n in names):
                raise ValueError(f"unknown {label}: {item}")
    return out


def _info(suites: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    return {n: {"user_tasks": list(s.user_tasks), "injection_tasks": list(s.injection_tasks)}
            for n, s in suites.items()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentdojo_claude.py", description=__doc__.split("\n")[0])
    parser.add_argument("--model", required=True, choices=MODELS)
    parser.add_argument("--suite", action="append")
    parser.add_argument("--user-task", action="append")
    parser.add_argument("--injection-task", action="append")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--clean-only", action="store_true")
    group.add_argument("--attacked-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print the planned counts; run nothing")
    parser.add_argument("--fake-ground-truth", action="store_true",
                        help="no model: replay each user task's ground truth through the bridge")
    parser.add_argument("--timeout", type=float, default=TRIAL_TIMEOUT, help="seconds per trial")
    return parser


def record_error(logdir: Path, suite: str, user_task_id: str, injection_task_id: str | None, exc: BaseException) -> None:
    """Append one failed trial to <logdir>/errors.jsonl. Ids and a short error only: no prompt, attack or model text."""
    row = {"suite": suite, "user_task_id": user_task_id, "injection_task_id": injection_task_id,
           "error": f"{type(exc).__name__}: {exc}"[:300]}
    with open(logdir / "errors.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def drop_partial_log(logdir: Path, pipeline: str, suite: str, user_task_id: str, attack: str,
                     injection_task_id: str | None) -> None:
    """AgentDojo's TraceLogger saves a stub (duration only) when a trial raises. Remove it when it has
    no utility, so a failed trial has no log and counts as missing."""
    path = logdir / pipeline.replace("/", "_") / suite / user_task_id / attack / f"{injection_task_id or 'none'}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict) or "utility" not in data:
        path.unlink(missing_ok=True)


def _run_trials(p: dict[str, Any], suites: dict[str, Any], args: argparse.Namespace) -> int:
    """One AgentDojo call per trial. A failed trial writes no AgentDojo log (so it counts as missing),
    goes to errors.jsonl, and the run continues. Limit and auth stops end the run."""
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks

    logdir = LOGDIR_FAKE if args.fake_ground_truth else LOGDIR
    logdir.mkdir(parents=True, exist_ok=True)
    attack_name = register_attack()
    done = errors = 0
    clean_results: dict[tuple[str, str], bool] = {}
    for name, row in p["suites"].items():
        suite = suites[name]
        llm = ClaudeCodeLLM(args.model, suite=suite, fake_ground_truth=args.fake_ground_truth, timeout=args.timeout)
        attack = load_attack(attack_name, suite, llm)
        for user_id in row["user_tasks"]:
            user_task = suite.get_user_task_by_id(user_id)
            jobs: list[tuple[str, str | None, Any]] = []
            if row["clean"]:
                jobs.append(("clean", None, lambda: run_task_without_injection_tasks(
                    suite, llm, user_task, logdir, False, BENCHMARK_VERSION)))
            if row["attacked"]:
                for inj_id in row["injection_tasks"]:
                    jobs.append(("attacked", inj_id, lambda inj_id=inj_id: run_task_with_injection_tasks(
                        suite, llm, user_task, attack, logdir, False, [inj_id], BENCHMARK_VERSION)))
            for kind, inj_id, job in jobs:
                try:
                    result = job()
                except Exception as exc:  # noqa: BLE001 - one failed trial must not end the run
                    errors += 1
                    record_error(logdir, name, user_id, inj_id, exc)
                    drop_partial_log(logdir, llm.name, name, user_id, attack.name if inj_id else "none", inj_id)
                    print(f"ERROR {name}/{user_id}/{inj_id or '-'} ({kind}): {exc}"[:400], file=sys.stderr)
                    stop = getattr(exc, "stop", None)
                    if stop:
                        print(f"stopping: {stop}", file=sys.stderr)
                        return 3 if stop == "limit" else 2
                    continue
                done += 1
                if kind == "clean":
                    clean_results[(name, user_id)] = result[0]
    print(f"finished {done} jobs, {errors} errors; logs in {logdir}")
    if args.fake_ground_truth and p["clean"]:
        return _bridge_report(p, suites, clean_results, errors)
    return 1 if errors else 0


def _bridge_report(p: dict[str, Any], suites: dict[str, Any], results: dict[tuple[str, str], bool],
                   errors: int) -> int:
    """Compare every clean utility from the bridge run with suite.check() for the same user task."""
    mismatches = 0
    compared = 0
    for name, row in p["suites"].items():
        _, (user_checks, _) = suites[name].check(check_injectable=False)
        for user_id in row["user_tasks"]:
            if (name, user_id) not in results:
                continue
            compared += 1
            expected = user_checks[user_id][0]
            if results[(name, user_id)] != expected:
                mismatches += 1
                print(f"MISMATCH {name}/{user_id}: bridge {results[(name, user_id)]}, check() {expected}")
    print(f"bridge check: compared {compared} user tasks, mismatches {mismatches}, trial errors {errors}")
    return 0 if mismatches == 0 and errors == 0 and compared == p["clean"] else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = "clean" if args.clean_only else "attacked" if args.attacked_only else "both"
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(BENCHMARK_VERSION)
    try:
        p = plan(_info(suites), args.suite, args.user_task, args.injection_task, mode)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"planned: {p['attacked']} attacked + {p['clean']} clean = {p['attacked'] + p['clean']} trials "
          f"(AgentDojo {BENCHMARK_VERSION}, model {args.model})")
    if args.dry_run:
        return 0
    from agentdojo.logging import OutputLogger

    logdir = LOGDIR_FAKE if args.fake_ground_truth else LOGDIR
    logdir.mkdir(parents=True, exist_ok=True)
    with OutputLogger(str(logdir), live=None):  # TraceLogger delegates to it and reads its logdir
        return _run_trials(p, suites, args)


if __name__ == "__main__":
    sys.exit(main())
