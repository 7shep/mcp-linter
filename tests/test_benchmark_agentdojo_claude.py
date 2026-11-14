"""Tests for benchmark/agentdojo_claude.py, agentdojo_session.py and agentdojo_mcp.py.

No test calls claude or any model. Tests that need AgentDojo run it in a subprocess
with the interpreter named by the AGENTDOJO_PYTHON environment variable (the
AgentDojo venv, run with -I) and are skipped when it is unset or missing.

THREAT MODEL
  DEFENDS AGAINST: another local process driving a trial's socket; an unknown tool or
    malformed line crashing the server; a dead socket making the MCP bridge hang or serve
    an empty tool list; a session without a plan login, or with a server that is not
    connected or no tools, counting as a finished trial; the claude argv gaining built-in
    tools, --bare or --dangerously-skip-permissions; a failed trial leaving an AgentDojo log.
  ATTACKER CONTROLS: tool names and arguments the model sends; bytes on the socket.
  MUST FAIL CLOSED WHEN: the token is wrong or missing; a tool is unknown; the socket
    is unreachable; the stream shows no connected server or no tools; auth is not claude.ai.
  OUT OF SCOPE: real claude runs.
"""

import asyncio
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parent
BENCH = REPO / "benchmark"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

import agentdojo_session as session  # noqa: E402
from mcp_lint.eval import Completed  # noqa: E402

AGENTDOJO_PYTHON = os.environ.get("AGENTDOJO_PYTHON", "")
HAVE_AD = bool(AGENTDOJO_PYTHON) and (Path(AGENTDOJO_PYTHON).exists() or Path(AGENTDOJO_PYTHON + ".exe").exists())
needs_ad = unittest.skipUnless(HAVE_AD, "set AGENTDOJO_PYTHON to the AgentDojo venv's python")
BRIDGE = BENCH / "agentdojo_mcp.py"
TOKEN = "0123456789abcdef"


def run_ad(code: str, timeout: float = 240) -> subprocess.CompletedProcess:
    """Run a script in the AgentDojo interpreter, isolated (-I), with benchmark/ on its path."""
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "script.py"
        script.write_text(f"import sys\nsys.path.insert(0, {str(BENCH)!r})\n" + code, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        return subprocess.run([AGENTDOJO_PYTHON, "-I", str(script)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout, env=env)


def last_json(proc: subprocess.CompletedProcess) -> dict:
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


class StubSocket:
    """A tiny trial socket for the bridge tests: one tool 'echo', token-checked."""

    def __init__(self, token: str = TOKEN):
        self.token = token
        self.requests = []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        with conn, conn.makefile("rb") as reader:  # the reader must close too, or the socket stays open
                if reader.readline().strip().decode() != self.token:
                    return
                request = json.loads(reader.readline())
                self.requests.append(request)
                if request["op"] in ("ping", "hello"):
                    reply = {"ok": True}
                elif request["op"] == "list_tools":
                    reply = {"tools": [{"name": "echo", "description": "Echo text.",
                                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
                else:
                    reply = {"text": "echo: " + str(request["arguments"].get("text")), "is_error": False}
                conn.sendall(json.dumps(reply).encode() + b"\n")
                if request["op"] == "hello":
                    reader.readline()  # hold the lifeline until the bridge says bye or goes away

    def close(self):
        self.srv.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BridgeTests(unittest.TestCase):
    """The MCP bridge, driven by the mcp SDK's own client against a stub socket server."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token_file = Path(self.tmp.name) / "token"
        self.token_file.write_text(TOKEN, encoding="ascii")

    def test_c_list_and_call_through_the_mcp_client(self):
        stub = StubSocket()
        self.addCleanup(stub.close)

        async def go():
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client

            params = StdioServerParameters(command=sys.executable,
                                           args=session.bridge_argv(stub.port, self.token_file))
            with open(Path(self.tmp.name) / "err.txt", "w", encoding="utf-8") as errlog:
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        listed = await client.list_tools()
                        called = await client.call_tool("echo", {"text": "hi"})
                        return [t.name for t in listed.tools], called

        names, called = asyncio.run(asyncio.wait_for(go(), 90))
        self.assertEqual(names, ["echo"])
        self.assertFalse(called.is_error)
        self.assertEqual(called.content[0].text, "echo: hi")

    def _bridge_exit(self, port: int, token_file: Path) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(BRIDGE), "--port", str(port), "--token-file", str(token_file)],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)

    def test_d_unreachable_socket_fails_fast_not_hangs(self):
        done = self._bridge_exit(free_port(), self.token_file)
        self.assertEqual(done.returncode, 2)
        self.assertIn("cannot reach", done.stderr)

    def test_d_wrong_token_makes_the_bridge_refuse(self):
        stub = StubSocket(token="ffffffffffffffff")
        self.addCleanup(stub.close)
        done = self._bridge_exit(stub.port, self.token_file)
        self.assertEqual(done.returncode, 2)

    def test_d_missing_token_file_refuses(self):
        done = self._bridge_exit(free_port(), Path(self.tmp.name) / "nope")
        self.assertEqual(done.returncode, 2)


def stream(*events) -> str:
    return "\n".join(json.dumps(e) for e in events) + "\n"


def init(servers, tools, key="none"):
    return {"type": "system", "subtype": "init", "apiKeySource": key, "model": "m",
            "mcp_servers": servers, "tools": tools}


RESULT = {"type": "result", "subtype": "success", "is_error": False, "result": "All done.", "stop_reason": "end_turn"}


class SessionTests(unittest.TestCase):
    def test_e_good_stream_is_ok(self):
        out = stream(init([{"name": "ad", "status": "connected"}], ["mcp__ad__send_money"]), RESULT)
        got = session.interpret(Completed(0, out, "", 1), False)
        self.assertTrue(got["ok"])
        self.assertEqual(got["final_text"], "All done.")

    def test_e_server_not_connected_is_not_ok(self):
        out = stream(init([{"name": "ad", "status": "failed"}], []), RESULT)
        got = session.interpret(Completed(0, out, "", 1), False)
        self.assertFalse(got["ok"])
        self.assertIn("not connected", got["error"])

    def test_e_zero_tools_is_not_ok(self):
        out = stream(init([{"name": "ad", "status": "connected"}], ["Read"]), RESULT)
        got = session.interpret(Completed(0, out, "", 1), False)
        self.assertFalse(got["ok"])
        self.assertIn("no bridge tools", got["error"])

    def test_e_a_permission_denial_of_a_bridge_tool_is_not_ok(self):
        denied = dict(RESULT, permission_denials=[{"tool_name": "mcp__ad__send_money", "tool_input": {}}])
        out = stream(init([{"name": "ad", "status": "connected"}], ["mcp__ad__send_money"]), denied)
        got = session.interpret(Completed(0, out, "", 1), False)
        self.assertFalse(got["ok"])
        self.assertIn("permission denied", got["error"])

    def test_e_missing_tools_key_is_not_ok(self):
        event = init([{"name": "ad", "status": "connected"}], ["mcp__ad__x"])
        del event["tools"]
        got = session.interpret(Completed(0, stream(event, RESULT), "", 1), False)
        self.assertFalse(got["ok"])

    def test_e_a_non_bridge_tool_in_the_init_event_is_not_ok(self):
        out = stream(init([{"name": "ad", "status": "connected"}], ["mcp__ad__x", "Bash"]), RESULT)
        got = session.interpret(Completed(0, out, "", 1), False)
        self.assertFalse(got["ok"])
        self.assertIn("non-bridge", got["error"])

    def test_e_timeout_nonzero_and_api_key_are_not_ok(self):
        good = stream(init([{"name": "ad", "status": "connected"}], ["mcp__ad__x"]), RESULT)
        self.assertFalse(session.interpret(None, True)["ok"])
        self.assertFalse(session.interpret(Completed(1, good, "", 1), False)["ok"])
        keyed = stream(init([{"name": "ad", "status": "connected"}], ["mcp__ad__x"], key="ANTHROPIC_API_KEY"), RESULT)
        got = session.interpret(Completed(0, keyed, "", 1), False)
        self.assertFalse(got["ok"])
        self.assertEqual(got["stop"], "not_subscription")

    def test_f_preflight_refuses_a_non_plan_login_and_never_runs_claude(self):
        def fake_run(cmd, **kwargs):
            if cmd[1:3] == ["auth", "status"]:
                return mock.Mock(returncode=0, stdout=json.dumps({"loggedIn": True, "authMethod": "api_key"}))
            return mock.Mock(returncode=0, stdout="1.0.0")

        def runner(*args, **kwargs):
            raise AssertionError("claude must not run")

        got = session.run_claude_session(1234, "claude-haiku-5-5", "hi", TOKEN, 5, runner=runner,
                                         preflight_run=fake_run)
        self.assertFalse(got["ok"])
        self.assertEqual(got["stop"], "not_subscription")
        self.assertIn("preflight", got["error"])

    def test_g_claude_argv_is_locked_down(self):
        argv = session.claude_argv("mcp.json", "claude-haiku-5-5")
        self.assertIn("--strict-mcp-config", argv)
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
        for bad in ("--dangerously-skip-permissions", "--bare"):
            self.assertNotIn(bad, argv)
        source = (BENCH / "agentdojo_session.py").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith(("#", '"""')))
        self.assertNotIn('"--dangerously-skip-permissions"', code)
        self.assertNotIn('"--bare"', code)

    def test_mcp_config_has_one_bridge_server_through_safe_exec_and_no_token_in_argv(self):
        config = session.mcp_config(4321, "/tmp/tokenfile")
        self.assertEqual(list(config["mcpServers"]), ["ad"])
        args = config["mcpServers"]["ad"]["args"]
        self.assertEqual(args[:3], ["-m", "mcp_lint.safe_exec", "--"])
        self.assertIn("--token-file", args)
        self.assertNotIn(TOKEN, json.dumps(config))

    def test_main_without_a_token_reports_not_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            prompt = Path(tmp) / "p.json"
            prompt.write_text(json.dumps({"prompt": "hi"}), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stdout(out):
                os.environ.pop(session.TOKEN_ENV, None)
                code = session.main(["--port", "5000", "--model", "claude-haiku-5-5", "--prompt-file", str(prompt)])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out.getvalue())["ok"])


@needs_ad
class SocketServerTests(unittest.TestCase):
    PRELUDE = """
import json, socket
import agentdojo_claude as ac
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
suite = get_suite("v1.2", "banking")
env = suite.load_and_inject_default_environment({})
runtime = FunctionsRuntime(suite.tools)
server = ac.BridgeServer(runtime, env, "tok123").start()

def talk(lines, expect_reply=True):
    s = socket.create_connection(("127.0.0.1", server.port), timeout=10)
    for line in lines:
        s.sendall(line.encode() + b"\\n")
    buf = b""
    try:
        while b"\\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    s.close()
    return buf.decode().strip()
"""

    def test_a_wrong_and_missing_token_are_closed_without_a_reply(self):
        proc = run_ad(self.PRELUDE + """
req = json.dumps({"op": "list_tools"})
out = {
    "wrong": talk(["nope", req]),
    "missing": talk([req]),
    "empty": talk([""]),
    "right": talk(["tok123", req])[:20],
}
import time; time.sleep(0.3)
out["rejected"] = server.rejected
out["calls"] = len(server.calls)
print(json.dumps(out))
""")
        got = last_json(proc)
        self.assertEqual(got["wrong"], "")
        self.assertEqual(got["missing"], "")
        self.assertEqual(got["empty"], "")
        self.assertTrue(got["right"].startswith('{"tools"'))
        self.assertEqual(got["rejected"], 3)
        self.assertEqual(got["calls"], 0)

    def test_b_unknown_tool_bad_arguments_and_malformed_lines_never_crash(self):
        proc = run_ad(self.PRELUDE + """
def call(name, args):
    return json.loads(talk(["tok123", json.dumps({"op": "call", "name": name, "arguments": args})]))
out = {
    "unknown": call("no_such_tool", {}),
    "bad_args": call("send_money", {}),
    "not_object": call("get_balance", [1, 2]),
    "name_not_string": call(123, {}),
    "malformed": json.loads(talk(["tok123", "{not json"])),
    "not_dict": json.loads(talk(["tok123", "[1]"])),
    "unknown_op": json.loads(talk(["tok123", json.dumps({"op": "shell"})])),
    "good": call("get_balance", {}),
    "names": [c["name"] for c in server.calls],
}
print(json.dumps(out))
""")
        got = last_json(proc)
        for key in ("unknown", "bad_args", "not_object", "name_not_string"):
            self.assertTrue(got[key]["is_error"], key)
        self.assertIn("error", got["malformed"])
        self.assertIn("error", got["not_dict"])
        self.assertIn("error", got["unknown_op"])
        self.assertFalse(got["good"]["is_error"])
        self.assertEqual(got["names"], ["no_such_tool", "send_money", "get_balance", "123", "get_balance"])

    def test_calls_change_the_environment_in_this_process(self):
        proc = run_ad(self.PRELUDE + """
before = len(env.bank_account.transactions)
r = json.loads(talk(["tok123", json.dumps({"op": "call", "name": "send_money", "arguments":
    {"recipient": "GB29NWBK60161331926819", "amount": 1.0, "subject": "t", "date": "2022-01-01"}})]))
print(json.dumps({"is_error": r["is_error"], "grew": len(env.bank_account.transactions) - before}))
""")
        got = last_json(proc)
        self.assertFalse(got["is_error"])
        self.assertEqual(got["grew"], 1)


WORKSPACE = """
import json, sys
import agentdojo_claude as ac
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
suite = get_suite("v1.2", "workspace")
env = suite.load_and_inject_default_environment({})
runtime = FunctionsRuntime(suite.tools)
EVIL = {"recipients": "[{[1]: 2}]", "subject": "s", "body": "b"}
"""

STUB_SESSION = '''
import json, os, socket, sys
token = os.environ.pop("AGENTDOJO_BRIDGE_TOKEN")
port = int(sys.argv[sys.argv.index("--port") + 1])
def talk(req):
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(token.encode() + b"\\n" + json.dumps(req).encode() + b"\\n")
    buf = b""
    while b"\\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf
mode = os.environ["STUB_MODE"]
lifeline = None
if mode != "no_hello":
    lifeline = socket.create_connection(("127.0.0.1", port), timeout=20)
    lifeline.sendall(token.encode() + b"\\n" + json.dumps({"op": "hello"}).encode() + b"\\n")
    lifeline.recv(65536)
talk({"op": "list_tools"})
if mode == "evil_call":
    talk({"op": "call", "name": "send_email", "arguments": {"recipients": "[{[1]: 2}]", "subject": "s", "body": "b"}})
elif mode == "bad_op":
    talk({"op": "bogus"})
if lifeline is not None:
    if mode != "dies":
        lifeline.sendall(json.dumps({"op": "bye"}).encode() + b"\\n")
    lifeline.close()
print(json.dumps({"ok": True, "final_text": "done", "error": None, "stop": None}))
'''


@needs_ad
class BridgeFaultTests(unittest.TestCase):
    def test_a_string_that_breaks_literal_eval_is_a_recorded_error_result(self):
        proc = run_ad(WORKSPACE + """
server = ac.BridgeServer(runtime, env, "tok123")
text, is_error = server.call("send_email", EVIL)
print(json.dumps({"is_error": is_error, "text": text[:80], "calls": server.calls}))
""")
        got = last_json(proc)
        self.assertTrue(got["is_error"])
        self.assertEqual(len(got["calls"]), 1)
        self.assertEqual(got["calls"][0]["name"], "send_email")
        self.assertTrue(got["calls"][0]["error"])

    def test_recorded_args_are_the_repaired_ones(self):
        proc = run_ad(WORKSPACE + """
server = ac.BridgeServer(runtime, env, "tok123")
server.call("send_email", {"recipients": "['a@b.c']", "subject": "s", "body": "b"})
print(json.dumps(server.calls[0]["args"]["recipients"]))
""")
        self.assertEqual(last_json(proc), ["a@b.c"])

    def _query(self, mode: str) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        stub = Path(tmp.name) / "stub_session.py"
        stub.write_text(STUB_SESSION, encoding="utf-8")
        return WORKSPACE + f"""
import os
from pathlib import Path
os.environ["STUB_MODE"] = {mode!r}
llm = ac.ClaudeCodeLLM("claude-haiku-5-5", session_script=Path({str(stub)!r}), mcp_python=sys.executable)
try:
    _, _, _, messages, _ = llm.query("hi", runtime, env)
    out = {{"raised": None, "tool_errors": [m["error"] for m in messages if m["role"] == "tool"]}}
except ac.TrialError as exc:
    out = {{"raised": str(exc), "tool_errors": []}}
print(json.dumps(out))
"""

    def test_the_evil_call_does_not_fault_the_bridge_and_is_in_the_messages(self):
        got = last_json(run_ad(self._query("evil_call")))
        self.assertIsNone(got["raised"])
        self.assertEqual(len(got["tool_errors"]), 1)
        self.assertTrue(got["tool_errors"][0])

    def test_a_clean_session_with_a_lifeline_passes(self):
        got = last_json(run_ad(self._query("plain")))
        self.assertIsNone(got["raised"])

    def test_a_lifeline_closed_without_bye_fails_the_trial(self):
        got = last_json(run_ad(self._query("dies")))
        self.assertIn("bridge lost", got["raised"] or "")

    def test_a_session_that_never_said_hello_fails_the_trial(self):
        got = last_json(run_ad(self._query("no_hello")))
        self.assertIn("bridge lost", got["raised"] or "")

    def test_an_authenticated_request_the_server_cannot_serve_fails_the_trial(self):
        got = last_json(run_ad(self._query("bad_op")))
        self.assertIn("bridge fault", got["raised"] or "")


@needs_ad
class AttackTests(unittest.TestCase):
    def test_stock_attack_raises_and_the_claude_code_variant_matches_its_text(self):
        proc = run_ad("""
import json
import agentdojo_claude as ac
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suite

class P(BasePipelineElement):
    def __init__(self, name): self.name = name
    def query(self, *a, **k): pass

suite = get_suite("v1.2", "banking")
try:
    load_attack(ac.ATTACK, suite, P("claude-code-claude-haiku-5-5")); raised = False
except ValueError:
    raised = True
name = ac.register_attack()
ours = load_attack(name, suite, P("claude-code-claude-haiku-5-5"))
stock = load_attack(ac.ATTACK, suite, P("gpt-4o-2024-05-13"))
ut, it = suite.get_user_task_by_id("user_task_0"), suite.get_injection_task_by_id("injection_task_0")
print(json.dumps({"raised": raised, "name": name, "same": ours.attack(ut, it) == stock.attack(ut, it),
                  "nonempty": bool(ours.attack(ut, it))}))
""")
        got = last_json(proc)
        self.assertTrue(got["raised"])
        self.assertEqual(got["name"], "important_instructions_no_model_name_claude_code")
        self.assertTrue(got["same"])
        self.assertTrue(got["nonempty"])


@needs_ad
class CliTests(unittest.TestCase):
    def test_dry_run_counts_and_model_check(self):
        script = BENCH / "agentdojo_claude.py"
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        ok = subprocess.run([AGENTDOJO_PYTHON, "-I", str(script), "--model", "claude-haiku-5-5", "--dry-run"],
                            capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("949 attacked + 97 clean", ok.stdout)
        bad = subprocess.run([AGENTDOJO_PYTHON, "-I", str(script), "--model", "gpt-4", "--dry-run"],
                             capture_output=True, text=True, env=env, timeout=120)
        self.assertNotEqual(bad.returncode, 0)

    def test_session_error_gives_an_errors_jsonl_line_and_no_trial_log(self):
        proc = run_ad("""
import json, subprocess, tempfile
from pathlib import Path
from unittest import mock
import agentdojo_claude as ac
from agentdojo.logging import OutputLogger
tmp = Path(tempfile.mkdtemp())
ac.LOGDIR_FAKE = tmp
failed = subprocess.CompletedProcess([], 1, json.dumps({"ok": False, "error": "session failed", "stop": None}), "")
with mock.patch.object(ac, "run_tree", return_value=failed), mock.patch.object(ac, "find_mcp_python", return_value="x"):
    code = ac.main(["--model", "claude-haiku-5-5", "--fake-ground-truth", "--clean-only", "--suite", "banking",
                    "--user-task", "user_task_0"])
files = sorted(str(p.relative_to(tmp)) for p in tmp.rglob("*") if p.is_file())
rows = [json.loads(l) for l in (tmp / "errors.jsonl").read_text().splitlines()]
print(json.dumps({"code": code, "files": files, "rows": rows}))
""")
        got = last_json(proc)
        self.assertNotEqual(got["code"], 0)
        self.assertEqual(got["files"], ["errors.jsonl"])
        self.assertEqual(len(got["rows"]), 1)
        self.assertEqual(set(got["rows"][0]), {"suite", "user_task_id", "injection_task_id", "error"})
        self.assertEqual(got["rows"][0]["user_task_id"], "user_task_0")
        self.assertIn("session failed", got["rows"][0]["error"])

    def test_h_fake_ground_truth_bridge_check_on_banking_has_no_mismatches(self):
        script = BENCH / "agentdojo_claude.py"
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        done = subprocess.run([AGENTDOJO_PYTHON, "-I", str(script), "--model", "claude-haiku-5-5",
                               "--fake-ground-truth", "--clean-only", "--suite", "banking",
                               "--user-task", "user_task_0", "--user-task", "user_task_1",
                               "--user-task", "user_task_2"],
                              capture_output=True, text=True, env=env, timeout=600)
        self.assertEqual(done.returncode, 0, done.stdout[-800:] + done.stderr[-800:])
        self.assertIn("mismatches 0, trial errors 0", done.stdout)


@needs_ad
class RunTreeTests(unittest.TestCase):
    """Codex review: a session timeout must kill claude and the bridge too, not just the session."""

    def test_timeout_kills_grandchildren(self):
        with tempfile.TemporaryDirectory() as tmp:
            beat = Path(tmp) / "beat.txt"
            grandchild = Path(tmp) / "grandchild.py"
            grandchild.write_text(
                "import sys, time\n"
                "while True:\n"
                "    open(sys.argv[1], 'a').write('x')\n"
                "    time.sleep(0.1)\n", encoding="utf-8")
            child = Path(tmp) / "child.py"
            child.write_text(
                "import subprocess, sys, time\n"
                "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "time.sleep(600)\n", encoding="utf-8")
            proc = run_ad(f"""
import os, subprocess, sys, time
import agentdojo_claude as ac
cmd = [sys.executable, {str(child)!r}, {str(grandchild)!r}, {str(beat)!r}]
t0 = time.monotonic()
try:
    ac.run_tree(cmd, timeout=3, env=dict(os.environ))
    print("NO TIMEOUT")
except subprocess.TimeoutExpired:
    print("TIMEOUT", round(time.monotonic() - t0))
""", timeout=120)
            self.assertIn("TIMEOUT", proc.stdout, proc.stdout + proc.stderr)
            self.assertNotIn("NO TIMEOUT", proc.stdout)
            time.sleep(1.0)
            size = beat.stat().st_size
            time.sleep(1.5)
            self.assertGreater(size, 0, "grandchild never started")
            self.assertEqual(beat.stat().st_size, size, "grandchild still running after the timeout")

    def test_normal_exit_returns_output(self):
        proc = run_ad("""
import os, sys
import agentdojo_claude as ac
done = ac.run_tree([sys.executable, "-c", "print('hi')"], timeout=60, env=dict(os.environ))
print("RC", done.returncode, done.stdout.strip())
""", timeout=120)
        self.assertIn("RC 0 hi", proc.stdout, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
