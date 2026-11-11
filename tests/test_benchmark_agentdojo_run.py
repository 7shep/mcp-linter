"""Tests for benchmark/agentdojo_run.py.

THREAT MODEL
  DEFENDS AGAINST: a run that talks to a non-local host, uses a Claude or OpenAI
    key from the environment, writes outside the fixed runs/local logdir, or starts
    with an unchecked model id or port, or with a model the local server doesn't list.
  ATTACKER CONTROLS: the --model-id, --port, filter and attack arguments.
  MUST FAIL CLOSED WHEN: the model id or port is malformed, a filter names an
    unknown suite or task, or the local server doesn't list the model.
  OUT OF SCOPE: AgentDojo's own scoring, and whether Ollama serves the model.
    No model is started or called by these tests.

The subprocess tests need AgentDojo's Python (AGENTDOJO_PYTHON, or the default
venv path) and skip when it is missing. The static and plan tests never skip.
"""

import http.server
import importlib.util
import os
import re
import subprocess
import sys
import threading
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS_DIR)
SCRIPT = os.path.join(REPO, "benchmark", "agentdojo_run.py")
# AgentDojo's Python comes only from AGENTDOJO_PYTHON. Unset means the tests that need it skip.
_AGENTDOJO_CANDIDATE = os.environ.get("AGENTDOJO_PYTHON", "")
# On Windows the interpreter file is python.exe, so accept the suffix too.
AGENTDOJO_PY = next(
    (p for p in (_AGENTDOJO_CANDIDATE, _AGENTDOJO_CANDIDATE + ".exe") if _AGENTDOJO_CANDIDATE and os.path.isfile(p)),
    "",
)
HAVE_AGENTDOJO = bool(AGENTDOJO_PY)

_spec = importlib.util.spec_from_file_location("agentdojo_run", SCRIPT)
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

# (user tasks, injection tasks) per suite, from the offline ground-truth pass.
SPEC_SHAPE = {"workspace": (40, 14), "travel": (20, 7), "banking": (16, 9), "slack": (21, 5)}


def synthetic_info():
    return {
        name: {
            "user_tasks": [f"user_task_{i}" for i in range(users)],
            "injection_tasks": [f"injection_task_{i}" for i in range(injs)],
        }
        for name, (users, injs) in SPEC_SHAPE.items()
    }


def _source():
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


class PlanTests(unittest.TestCase):
    def test_full_plan_matches_spec_totals(self):
        p = run.plan(synthetic_info())
        self.assertEqual(p["attacked"], 949)
        self.assertEqual(p["clean"], 97)
        self.assertEqual(p["suites"]["workspace"]["attacked"], 560)
        self.assertEqual(p["suites"]["workspace"]["clean"], 40)
        self.assertEqual(p["suites"]["travel"]["attacked"], 140)
        self.assertEqual(p["suites"]["banking"]["attacked"], 144)
        self.assertEqual(p["suites"]["slack"]["attacked"], 105)

    def test_clean_only_and_attacked_only(self):
        clean = run.plan(synthetic_info(), mode="clean")
        self.assertEqual((clean["clean"], clean["attacked"]), (97, 0))
        attacked = run.plan(synthetic_info(), mode="attacked")
        self.assertEqual((attacked["clean"], attacked["attacked"]), (0, 949))

    def test_user_task_filter_applies_to_every_suite(self):
        p = run.plan(synthetic_info(), user_tasks=["user_task_0"])
        self.assertEqual(p["clean"], 4)
        self.assertEqual(p["attacked"], 14 + 7 + 9 + 5)

    def test_injection_task_filter_and_suite_selection(self):
        p = run.plan(synthetic_info(), suites=["slack"], injection_tasks=["injection_task_1", "injection_task_2"])
        self.assertEqual(list(p["suites"]), ["slack"])
        self.assertEqual(p["attacked"], 21 * 2)
        self.assertEqual(p["clean"], 21)

    def test_unknown_suite_is_refused(self):
        with self.assertRaises(ValueError):
            run.plan(synthetic_info(), suites=["nope"])

    def test_unknown_task_id_is_refused(self):
        with self.assertRaises(ValueError):
            run.plan(synthetic_info(), user_tasks=["user_task_999"])
        with self.assertRaises(ValueError):
            run.plan(synthetic_info(), injection_tasks=["injection_task_999"])

    def test_format_plan_total_line(self):
        text = run.format_plan(run.plan(synthetic_info()))
        self.assertIn("TOTAL attacked=949 clean=97 trials=1046", text)


class ValidationTests(unittest.TestCase):
    def test_model_ids_accepted(self):
        for model in ("qwen2.5:7b", "qwen3:8b", "llama3.1_8b-instruct"):
            run.validate_model_id(model)

    def test_bad_model_ids_refused(self):
        for model in ("bad model;rm", "", "a/b", "x\n", "x y", "$(id)"):
            with self.subTest(model=model), self.assertRaises(ValueError):
                run.validate_model_id(model)

    def test_ports_in_range_accepted(self):
        for port in (1, 11434, 65535):
            run.validate_port(port)

    def test_bad_ports_refused(self):
        for port in (0, -1, 65536, 70000):
            with self.subTest(port=port), self.assertRaises(ValueError):
                run.validate_port(port)


class StaticTests(unittest.TestCase):
    """Read the source. These never skip and need no agentdojo."""

    def test_logdir_is_the_fixed_runs_local_path(self):
        src = _source()
        self.assertIn('LOGDIR = REPO / "benchmark" / "results" / "agentdojo" / "runs" / "local"', src)
        self.assertEqual(run.LOGDIR.parts[-5:], ("benchmark", "results", "agentdojo", "runs", "local"))
        self.assertNotIn("--logdir", src)

    def test_api_keys_are_removed_from_environ(self):
        src = _source()
        self.assertIn('os.environ.pop("ANTHROPIC_API_KEY", None)', src)
        self.assertIn('os.environ.pop("OPENAI_API_KEY", None)', src)

    def test_only_network_host_is_localhost(self):
        src = _source()
        hosts = set(re.findall(r"://([^/\s\"'{}:]+)", src))
        self.assertEqual(hosts, {"localhost"})
        self.assertNotIn("anthropic.com", src)
        self.assertNotIn("openai.com", src)

    def test_top_level_imports_are_stdlib_only(self):
        stdlib = {"__future__", "argparse", "json", "os", "re", "sys", "urllib", "pathlib"}
        for line in _source().splitlines():
            m = re.match(r"(?:from|import)\s+([A-Za-z_][\w.]*)", line)
            if m:
                self.assertIn(m.group(1).split(".")[0], stdlib, line)
        self.assertNotIn("mcp_lint", _source())


class RunCasesTests(unittest.TestCase):
    """Per-task isolation with fake benchmark functions. No AgentDojo needed."""

    def _info(self):
        return {"s1": {"user_tasks": ["u0", "u1", "u2"], "injection_tasks": ["i0", "i1"]}}

    def _fakes(self, fail_clean=None, fail_attacked=None):
        calls = {"clean": [], "attacked": []}

        def clean_fn(suite, uids):
            calls["clean"].append(uids[0])
            if uids[0] == fail_clean:
                raise RuntimeError("boom " * 80)
            return {"utility_results": {(uids[0], ""): True}, "security_results": {}}

        def attacked_fn(suite, attack, uids, iids):
            calls["attacked"].append((uids[0], iids[0]))
            if (uids[0], iids[0]) == fail_attacked:
                raise ValueError("bad output")
            return {"utility_results": {}, "security_results": {(uids[0], iids[0]): False}}

        return calls, clean_fn, attacked_fn

    def test_one_failing_clean_task_logs_one_entry_and_later_tasks_run(self):
        import tempfile
        import json as _json

        p = run.plan(self._info())
        calls, clean_fn, attacked_fn = self._fakes(fail_clean="u1")
        with tempfile.TemporaryDirectory() as tmp:
            totals = run.run_cases(p, {"s1": None}, "important_instructions", tmp, clean_fn, attacked_fn,
                                   lambda n, s: None, emit=lambda *_: None)
            with open(os.path.join(tmp, "errors.jsonl"), encoding="utf-8") as f:
                entries = [_json.loads(line) for line in f]
        self.assertEqual(calls["clean"], ["u0", "u1", "u2"])  # u2 still ran after u1 failed
        self.assertEqual(len(calls["attacked"]), 6)  # every attacked pair still ran
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["suite"], "s1")
        self.assertEqual(entries[0]["user_task_id"], "u1")
        self.assertIsNone(entries[0]["injection_task_id"])
        self.assertTrue(entries[0]["error"].startswith("RuntimeError: boom"))
        self.assertLessEqual(len(entries[0]["error"]), len("RuntimeError: ") + 300)
        self.assertEqual(totals["s1"]["clean"], 2)
        self.assertEqual(totals["s1"]["clean_errors"], 1)
        self.assertEqual(totals["s1"]["attacked"], 6)

    def test_failing_attacked_pair_is_logged_with_both_ids(self):
        import tempfile
        import json as _json

        p = run.plan(self._info())
        calls, clean_fn, attacked_fn = self._fakes(fail_attacked=("u2", "i1"))
        with tempfile.TemporaryDirectory() as tmp:
            run.run_cases(p, {"s1": None}, "important_instructions", tmp, clean_fn, attacked_fn,
                          lambda n, s: None, emit=lambda *_: None)
            with open(os.path.join(tmp, "errors.jsonl"), encoding="utf-8") as f:
                entries = [_json.loads(line) for line in f]
        self.assertEqual(len(entries), 1)
        self.assertEqual((entries[0]["user_task_id"], entries[0]["injection_task_id"]), ("u2", "i1"))
        self.assertIn("ValueError: bad output", entries[0]["error"])
        self.assertEqual(len(calls["attacked"]), 6)

    def test_keyboard_interrupt_stops_the_run(self):
        import tempfile

        p = run.plan(self._info())

        def clean_fn(suite, uids):
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(KeyboardInterrupt):
                run.run_cases(p, {"s1": None}, "important_instructions", tmp, clean_fn,
                              lambda *a: None, lambda n, s: None, emit=lambda *_: None)
            self.assertFalse(os.path.exists(os.path.join(tmp, "errors.jsonl")))


class DecideSuiteTests(unittest.TestCase):
    """Pure decision logic for --self-check, with fake results. No AgentDojo needed."""

    IDS = ["a", "b", "c"]

    def test_all_good_passes(self):
        d = run.decide_suite(self.IDS, ["c"], {"a": True, "b": True}, {"a": False, "b": False, "c": False})
        self.assertTrue(d["ok"])
        self.assertEqual(d["checked"], 2)
        self.assertEqual(d["empty"], ["c"])
        self.assertEqual(d["baseline_false"], 3)

    def test_ground_truth_not_true_fails(self):
        d = run.decide_suite(self.IDS, ["c"], {"a": False, "b": True}, {"a": False, "b": False, "c": False})
        self.assertFalse(d["ok"])
        self.assertEqual(d["gt_failed"], ["a"])

    def test_empty_ground_truth_task_is_not_checked_against_truth(self):
        # "c" has no ground-truth result and is empty, so only its baseline matters.
        d = run.decide_suite(self.IDS, ["c"], {"a": True, "b": True}, {"a": False, "b": False, "c": False})
        self.assertTrue(d["ok"])
        self.assertEqual(d["gt_failed"], [])

    def test_baseline_true_on_empty_task_fails_and_is_named(self):
        # The travel-6 case: security True with no action at all.
        d = run.decide_suite(self.IDS, ["c"], {"a": True, "b": True}, {"a": False, "b": False, "c": True})
        self.assertFalse(d["ok"])
        self.assertEqual(d["baseline_not_false"], ["c"])

    def test_baseline_true_on_checkable_task_fails(self):
        d = run.decide_suite(self.IDS, [], {"a": True, "b": True, "c": True}, {"a": True, "b": False, "c": False})
        self.assertFalse(d["ok"])
        self.assertEqual(d["baseline_not_false"], ["a"])

    def test_missing_ground_truth_result_fails_closed(self):
        d = run.decide_suite(self.IDS, ["c"], {"a": True}, {"a": False, "b": False, "c": False})
        self.assertFalse(d["ok"])
        self.assertIn("b", d["missing"])

    def test_missing_baseline_fails_closed(self):
        d = run.decide_suite(self.IDS, ["c"], {"a": True, "b": True}, {"a": False, "b": False})
        self.assertFalse(d["ok"])
        self.assertIn("c", d["missing"])

    def test_non_bool_baseline_is_not_false(self):
        d = run.decide_suite(self.IDS, ["c"], {"a": True, "b": True}, {"a": False, "b": False, "c": None})
        self.assertFalse(d["ok"])

    def test_empty_suite_fails(self):
        d = run.decide_suite([], [], {}, {})
        self.assertFalse(d["ok"])


@unittest.skipUnless(HAVE_AGENTDOJO, "set AGENTDOJO_PYTHON to AgentDojo's python to run these tests")
class AgentDojoProcessTests(unittest.TestCase):
    def _run(self, *args, timeout=900):
        return subprocess.run(
            [AGENTDOJO_PY, "-I", SCRIPT, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=REPO,
        )

    def test_dry_run_totals(self):
        proc = self._run("--model-id", "qwen2.5:7b", "--dry-run", timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("TOTAL attacked=949 clean=97 trials=1046", proc.stdout)
        for suite, row in (("workspace", "560"), ("travel", "140"), ("banking", "144"), ("slack", "105")):
            self.assertRegex(proc.stdout, rf"{suite}\s+\d+\s+\d+\s+\d+\s+{row}")

    def test_bad_model_id_refused(self):
        proc = self._run("--model-id", "bad model;rm", "--dry-run", timeout=300)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refused", proc.stderr)

    def test_bad_port_refused(self):
        proc = self._run("--model-id", "qwen2.5:7b", "--port", "70000", "--dry-run", timeout=300)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refused", proc.stderr)

    def test_model_not_listed_by_server_is_refused(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"object": "list", "data": [{"id": "qwen2.5:7b", "object": "model"}]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            proc = self._run("--model-id", "other:1b", "--port", str(port), timeout=300)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("not listed", proc.stderr)

    def test_self_check_exits_zero_for_all_suites(self):
        proc = self._run("--self-check")
        self.assertIn("workspace:", proc.stdout)
        self.assertIn("banking:", proc.stdout)
        self.assertIn("travel:", proc.stdout)
        self.assertIn("slack:", proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:])
        self.assertEqual(len(re.findall(r"no-action baseline false \d+/\d+ -> PASS", proc.stdout)), 4)
        self.assertIn("SELF-CHECK PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
