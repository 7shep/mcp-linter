import json
import tempfile
import unittest
from pathlib import Path

from mcp_lint.eval import (
    Completed,
    claude_command,
    load_results,
    mcp_config,
    paired_diff,
    parse_stream,
    report_tables,
    run_eval,
    summarize,
)
from mcp_lint.evaltasks import Task, check_answer, extract_answer, generate, make_tasks

PATHS = {"SANDBOX": "/sb", "SANDBOX_URI": "file:///sb", "REPO": "/repo", "BASE": "/base"}


def stream(result_text="ANSWER: 42", *, is_error=False, subtype="success", turns=3,
           tool_result="some output"):
    events = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "mcp__srv__read", "input": {"path": "x"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": tool_result}]}]}},
        {"type": "result", "subtype": subtype, "is_error": is_error, "num_turns": turns,
         "duration_ms": 1234, "result": result_text, "total_cost_usd": 0.0123,
         "usage": {"input_tokens": 10, "cache_creation_input_tokens": 1000,
                   "cache_read_input_tokens": 5000, "output_tokens": 50},
         "modelUsage": {"claude-haiku-x": {}}},
    ]
    return "\n".join(json.dumps(e) for e in events) + "\n"


class ParseStreamTests(unittest.TestCase):
    def test_reads_result_usage_and_tool_calls(self):
        p = parse_stream(stream())
        self.assertEqual(p["turns"], 3)
        self.assertEqual(p["total_tokens"], 6060)
        self.assertEqual(p["cost_usd"], 0.0123)
        self.assertEqual(p["models"], ["claude-haiku-x"])
        [call] = p["tool_calls"]
        self.assertEqual((call["tool"], call["result_chars"], call["truncated"]), ("mcp__srv__read", 11, False))

    def test_detects_truncated_tool_output(self):
        p = parse_stream(stream(tool_result="Error: MCP tool response (87000 tokens) exceeds maximum allowed tokens (25000)"))
        self.assertTrue(p["tool_calls"][0]["truncated"])

    def test_plain_json_output_works_too(self):
        one = json.loads(stream().splitlines()[-1])
        self.assertEqual(parse_stream(json.dumps(one))["turns"], 3)

    def test_ignores_noise_and_requires_result(self):
        p = parse_stream("warning: something\n" + stream())
        self.assertEqual(p["turns"], 3)
        with self.assertRaises(ValueError):
            parse_stream("not json\n")


class AnswerTests(unittest.TestCase):
    def task(self, answer, match="exact"):
        return Task(id="t", server="s", split="test", prompt="", answer=answer, match=match)

    def test_extract_last_answer_line(self):
        text = "I think ANSWER: no\nworking...\nANSWER: r-abc123\n"
        self.assertEqual(extract_answer(text), "r-abc123")
        self.assertEqual(extract_answer("**ANSWER:** `Reno`"), "`Reno`")
        self.assertIsNone(extract_answer("no answer here"))
        self.assertIsNone(extract_answer(None))

    def test_exact_normalizes_quotes_case_and_period(self):
        t = self.task("Young Ribbon Candle")
        for got in ["Young Ribbon Candle", "`young ribbon candle`", '"Young Ribbon Candle".', "**Young  Ribbon Candle**"]:
            self.assertTrue(check_answer(t, got), got)
        self.assertFalse(check_answer(t, "Young Ribbon"))
        self.assertFalse(check_answer(t, None))

    def test_int_match(self):
        t = self.task("8000", "int")
        self.assertTrue(check_answer(t, "8,000"))
        self.assertTrue(check_answer(t, "8000 lines"))
        self.assertFalse(check_answer(t, "7999"))
        self.assertFalse(check_answer(t, "between 7999 and 8000"))

    def test_num_match(self):
        t = self.task("961.04", "num")
        self.assertTrue(check_answer(t, "$961.04"))
        self.assertFalse(check_answer(t, "961.4"))

    def test_sha_match_needs_7_char_prefix(self):
        t = self.task("7a9d7b854c4a8dc5bb819755f402a16a4cc1a51a", "sha")
        self.assertTrue(check_answer(t, "7a9d7b8"))
        self.assertTrue(check_answer(t, "`7a9d7b854c4a8dc5bb819755f402a16a4cc1a51a`"))
        self.assertFalse(check_answer(t, "7a9d7b"))
        self.assertFalse(check_answer(t, "7a9d7b9"))


class TaskGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sb = generate()
        shas = {i: f"{i:040x}" for i in range(1, len(cls.sb.commits) + 1)}
        cls.tasks = make_tasks(cls.sb, shas)

    def test_deterministic(self):
        again = generate()
        self.assertEqual(again.log[:5], self.sb.log[:5])
        self.assertEqual(again.commits[-1], self.sb.commits[-1])

    def test_15_tasks_per_server_5_held_out(self):
        for server in ("filesystem", "markitdown", "git"):
            mine = [t for t in self.tasks if t.server == server]
            self.assertEqual(len(mine), 15)
            self.assertEqual(sum(t.split == "test" for t in mine), 5)
        self.assertEqual(len({t.id for t in self.tasks}), 45)

    def test_answers_come_from_the_data(self):
        by_kind = {}
        for t in self.tasks:
            if t.server == "filesystem":
                by_kind.setdefault(t.kind, t)  # first task of each kind
        self.assertEqual(by_kind["log_count"].answer, str(len(self.sb.log)))
        self.assertEqual(by_kind["log_last"].answer, self.sb.log[-1]["req"])
        self.assertEqual(by_kind["sub_count"].answer, "111")  # file_1, file_10-19, file_100-199
        line = int(by_kind["log_line"].prompt.split("on line ")[1].rstrip("?").replace(",", ""))
        self.assertEqual(by_kind["log_line"].answer, self.sb.log[line - 1]["req"])

    def test_render_fills_placeholders(self):
        t = next(t for t in self.tasks if t.server == "git")
        self.assertIn("/repo", t.render(PATHS))
        self.assertNotIn("{", t.render(PATHS))

    def test_committed_tasks_match_generator(self):
        root = Path(__file__).resolve().parents[1] / "eval" / "tasks"
        committed = json.loads((root / "filesystem.json").read_text(encoding="utf-8"))["tasks"]
        fresh = [t for t in self.tasks if t.server == "filesystem"]
        self.assertEqual([(t["id"], t["answer"], t["split"]) for t in committed],
                         [(t.id, t.answer, t.split) for t in fresh])


class ConfigTests(unittest.TestCase):
    def test_baseline_runs_server_via_minimal_env_wrapper(self):
        cfg = mcp_config("filesystem", "baseline", PATHS, python="py")
        srv = cfg["mcpServers"]["srv"]
        self.assertEqual(srv["command"], "py")
        self.assertEqual(srv["args"][:3], ["-m", "mcp_lint.safe_exec", "--"])
        self.assertEqual(srv["args"][-1], "/base")
        self.assertNotIn("env", srv)

    def test_fixed_uses_proxy_with_descriptions(self):
        args = mcp_config("git", "fixed", PATHS, proxy_log="log.jsonl", python="py")["mcpServers"]["srv"]["args"]
        self.assertEqual(args[:3], ["-m", "mcp_lint", "proxy"])
        self.assertIn("--descriptions", args)
        self.assertIn("--log", args)
        self.assertEqual(args[args.index("--") + 1:][-2:], ["--repository", "/repo"])

    def test_ablations_switch_fixes(self):
        def args(cond):
            return mcp_config("git", cond, PATHS, python="py")["mcpServers"]["srv"]["args"]
        self.assertIn("--no-errors", args("paging_only"))
        self.assertNotIn("--descriptions", args("paging_only"))
        self.assertIn("--no-paging", args("descriptions_only"))
        self.assertIn("--descriptions", args("descriptions_only"))
        self.assertNotIn("--no-errors", args("errors_only"))

    def test_claude_command_disables_builtins_and_scopes_tools(self):
        cmd = claude_command("cfg.json", "git", "haiku", 20)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertIn("--strict-mcp-config", cmd)
        allowed = cmd[cmd.index("--allowedTools") + 1].split(",")
        self.assertIn("mcp__srv__git_log", allowed)
        self.assertNotIn("mcp__srv__git_commit", allowed)
        self.assertEqual(cmd[cmd.index("--model") + 1], "haiku")
        self.assertEqual(cmd[cmd.index("--max-turns") + 1], "20")


class FakeRunner:
    """Answers correctly for 'fixed', wrongly for 'baseline'; can hit a limit."""

    def __init__(self, tasks, limit_after=None):
        self.answers = {t.id: t.answer for t in tasks}
        self.calls = 0
        self.limit_after = limit_after

    def __call__(self, cmd, stdin, cwd, timeout):
        self.calls += 1
        if self.limit_after is not None and self.calls > self.limit_after:
            return Completed(1, stream("Claude AI usage limit reached", is_error=True), "", 10)
        cfg = json.loads(Path(cmd[cmd.index("--mcp-config") + 1]).read_text(encoding="utf-8"))
        fixed = "proxy" in cfg["mcpServers"]["srv"]["args"]
        task_id = next(t for t, a in self.answers.items() if t in stdin) if False else None
        answer = self.correct(stdin) if fixed else "wrong"
        return Completed(0, stream(f"done\nANSWER: {answer}", turns=2 if fixed else 6), "", 10)

    def correct(self, stdin):
        for marker, answer in self.answers.items():
            if marker in stdin:
                return answer
        return "?"


def fake_tasks():
    return [Task(id=f"t{i}", server="filesystem", split="test", prompt=f"question marker-t{i}",
                 answer=f"a{i}") for i in range(3)]


class MarkerRunner(FakeRunner):
    def __init__(self, tasks, **kw):
        super().__init__(tasks, **kw)
        self.answers = {f"marker-{t.id}": t.answer for t in tasks}


class RunEvalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.results = self.base / "results.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def run_eval(self, runner, tasks, runs=2):
        return run_eval(tasks, ["baseline", "fixed"], runs, self.results, base=self.base,
                        runner=runner, log=lambda _: None)

    def test_records_one_line_per_run(self):
        tasks = fake_tasks()
        stats = self.run_eval(MarkerRunner(tasks), tasks)
        rows = load_results(self.results)
        self.assertEqual((stats["ran"], len(rows)), (12, 12))
        fixed = [r for r in rows if r["condition"] == "fixed"]
        self.assertTrue(all(r["success"] for r in fixed))
        self.assertFalse(any(r["success"] for r in rows if r["condition"] == "baseline"))
        self.assertEqual(fixed[0]["total_tokens"], 6060)
        for key in ("task", "condition", "model", "success", "answer", "turns", "cost_usd", "duration_ms", "error"):
            self.assertIn(key, fixed[0])

    def test_resumes_without_repeating_runs(self):
        tasks = fake_tasks()
        self.run_eval(MarkerRunner(tasks), tasks, runs=1)
        runner = MarkerRunner(tasks)
        stats = self.run_eval(runner, tasks, runs=2)
        self.assertEqual((runner.calls, stats["skipped"]), (6, 6))
        self.assertEqual(len(load_results(self.results)), 12)

    def test_stops_at_usage_limit_and_retries_it_later(self):
        tasks = fake_tasks()
        stats = self.run_eval(MarkerRunner(tasks, limit_after=2), tasks, runs=1)
        self.assertEqual((stats["ran"], stats["limit"]), (3, 1))
        rows = load_results(self.results)
        self.assertTrue(rows[-1]["limit_hit"])
        runner = MarkerRunner(tasks)
        self.run_eval(runner, tasks, runs=1)
        self.assertEqual(runner.calls, 4)  # the limit-hit run is retried

    def test_survives_a_half_written_line(self):
        self.results.write_text('{"task": "t0", "condition": "fixed", "model": "haiku", "run": 1}\n{"tru',
                                encoding="utf-8")
        self.assertEqual(len(load_results(self.results)), 1)


class AggregationTests(unittest.TestCase):
    def rows(self):
        out = []
        for task in ("a", "b"):
            for run in (1, 2, 3):
                out.append({"task": task, "server": "git", "split": "test", "condition": "baseline",
                            "run": run, "success": run == 1, "total_tokens": 1000 * run, "turns": 4,
                            "cost_usd": 0.01})
                out.append({"task": task, "server": "git", "split": "test", "condition": "fixed",
                            "run": run, "success": True, "total_tokens": 500, "turns": 2,
                            "cost_usd": 0.005})
        return out

    def test_summarize(self):
        s = summarize([r for r in self.rows() if r["condition"] == "baseline"])
        self.assertEqual(s["runs"], 6)
        self.assertAlmostEqual(s["success"], 2 / 6)
        self.assertAlmostEqual(s["tokens_mean"], 2000)
        self.assertEqual(s["tokens_median"], 2000)
        self.assertAlmostEqual(s["cost_total"], 0.06)
        self.assertIsNotNone(s["success_rep_sd"])

    def test_paired_diff(self):
        d = paired_diff(self.rows(), "total_tokens", "baseline", "fixed")
        self.assertEqual(d["tasks"], 2)
        self.assertAlmostEqual(d["mean"], -1500)
        self.assertLessEqual(d["ci_low"], d["mean"])
        s = paired_diff(self.rows(), "success", "baseline", "fixed")
        self.assertAlmostEqual(s["mean"], 2 / 3)

    def test_report_tables_render(self):
        text = report_tables(self.rows())
        self.assertIn("| git | baseline | 6 | 33%", text)
        self.assertIn("| **all** | fixed |", text)
        self.assertIn("Paired per-task differences", text)
        self.assertEqual(report_tables(self.rows(), split="dev"), "No results for split 'dev'.")


if __name__ == "__main__":
    unittest.main()
