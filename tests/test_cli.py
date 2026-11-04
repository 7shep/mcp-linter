import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

from mcp_lint.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "fixtures", "sample_tools.json")
DEMO_SERVER = os.path.join(HERE, "fixtures", "demo_server.py")
DEMO_FIXTURES = os.path.join(HERE, "fixtures", "demo_fixtures.json")


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class CheckCommandTests(unittest.TestCase):
    def test_reports_findings_and_fails_on_error(self):
        code, out = run_cli("check", SAMPLE)
        self.assertEqual(code, 1)  # delete_thing has no description
        self.assertIn("delete_thing", out)
        self.assertIn("S2 [user]", out)
        self.assertIn("1/3 tools clean", out)
        self.assertIn("(server)", out)  # S5: no shared prefix
        self.assertIn("tokens (estimated)", out)

    def test_fail_on_never(self):
        code, _ = run_cli("check", SAMPLE, "--fail-on", "never")
        self.assertEqual(code, 0)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            run_cli("check", SAMPLE, "--json", path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(data["tool_count"], 3)
        self.assertEqual(data["summary"]["error"], 1)
        by_name = {t["name"]: t["findings"] for t in data["tools"]}
        self.assertEqual(by_name["search_contacts"], [])
        self.assertEqual([f["rule"] for f in data["server_findings"]], ["S5"])
        self.assertGreater(data["definition_tokens"]["total"], 0)
        self.assertIn("estimate", data["definition_tokens"]["method"])


class RunCommandTests(unittest.TestCase):
    """End-to-end: start a real MCP server over stdio."""

    def test_lints_live_server(self):
        code, out = run_cli("run", "--fail-on", "warning", "--", sys.executable, DEMO_SERVER)
        self.assertIn("demo-server", out)
        self.assertIn("2 tools checked", out)
        self.assertIn("S2 [id]", out)
        self.assertNotIn("search_contacts\n", out)  # clean tool has no section
        self.assertEqual(code, 1)

    def test_probe_live_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, out = run_cli("run", "--probe", DEMO_FIXTURES, "--json", path,
                                "--", sys.executable, DEMO_SERVER)
            with open(path, encoding="utf-8") as fh:
                probes = {p["label"] or p["tool"]: p for p in json.load(fh)["probes"]}
        self.assertIn("3 ran, 3 blocked, 1 skipped", out)
        self.assertEqual(probes["basic"]["status"], "ok")
        self.assertEqual(probes["empty query"]["status"], "tool_error")
        self.assertEqual(probes["missing query"]["status"], "blocked")
        self.assertEqual(probes["skipped"]["status"], "skipped")
        self.assertIn("allow_destructive", probes["not read-only"]["reason"])
        self.assertEqual(probes["allowed"]["status"], "ok")
        self.assertEqual(probes["no_such_tool"]["status"], "blocked")
        self.assertEqual(code, 0)  # probes don't affect exit code yet; only findings do

    def test_probe_rules_on_live_server(self):
        # `get` echoes its id, so a 120k-char id gives a ~30k-token response.
        with tempfile.TemporaryDirectory() as tmp:
            fixtures = os.path.join(tmp, "big.json")
            with open(fixtures, "w", encoding="utf-8") as fh:
                json.dump({"probes": [{"tool": "get", "label": "huge", "args": {"id": "x" * 120_000},
                                       "allow_destructive": True}]}, fh)
            code, out = run_cli("run", "--probe", fixtures, "--", sys.executable, DEMO_SERVER)
        self.assertIn("x P1 Probe 'get (huge)' returned ~30,000 tokens", out)
        self.assertIn("! P5", out)
        self.assertEqual(code, 1)  # P1 error trips the default --fail-on error

    def test_init_fixtures_from_live_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixtures.json")
            code, out = run_cli("init-fixtures", path, "--", sys.executable, DEMO_SERVER)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            # Refuses to overwrite without --force.
            with contextlib.redirect_stderr(io.StringIO()):
                again, _ = run_cli("init-fixtures", path, "--from", SAMPLE)
        self.assertEqual((code, again), (0, 2))
        self.assertEqual([p["tool"] for p in data["probes"]], ["search_contacts", "get"])
        self.assertIn("1 tools are not marked read-only", out)

    def test_missing_command(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = run_cli("run")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
