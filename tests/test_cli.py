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


class RunCommandTests(unittest.TestCase):
    """End-to-end: start a real MCP server over stdio."""

    def test_lints_live_server(self):
        code, out = run_cli("run", "--fail-on", "warning", "--", sys.executable, DEMO_SERVER)
        self.assertIn("demo-server", out)
        self.assertIn("2 tools checked", out)
        self.assertIn("S2 [id]", out)
        self.assertNotIn("search_contacts\n", out)  # clean tool has no section
        self.assertEqual(code, 1)

    def test_missing_command(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = run_cli("run")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
