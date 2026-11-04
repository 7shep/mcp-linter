import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from mcp_lint.fixtures import FixtureError, Probe, check_probe, load_fixtures, template
from mcp_lint.models import ToolDef
from mcp_lint.probe import capture


def write_tmp(data):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data if isinstance(data, str) else json.dumps(data))
    return path


READ_ONLY = {"readOnlyHint": True}
SEARCH = ToolDef(
    name="search",
    input_schema={
        "type": "object",
        "properties": {"query": {"type": "string"}, "limit": {"type": "integer"},
                       "mode": {"type": "string", "enum": ["fast", "full"]}},
        "required": ["query"],
    },
    annotations=READ_ONLY,
)
WRITE = ToolDef(name="write", input_schema={"type": "object", "properties": {"path": {"type": "string"}}})
TOOLS = {"search": SEARCH, "write": WRITE}


class DestructiveTests(unittest.TestCase):
    def test_defaults_follow_spec(self):
        self.assertTrue(ToolDef("t").destructive)  # no hints: assume it may change data
        self.assertFalse(ToolDef("t", annotations={"readOnlyHint": True}).destructive)
        self.assertFalse(ToolDef("t", annotations={"destructiveHint": False}).destructive)
        self.assertTrue(ToolDef("t", annotations={"readOnlyHint": False}).destructive)


class LoadTests(unittest.TestCase):
    def test_loads_and_expands(self):
        os.environ["MCP_LINT_TEST_VAR"] = "hello"
        path = write_tmp({"version": 1, "probes": [
            {"tool": "search", "args": {"query": "${MCP_LINT_TEST_VAR}", "dirs": ["${FIXTURES_DIR}/x"]},
             "label": "l", "expect_error": True},
        ]})
        try:
            [p] = load_fixtures(path)
        finally:
            os.remove(path)
        self.assertEqual(p.args["query"], "hello")
        folder = os.path.dirname(os.path.abspath(path)).replace("\\", "/")
        self.assertEqual(p.args["dirs"], [folder + "/x"])
        self.assertTrue(p.expect_error)
        self.assertFalse(p.skip)

    def test_unknown_variable_left_alone(self):
        path = write_tmp({"probes": [{"tool": "t", "args": {"a": "${NOPE_NOT_SET_123}"}}]})
        try:
            [p] = load_fixtures(path)
        finally:
            os.remove(path)
        self.assertEqual(p.args["a"], "${NOPE_NOT_SET_123}")

    def test_malformed_files_raise(self):
        for bad in ("not json", {"probes": "x"}, {"probes": [{"args": {}}]},
                    {"probes": [{"tool": "t", "args": []}]}, {"version": 2, "probes": []}):
            path = write_tmp(bad)
            try:
                with self.assertRaises(FixtureError, msg=bad):
                    load_fixtures(path)
            finally:
                os.remove(path)


class CheckProbeTests(unittest.TestCase):
    def test_valid_probe_runs(self):
        self.assertEqual(check_probe(Probe("search", {"query": "a", "limit": 3, "mode": "fast"}), TOOLS), [])

    def test_unknown_tool(self):
        [msg] = check_probe(Probe("nope"), TOOLS)
        self.assertIn("no tool named", msg)

    def test_missing_required_and_wrong_type(self):
        problems = check_probe(Probe("search", {"limit": "3"}), TOOLS)
        self.assertTrue(any("missing required args: query" in p for p in problems))
        self.assertTrue(any("'limit' should be integer" in p for p in problems))

    def test_bool_is_not_integer(self):
        self.assertTrue(check_probe(Probe("search", {"query": "a", "limit": True}), TOOLS))

    def test_destructive_needs_opt_in(self):
        [msg] = check_probe(Probe("write", {"path": "x"}), TOOLS)
        self.assertIn("allow_destructive", msg)
        self.assertEqual(check_probe(Probe("write", {"path": "x"}, allow_destructive=True), TOOLS), [])

    def test_expect_error_skips_arg_checks_but_not_safety(self):
        self.assertEqual(check_probe(Probe("search", {"limit": "bad"}, expect_error=True), TOOLS), [])
        self.assertTrue(check_probe(Probe("write", {}, expect_error=True), TOOLS))


class TemplateTests(unittest.TestCase):
    def test_template_is_skipped_and_stubs_required(self):
        data = template([SEARCH, WRITE])
        s, w = data["probes"]
        self.assertEqual(s["args"], {"query": "TODO"})
        self.assertTrue(s["skip"] and w["skip"])
        self.assertNotIn("_warning", s)
        self.assertIn("_warning", w)

    def test_template_round_trips_through_loader(self):
        path = write_tmp(template([SEARCH]))
        try:
            [p] = load_fixtures(path)
        finally:
            os.remove(path)
        self.assertTrue(p.skip)


class CaptureTests(unittest.TestCase):
    def test_counts_text_and_content_types(self):
        result = SimpleNamespace(
            content=[SimpleNamespace(type="text", text="abcd" * 10), SimpleNamespace(type="image")],
            structured_content=None,
            is_error=False,
        )
        r = capture(Probe("search", {"query": "a"}), result, 12)
        self.assertEqual((r.status, r.chars, r.tokens, r.latency_ms), ("ok", 40, 10, 12))
        self.assertEqual(r.content_types, {"text": 1, "image": 1})

    def test_structured_only_result_is_counted(self):
        result = SimpleNamespace(content=[], structured_content={"a": 1}, is_error=True)
        r = capture(Probe("search"), result, 1)
        self.assertEqual(r.status, "tool_error")
        self.assertGreater(r.chars, 0)


if __name__ == "__main__":
    unittest.main()
