import unittest

from mcp_lint.fixtures import error_probes
from mcp_lint.models import Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.rules.probe import error_issues, p4_error_quality

RO = {"readOnlyHint": True}


def tool(name="t", required=(), annotations=RO, **props):
    return ToolDef(name=name, input_schema={"type": "object", "properties": props, "required": list(required)},
                   annotations=annotations)


def err(text, status="tool_error", target="path", args=None, may_succeed=False, tool="t", label="x"):
    return ProbeResult(tool=tool, label=label, args=args or {}, expect_error=True, status=status,
                       reason=text if status == "protocol_error" else None,
                       text="" if status == "protocol_error" else text,
                       target=target, may_succeed=may_succeed)


class ErrorProbeGenerationTests(unittest.TestCase):
    def test_generates_each_kind(self):
        t = tool(required=["path", "mode"], path={"type": "string"},
                 mode={"type": "string", "enum": ["a", "b"]}, depth={"type": "integer"})
        probes = {p.label: p for p in error_probes([t])}
        self.assertEqual(set(probes), {"auto: missing path", "auto: path wrong type",
                                       "auto: mode invalid value", "auto: unknown path"})
        self.assertNotIn("path", probes["auto: missing path"].args)
        self.assertEqual(probes["auto: missing path"].args["mode"], "a")  # placeholder for the rest
        self.assertEqual(probes["auto: path wrong type"].args["path"], 12345)
        self.assertEqual(probes["auto: unknown path"].args["path"], "/mcp-lint/does/not/exist.txt")
        self.assertTrue(probes["auto: unknown path"].may_succeed)
        self.assertFalse(probes["auto: missing path"].may_succeed)
        for p in probes.values():
            self.assertTrue(p.expect_error and p.auto)

    def test_unknown_url_uses_reserved_domain(self):
        [*_, unknown] = error_probes([tool(required=["url"], url={"type": "string"})])
        self.assertIn(".invalid/", unknown.args["url"])

    def test_skips_tools_that_are_not_read_only(self):
        self.assertEqual(error_probes([tool(required=["p"], annotations={}, p={"type": "string"})]), [])
        additive = {"readOnlyHint": False, "destructiveHint": False}
        self.assertEqual(error_probes([tool(required=["p"], annotations=additive, p={"type": "string"})]), [])

    def test_skips_tools_without_params(self):
        self.assertEqual(error_probes([tool()]), [])

    def test_optional_only_tool_gets_wrong_type_only(self):
        [p] = error_probes([tool(limit={"type": "integer"})])
        self.assertEqual(p.label, "auto: limit wrong type")


class ErrorIssueTests(unittest.TestCase):
    def test_good_messages_pass(self):
        for text in (
            "Input validation error: path: Invalid input: expected string, received number",
            "Invalid timezone: 'No time zone found with key Mars/Base'",
            "Access denied - path outside allowed directories: /x not in /sandbox",
        ):
            self.assertEqual(error_issues(err(text)), [], text)

    def test_stack_trace(self):
        text = 'Traceback (most recent call last):\n  File "s.py", line 3, in f\nKeyError: path'
        self.assertIn("stack_trace", error_issues(err(text)))
        js = "TypeError: x is undefined\n    at readFile (/srv/index.js:12:5)"
        self.assertIn("stack_trace", error_issues(err(js)))

    def test_opaque(self):
        for text in ("Error executing tool search_contacts", "Internal error", "Error: 500",
                     "An unexpected error occurred.", "failed"):
            self.assertEqual(error_issues(err(text)), ["opaque"], text)

    def test_opaque_protocol_error_strips_client_type_name(self):
        self.assertEqual(error_issues(err("McpError: Internal error", status="protocol_error")), ["opaque"])

    def test_empty(self):
        self.assertEqual(error_issues(err("")), ["empty"])

    def test_no_guidance(self):
        self.assertEqual(error_issues(err("Operation could not be completed", target="query")), ["no_guidance"])

    def test_naming_the_input_counts_as_guidance(self):
        self.assertEqual(error_issues(err("bad query", target="query")), [])
        self.assertEqual(error_issues(err("nope: /tmp/x.txt", target=None, args={"p": "/tmp/x.txt"})), [])

    def test_accepted_invalid_args(self):
        self.assertEqual(error_issues(err("results", status="ok")), ["accepted"])

    def test_unknown_value_may_succeed(self):
        self.assertEqual(error_issues(err("no matches", status="ok", may_succeed=True)), [])


class P4Tests(unittest.TestCase):
    def test_groups_by_tool_and_kind(self):
        results = [
            err("Error executing tool t", label="a"),
            err("Error executing tool t", label="b"),
            err("expected string, received number", label="c"),
        ]
        [f] = p4_error_quality({}, results)
        self.assertEqual((f.rule, f.severity, f.tool), ("P4", Severity.WARNING, "t"))
        self.assertTrue(f.message.startswith("2 of 3 error probes said only that the call failed"))
        self.assertIn("ToolError", f.hint)

    def test_ignores_probes_not_expecting_errors_or_not_run(self):
        normal = ProbeResult(tool="t", label="", args={}, expect_error=False, status="tool_error",
                             text="Internal error")
        blocked = err("Internal error", status="blocked")
        self.assertEqual(p4_error_quality({}, [normal, blocked]), [])

    def test_severities(self):
        by_tool = {f.tool: f for f in p4_error_quality({}, [
            err("", tool="empty"), err("Operation could not be completed", target="q", tool="vague"),
            err("ok", status="ok", tool="accepts")])}
        self.assertEqual(by_tool["empty"].severity, Severity.WARNING)
        self.assertIn("empty error", by_tool["empty"].message)
        self.assertEqual(by_tool["vague"].severity, Severity.INFO)
        self.assertEqual(by_tool["accepts"].severity, Severity.INFO)
        self.assertIn("accepted invalid arguments", by_tool["accepts"].message)


if __name__ == "__main__":
    unittest.main()
