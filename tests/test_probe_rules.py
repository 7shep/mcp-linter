import unittest

from mcp_lint.models import Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.rules.probe import (
    has_verbosity_control,
    p1_response_size,
    p5_concise_mode,
    run_probe_rules,
)


def tool(name="read", **props):
    return ToolDef(name=name, input_schema={"type": "object", "properties": props})


def result(tokens, tool="read", status="ok", label=""):
    return ProbeResult(tool=tool, label=label, args={}, expect_error=False,
                       status=status, chars=tokens * 4, tokens=tokens, latency_ms=1)


TOOLS = {"read": tool()}


class P1Tests(unittest.TestCase):
    def test_small_response_passes(self):
        self.assertEqual(p1_response_size(TOOLS, [result(5_000)]), [])

    def test_warning_over_5k(self):
        [f] = p1_response_size(TOOLS, [result(5_001, label="big")])
        self.assertEqual((f.rule, f.severity, f.tool), ("P1", Severity.WARNING, "read"))
        self.assertIn("read (big)", f.message)
        self.assertIn("estimated", f.message)

    def test_error_over_25k(self):
        [f] = p1_response_size(TOOLS, [result(87_224)])
        self.assertEqual(f.severity, Severity.ERROR)
        self.assertIn("87,224", f.message)

    def test_huge_error_responses_count_too(self):
        self.assertEqual(len(p1_response_size(TOOLS, [result(30_000, status="tool_error")])), 1)

    def test_probes_that_did_not_run_ignored(self):
        for status in ("skipped", "blocked", "protocol_error"):
            self.assertEqual(p1_response_size(TOOLS, [result(99_999, status=status)]), [])


class VerbosityControlTests(unittest.TestCase):
    def test_param_names(self):
        for name in ("response_format", "responseFormat", "verbosity", "fields", "detail_level"):
            self.assertTrue(has_verbosity_control(tool(**{name: {"type": "string"}})), name)

    def test_enum_values(self):
        t = tool(mode={"type": "string", "enum": ["Concise", "Detailed"]})
        self.assertTrue(has_verbosity_control(t))

    def test_paging_is_not_verbosity(self):
        t = tool(path={"type": "string"}, head={"type": "integer"}, limit={"type": "integer"})
        self.assertFalse(has_verbosity_control(t))


class P5Tests(unittest.TestCase):
    def test_small_responses_pass(self):
        self.assertEqual(p5_concise_mode(TOOLS, [result(1_000)]), [])

    def test_info_then_warning_by_size(self):
        [info] = p5_concise_mode(TOOLS, [result(1_500)])
        self.assertEqual(info.severity, Severity.INFO)
        [warn] = p5_concise_mode(TOOLS, [result(6_000)])
        self.assertEqual(warn.severity, Severity.WARNING)

    def test_one_finding_per_tool_using_biggest_probe(self):
        [f] = p5_concise_mode(TOOLS, [result(1_500), result(9_000), result(2_000)])
        self.assertIn("9,000", f.message)

    def test_tool_with_response_format_passes(self):
        tools = {"read": tool(response_format={"type": "string", "enum": ["concise", "detailed"]})}
        self.assertEqual(p5_concise_mode(tools, [result(50_000)]), [])

    def test_error_responses_ignored(self):
        self.assertEqual(p5_concise_mode(TOOLS, [result(9_000, status="tool_error")]), [])


class RunProbeRulesTests(unittest.TestCase):
    def test_runs_all_rules(self):
        rules = sorted(f.rule for f in run_probe_rules([tool()], [result(30_000)]))
        self.assertEqual(rules, ["P1", "P3", "P5"])

    def test_no_results_no_findings(self):
        self.assertEqual(run_probe_rules([tool()], []), [])


if __name__ == "__main__":
    unittest.main()
