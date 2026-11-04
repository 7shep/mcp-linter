import unittest

from mcp_lint.models import Finding, Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.score import (
    DEFINITION_BUDGET,
    HALF_LIFE,
    RESPONSE_BUDGET,
    SERVER_HALF_LIFE,
    server_waste,
    grade,
    score_server,
    score_tool,
    to_score,
)

UUID = "3f2b8c1e-9d4a-4e6b-8a1c-0f5e7d2b9c34"


def tool(name="t", desc="Short.", **props):
    return ToolDef(name=name, description=desc, input_schema={"type": "object", "properties": props})


def finding(rule, severity=Severity.WARNING, kind=None, tool="t", param=None):
    return Finding(rule=rule, severity=severity, tool=tool, message="m", kind=kind, param=param)


def probe(tokens, status="ok", text="", tool="t", expect_error=False):
    return ProbeResult(tool=tool, label="", args={}, expect_error=expect_error, status=status,
                       text=text, chars=tokens * 4, tokens=tokens)


class ScaleTests(unittest.TestCase):
    def test_halves_every_half_life(self):
        self.assertEqual(to_score(0), 100)
        self.assertEqual(to_score(HALF_LIFE), 50)
        self.assertEqual(to_score(2 * HALF_LIFE), 25)

    def test_grades(self):
        self.assertEqual([grade(s) for s in (100, 90, 89, 75, 50, 25, 24, 0)],
                         ["A", "A", "B", "B", "C", "D", "F", "F"])


class ToolScoreTests(unittest.TestCase):
    def test_clean_tool_scores_100(self):
        s = score_tool(tool(), [], [])
        self.assertEqual((s.score, s.grade, s.waste, s.costs), (100, "A", 0, []))

    def test_big_response_costs_its_excess_tokens(self):
        s = score_tool(tool(), [], [probe(87_224)])
        self.assertEqual(s.waste, 87_224 - RESPONSE_BUDGET)
        self.assertEqual(s.score, 0)
        self.assertEqual(s.costs[0].note, "87,224-token response")

    def test_weighting_big_response_beats_short_description(self):
        # Alex's rule: weight by tokens/context wasted, not a flat count.
        short_desc = score_tool(tool(), [finding("S1")], [])
        huge = score_tool(tool(), [], [probe(30_000)])
        bad_error = score_tool(tool(), [finding("P4", kind="opaque")], [])
        self.assertGreater(short_desc.score, bad_error.score)
        self.assertGreater(bad_error.score, huge.score)

    def test_definition_overhead(self):
        big = tool(desc="word " * 2000)  # ~2.5k-token definition
        s = score_tool(big, [], [])
        [cost] = s.costs
        self.assertEqual(cost.source, "definition")
        self.assertGreater(cost.tokens, (2_400 - DEFINITION_BUDGET) * 2 - 200)

    def test_fixed_costs_add_up_per_param(self):
        s = score_tool(tool(), [finding("S2", param="id"), finding("S2", param="q")], [])
        self.assertEqual(s.waste, 600)
        self.assertTrue(all("[" in c.note for c in s.costs))

    def test_p4_kinds_cost_differently(self):
        opaque = score_tool(tool(), [finding("P4", kind="opaque")], []).waste
        vague = score_tool(tool(), [finding("P4", Severity.INFO, kind="no_guidance")], []).waste
        self.assertGreater(opaque, vague)

    def test_measured_response_supersedes_s7_guess(self):
        guess = score_tool(tool(), [finding("S7")], [])
        measured_small = score_tool(tool(), [finding("S7")], [probe(500)])
        self.assertEqual(guess.waste, 2_000)
        self.assertEqual(measured_small.waste, 0)

    def test_p1_and_p5_findings_not_double_counted(self):
        s = score_tool(tool(), [finding("P1", Severity.ERROR), finding("P5")], [probe(10_000)])
        self.assertEqual(s.waste, (10_000 - RESPONSE_BUDGET) + 300)  # P1 measured once + P5 fixed

    def test_p2_measures_id_tokens(self):
        text = "\n".join([UUID] * 50)
        s = score_tool(tool(), [finding("P2")], [probe(500, text=text)])
        [cost] = [c for c in s.costs if c.source == "P2"]
        self.assertGreater(cost.tokens, 400)  # nearly all of it is IDs


class ServerScoreTests(unittest.TestCase):
    def test_usage_costs_averaged_definitions_summed(self):
        tools = [tool("good"), tool("bad")]
        s = score_server(tools, [finding("P4", kind="opaque", tool="bad")], None)
        self.assertEqual([t.tool for t in s.tools], ["bad", "good"])
        # 1,500 usage waste averaged over 2 tools, times min(3, 2) tools used.
        self.assertEqual(s.waste, 1_500)
        self.assertEqual(s.score, to_score(1_500, SERVER_HALF_LIFE))
        self.assertFalse(s.probed)
        heavy = [tool(f"t{i}", desc="word " * 1000) for i in range(4)]
        defs = sum(c.tokens for t in score_server(heavy, [], None).tools for c in t.costs)
        self.assertEqual(server_waste(score_server(heavy, [], None).tools), defs)

    def test_one_bad_tool_drags_the_server_down(self):
        # A mean of tool *scores* hid filesystem's 87k-token tool; waste doesn't.
        tools = [tool(f"t{i}") for i in range(14)]
        probes = [probe(87_224, tool="t0")]
        self.assertLess(score_server(tools, [], probes).score, 50)

    def test_requested_size_and_paged_responses_not_charged(self):
        asked = ProbeResult(tool="t", label="", args={"max_length": 999999}, expect_error=False,
                            status="ok", text="x", chars=80_000, tokens=20_000)
        paged = probe(4_000, text="[Reading 1000 lines from start (total: 20000 lines, 19000 remaining)]\n...")
        self.assertEqual(score_tool(tool(), [], [asked]).waste, 0)
        self.assertEqual(score_tool(tool(), [], [paged]).waste, 0)

    def test_error_probes_dont_count_as_responses(self):
        s = score_server([tool()], [], [probe(50_000, status="ok", expect_error=True)])
        self.assertEqual(s.tools[0].waste, 0)
        self.assertTrue(s.probed)

    def test_server_findings_ignored(self):
        f = Finding(rule="S6", severity=Severity.ERROR, tool=None, message="m")
        self.assertEqual(score_server([tool()], [f], None).score, 100)

    def test_empty_server(self):
        self.assertEqual(score_server([], [], None).score, 100)


if __name__ == "__main__":
    unittest.main()
