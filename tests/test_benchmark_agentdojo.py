"""Tests for benchmark/agentdojo_crosscheck.py.

THREAT MODEL
  DEFENDS AGAINST: the cross-check silently counting a path as covered, or
    counting action/text cases as exfil, or copying task text into its outputs.
  ATTACKER CONTROLS: nothing at run time; the inputs are committed exports.
  MUST FAIL CLOSED WHEN: a source is untagged (counted as a miss), a sink list
    is empty (sink leg False), or an attack kind is unknown.
  OUT OF SCOPE: whether the tagger's labels are right (reviewed separately).
"""

import json
import os
import re
import subprocess
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS_DIR)
BENCH = os.path.join(REPO, "benchmark")
AGENTDOJO = os.path.join(BENCH, "results", "agentdojo")
if BENCH not in sys.path:
    sys.path.insert(0, BENCH)

import agentdojo_crosscheck as xc  # noqa: E402

U, P, E = xc.UNTRUSTED, xc.PRIVATE, xc.EXTERNAL
SCRIPT = os.path.join(BENCH, "agentdojo_crosscheck.py")
ID_PATTERN = re.compile(r"^[a-z0-9_]+$")


def _load(name):
    with open(os.path.join(AGENTDOJO, name), encoding="utf-8") as f:
        return json.load(f)


def _kinds_entry(kind, private_sources, sinks):
    return {"kind": kind, "private_sources": private_sources, "sinks": sinks}


class EvaluateCaseTests(unittest.TestCase):
    def test_all_three_legs_cover_the_path(self):
        tags = {"read_mail": {U}, "read_notes": {P}, "send_mail": {E}}
        leg = xc.evaluate_case(["read_mail"], ["send_mail"], ["read_notes"], "exfil", tags)
        self.assertTrue(leg["source_u"])
        self.assertTrue(leg["private_p"])
        self.assertTrue(leg["sink_e"])
        self.assertTrue(leg["path_covered"])

    def test_untagged_source_is_not_covered(self):
        tags = {"read_notes": {P}, "send_mail": {E}}
        leg = xc.evaluate_case(["read_mail"], ["send_mail"], ["read_notes"], "exfil", tags)
        self.assertFalse(leg["source_u"])
        self.assertFalse(leg["path_covered"])

    def test_untagged_source_counts_as_source_miss_in_suite(self):
        summary = xc.summarize_suite(
            {"user_task_0": {"source_tools": ["read_mail"]}},
            {"injection_task_0": {"calls": ["send_mail"]}},
            {"injection_task_0": _kinds_entry("exfil", ["read_notes"], ["send_mail"])},
            {"read_notes": frozenset({P}), "send_mail": frozenset({E})},
        )
        self.assertEqual(summary["fail_source_u"], 1)
        self.assertEqual(summary["path_covered"], 0)
        self.assertEqual(summary["missed_sources"], ["read_mail"])

    def test_empty_private_sources_means_in_context(self):
        tags = {"read_mail": {U}, "send_mail": {E}}
        leg = xc.evaluate_case(["read_mail"], ["send_mail"], [], "exfil", tags)
        self.assertTrue(leg["private_p"])
        self.assertTrue(leg["path_covered"])

    def test_action_case_never_counts_toward_exfil(self):
        tags = {"read_mail": {U}, "read_notes": {P}, "send_mail": {E}}
        leg = xc.evaluate_case(["read_mail"], ["send_mail"], [], "action", tags)
        self.assertFalse(leg["path_covered"])
        self.assertIsNone(leg["private_p"])
        summary = xc.summarize_suite(
            {"user_task_0": {"source_tools": ["read_mail"]}},
            {"injection_task_0": {"calls": ["send_mail"]}},
            {"injection_task_0": _kinds_entry("action", [], ["send_mail"])},
            tags,
        )
        self.assertEqual(summary["exfil_cases"], 0)
        self.assertEqual(summary["path_covered"], 0)
        self.assertEqual(summary["action_cases"], 1)
        self.assertEqual(summary["action_sink_e"], 1)

    def test_empty_sinks_leave_sink_leg_false(self):
        tags = {"read_mail": {U}, "send_mail": {E}}
        leg = xc.evaluate_case(["read_mail"], [], [], "exfil", tags)
        self.assertFalse(leg["sink_e"])
        self.assertFalse(leg["path_covered"])

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            xc.evaluate_case([], [], [], "steal", {})


class SuiteSummaryTests(unittest.TestCase):
    def test_missed_private_and_sink_lists_are_sorted_and_exfil_only(self):
        summary = xc.summarize_suite(
            {"user_task_0": {"source_tools": ["read_mail"]}},
            {"injection_task_0": {"calls": []}, "injection_task_1": {"calls": []}},
            {
                "injection_task_0": _kinds_entry("exfil", ["zeta", "alpha"], ["send_b", "send_a"]),
                "injection_task_1": _kinds_entry("action", ["ignored"], ["send_c"]),
            },
            {"alpha": frozenset({P}), "send_a": frozenset({E})},
        )
        self.assertEqual(summary["missed_private"], ["zeta"])
        self.assertEqual(summary["missed_sinks"], ["send_b"])
        self.assertEqual(summary["security_cases"], 2)

    def test_mismatched_kinds_are_rejected(self):
        with self.assertRaises(ValueError):
            xc.summarize_suite({}, {"injection_task_0": {"calls": []}}, {}, {})


class InputSchemaTests(unittest.TestCase):
    def test_cases_json_has_only_the_documented_keys(self):
        cases = _load("cases.json")
        self.assertEqual(set(cases), {"benchmark_version", "suites"})
        for suite in cases["suites"].values():
            self.assertEqual(set(suite), {"user_tasks", "injection_tasks"})
            for task in suite["user_tasks"].values():
                self.assertEqual(set(task), {"source_tools", "vectors"})
            for task in suite["injection_tasks"].values():
                self.assertEqual(set(task), {"calls"})

    def test_attack_kinds_has_only_the_documented_keys(self):
        kinds = _load("attack_kinds.json")
        self.assertEqual(set(kinds), {"notes", "suites"})
        self.assertIsInstance(kinds["notes"], str)
        for suite in kinds["suites"].values():
            for entry in suite.values():
                self.assertEqual(set(entry), {"kind", "private_sources", "sinks"})
                self.assertIn(entry["kind"], xc.KINDS)
                self.assertIsInstance(entry["private_sources"], list)
                self.assertIsInstance(entry["sinks"], list)

    def test_cases_hold_only_identifiers(self):
        cases = _load("cases.json")
        strings = []
        for suite in cases["suites"].values():
            for task in suite["user_tasks"].values():
                strings += task["source_tools"] + task["vectors"]
            for task in suite["injection_tasks"].values():
                strings += task["calls"]
        self.assertTrue(strings)
        for value in strings:
            self.assertRegex(value, ID_PATTERN)

    def test_attack_kinds_hold_only_identifiers_outside_notes(self):
        kinds = _load("attack_kinds.json")
        for suite in kinds["suites"].values():
            for entry in suite.values():
                for value in entry["private_sources"] + entry["sinks"]:
                    self.assertRegex(value, ID_PATTERN)

    def test_total_security_case_count_is_949(self):
        cases = _load("cases.json")
        total = sum(len(s["user_tasks"]) * len(s["injection_tasks"])
                    for s in cases["suites"].values())
        self.assertEqual(total, 949)


class CommittedOutputTests(unittest.TestCase):
    def test_check_mode_exits_zero(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--check"], cwd=REPO,
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_committed_json_counts_949_cases_per_profile(self):
        with open(os.path.join(AGENTDOJO, "crosscheck.json"), encoding="utf-8") as f:
            report = json.load(f)
        for profile in ("strict", "inclusive"):
            self.assertEqual(report["profiles"][profile]["total"]["security_cases"], 949)

    def test_build_report_is_deterministic(self):
        self.assertEqual(xc.render_markdown(xc.build_report()),
                         xc.render_markdown(xc.build_report()))


if __name__ == "__main__":
    unittest.main()
