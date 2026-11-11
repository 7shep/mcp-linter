"""Tests for the draft v2 trifecta tagger (benchmark/tagging_v2.py) and its reports.

THREAT MODEL
  DEFENDS AGAINST: v2 dropping a v1 tag (so a server that v1 flags looks safer),
    a read tool that carries inbound or private data hiding from the new rules,
    a write or send verb picking up read-side tags, and malformed tool names or
    schemas crashing the tagger.
  ATTACKER CONTROLS: tool name, inputSchema, annotations.
  MUST FAIL CLOSED WHEN: a read tool's name says it reads inbound or private data
    and no local path parameter rules that out.
  OUT OF SCOPE: descriptions, whether v2's rules are right on every real server
    (the survey and AgentDojo numbers are reported, not asserted here), and the
    holdout split (v2 is tuned on AgentDojo, so its numbers are dev-set numbers).
"""

import glob
import json
import os
import subprocess
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS_DIR)
BENCH = os.path.join(REPO, "benchmark")
if BENCH not in sys.path:
    sys.path.insert(0, BENCH)

from mcp_lint.models import ToolDef  # noqa: E402
import tagging  # noqa: E402
import tagging_v2  # noqa: E402
from tagging import ALL_TAGS, Tag, tags_for  # noqa: E402

PR, UR, EW = Tag.PRIVATE_READ, Tag.UNTRUSTED_READ, Tag.EXTERNAL_WRITE
NEW_RULES = frozenset({"U-INBOUND", "U-SHARED-FILE", "P-NOUN-V2", "P-MESSAGE",
                       "P-USER-PROFILE", "P-CLOUD-FILE"})
STR = {"type": "string"}
SURVEY_TOOLS = os.path.join(REPO, "survey", "tools")
AGENTDOJO_TOOLS = os.path.join(BENCH, "results", "agentdojo", "tools")


def tool(name, props=None):
    """A ToolDef with an object schema; ``props`` None means no parameters."""
    schema = {"type": "object", "properties": dict(props or {})}
    return ToolDef.from_dict({"name": name, "inputSchema": schema})


def rules_of(evidence):
    return {e.rule for e in evidence}


def new_rules_of(name, props=None):
    return rules_of(tagging_v2.tag_tool(tool(name, props))) & NEW_RULES


class SupersetTests(unittest.TestCase):
    def _check_directory(self, directory):
        paths = sorted(glob.glob(os.path.join(directory, "*.json")))
        self.assertTrue(paths, f"no tool lists in {directory}")
        for path in paths:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for raw in data["tools"]:
                t = ToolDef.from_dict(raw)
                v1 = tagging.tag_tool(t)
                v2 = tagging_v2.tag_tool(t)
                self.assertTrue(set(v1) <= set(v2), f"{path}: {t.name} lost v1 evidence")
                for profile in ("strict", "inclusive"):
                    self.assertTrue(
                        tags_for(v1, profile) <= tags_for(v2, profile),
                        f"{path}: {t.name} lost a {profile} tag",
                    )

    def test_survey_lists_are_superset(self):
        self._check_directory(SURVEY_TOOLS)

    def test_agentdojo_lists_are_superset(self):
        self._check_directory(AGENTDOJO_TOOLS)


class PositiveTests(unittest.TestCase):
    def test_recent_transactions_is_inbound_and_private(self):
        found = rules_of(tagging_v2.tag_tool(tool("get_most_recent_transactions")))
        self.assertIn("U-INBOUND", found)
        self.assertIn("P-NOUN-V2", found)

    def test_calendar_events_are_inbound(self):
        self.assertIn("U-INBOUND", new_rules_of("get_day_calendar_events"))

    def test_channels_are_inbound(self):
        self.assertIn("U-INBOUND", new_rules_of("get_channels"))

    def test_channel_messages_are_private(self):
        self.assertIn("P-MESSAGE", new_rules_of("read_channel_messages"))

    def test_user_information_is_private_profile(self):
        self.assertIn("P-USER-PROFILE", new_rules_of("get_user_information"))

    def test_list_files_without_params_is_shared_and_cloud(self):
        found = new_rules_of("list_files")
        self.assertIn("U-SHARED-FILE", found)
        self.assertIn("P-CLOUD-FILE", found)

    def test_search_files_with_query_is_shared_and_cloud(self):
        found = new_rules_of("search_files", {"query": STR})
        self.assertIn("U-SHARED-FILE", found)
        self.assertIn("P-CLOUD-FILE", found)

    def test_search_files_by_filename_is_shared(self):
        self.assertIn("U-SHARED-FILE", new_rules_of("search_files_by_filename", {"filename": STR}))

    def test_new_rules_carry_their_confidence_and_tag(self):
        ev = {e.rule: e for e in tagging_v2.tag_tool(tool("get_most_recent_transactions"))}
        self.assertEqual(ev["U-INBOUND"].tag, UR)
        self.assertEqual(ev["U-INBOUND"].confidence, tagging_v2.HIGH)
        self.assertEqual(ev["P-NOUN-V2"].tag, PR)
        self.assertEqual(ev["P-NOUN-V2"].confidence, tagging_v2.HIGH)
        cloud = {e.rule: e for e in tagging_v2.tag_tool(tool("list_files"))}
        self.assertEqual(cloud["U-SHARED-FILE"].confidence, tagging_v2.MEDIUM)
        self.assertEqual(cloud["P-CLOUD-FILE"].confidence, tagging_v2.MEDIUM)

    def test_inbound_detail_names_matched_words(self):
        ev = [e for e in tagging_v2.tag_tool(tool("get_most_recent_transactions"))
              if e.rule == "U-INBOUND"]
        self.assertEqual(len(ev), 1)
        self.assertIn("transaction", ev[0].detail)


class NearMissTests(unittest.TestCase):
    def test_read_file_with_path_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("read_file", {"path": STR}), set())

    def test_read_file_with_file_path_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("read_file", {"file_path": STR}), set())

    def test_create_calendar_event_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("create_calendar_event"), set())

    def test_send_channel_message_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("send_channel_message"), set())

    def test_get_current_time_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("get_current_time"), set())

    def test_forge_get_file_contents_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("get_file_contents", {"owner": STR, "repo": STR, "path": STR}),
                         set())

    def test_delete_file_gets_no_new_rules(self):
        self.assertEqual(new_rules_of("delete_file"), set())


class MalformedTests(unittest.TestCase):
    def test_list_schema_does_not_raise(self):
        t = ToolDef.from_dict({"name": "get_channels", "inputSchema": []})
        t.input_schema = [1, 2]
        tagging_v2.tag_tool(t)

    def test_non_string_name_does_not_raise(self):
        t = ToolDef.from_dict({"name": "x", "inputSchema": {"properties": {}}})
        t.name = 7
        tagging_v2.tag_tool(t)
        t.name = None
        tagging_v2.tag_tool(t)

    def test_non_dict_properties_do_not_raise(self):
        t = ToolDef.from_dict({"name": "list_files", "inputSchema": {"properties": []}})
        tagging_v2.tag_tool(t)


class PublicApiTests(unittest.TestCase):
    def test_reexports_match_v1(self):
        self.assertIs(tagging_v2.Tag, tagging.Tag)
        self.assertIs(tagging_v2.ALL_TAGS, tagging.ALL_TAGS)
        self.assertIs(tagging_v2.Evidence, tagging.Evidence)
        self.assertIs(tagging_v2.tags_for, tagging.tags_for)
        self.assertIs(tagging_v2.minimal_trifecta_sets, tagging.minimal_trifecta_sets)
        self.assertEqual(tagging_v2.HIGH, tagging.HIGH)
        self.assertEqual(tagging_v2.MEDIUM, tagging.MEDIUM)
        self.assertEqual(tagging_v2.ALL_TAGS, frozenset({PR, UR, EW}))

    def test_version_is_draft(self):
        self.assertEqual(tagging_v2.VERSION, "v2-draft")


def _run(*args):
    return subprocess.run([sys.executable, *args], cwd=REPO, capture_output=True,
                          text=True, timeout=300)


class CheckScriptTests(unittest.TestCase):
    def test_survey_check_passes(self):
        result = _run(os.path.join(BENCH, "tag_survey.py"), "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_crosscheck_v1_check_passes(self):
        result = _run(os.path.join(BENCH, "agentdojo_crosscheck.py"), "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_crosscheck_v2_check_passes(self):
        result = _run(os.path.join(BENCH, "agentdojo_crosscheck.py"), "--check", "--tagger", "v2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_v2_survey_diff_check_passes(self):
        result = _run(os.path.join(BENCH, "tagging_v2_report.py"), "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
