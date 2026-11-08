"""Tests for the lethal-trifecta tagger in benchmark/tagging.py and the survey script.

THREAT MODEL
  DEFENDS AGAINST: a server understating a tool through annotations, naming-style
    tricks, or malformed schemas crashing the tagger.
  ATTACKER CONTROLS: tool name, inputSchema, annotations.
  MUST FAIL CLOSED WHEN: the schema declares no properties, annotations contradict
    the name, or the schema is malformed.
  OUT OF SCOPE: homoglyph/Unicode names, descriptive names that hide capability
    (the benchmark measures that separately), descriptions.
"""

import json
import os
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS_DIR)
BENCH = os.path.join(REPO, "benchmark")
if BENCH not in sys.path:
    sys.path.insert(0, BENCH)

from mcp_lint.models import MAX_NESTING, ToolDef, nesting_depth  # noqa: E402
import tag_survey  # noqa: E402
from tagging import (  # noqa: E402
    Evidence,
    Tag,
    minimal_trifecta_sets,
    tag_tool,
    tags_for,
)

PR, UR, EW = Tag.PRIVATE_READ, Tag.UNTRUSTED_READ, Tag.EXTERNAL_WRITE
STR = {"type": "string"}


def tool(name, props=None, annotations=None):
    """A ToolDef; ``props`` None means the schema declares no properties at all."""
    schema = {"type": "object", "properties": props} if props is not None else {}
    return ToolDef(name=name, input_schema=schema, annotations=annotations or {})


def pairs(evidence):
    return {(e.tag, e.confidence) for e in evidence}


def rules(evidence):
    return {e.rule for e in evidence}


class ExternalWriteTests(unittest.TestCase):
    def test_send_email_is_external_write_under_strict(self):
        t = tool("send_email", {"to": STR, "subject": STR, "body": STR},
                 {"readOnlyHint": True, "openWorldHint": False})
        ev = tag_tool(t)
        self.assertIn(EW, tags_for(ev, "strict"))
        self.assertIn((EW, "high"), pairs(ev))

    def test_send_verb_across_name_styles(self):
        for name in ["sendEmail", "send-email", "SEND_EMAIL", "mail_send"]:
            with self.subTest(name=name):
                ev = tag_tool(tool(name, {"body": STR}))
                self.assertIn(EW, tags_for(ev, "strict"))

    def test_malformed_schemas_fail_closed(self):
        schemas = [
            {"properties": [1, 2]},
            {"properties": "nope"},
            {"properties": {"a": {"type": {"x": 1}}}},
            {"properties": {"a": {"type": [{"x": 1}, "string"]}}},
            {"properties": {"a": {"type": []}}},
        ]
        for schema in schemas:
            with self.subTest(schema=schema):
                self.assertIn(EW, tags_for(tag_tool(ToolDef(name="send_x", input_schema=schema)), "strict"))
        self.assertIsInstance(tag_tool(ToolDef(name=5, input_schema={})), list)

    def test_malformed_input_returns_a_list(self):
        deep = {"type": "string"}
        for _ in range(200):
            deep = {"nested": deep}
        self.assertGreater(nesting_depth({"properties": {"a": deep}}), MAX_NESTING)
        cases = [
            ToolDef(name="x", input_schema={"properties": [1, 2]}),
            ToolDef(name="x", input_schema={"properties": {"a": 5}}),
            ToolDef(name="x", input_schema="nope"),
            ToolDef(name="send_x", annotations="nope"),
            ToolDef(name="", input_schema={"properties": {"a": STR}}),
            ToolDef(name="send_deep", input_schema={"properties": {"a": deep}}),
        ]
        for t in cases:
            with self.subTest(name=t.name, schema=repr(t.input_schema)[:60]):
                self.assertIsInstance(tag_tool(t), list)

    def test_send_without_declared_properties_fails_closed(self):
        ev = tag_tool(tool("send_message"))
        self.assertIn(EW, tags_for(ev, "strict"))

    def test_enum_only_send_gets_no_external_write(self):
        t = ToolDef(name="send_status", input_schema={
            "type": "object", "properties": {"mode": {"type": "string", "enum": ["a", "b"]}}})
        ev = tag_tool(t)
        self.assertEqual([e for e in ev if e.tag is EW], [])

    def test_nullable_string_counts_as_data(self):
        t = tool("send_note", {"text": {"type": ["string", "null"]}})
        ev = tag_tool(t)
        self.assertIn((EW, "high"), pairs(ev))
        self.assertIn("E-SEND", rules(ev))

    def test_nested_recipients_give_e_recipient(self):
        t = tool("update_profile", {"options": {
            "type": "object", "properties": {"recipients": {"type": "array"}}}})
        ev = tag_tool(t)
        self.assertIn("E-RECIPIENT", rules(ev))
        self.assertIn((EW, "high"), pairs(ev))

    def test_unconstrained_url_fetch(self):
        ev = tag_tool(tool("fetch", {"url": STR}))
        self.assertIn((UR, "high"), pairs(ev))
        self.assertIn((EW, "medium"), pairs(ev))
        self.assertNotIn(EW, tags_for(ev, "strict"))
        self.assertIn(UR, tags_for(ev, "strict"))

    def test_constrained_url_gets_no_url_rules(self):
        ev = tag_tool(tool("fetch", {"url": {"type": "string", "enum": ["https://example.com"]}}))
        self.assertFalse(rules(ev) & {"U-URL-READ", "E-URL-EGRESS"})


class BenignNearMissTests(unittest.TestCase):
    def test_create_relations_nested_from_to(self):
        t = tool("create_relations", {"relations": {"type": "array", "items": {
            "type": "object",
            "properties": {"from": STR, "to": STR, "relationType": STR}}}})
        self.assertNotIn(EW, tags_for(tag_tool(t), "inclusive"))

    def test_top_level_move_from_to_has_no_recipient(self):
        ev = tag_tool(tool("move", {"from": STR, "to": STR, "content": STR}))
        self.assertNotIn("E-RECIPIENT", rules(ev))

    def test_no_param_feedback_tool_with_open_world_hint(self):
        t = ToolDef(name="give_feedback_to_x",
                    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                    annotations={"openWorldHint": True})
        self.assertNotIn(EW, tags_for(tag_tool(t), "inclusive"))

    def test_get_current_time_has_no_evidence(self):
        self.assertEqual(tag_tool(tool("get_current_time", {"timezone": STR})), [])

    def test_write_file_and_git_commit_are_not_external_write(self):
        for t in [tool("write_file", {"path": STR, "content": STR}),
                  tool("git_commit", {"repo_path": STR, "message": STR})]:
            with self.subTest(name=t.name):
                self.assertNotIn(EW, tags_for(tag_tool(t), "inclusive"))

    def test_api_post_search_is_treated_as_search(self):
        ev = tag_tool(tool("API-post-search", {"query": STR}))
        self.assertNotIn("E-SEND", rules(ev))
        self.assertIn("U-SEARCH", rules(ev))

    def test_api_get_user_is_private_read_medium(self):
        ev = tag_tool(tool("API-get-user", {"user_id": STR}))
        self.assertIn((PR, "medium"), pairs(ev))

    def test_email_search_has_no_e_send(self):
        ev = tag_tool(tool("email_search", {"query": STR}))
        self.assertNotIn("E-SEND", rules(ev))

    def test_git_status_is_private_read_medium(self):
        ev = tag_tool(tool("git_status", {"repo_path": STR}))
        self.assertIn((PR, "medium"), pairs(ev))

    def test_git_show_is_private_read_high(self):
        ev = tag_tool(tool("git_show", {"repo_path": STR, "revision": STR}))
        self.assertIn((PR, "high"), pairs(ev))


class PositiveCoverageTests(unittest.TestCase):
    def test_start_process_runs_code(self):
        ev = tag_tool(tool("start_process", {"command": STR}))
        self.assertIn((EW, "high"), pairs(ev))
        self.assertIn((PR, "medium"), pairs(ev))
        self.assertIn((UR, "medium"), pairs(ev))

    def test_get_file_contents_on_forge(self):
        ev = tag_tool(tool("get_file_contents", {"owner": STR, "repo": STR, "path": STR}))
        self.assertIn((PR, "high"), pairs(ev))
        self.assertIn((UR, "medium"), pairs(ev))

    def test_get_issue_is_untrusted_high(self):
        ev = tag_tool(tool("get_issue", {"owner": STR, "repo": STR,
                                         "issue_number": {"type": "integer"}}))
        self.assertIn((UR, "high"), pairs(ev))


class AnnotationHintTests(unittest.TestCase):
    def test_hints_only_add_evidence(self):
        base = tool("search_x", {"query": STR})
        hinted = tool("search_x", {"query": STR}, {"readOnlyHint": True, "openWorldHint": True})
        base_ev = tag_tool(base)
        hinted_ev = tag_tool(hinted)
        self.assertTrue(set(base_ev) <= set(hinted_ev))
        self.assertIn("U-OPEN-READ", rules(hinted_ev))
        self.assertIn(UR, tags_for(hinted_ev, "inclusive"))

    def test_open_world_false_keeps_private_read_high(self):
        ev = tag_tool(tool("read_file", {"path": STR}, {"openWorldHint": False}))
        self.assertIn((PR, "high"), pairs(ev))
        self.assertIn(PR, tags_for(ev, "strict"))


class MinimalSetTests(unittest.TestCase):
    def test_single_server_holding_all_three_wins(self):
        servers = {"a": {PR, UR, EW}, "b": {PR}, "c": {UR, EW}, "d": {PR, EW}}
        self.assertEqual(minimal_trifecta_sets(servers), [("a",)])

    def test_two_servers_needed(self):
        servers = {"a": {PR, UR}, "b": {EW}, "c": {PR}}
        self.assertEqual(minimal_trifecta_sets(servers), [("a", "b")])

    def test_three_servers_needed(self):
        servers = {"a": {PR}, "b": {UR}, "c": {EW}}
        self.assertEqual(minimal_trifecta_sets(servers), [("a", "b", "c")])

    def test_no_cover_returns_empty(self):
        self.assertEqual(minimal_trifecta_sets({"a": {PR, UR}, "b": {PR}}), [])
        self.assertEqual(minimal_trifecta_sets({}), [])

    def test_multiple_minimal_sets_are_all_returned_sorted(self):
        servers = {"a": {PR}, "b": {UR}, "c": {EW}, "d": {UR}, "e": {PR}}
        self.assertEqual(minimal_trifecta_sets(servers), [
            ("a", "b", "c"), ("a", "c", "d"), ("b", "c", "e"), ("c", "d", "e")])

    def test_empty_tag_servers_are_ignored(self):
        self.assertEqual(minimal_trifecta_sets({"a": set(), "b": {PR, UR, EW}}), [("b",)])
        self.assertEqual(minimal_trifecta_sets({"a": set(), "b": {PR}, "c": {UR, EW}}),
                         [("b", "c")])

    def test_input_order_does_not_change_result(self):
        servers = {"a": {PR}, "b": {UR}, "c": {EW}, "d": {UR}, "e": {PR}}
        reordered = dict(reversed(list(servers.items())))
        self.assertEqual(minimal_trifecta_sets(servers), minimal_trifecta_sets(reordered))


class ProfileTests(unittest.TestCase):
    def test_strict_drops_medium_and_inclusive_keeps_it(self):
        ev = [Evidence(PR, "high", "P-X", "d"), Evidence(UR, "medium", "U-X", "d")]
        self.assertEqual(tags_for(ev, "strict"), frozenset({PR}))
        self.assertEqual(tags_for(ev, "inclusive"), frozenset({PR, UR}))
        self.assertEqual(tags_for(ev), frozenset({PR, UR}))

    def test_unknown_profile_raises(self):
        with self.assertRaises(KeyError):
            tags_for([], "loose")


class SurveyTests(unittest.TestCase):
    TOOLS_DIR = os.path.join(REPO, "survey", "tools")

    def test_survey_sees_18_servers_and_230_tools(self):
        report = tag_survey.build_report(self.TOOLS_DIR, tag_survey.REVIEW_PATH)
        self.assertEqual(len(report["servers"]), 18)
        self.assertEqual(sum(s["tools"] for s in report["servers"].values()), 230)

    def test_recomputed_report_matches_committed_json(self):
        report = json.loads(json.dumps(
            tag_survey.build_report(self.TOOLS_DIR, tag_survey.REVIEW_PATH)))
        with open(tag_survey.JSON_PATH, encoding="utf-8") as f:
            committed = json.load(f)
        self.assertEqual(report, committed)

    def _review_with(self, fps=(), fns=()):
        review = {
            "apparent_false_positives": list(fps),
            "apparent_false_negatives": list(fns),
        }
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "review.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(review, f)
        return path

    def test_false_positive_on_unassigned_tag_raises(self):
        path = self._review_with(fps=[{"server": "git", "tool": "git_status",
                                       "tag": "EXTERNAL_WRITE", "reason": "test"}])
        with self.assertRaisesRegex(ValueError, "git_status"):
            tag_survey.build_report(self.TOOLS_DIR, path)

    def test_false_negative_on_assigned_tag_raises(self):
        path = self._review_with(fns=[{"server": "git", "tool": "git_show",
                                       "tag": "PRIVATE_READ", "reason": "test"}])
        with self.assertRaisesRegex(ValueError, "git_show"):
            tag_survey.build_report(self.TOOLS_DIR, path)


class SchemaEvasionTests(unittest.TestCase):
    def test_undeclared_or_badly_limited_text_still_carries_data(self):
        schemas = [
            {"properties": {}},
            {"properties": {}, "additionalProperties": True},
            {"properties": {}, "patternProperties": {".*": STR}},
            {"properties": {"n": {"type": "integer"}}, "additionalProperties": STR},
            {"properties": {"body": {"enum": "x"}}},
            {"properties": {"body": {"enum": []}}},
            {"properties": {"body": {"pattern": 5}}},
            {"properties": {"body": {"pattern": ".*"}}},
            {"properties": {"body": {"pattern": "^.+$"}}},
        ]
        for schema in schemas:
            with self.subTest(schema=schema):
                ev = tag_tool(ToolDef(name="send_email", input_schema=schema))
                self.assertIn(EW, tags_for(ev, "strict"))

    def test_real_limits_still_block_data(self):
        for schema in [
            {"properties": {"mode": {"type": "string", "enum": ["a", "b"]}}},
            {"properties": {"mode": {"const": "a"}}},
            {"properties": {"code": {"type": "string", "pattern": "^[a-z]{2}$"}}, "additionalProperties": False},
        ]:
            with self.subTest(schema=schema):
                ev = [e for e in tag_tool(ToolDef(name="send_status", input_schema=schema)) if e.rule == "E-SEND"]
                self.assertEqual(ev, [])

    def test_url_limit_must_be_anchored(self):
        ev = tag_tool(tool("fetch", {"url": {"type": "string", "pattern": "^https?://"}}))
        self.assertIn("E-URL-EGRESS", rules(ev))
        ev = tag_tool(tool("fetch", {"url": {"type": "string", "pattern": "^https://docs[.]example[.]com/[a-z]+$"}}))
        self.assertFalse(rules(ev) & {"U-URL-READ", "E-URL-EGRESS"})

    def test_constrained_url_cannot_shadow_an_open_one(self):
        ev = tag_tool(tool("fetch", {"URL": {"enum": ["a"]}, "url": STR}))
        self.assertIn("E-URL-EGRESS", rules(ev))

    def test_too_deep_schema_gets_all_three_tags(self):
        deep = {"properties": {"command": STR}}
        for _ in range(40):
            deep = {"type": "object", "properties": {"a": deep}}
        ev = tag_tool(ToolDef(name="do_thing", input_schema=deep))
        self.assertEqual({t.value for t in tags_for(ev, "inclusive")},
                         {"PRIVATE_READ", "UNTRUSTED_READ", "EXTERNAL_WRITE"})

    def test_non_object_schema_gets_all_three_tags(self):
        for schema in ["nope", {"properties": [1, 2]}]:
            with self.subTest(schema=schema):
                ev = tag_tool(ToolDef(name="do_thing", input_schema=schema))
                self.assertEqual({t.value for t in tags_for(ev, "inclusive")},
                                 {"PRIVATE_READ", "UNTRUSTED_READ", "EXTERNAL_WRITE"})
                self.assertEqual(tags_for(ev, "strict"), frozenset())


class DesignToolSetTests(unittest.TestCase):
    """The Flagged column of DESIGN.md section 4, groups A to D."""

    @staticmethod
    def _flagged(tools, profile):
        held = set()
        for t in tools:
            held |= {x.value for x in tags_for(tag_tool(t), profile)}
        return held == {"PRIVATE_READ", "UNTRUSTED_READ", "EXTERNAL_WRITE"}

    def test_flagged_column(self):
        num = {"type": "integer"}
        record = tool("read_customer_record", {"customer_id": STR})
        ticket = tool("get_ticket", {"ticket_id": num})
        mail = tool("send_email", {"to": STR, "subject": STR, "body": STR})
        issue = tool("get_issue", {"owner": STR, "repo": STR, "issue_number": num})
        cases = {
            "A-helpdesk": ([record, ticket, mail], True, True),
            "A-forge": ([tool("get_file_contents", {"owner": STR, "repo": STR, "path": STR}), issue,
                         tool("add_issue_comment", {"owner": STR, "repo": STR, "issue_number": num, "body": STR})],
                        True, True),
            "B-no-private": ([ticket, mail], False, False),
            "B-no-untrusted": ([record, mail], False, False),
            "B-no-write": ([record, ticket], False, False),
            "C-send": ([record, ticket, tool("sync_notes", {"remote_note": STR})], False, False),
            "C-untrusted": ([record, tool("load_item", {"item_id": STR}), mail], False, False),
            "C-private": ([tool("lookup", {"key": STR}), ticket, mail], False, False),
            "C-two": ([record, tool("digest_queue", {"limit": num}), tool("stash_summary", {"text": STR})],
                      False, False),
            "D-mail": ([record, ticket, mail], True, True),
            "D-fetch": ([tool("read_file", {"path": STR}), tool("fetch_url", {"url": STR})], False, True),
            "D-issue": ([record, ticket,
                         tool("create_issue", {"owner": STR, "repo": STR, "title": STR, "body": STR})], True, True),
            "D-channel": ([record, ticket, tool("post_message", {"channel": STR, "text": STR})], True, True),
        }
        for name, (tools, strict, inclusive) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self._flagged(tools, "strict"), strict)
                self.assertEqual(self._flagged(tools, "inclusive"), inclusive)


if __name__ == "__main__":
    unittest.main()
