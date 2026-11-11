"""Tests for the pure trifecta guard policy in mcp_lint.guard (G2).

THREAT MODEL
  DEFENDS AGAINST: an untrusted read followed by a sink call in the same session;
    a renamed or re-added sink slipping past after a retag; unknown or malformed
    tools being treated as harmless.
  ATTACKER CONTROLS: tool names, input schemas, and the order of calls.
  MUST FAIL CLOSED WHEN: a name is unknown, a schema is malformed, or an untrusted
    call failed (observe_call does not look at the outcome).
  OUT OF SCOPE: see the module docstring of mcp_lint.guard.
"""

import unittest

from mcp_lint.guard import (
    GUARD_NAME_HINTS,
    GUARD_PARAM_HINTS,
    Decision,
    GuardMode,
    TrifectaGuard,
    Verdict,
    guard_tags,
    unsure_sink,
)
from mcp_lint.models import ToolDef
from mcp_lint.trifecta import ALL_TAGS, Tag, tag_tool

STR = {"type": "string"}
INT = {"type": "integer"}
PRIVATE_VALUE = "C-1042"  # a sample private value; the guard is never given it


def tool(name, props, annotations=None):
    return ToolDef(name=name, input_schema={"type": "object", "properties": props},
                   annotations=annotations or {})


RECORD = tool("read_customer_record", {"customer_id": STR})
TICKET = tool("get_ticket", {"ticket_id": INT})
MAIL = tool("send_email", {"to": STR, "subject": STR, "body": STR})
READ_FILE = tool("read_file", {"path": STR})
WRITE_FILE = tool("write_file", {"path": STR, "content": STR})
FETCH_URL = tool("fetch_url", {"url": STR})
SYNC_NOTES = tool("sync_notes", {"remote_note": STR})
MOVE_FILE = tool("move_file", {"source": STR, "destination": STR})
GIT_COMMIT = tool("git_commit", {"repo_path": STR, "message": STR})
ECHO = tool("echo", {"message": STR})
CATALOG = [RECORD, TICKET, MAIL, READ_FILE, WRITE_FILE, FETCH_URL, SYNC_NOTES,
           MOVE_FILE, GIT_COMMIT, ECHO]


class BlockFlowTests(unittest.TestCase):
    def test_untrusted_read_then_send_email_is_blocked_in_block_mode(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        d = g.check_call("send_email")
        self.assertIsInstance(d, Decision)
        self.assertEqual(d.verdict, Verdict.BLOCK)
        self.assertEqual(d.tool, "send_email")
        msg = d.message
        for required in ("mcp-lint guard", "send_email", "get_ticket", "UNTRUSTED_READ",
                         "EXTERNAL_WRITE", "was not sent", "retry", "route around",
                         "Tell the user", "new session", "--guard warn"):
            with self.subTest(required=required):
                self.assertIn(required, msg)
        self.assertNotIn(PRIVATE_VALUE, msg)
        self.assertTrue(g.tainted)
        self.assertEqual(g.tainted_by, ["get_ticket"])

    def test_send_email_with_no_prior_read_is_allowed(self):
        g = TrifectaGuard("block", CATALOG)
        d = g.check_call("send_email")
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertEqual(d.message, "")

    def test_private_read_alone_does_not_taint_or_block(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("read_customer_record")
        d = g.check_call("send_email")
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertFalse(g.tainted)
        self.assertEqual(g.private_reads, ["read_customer_record"])

    def test_warn_mode_warns_with_prefix_and_sends(self):
        g = TrifectaGuard("warn", CATALOG)
        g.observe_call("get_ticket")
        d = g.check_call("send_email")
        self.assertEqual(d.verdict, Verdict.WARN)
        self.assertTrue(d.message.startswith("[mcp-lint guard: warning]"))
        self.assertIn("send_email", d.message)
        self.assertIn("get_ticket", d.message)
        self.assertIn("was sent", d.message)
        self.assertNotIn(PRIVATE_VALUE, d.message)

    def test_off_mode_allows_everything_and_records_nothing(self):
        g = TrifectaGuard("off", CATALOG)
        g.observe_call("get_ticket")
        g.observe_call("read_customer_record")
        d = g.check_call("send_email")
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertEqual(d.message, "")
        self.assertFalse(g.tainted)
        self.assertEqual(g.tainted_by, [])
        self.assertEqual(g.private_reads, [])

    def test_benign_near_misses_are_never_blocked_in_a_tainted_session(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        for name in ["read_file", "read_customer_record", "write_file", "move_file",
                     "git_commit", "echo"]:
            with self.subTest(name=name):
                self.assertFalse(g.is_sink(name))
                self.assertEqual(g.check_call(name).verdict, Verdict.ALLOW)


class RetagTests(unittest.TestCase):
    def test_taint_survives_retag(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        g.retag(CATALOG)
        self.assertTrue(g.tainted)
        self.assertEqual(g.tainted_by, ["get_ticket"])

    def test_renamed_sink_is_blocked_after_retag(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        renamed = ToolDef(name="dispatch_message",
                          input_schema={"type": "object", "properties": {"to": STR, "body": STR}})
        g.retag([RECORD, TICKET, renamed])
        self.assertFalse(g.knows("send_email"))
        self.assertEqual(g.check_call("dispatch_message").verdict, Verdict.BLOCK)

    def test_sink_added_by_retag_is_blocked(self):
        g = TrifectaGuard("block", [TICKET, READ_FILE])
        self.assertFalse(g.knows("sync_notes"))
        g.observe_call("get_ticket")
        g.retag(CATALOG)
        self.assertTrue(g.knows("sync_notes"))
        self.assertTrue(g.is_sink("sync_notes"))
        self.assertEqual(g.check_call("sync_notes").verdict, Verdict.BLOCK)

    def test_removing_the_untrusted_tool_keeps_taint(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        g.retag([RECORD, MAIL])
        self.assertTrue(g.tainted)
        self.assertEqual(g.tainted_by, ["get_ticket"])
        self.assertEqual(g.check_call("send_email").verdict, Verdict.BLOCK)

    def test_duplicate_names_take_the_union_of_tags(self):
        # A harmless twin under the same name must not hide the sink, in either order.
        sink = ToolDef(name="sync_notes", input_schema={"type": "object", "properties": {"remote_note": STR}})
        harmless = ToolDef(name="sync_notes",
                           input_schema={"type": "object", "properties": {"limit": INT}})
        for tools in ([sink, harmless], [harmless, sink]):
            with self.subTest(order=[next(iter(t.input_schema["properties"])) for t in tools]):
                g = TrifectaGuard("block", tools)
                self.assertTrue(g.is_sink("sync_notes"))
                g.observe_call("get_ticket")  # not in the table: fail closed, taints
                self.assertTrue(g.tainted)
                self.assertEqual(g.check_call("sync_notes").verdict, Verdict.BLOCK)


class CallArgumentTests(unittest.TestCase):
    """The attacker shapes the sink's arguments, and upstreams don't always enforce
    their schema, so a call is tagged as if the schema declared what it sends."""

    NUMERIC_SEND = ToolDef(name="send_email", input_schema={
        "type": "object", "properties": {"n": INT}, "additionalProperties": False})

    def tainted(self, tools):
        g = TrifectaGuard("block", list(tools) + [TICKET])
        g.observe_call("get_ticket")
        return g

    def test_fitting_arguments_keep_a_non_text_tool_allowed(self):
        g = self.tainted([self.NUMERIC_SEND])
        self.assertFalse(g.is_sink("send_email"))
        self.assertEqual(g.check_call("send_email", {"n": 3}).verdict, Verdict.ALLOW)
        self.assertEqual(g.check_call("send_email", {}).verdict, Verdict.ALLOW)
        self.assertEqual(g.check_call("send_email").verdict, Verdict.ALLOW)

    def test_undeclared_text_arguments_make_it_a_sink(self):
        g = self.tainted([self.NUMERIC_SEND])
        decision = g.check_call("send_email", {"to": "x@example.test", "body": "placeholder"})
        self.assertEqual(decision.verdict, Verdict.BLOCK)
        self.assertNotIn("placeholder", decision.message)

    def test_text_in_a_numeric_parameter_makes_it_a_sink(self):
        g = self.tainted([self.NUMERIC_SEND])
        self.assertEqual(g.check_call("send_email", {"n": "placeholder"}).verdict, Verdict.BLOCK)
        self.assertEqual(g.check_call("send_email", {"n": {"a": 1}}).verdict, Verdict.BLOCK)

    def test_value_outside_an_enum_makes_it_a_sink(self):
        tool = ToolDef(name="send_status", input_schema={
            "type": "object", "properties": {"status": {"type": "string", "enum": ["ok", "late"]}}})
        g = self.tainted([tool])
        self.assertEqual(g.check_call("send_status", {"status": "ok"}).verdict, Verdict.ALLOW)
        self.assertEqual(g.check_call("send_status", {"status": "placeholder"}).verdict, Verdict.BLOCK)

    def test_odd_arguments_to_a_reader_stay_allowed(self):
        # The widened schema is still tagged by the tagger: a read verb gains no sink tag.
        g = self.tainted([RECORD])
        self.assertEqual(g.check_call("read_customer_record", {"customer_id": "C-1", "extra": "x"}).verdict,
                         Verdict.ALLOW)

    def test_arguments_that_are_not_an_object_count_as_open(self):
        g = self.tainted([self.NUMERIC_SEND])
        self.assertEqual(g.check_call("send_email", ["placeholder"]).verdict, Verdict.BLOCK)

    def test_duplicate_fits_any_definition(self):
        other = ToolDef(name="send_email", input_schema={
            "type": "object", "properties": {"m": {"type": "boolean"}}, "additionalProperties": False})
        g = self.tainted([self.NUMERIC_SEND, other])
        self.assertEqual(g.check_call("send_email", {"m": True}).verdict, Verdict.ALLOW)
        self.assertEqual(g.check_call("send_email", {"n": 1}).verdict, Verdict.ALLOW)


class MessageCapTests(unittest.TestCase):
    def test_tainted_by_listing_is_capped(self):
        g = TrifectaGuard("block", [MAIL])
        for i in range(40):
            g.observe_call(f"mystery_{i}")
        message = g.check_call("send_email").message
        self.assertIn("mystery_0", message)
        self.assertNotIn("mystery_39", message)
        self.assertIn("and 35 more", message)


class UnknownToolTests(unittest.TestCase):
    def test_unknown_tool_gets_all_tags(self):
        g = TrifectaGuard("block", CATALOG)
        self.assertFalse(g.knows("no_such_tool"))
        self.assertEqual(g.tags("no_such_tool"), ALL_TAGS)
        self.assertTrue(g.is_sink("no_such_tool"))

    def test_unknown_tool_is_blocked_in_a_tainted_session(self):
        g = TrifectaGuard("block", CATALOG)
        self.assertEqual(g.check_call("no_such_tool").verdict, Verdict.ALLOW)
        g.observe_call("get_ticket")
        self.assertEqual(g.check_call("no_such_tool").verdict, Verdict.BLOCK)

    def test_observing_an_unknown_tool_taints_a_fresh_guard(self):
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("mystery_tool")
        self.assertTrue(g.tainted)
        self.assertEqual(g.tainted_by, ["mystery_tool"])


class UnsureSinkTests(unittest.TestCase):
    def test_sync_notes_is_an_unsure_sink(self):
        self.assertTrue(unsure_sink(SYNC_NOTES))
        self.assertIn(Tag.EXTERNAL_WRITE, guard_tags(SYNC_NOTES))

    def test_local_tools_are_not_unsure_sinks(self):
        for t in (MOVE_FILE, GIT_COMMIT, ECHO, WRITE_FILE):
            with self.subTest(name=t.name):
                self.assertFalse(unsure_sink(t))

    def test_sync_tool_with_only_non_text_params_is_not_a_sink(self):
        t = ToolDef(name="sync_status", input_schema={"type": "object", "properties": {
            "limit": INT,
            "dry_run": {"type": "boolean"},
            "mode": {"type": "string", "enum": ["a", "b"]},
        }})
        self.assertFalse(unsure_sink(t))
        self.assertNotIn(Tag.EXTERNAL_WRITE, guard_tags(t))

    def test_name_hint_tool_with_open_string_is_an_unsure_sink(self):
        t = tool("export_report", {"report": STR})
        # Premise: the tagger itself gives no EXTERNAL_WRITE for this tool.
        self.assertNotIn(Tag.EXTERNAL_WRITE, {e.tag for e in tag_tool(t)})
        self.assertTrue(unsure_sink(t))
        self.assertIn(Tag.EXTERNAL_WRITE, guard_tags(t))

    def test_hint_sets_are_exact(self):
        self.assertEqual(GUARD_NAME_HINTS, frozenset(
            "sync remote export submit upload publish share send post notify webhook external "
            "outbound transfer forward deliver dispatch relay broadcast email mail reply invite "
            "tweet".split()))
        self.assertEqual(GUARD_PARAM_HINTS, frozenset("remote external outbound webhook".split()))


class MalformedSchemaTests(unittest.TestCase):
    def test_malformed_schema_is_untrusted_and_sink(self):
        for schema in ["not a dict", {"properties": []}]:
            with self.subTest(schema=schema):
                t = ToolDef(name="read_thing", input_schema=schema)
                self.assertEqual(guard_tags(t), ALL_TAGS)
                g = TrifectaGuard("block", [t])
                self.assertEqual(g.check_call("read_thing").verdict, Verdict.ALLOW)
                g.observe_call("read_thing")
                self.assertTrue(g.tainted)
                self.assertEqual(g.check_call("read_thing").verdict, Verdict.BLOCK)


class FetchUrlTests(unittest.TestCase):
    def test_fetch_url_is_allowed_once_then_blocked_after_it_taints(self):
        g = TrifectaGuard("block", CATALOG)
        self.assertTrue(g.is_sink("fetch_url"))
        self.assertEqual(g.check_call("fetch_url").verdict, Verdict.ALLOW)
        g.observe_call("fetch_url")
        self.assertEqual(g.tainted_by, ["fetch_url"])
        self.assertEqual(g.check_call("fetch_url").verdict, Verdict.BLOCK)


class OutcomeAgnosticTests(unittest.TestCase):
    def test_failed_untrusted_call_still_taints(self):
        # observe_call takes no outcome argument: a call that errored or raised upstream
        # is observed exactly like a successful one, so it still taints.
        g = TrifectaGuard("block", CATALOG)
        g.observe_call("get_ticket")
        self.assertTrue(g.tainted)
        self.assertEqual(g.check_call("send_email").verdict, Verdict.BLOCK)


class ModeTests(unittest.TestCase):
    def test_mode_accepts_strings_and_enum_members(self):
        self.assertIs(TrifectaGuard("off").mode, GuardMode.OFF)
        self.assertIs(TrifectaGuard("warn").mode, GuardMode.WARN)
        self.assertIs(TrifectaGuard("block").mode, GuardMode.BLOCK)
        self.assertIs(TrifectaGuard(GuardMode.BLOCK).mode, GuardMode.BLOCK)

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            TrifectaGuard("bogus")
        with self.assertRaises(ValueError):
            GuardMode("bogus")


class BookkeepingTests(unittest.TestCase):
    def test_tainted_by_and_private_reads_keep_first_seen_order_without_duplicates(self):
        g = TrifectaGuard("block", CATALOG)
        for name in ["get_ticket", "read_customer_record", "get_ticket", "read_customer_record"]:
            g.observe_call(name)
        self.assertEqual(g.tainted_by, ["get_ticket"])
        self.assertEqual(g.private_reads, ["read_customer_record"])


if __name__ == "__main__":
    unittest.main()
