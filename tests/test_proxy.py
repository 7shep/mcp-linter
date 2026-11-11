import asyncio
import io
import json
import os
import tempfile
import unittest

import mcp_types as types

from mcp_lint.proxy import (
    FixOptions,
    fix_result,
    load_descriptions,
    page_text,
    paging_param_names,
    rewrite_tool,
    split_paging_args,
)
from mcp_lint.guard import TrifectaGuard
from mcp_lint.trifecta import Tag
from mcp_lint.proxy import CallLog, ProxyCore


def tool(name="read", props=None, description="Read a file.", output_schema=None):
    schema = {"type": "object", "properties": props if props is not None else {"path": {"type": "string"}}}
    return types.Tool(name=name, description=description, input_schema=schema,
                      output_schema=output_schema)


def result(text, is_error=False, structured=None):
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)],
                                is_error=is_error, structured_content=structured)


BIG = "\n".join(f"row {i:05d} " + "x" * 30 for i in range(1, 2001)) + "\n"  # ~10k tokens


class PageTextTests(unittest.TestCase):
    def test_small_text_unchanged(self):
        self.assertEqual(page_text("hello\nworld\n"), ("hello\nworld\n", False))

    def test_big_text_cut_with_note(self):
        out, paged = page_text(BIG, page_tokens=500)
        self.assertTrue(paged)
        note, *lines = out.split("\n")
        self.assertRegex(note, r"^\[showing lines 1-\d+ of 2000; pass offset=\d+ for more\]$")
        self.assertLessEqual(len("\n".join(lines)), 500 * 4)
        self.assertEqual(lines[0], "row 00001 " + "x" * 30)
        end = int(note.split("offset=")[1].rstrip("for more]").strip())
        self.assertEqual(end, len(lines))

    def test_offset_and_limit(self):
        out, paged = page_text(BIG, offset=1499, limit=2)
        self.assertTrue(paged)
        self.assertEqual(out.split("\n"), [
            "[showing lines 1500-1501 of 2000; pass offset=1501 for more]",
            "row 01500 " + "x" * 30, "row 01501 " + "x" * 30])

    def test_last_page_says_end(self):
        out, _ = page_text(BIG, offset=1998)
        self.assertTrue(out.startswith("[showing lines 1999-2000 of 2000; end of response]"))

    def test_offset_on_small_text_still_pages(self):
        out, paged = page_text("a\nb\nc", offset=1, limit=1)
        self.assertEqual((out, paged), ("[showing lines 2-2 of 3; pass offset=2 for more]\nb", True))

    def test_offset_past_end(self):
        out, _ = page_text("a\nb", offset=10)
        self.assertIn("past the end", out)

    def test_explicit_limit_is_capped(self):
        out, _ = page_text(BIG, limit=2000, page_tokens=100)
        # at most 5 pages of 100 tokens (~2,000 chars)
        self.assertLessEqual(len(out), 5 * 100 * 4 + 200)

    def test_single_huge_line_is_cut(self):
        out, paged = page_text("y" * 50_000, page_tokens=100)
        self.assertTrue(paged)
        self.assertIn("line cut", out)
        self.assertLess(len(out), 1_000)


class RewriteToolTests(unittest.TestCase):
    def test_adds_paging_params_and_drops_output_schema(self):
        t = rewrite_tool(tool(output_schema={"type": "object"}), FixOptions())
        self.assertIn("offset", t.input_schema["properties"])
        self.assertIn("limit", t.input_schema["properties"])
        self.assertIn("path", t.input_schema["properties"])
        self.assertIsNone(t.output_schema)

    def test_does_not_mutate_original(self):
        original = tool()
        rewrite_tool(original, FixOptions())
        self.assertNotIn("offset", original.input_schema["properties"])

    def test_uses_prefixed_names_when_taken(self):
        t = rewrite_tool(tool(props={"offset": {"type": "integer"}}), FixOptions())
        self.assertIn("page_offset", t.input_schema["properties"])
        self.assertEqual(paging_param_names(t.input_schema), ("page_offset", "page_limit"))

    def test_description_replaced_only_when_listed(self):
        opts = FixOptions(paging=False, descriptions={"read": "A much better description."})
        self.assertEqual(rewrite_tool(tool(), opts).description, "A much better description.")
        self.assertEqual(rewrite_tool(tool(name="other"), opts).description, "Read a file.")

    def test_all_off_is_identity(self):
        t = tool()
        self.assertIs(rewrite_tool(t, FixOptions(paging=False, errors=False)), t)


class SplitArgsTests(unittest.TestCase):
    def test_strips_paging_args(self):
        args, off, lim = split_paging_args(tool(), {"path": "a", "offset": "5", "limit": 3})
        self.assertEqual((args, off, lim), ({"path": "a"}, 5, 3))

    def test_bad_values_fall_back(self):
        _, off, lim = split_paging_args(tool(), {"offset": "x", "limit": -4})
        self.assertEqual((off, lim), (0, 1))

    def test_keeps_upstream_offset(self):
        t = tool(props={"offset": {"type": "integer"}})
        args, off, _ = split_paging_args(t, {"offset": 7, "page_offset": 2})
        self.assertEqual((args, off), ({"offset": 7}, 2))


class FixResultTests(unittest.TestCase):
    def test_pages_big_result_and_drops_structured(self):
        fixed, rep = fix_result(result(BIG, structured={"content": BIG}), FixOptions())
        self.assertTrue(rep.paged)
        self.assertIsNone(fixed.structured_content)
        self.assertTrue(fixed.content[0].text.startswith("[showing lines 1-"))
        self.assertGreater(rep.upstream_tokens, rep.returned_tokens)

    def test_flags_error_text_as_error(self):
        fixed, rep = fix_result(result("Error: file not found"), FixOptions())
        self.assertTrue(fixed.is_error)
        self.assertTrue(rep.error_flagged)

    def test_leaves_real_errors_and_normal_text(self):
        for r in (result("Error: nope", is_error=True), result("all good")):
            fixed, rep = fix_result(r, FixOptions())
            self.assertIs(fixed, r)
            self.assertFalse(rep.error_flagged)

    def test_errors_fix_can_be_switched_off(self):
        fixed, _ = fix_result(result("Error: file not found"), FixOptions(errors=False))
        self.assertFalse(fixed.is_error)

    def test_paging_can_be_switched_off(self):
        fixed, rep = fix_result(result(BIG), FixOptions(paging=False))
        self.assertFalse(rep.paged)
        self.assertEqual(fixed.content[0].text, BIG)

    def test_keeps_non_text_blocks(self):
        r = types.CallToolResult(content=[types.TextContent(type="text", text=BIG),
                                          types.ImageContent(type="image", data="AAAA", mime_type="image/png")])
        fixed, _ = fix_result(r, FixOptions())
        self.assertEqual([b.type for b in fixed.content], ["text", "image"])


class LoadDescriptionsTests(unittest.TestCase):
    def test_reads_and_skips_notes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.json")
            with open(p, "w") as fh:
                json.dump({"_note": "x", "descriptions": {"a": "b", "_c": "d"}}, fh)
            self.assertEqual(load_descriptions(p), {"a": "b"})

    def test_rejects_bad_shape(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.json")
            with open(p, "w") as fh:
                json.dump({"descriptions": {"a": 1}}, fh)
            with self.assertRaises(ValueError):
                load_descriptions(p)

    def test_committed_fix_files_load(self):
        root = os.path.join(os.path.dirname(__file__), "..", "eval", "fixes")
        for name in os.listdir(root):
            self.assertTrue(load_descriptions(os.path.join(root, name)), name)


# --- trifecta guard wiring (ProxyCore with a fake upstream) ---------------------

def gtool(name, props, description):
    return types.Tool(name=name, description=description,
                      input_schema={"type": "object", "properties": props})


GUARD_TOOLS = [
    gtool("read_customer_record", {"customer_id": {"type": "string"}}, "Read a customer record."),
    gtool("get_ticket", {"ticket_id": {"type": "integer"}}, "Get a support ticket."),
    gtool("send_email", {"to": {"type": "string"}, "subject": {"type": "string"},
                         "body": {"type": "string"}}, "Send an email."),
    gtool("read_file", {"path": {"type": "string"}}, "Read a file."),
]
PERMITTED = {"to": "alice@harbor-desk.example", "subject": "Plan", "body": "placeholder"}


class FakeUpstream:
    def __init__(self, tools, raise_on=(), fail_list=False):
        self.tools = list(tools)
        self.calls: list[str] = []
        self.args_seen: list[tuple[str, dict]] = []
        self.list_count = 0
        self.raise_on = set(raise_on)
        self.fail_list = fail_list

    async def list_tools(self, params=None):
        self.list_count += 1
        if self.fail_list:
            raise RuntimeError("upstream list failed")
        return types.ListToolsResult(tools=list(self.tools))

    async def call_tool(self, name, args):
        self.calls.append(name)
        self.args_seen.append((name, dict(args)))
        if name in self.raise_on:
            raise RuntimeError(f"upstream failed on {name}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ok {name}")],
                                    is_error=False)


def ok_for(name):
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"ok {name}")],
                                is_error=False)


def make_core(upstream, guard=None, log=None, errlog=None, opts=None):
    return ProxyCore(opts or FixOptions(), upstream.list_tools, upstream.call_tool, guard=guard,
                     log=log, errlog=errlog if errlog is not None else io.StringIO())


def list_changed():
    return types.ToolListChangedNotification(method="notifications/tools/list_changed")


def read_rows(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class ProxyCoreTests(unittest.TestCase):
    def test_guard_off_is_todays_behaviour(self):
        for guard in (None, TrifectaGuard("off", GUARD_TOOLS)):
            with self.subTest(guard=guard):
                opts = FixOptions()
                with tempfile.TemporaryDirectory() as d:
                    log_path = os.path.join(d, "log.jsonl")
                    up = FakeUpstream(GUARD_TOOLS)
                    core = make_core(up, guard=guard, log=CallLog(log_path), opts=opts)

                    async def run():
                        await core.refresh()
                        a = await core.call_tool("get_ticket", {"ticket_id": 4417})
                        b = await core.call_tool("send_email", dict(PERMITTED))
                        await core.on_upstream_message(list_changed())
                        await core.list_tools()
                        await core.call_tool("unknown_name", {})
                        return a, b

                    a, b = asyncio.run(run())
                    self.assertEqual(up.calls, ["get_ticket", "send_email", "unknown_name"])
                    self.assertEqual(a, fix_result(ok_for("get_ticket"), opts)[0])
                    self.assertEqual(b, fix_result(ok_for("send_email"), opts)[0])
                    self.assertEqual(up.list_count, 1)
                    rows = read_rows(log_path)
                    self.assertEqual(len(rows), 3)
                    for row in rows:
                        self.assertNotIn("guard", row)

    def test_block_refuses_sink_after_untrusted_read(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = os.path.join(d, "log.jsonl")
            up = FakeUpstream(GUARD_TOOLS)
            core = make_core(up, guard=TrifectaGuard("block"), log=CallLog(log_path))

            async def run():
                await core.refresh()
                await core.call_tool("get_ticket", {"ticket_id": 4417})
                return await core.call_tool("send_email", dict(PERMITTED))

            result = asyncio.run(run())
            self.assertTrue(result.is_error)
            text = result.content[0].text
            self.assertIn("mcp-lint guard", text)
            self.assertIn("was not sent", text)
            self.assertEqual(up.calls, ["get_ticket"])
            rows = read_rows(log_path)
            self.assertEqual(rows[-1]["tool"], "send_email")
            self.assertEqual(rows[-1]["guard"], "block")

    def test_block_allows_sink_without_untrusted_read(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            await core.call_tool("read_customer_record", {"customer_id": "C-1042"})
            return await core.call_tool("send_email", dict(PERMITTED))

        result = asyncio.run(run())
        self.assertEqual(up.calls, ["read_customer_record", "send_email"])
        self.assertFalse(result.is_error)

    def test_warn_forwards_with_notice_first(self):
        up = FakeUpstream(GUARD_TOOLS)
        errlog = io.StringIO()
        core = make_core(up, guard=TrifectaGuard("warn"), errlog=errlog)

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            return await core.call_tool("send_email", dict(PERMITTED))

        result = asyncio.run(run())
        self.assertEqual(up.calls, ["get_ticket", "send_email"])
        self.assertTrue(result.content[0].text.startswith("[mcp-lint guard: warning]"))
        self.assertEqual(result.content[1].text, "ok send_email")
        self.assertIn("mcp-lint guard", errlog.getvalue())

    def test_untrusted_call_that_raises_still_taints(self):
        up = FakeUpstream(GUARD_TOOLS, raise_on={"get_ticket"})
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            with self.assertRaises(RuntimeError):
                await core.call_tool("get_ticket", {"ticket_id": 4417})
            return await core.call_tool("send_email", dict(PERMITTED))

        result = asyncio.run(run())
        self.assertTrue(result.is_error)
        self.assertEqual(up.calls, ["get_ticket"])

    def test_list_changed_renamed_sink_is_retagged_and_blocked(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            up.tools = [t for t in GUARD_TOOLS if t.name != "send_email"] + [
                gtool("dispatch_message", {"to": {"type": "string"}, "body": {"type": "string"}},
                      "Send a message.")]
            await core.on_upstream_message(list_changed())
            listed = await core.list_tools()
            blocked = await core.call_tool("dispatch_message", {"to": "a@b.example", "body": "x"})
            return listed, blocked

        listed, blocked = asyncio.run(run())
        self.assertIn("dispatch_message", [t.name for t in listed.tools])
        self.assertTrue(blocked.is_error)
        self.assertNotIn("dispatch_message", up.calls)
        self.assertEqual(up.list_count, 2)

    def test_unknown_name_relists_once_and_blocks_when_tainted(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            up.tools.append(gtool("post_message", {"channel": {"type": "string"},
                                                   "text": {"type": "string"}}, "Post a message."))
            blocked = await core.call_tool("post_message", {"channel": "general", "text": "hi"})
            never = await core.call_tool("never_listed", {})
            return blocked, never

        blocked, never = asyncio.run(run())
        self.assertTrue(blocked.is_error)
        self.assertTrue(never.is_error)
        self.assertEqual(up.calls, ["get_ticket"])
        self.assertEqual(up.list_count, 3)  # startup + one re-list per unknown name

    def test_failed_relist_fails_closed_when_tainted(self):
        up = FakeUpstream(GUARD_TOOLS)
        errlog = io.StringIO()
        core = make_core(up, guard=TrifectaGuard("block"), errlog=errlog)

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            await core.on_upstream_message(list_changed())
            up.fail_list = True
            return await core.call_tool("read_file", {"path": "notes.txt"})

        result = asyncio.run(run())
        self.assertTrue(result.is_error)
        self.assertIn("mcp-lint guard", result.content[0].text)
        self.assertNotIn("read_file", up.calls)
        self.assertIn("could not re-list", errlog.getvalue())

    def test_paging_args_stripped_in_block_mode(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            return await core.call_tool("read_customer_record",
                                        {"customer_id": "C-1042", "offset": 5, "limit": 2})

        result = asyncio.run(run())
        self.assertFalse(result.is_error)
        self.assertEqual(up.args_seen, [("read_customer_record", {"customer_id": "C-1042"})])

    def test_failed_list_tools_refresh_fails_closed(self):
        up = FakeUpstream(GUARD_TOOLS)
        errlog = io.StringIO()
        core = make_core(up, guard=TrifectaGuard("block"), errlog=errlog)

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            await core.on_upstream_message(list_changed())
            up.fail_list = True
            listed = await core.list_tools()  # must not raise
            up.fail_list = True
            blocked = await core.call_tool("read_file", {"path": "notes.txt"})
            return listed, blocked

        listed, blocked = asyncio.run(run())
        self.assertEqual([t.name for t in listed.tools], [t.name for t in GUARD_TOOLS])
        self.assertTrue(core.stale)
        self.assertTrue(blocked.is_error)
        self.assertNotIn("read_file", up.calls)
        self.assertIn("could not re-list", errlog.getvalue())

    def test_list_changed_during_refresh_is_not_lost(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))
        original = up.list_tools

        async def list_with_notice(params=None):
            result = await original(params)
            if up.list_count == 2:  # the notice lands while the re-list is in flight
                await core.on_upstream_message(list_changed())
            return result

        core._list_page = list_with_notice

        async def run():
            await core.refresh()
            await core.on_upstream_message(list_changed())
            await core.list_tools()

        asyncio.run(run())
        self.assertTrue(core.stale)

    def test_duplicate_name_twin_does_not_hide_the_sink(self):
        twin = gtool("send_email", {"n": {"type": "integer"}}, "x")
        for tools in (GUARD_TOOLS + [twin], [twin] + GUARD_TOOLS):
            with self.subTest(twin_first=tools[0] is twin):
                up = FakeUpstream(tools)
                core = make_core(up, guard=TrifectaGuard("block"))

                async def run():
                    await core.refresh()
                    await core.call_tool("get_ticket", {"ticket_id": 4417})
                    return await core.call_tool("send_email", dict(PERMITTED))

                result = asyncio.run(run())
                self.assertTrue(result.is_error)
                self.assertEqual(up.calls, ["get_ticket"])

    def test_undeclared_arguments_to_a_numeric_sink_are_blocked(self):
        numeric = gtool("send_email", {"n": {"type": "integer"}}, "x")
        tools = [t for t in GUARD_TOOLS if t.name != "send_email"] + [numeric]
        up = FakeUpstream(tools)
        core = make_core(up, guard=TrifectaGuard("block"))

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            fits = await core.call_tool("send_email", {"n": 2, "offset": 0})  # paging args don't count
            extra = await core.call_tool("send_email", {"to": "a@b.example", "body": "placeholder"})
            text = await core.call_tool("send_email", {"n": "placeholder"})
            return fits, extra, text

        fits, extra, text = asyncio.run(run())
        self.assertFalse(fits.is_error)
        self.assertTrue(extra.is_error)
        self.assertTrue(text.is_error)
        self.assertEqual(up.calls, ["get_ticket", "send_email"])

    def test_retag_while_untrusted_call_in_flight_still_taints(self):
        browse = gtool("browse_items", {"q": {"type": "string"}}, "x")
        browse = browse.model_copy(update={"annotations": types.ToolAnnotations(
            read_only_hint=True, open_world_hint=True)})
        plain_browse = gtool("browse_items", {"q": {"type": "string"}}, "x")
        noop = gtool("noop", {}, "x")
        mail = next(t for t in GUARD_TOOLS if t.name == "send_email")
        up = FakeUpstream([browse, mail, noop])
        core = make_core(up, guard=TrifectaGuard("block"))
        original = up.call_tool

        async def run():
            gate = asyncio.Event()

            async def call(name, args):
                if name == "browse_items":
                    up.tools = [plain_browse, mail, noop]  # same name, no longer untrusted
                    await core.on_upstream_message(list_changed())
                    await gate.wait()
                return await original(name, args)

            core._call_upstream = call
            await core.refresh()
            self.assertIn(Tag.UNTRUSTED_READ, core._guard.tags("browse_items"))
            task = asyncio.create_task(core.call_tool("browse_items", {"q": "x"}))
            await asyncio.sleep(0.05)
            await core.call_tool("noop", {})  # triggers the re-list and re-tag
            self.assertNotIn(Tag.UNTRUSTED_READ, core._guard.tags("browse_items"))
            gate.set()
            await task
            return await core.call_tool("send_email", dict(PERMITTED))

        result = asyncio.run(run())
        self.assertTrue(result.is_error)
        self.assertNotIn("send_email", up.calls)

    def test_sink_while_untrusted_call_in_flight_is_blocked(self):
        up = FakeUpstream(GUARD_TOOLS)
        core = make_core(up, guard=TrifectaGuard("block"))
        original = up.call_tool

        async def run():
            gate = asyncio.Event()

            async def call(name, args):
                if name == "get_ticket":
                    await gate.wait()
                return await original(name, args)

            core._call_upstream = call
            await core.refresh()
            task = asyncio.create_task(core.call_tool("get_ticket", {"ticket_id": 4417}))
            await asyncio.sleep(0.05)
            blocked = await core.call_tool("send_email", dict(PERMITTED))
            gate.set()
            await task
            return blocked

        blocked = asyncio.run(run())
        self.assertTrue(blocked.is_error)
        self.assertNotIn("send_email", up.calls)

    def test_notice_lines_stay_on_one_line(self):
        up = FakeUpstream(GUARD_TOOLS)
        errlog = io.StringIO()
        core = make_core(up, guard=TrifectaGuard("block"), errlog=errlog)

        async def run():
            await core.refresh()
            await core.call_tool("get_ticket", {"ticket_id": 4417})
            return await core.call_tool("send\nmcp-lint guard: fake line", {})

        result = asyncio.run(run())
        self.assertTrue(result.is_error)
        lines = [line for line in errlog.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 1)


if __name__ == "__main__":
    unittest.main()
