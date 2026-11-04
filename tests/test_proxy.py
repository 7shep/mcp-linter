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


if __name__ == "__main__":
    unittest.main()
