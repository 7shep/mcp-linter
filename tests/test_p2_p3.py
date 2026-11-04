import unittest

from mcp_lint.models import Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.rules.probe import has_paging_params, opaque_share, p2_opaque_ids, p3_paging_hints

UUIDS = [
    "3f2b8c1e-9d4a-4e6b-8a1c-0f5e7d2b9c34",
    "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "0c9e7a51-2b3d-4f6e-9a8b-7c6d5e4f3a2b",
    "7d6c5b4a-3e2f-4a1b-9c8d-e7f6a5b4c3d2",
    "e4d3c2b1-a0f9-4e8d-b7c6-a5f4e3d2c1b0",
]


def result(text, tool="t", status="ok", label="", tokens=None):
    return ProbeResult(tool=tool, label=label, args={}, expect_error=False, status=status,
                       text=text, chars=len(text), tokens=tokens if tokens is not None else len(text) // 4)


def tool(name="t", *params):
    return ToolDef(name=name, input_schema={"type": "object", "properties": {p: {"type": "string"} for p in params}})


class OpaqueShareTests(unittest.TestCase):
    def test_counts_uuid_hex_and_random_tokens(self):
        text = ("id 3f2b8c1e-9d4a-4e6b-8a1c-0f5e7d2b9c34 sha 9fceb02d0ae598e95dc970b74767f19372d61af8 "
                "tok aB3dEf6hIj9kLmN2pQr5sT")
        count, share, example = opaque_share(text)
        self.assertEqual(count, 3)
        self.assertEqual(example, "3f2b8c1e-9d4a-4e6b-8a1c-0f5e7d2b9c34")
        self.assertGreater(share, 0.5)

    def test_readable_text_has_none(self):
        for text in ("Read the file at /home/alex/notes.txt", "Order 1234567890123456 shipped",  # digits only
                     "deadbeefcafe", "camelCaseIdentifierName", "Python3 is great"):
            self.assertEqual(opaque_share(text)[0], 0, text)

    def test_empty(self):
        self.assertEqual(opaque_share(""), (0, 0.0, None))


class P2Tests(unittest.TestCase):
    def test_id_heavy_response_warns(self):
        text = "\n".join(f"- {u}" for u in UUIDS)
        [f] = p2_opaque_ids({}, [result(text)])
        self.assertEqual((f.rule, f.severity), ("P2", Severity.WARNING))
        self.assertIn("5 opaque IDs", f.message)

    def test_ids_labelled_with_names_pass(self):
        # Names next to IDs is what the post recommends, even if IDs are a big share.
        lines = "\n".join(f"- Apollo checklist, owner Ada: {u}" for u in UUIDS)
        self.assertEqual(p2_opaque_ids({}, [result(lines)]), [])
        import json
        objs = json.dumps([{"id": u, "title": f"Quarterly plan {i}"} for i, u in enumerate(UUIDS)])
        self.assertEqual(p2_opaque_ids({}, [result(objs)]), [])

    def test_multiline_entries_count_as_labelled(self):
        # Real mcp-server-git log format: the hash line alone has no words,
        # but the entry's Message line does.
        log = "Commit history:\n" + "".join(
            f"Commit: {9 * i:040x}\nAuthor: t\nDate: 2026-11-04\nMessage: commit number {i} fixes things\n\n\n"
            for i in range(1, 40))
        self.assertEqual(p2_opaque_ids({}, [result(log)]), [])

    def test_json_ids_without_labels_warn(self):
        import json
        objs = json.dumps({"results": [{"id": u, "parent_id": UUIDS[0]} for u in UUIDS]})
        [f] = p2_opaque_ids({}, [result(objs)])
        self.assertEqual(f.severity, Severity.WARNING)
        bare_list = json.dumps({"ids": UUIDS})
        self.assertEqual(len(p2_opaque_ids({}, [result(bare_list)])), 1)

    def test_needs_several_ids(self):
        self.assertEqual(p2_opaque_ids({}, [result(" ".join(UUIDS[:4]))]), [])

    def test_errors_ignored(self):
        self.assertEqual(p2_opaque_ids({}, [result(" ".join(UUIDS), status="tool_error")]), [])


BIG = "line number 7 of the file\n" * 1000  # ~6.5k tokens


class P3Tests(unittest.TestCase):
    def test_big_response_without_hint_or_params_warns(self):
        [f] = p3_paging_hints({"t": tool("t", "uri")}, [result(BIG, label="big")])
        self.assertEqual((f.rule, f.severity), ("P3", Severity.WARNING))
        self.assertIn("no paging or limit parameters", f.message)

    def test_tool_with_paging_params_is_info(self):
        [f] = p3_paging_hints({"t": tool("t", "url", "max_length")}, [result(BIG)])
        self.assertEqual(f.severity, Severity.INFO)

    def test_hint_in_response_passes(self):
        for hint in ("[Reading 1000 lines from start (total: 20000 lines, 19000 remaining)]",
                     '{"next_cursor": "abc"}', "<content truncated. Call again with start_index=5000>",
                     "Showing 50 of 1200 results"):
            self.assertEqual(p3_paging_hints({}, [result(hint + "\n" + BIG)]), [], hint)

    def test_hint_words_inside_content_dont_count(self):
        # Real case: Python docs say "ignore the remaining items" mid-page.
        text = BIG + "zip() will ignore the remaining items in the longer iterables.\n" + BIG
        self.assertEqual(len(p3_paging_hints({}, [result(text)])), 1)

    def test_small_response_passes(self):
        self.assertEqual(p3_paging_hints({}, [result("short")]), [])

    def test_paging_params(self):
        for p in ("limit", "offset", "start_index", "max_length", "pageToken", "head"):
            self.assertTrue(has_paging_params(tool("t", p)), p)
        self.assertFalse(has_paging_params(tool("t", "uri", "path")))


if __name__ == "__main__":
    unittest.main()
