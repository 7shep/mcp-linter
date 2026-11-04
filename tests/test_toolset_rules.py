import unittest

from mcp_lint.models import Severity, ToolDef
from mcp_lint.rules.static import (
    s4_near_duplicates,
    s5_name_prefixes,
    s6_definition_tokens,
    s7_unbounded_lists,
)
from mcp_lint.text import naming_style, split_name


def t(name, desc="", params=()):
    props = {p: {"type": "string", "description": p} for p in params}
    return ToolDef(name=name, description=desc, input_schema={"type": "object", "properties": props})


class TextHelperTests(unittest.TestCase):
    def test_split_name(self):
        self.assertEqual(split_name("github_listPullRequests"), ["github", "list", "pull", "requests"])
        self.assertEqual(split_name("get-tiny-image"), ["get", "tiny", "image"])
        self.assertEqual(split_name("HTMLParser.run"), ["html", "parser", "run"])

    def test_naming_style(self):
        self.assertEqual(naming_style("a_b"), "snake_case")
        self.assertEqual(naming_style("a-b"), "kebab-case")
        self.assertEqual(naming_style("aB"), "camelCase")
        self.assertIsNone(naming_style("echo"))


class S4Tests(unittest.TestCase):
    def test_flags_same_text_and_params(self):
        tools = [
            t("read_file", "Read the complete contents of a file as text.", ["path", "head", "tail"]),
            t("read_text_file", "Read the complete contents of a text file.", ["path", "head", "tail"]),
            t("move_file", "Move or rename files and directories.", ["source", "destination"]),
        ]
        [f] = s4_near_duplicates(tools)
        self.assertEqual((f.tool, f.related), ("read_file", ["read_text_file"]))
        self.assertEqual(f.severity, Severity.WARNING)

    def test_templated_descriptions_with_different_params_pass(self):
        # Same boilerplate, different objects: not duplicates.
        tools = [
            t("create_issue", "Create a new issue in a GitHub repository.", ["owner", "repo", "title", "body"]),
            t("create_repository", "Create a new GitHub repository in your account.", ["name", "private"]),
        ]
        self.assertEqual(s4_near_duplicates(tools), [])

    def test_opposite_actions_pass(self):
        # Real false positives from Notion and Chrome DevTools.
        for a, b in (("API-retrieve-a-block", "API-delete-a-block"), ("screencast_start", "screencast_stop")):
            tools = [t(a, "Retrieve a block object using the ID specified.", ["block_id"]),
                     t(b, "Delete a block object using the ID specified.", ["block_id"])]
            self.assertEqual(s4_near_duplicates(tools), [], (a, b))

    def test_different_tools_pass(self):
        tools = [
            t("get_weather", "Current weather for a city.", ["city"]),
            t("send_email", "Send an email to a recipient.", ["to", "subject", "body"]),
        ]
        self.assertEqual(s4_near_duplicates(tools), [])


class S5Tests(unittest.TestCase):
    def test_consistent_prefix_passes(self):
        tools = [t("git_status"), t("git_diff"), t("git_commit")]
        self.assertEqual(s5_name_prefixes(tools), [])

    def test_flags_tool_missing_majority_prefix(self):
        tools = [t("git_status"), t("git_diff"), t("commit")]
        [f] = s5_name_prefixes(tools)
        self.assertEqual((f.tool, f.severity), ("commit", Severity.WARNING))
        self.assertIn("'git'", f.message)

    def test_verb_is_not_a_prefix(self):
        # get-sum / get-image share "get", which is an action, not a service.
        [f] = s5_name_prefixes([t("get-sum"), t("get-image"), t("echo")])
        self.assertIsNone(f.tool)
        self.assertEqual(f.severity, Severity.INFO)

    def test_mixed_styles(self):
        findings = s5_name_prefixes([t("svc_one"), t("svc-two"), t("svc_three")])
        self.assertTrue(any("Mixed naming styles" in f.message for f in findings))

    def test_empty(self):
        self.assertEqual(s5_name_prefixes([]), [])


class S6Tests(unittest.TestCase):
    def test_small_definitions_pass(self):
        self.assertEqual(s6_definition_tokens([t("a", "short")]), [])

    def test_warning_and_error_thresholds(self):
        big = "word " * 2000  # ~10k chars, ~2.5k tokens per tool
        [warn] = s6_definition_tokens([t(f"tool_{i}", big) for i in range(5)])
        self.assertEqual(warn.severity, Severity.WARNING)
        self.assertIsNone(warn.tool)
        self.assertIn("estimated", warn.message)
        [err] = s6_definition_tokens([t(f"tool_{i}", big) for i in range(11)])
        self.assertEqual(err.severity, Severity.ERROR)


class S7Tests(unittest.TestCase):
    def test_flags_unbounded_list(self):
        for name in ("list_users", "github_list_issues", "get_all_orders", "listProjects"):
            self.assertEqual(len(s7_unbounded_lists([t(name, params=["org"])])), 1, name)

    def test_limit_or_filter_params_pass(self):
        for params in (["limit"], ["perPage"], ["page_token"], ["query"], ["status"]):
            self.assertEqual(s7_unbounded_lists([t("list_users", params=params)]), [], params)

    def test_non_list_tools_ignored(self):
        self.assertEqual(s7_unbounded_lists([t("get_user", params=["user_id"])]), [])
        self.assertEqual(s7_unbounded_lists([t("create_list", params=["title"])]), [])


if __name__ == "__main__":
    unittest.main()
