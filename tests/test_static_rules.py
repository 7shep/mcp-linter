import unittest

from mcp_lint.models import Severity, ToolDef
from mcp_lint.rules.static import (
    s1_description_length,
    s2_vague_param_names,
    s3_param_documentation,
)

GOOD_DESC = (
    "Search the user's contacts by name, email, or company and return up to "
    "ten matches with their name, email, and company."
)


def tool(desc=GOOD_DESC, **props):
    return ToolDef(name="t", description=desc,
                   input_schema={"type": "object", "properties": props})


class S1Tests(unittest.TestCase):
    def test_missing_description_is_error(self):
        for desc in (None, "", "   "):
            [f] = s1_description_length(tool(desc))
            self.assertEqual(f.severity, Severity.ERROR)

    def test_short_description_is_warning(self):
        [f] = s1_description_length(tool("Gets a user."))
        self.assertEqual(f.severity, Severity.WARNING)
        self.assertIn("3 words", f.message)

    def test_long_enough_description_passes(self):
        self.assertEqual(s1_description_length(tool()), [])


class S2Tests(unittest.TestCase):
    def test_vague_name_without_description_flagged(self):
        [f] = s2_vague_param_names(tool(user={"type": "string"}))
        self.assertEqual(f.param, "user")

    def test_vague_name_is_case_insensitive(self):
        self.assertEqual(len(s2_vague_param_names(tool(ID={"type": "string"}))), 1)

    def test_vague_name_with_description_passes(self):
        t = tool(id={"type": "string", "description": "Contact ID from search_contacts."})
        self.assertEqual(s2_vague_param_names(t), [])

    def test_specific_name_passes(self):
        self.assertEqual(s2_vague_param_names(tool(user_id={"type": "string"})), [])


class S3Tests(unittest.TestCase):
    def test_fully_documented_param_passes(self):
        t = tool(limit={"type": "integer", "description": "Max results."})
        self.assertEqual(s3_param_documentation(t), [])

    def test_missing_type_is_warning(self):
        [f] = s3_param_documentation(tool(fields={"description": "Fields to include."}))
        self.assertEqual(f.severity, Severity.WARNING)

    def test_enum_or_anyof_counts_as_type(self):
        for spec in ({"enum": ["a", "b"]}, {"anyOf": [{"type": "string"}, {"type": "null"}]}):
            spec = dict(spec, description="x")
            self.assertEqual(s3_param_documentation(tool(p=spec)), [])

    def test_missing_description_is_info(self):
        [f] = s3_param_documentation(tool(limit={"type": "integer"}))
        self.assertEqual(f.severity, Severity.INFO)

    def test_no_params_no_findings(self):
        self.assertEqual(s3_param_documentation(ToolDef(name="t")), [])


if __name__ == "__main__":
    unittest.main()
