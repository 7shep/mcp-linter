"""False-positive guard: security rules on the saved tool lists of 18 real servers.

These servers are assumed benign, so any S8 warning or error on them is a
false positive. Update ``KNOWN_INFO`` only after checking that a new info
finding really is harmless.
"""

import glob
import json
import os
import unittest

from mcp_lint.models import Severity, ToolDef
from mcp_lint.rules.security import s8_hidden_text

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "survey", "tools")

# Desktop Commander's start_search mentions ".env" as an example file to look for.
KNOWN_INFO = {("desktop-commander.json", "start_search", "secret_path")}


def load_servers():
    for path in sorted(glob.glob(os.path.join(TOOLS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        yield os.path.basename(path), [ToolDef.from_dict(t) for t in data["tools"]]


class SurveyToolsTests(unittest.TestCase):
    def test_all_servers_present(self):
        servers = dict(load_servers())
        self.assertEqual(len(servers), 18)
        self.assertEqual(sum(len(tools) for tools in servers.values()), 230)

    def test_s8_has_no_false_positives(self):
        for name, tools in load_servers():
            for f in s8_hidden_text(tools):
                with self.subTest(server=name, tool=f.tool, kind=f.kind):
                    self.assertEqual(f.severity, Severity.INFO, f.message)
                    self.assertIn((name, f.tool, f.kind), KNOWN_INFO, f.message)


if __name__ == "__main__":
    unittest.main()
