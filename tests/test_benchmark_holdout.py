"""The tagger holdout: labels cover every captured tool, and the score is current."""

import glob
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOLDOUT = os.path.join(REPO, "benchmark", "holdout")


def _labels(server):
    out = {}
    for path in glob.glob(os.path.join(HOLDOUT, "labels", f"{server}*.json")):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data["server"] == server:
            out.update(data["tools"])
    return out


class HoldoutLabelTests(unittest.TestCase):
    def test_every_tool_has_one_complete_label(self):
        paths = sorted(glob.glob(os.path.join(HOLDOUT, "tools", "*.json")))
        self.assertEqual(len(paths), 6)
        for path in paths:
            server = os.path.splitext(os.path.basename(path))[0]
            with open(path, encoding="utf-8") as f:
                names = [t["name"] for t in json.load(f)["tools"]]
            labels = _labels(server)
            with self.subTest(server=server):
                self.assertEqual(len(names), len(set(names)))
                self.assertEqual(set(names), set(labels))
                for name, label in labels.items():
                    self.assertTrue(all(isinstance(label[k], bool) for k in "PUE"), name)
                    self.assertTrue(label["why"].strip(), name)

    def test_captures_hold_no_placeholder_credentials(self):
        for path in glob.glob(os.path.join(HOLDOUT, "tools", "*.json")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("placeholder-not-a-real-credential", f.read(), path)


class HoldoutScoreTests(unittest.TestCase):
    def test_committed_score_is_current(self):
        script = os.path.join(REPO, "benchmark", "holdout_score.py")
        proc = subprocess.run([sys.executable, script, "--check"], cwd=REPO,
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
