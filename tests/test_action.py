"""Tests for scripts/action_lock_check.py (the GitHub Action's lock-check runner)."""

from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "action_lock_check.py"

_spec = importlib.util.spec_from_file_location("action_lock_check", SCRIPT)
action = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action)
build_argv = action.build_argv

FAKE_LINT = "/opt/mcp-lint/bin/mcp-lint"


def env(**values: str) -> dict[str, str]:
    base = {"MCP_LINT": FAKE_LINT, "INPUT_COMMAND": "python server.py"}
    base.update(values)
    return base


def mcp_lint_exe() -> Path:
    """The venv's mcp-lint, a sibling of sys.executable (Scripts/ on Windows, bin/ elsewhere)."""
    return Path(sys.executable).parent / ("mcp-lint.exe" if os.name == "nt" else "mcp-lint")


class BuildArgvTests(unittest.TestCase):
    def test_defaults_for_command(self):
        self.assertEqual(
            build_argv(env()),
            [FAKE_LINT, "lock", "--check", "--lock", "mcp-lint.lock", "--fail-on", "warning",
             "--", "python", "server.py"])

    def test_empty_optional_inputs_use_defaults(self):
        argv = build_argv(env(INPUT_LOCK="", INPUT_FAIL_ON="  ", INPUT_JSON=""))
        self.assertIn("mcp-lint.lock", argv)
        self.assertEqual(argv[argv.index("--fail-on") + 1], "warning")
        self.assertNotIn("--json", argv)

    def test_custom_lock_fail_on_and_json(self):
        argv = build_argv(env(INPUT_LOCK="locks/a.lock", INPUT_FAIL_ON="error",
                              INPUT_JSON="out/report.json"))
        self.assertEqual(argv[3:9], ["--lock", "locks/a.lock", "--fail-on", "error",
                                     "--json", "out/report.json"])

    def test_every_fail_on_level_is_accepted(self):
        for level in ("info", "warning", "error", "never"):
            with self.subTest(level=level):
                argv = build_argv(env(INPUT_FAIL_ON=level))
                self.assertEqual(argv[argv.index("--fail-on") + 1], level)

    def test_invalid_fail_on_is_rejected(self):
        for bad in ("critical", "WARNING", "none"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "fail-on"):
                build_argv(env(INPUT_FAIL_ON=bad))

    def test_missing_mcp_lint_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "MCP_LINT"):
            build_argv({"INPUT_COMMAND": "python server.py"})

    def test_neither_command_nor_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            build_argv({"MCP_LINT": FAKE_LINT})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            build_argv({"MCP_LINT": FAKE_LINT, "INPUT_COMMAND": "  \n ", "INPUT_URL": ""})

    def test_command_and_url_together_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            build_argv(env(INPUT_URL="http://127.0.0.1:8765/mcp"))

    def test_quoting_is_split_like_a_shell_word_list(self):
        argv = build_argv(env(INPUT_COMMAND='npx -y "@scope/pkg@1.2.3" --flag "a b"'))
        self.assertEqual(argv[-6:], ["--", "npx", "-y", "@scope/pkg@1.2.3", "--flag", "a b"])

    def test_unbalanced_quotes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "could not be parsed"):
            build_argv(env(INPUT_COMMAND='python "server.py'))

    def test_empty_command_after_splitting_is_rejected(self):
        for bad in ('""', "''"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "empty"):
                build_argv(env(INPUT_COMMAND=bad))

    def test_url_mode(self):
        argv = build_argv({"MCP_LINT": FAKE_LINT, "INPUT_URL": " http://127.0.0.1:8765/mcp "})
        self.assertEqual(
            argv,
            [FAKE_LINT, "lock", "--check", "--lock", "mcp-lint.lock", "--fail-on", "warning",
             "--url", "http://127.0.0.1:8765/mcp"])

    def test_pass_env_separators(self):
        argv = build_argv(env(INPUT_PASS_ENV="ALPHA BETA,GAMMA\nDELTA\t EPSILON,,  "))
        names = [argv[i + 1] for i, a in enumerate(argv) if a == "--pass-env"]
        self.assertEqual(names, ["ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON"])
        self.assertLess(argv.index("--pass-env"), argv.index("--"))

    def test_pass_env_names_are_validated(self):
        for ok in ("TOKEN", "_x", "a1_B2"):
            with self.subTest(ok=ok):
                build_argv(env(INPUT_PASS_ENV=ok))
        for bad in ("1ABC", "A-B", "A.B", "A=B", "$HOME", "A;rm"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "pass-env"):
                build_argv(env(INPUT_PASS_ENV=bad))

    def test_pass_env_with_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "pass-env"):
            build_argv({"MCP_LINT": FAKE_LINT, "INPUT_URL": "http://x/mcp", "INPUT_PASS_ENV": "TOKEN"})

    def test_blank_pass_env_with_url_is_fine(self):
        argv = build_argv({"MCP_LINT": FAKE_LINT, "INPUT_URL": "http://x/mcp", "INPUT_PASS_ENV": " \n "})
        self.assertNotIn("--pass-env", argv)

    def test_header_env_lines(self):
        argv = build_argv({
            "MCP_LINT": FAKE_LINT,
            "INPUT_URL": "http://127.0.0.1:8765/mcp",
            "INPUT_HEADER_ENV": "Authorization=MCP_TOKEN\n\n   \n  X-Api-Key=API_KEY  \n",
        })
        headers = [argv[i + 1] for i, a in enumerate(argv) if a == "--header-env"]
        self.assertEqual(headers, ["Authorization=MCP_TOKEN", "X-Api-Key=API_KEY"])
        self.assertEqual(argv[-2:], ["--url", "http://127.0.0.1:8765/mcp"])

    def test_header_env_is_passed_as_a_single_argument(self):
        argv = build_argv({"MCP_LINT": FAKE_LINT, "INPUT_URL": "http://x/mcp",
                           "INPUT_HEADER_ENV": "X-Api-Key=API_KEY"})
        self.assertEqual(argv[argv.index("--header-env") + 1], "X-Api-Key=API_KEY")

    def test_header_env_format_is_validated(self):
        bad_lines = [
            "Authorization",            # no '='
            "Authorization=",           # no variable name
            "Authorization=1TOKEN",     # variable name starts with a digit
            "Bad Name=TOKEN",           # space in header name
            "Authorization=TOKEN X",    # extra text
            "=TOKEN",                   # no header name
        ]
        for line in bad_lines:
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "header-env"):
                build_argv({"MCP_LINT": FAKE_LINT, "INPUT_URL": "http://x/mcp",
                            "INPUT_HEADER_ENV": line})

    def test_header_env_with_command_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "header-env"):
            build_argv(env(INPUT_HEADER_ENV="Authorization=TOKEN"))

    def test_blank_header_env_with_command_is_fine(self):
        argv = build_argv(env(INPUT_HEADER_ENV="\n  \n"))
        self.assertNotIn("--header-env", argv)


class MainIntegrationTests(unittest.TestCase):
    """Run the script as a subprocess, the way the action does."""

    def setUp(self):
        self.lint = mcp_lint_exe()
        self.assertTrue(self.lint.exists(), f"mcp-lint not found at {self.lint}")
        self.server_cmd = (
            f"{shlex.quote(Path(sys.executable).as_posix())} tests/fixtures/demo_server.py")

    def run_script(self, **inputs: str):
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith("INPUT_") and k != "GITHUB_STEP_SUMMARY"}
        clean.update({"MCP_LINT": str(self.lint), "INPUT_COMMAND": self.server_cmd})
        for key, value in inputs.items():
            if value is None:
                clean.pop(key, None)
            else:
                clean[key] = value
        return subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=str(REPO), env=clean,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)

    def test_unchanged_server_exits_0(self):
        result = self.run_script(INPUT_LOCK="tests/fixtures/demo.lock")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The launch command differs from the one locked (a different python path): INFO only.
        self.assertIn("0 errors, 0 warnings", result.stdout)

    def test_tampered_server_exits_1_and_reports_the_change(self):
        result = self.run_script(INPUT_LOCK="tests/fixtures/demo_tampered.lock")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("description_changed", result.stdout)
        self.assertIn("::error::Tool definitions changed since tests/fixtures/demo_tampered.lock",
                      result.stdout)

    def test_command_and_url_together_exits_2(self):
        result = self.run_script(
            INPUT_LOCK="tests/fixtures/demo.lock", INPUT_URL="http://127.0.0.1:9/mcp")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("::error::", result.stdout)

    def test_step_summary_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            summary.write_text("", encoding="utf-8")
            result = self.run_script(
                INPUT_LOCK="tests/fixtures/demo.lock", GITHUB_STEP_SUMMARY=str(summary))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = summary.read_text(encoding="utf-8")
        self.assertIn("### mcp-lint lock --check", text)
        self.assertIn("Exit code: 0", text)


if __name__ == "__main__":
    unittest.main()
