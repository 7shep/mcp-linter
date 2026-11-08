import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_release_version.py"

_spec = importlib.util.spec_from_file_location("check_release_version", SCRIPT)
crv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crv)


class TagMatchesTests(unittest.TestCase):
    def test_tags_that_match_1_2_0(self):
        for tag in ("v1.2", "v1.2.0", "1.2", "1.2.0"):
            with self.subTest(tag=tag):
                self.assertTrue(crv.tag_matches(tag, "1.2.0"))

    def test_tags_that_do_not_match_1_2_0(self):
        for tag in ("v1.2.1", "v1.3", "v1", "vfoo", ""):
            with self.subTest(tag=tag):
                self.assertFalse(crv.tag_matches(tag, "1.2.0"))

    def test_more_than_three_parts_never_match(self):
        self.assertFalse(crv.tag_matches("v1.2.0.0", "1.2.0"))

    def test_non_numeric_parts_never_match(self):
        self.assertFalse(crv.tag_matches("v1.2.0rc1", "1.2.0"))
        self.assertFalse(crv.tag_matches("v1..0", "1.2.0"))

    def test_only_one_leading_v_is_stripped(self):
        self.assertFalse(crv.tag_matches("vv1.2.0", "1.2.0"))


def _write_repo(root: Path, pyproject_version: str, init_version: str) -> None:
    (root / "src" / "mcp_lint").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[build-system]\n"
        'requires = ["hatchling"]\n\n'
        "[project]\n"
        'name = "mcp-linter"\n'
        f'version = "{pyproject_version}"\n\n'
        "[tool.other]\n"
        'version = "9.9.9"\n',
        encoding="utf-8",
    )
    (root / "src" / "mcp_lint" / "__init__.py").write_text(
        f'__version__ = "{init_version}"\n', encoding="utf-8"
    )


class ReadVersionsTests(unittest.TestCase):
    def test_reads_project_version_not_other_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.2.0")
            self.assertEqual(crv.read_versions(root), ("1.2.0", "1.2.0"))

    def test_returns_both_versions_when_they_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.1.0")
            self.assertEqual(crv.read_versions(root), ("1.2.0", "1.1.0"))


class MainTests(unittest.TestCase):
    def _run(self, argv, root):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = crv.main(argv, root=root)
        return code, out.getvalue(), err.getvalue()

    def test_two_file_mismatch_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.1.0")
            code, _, err = self._run(["check", "v1.2"], root)
            self.assertEqual(code, 1)
            self.assertIn("version mismatch", err)

    def test_mismatch_exits_1_even_when_tag_matches_pyproject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.1.0")
            code, _, _ = self._run(["check", "v1.2.0"], root)
            self.assertEqual(code, 1)

    def test_matching_fake_repo_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.2.0")
            code, out, _ = self._run(["check", "v1.2"], root)
            self.assertEqual(code, 0)
            self.assertIn("matches", out)

    def test_wrong_tag_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_repo(root, "1.2.0", "1.2.0")
            code, _, err = self._run(["check", "v1.2.1"], root)
            self.assertEqual(code, 1)
            self.assertIn("does not match", err)

    def test_usage_error_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = self._run(["check"], Path(tmp))
            self.assertEqual(code, 2)
            self.assertIn("usage", err)


class RealRepoTests(unittest.TestCase):
    def test_pyproject_and_init_versions_are_equal(self):
        pyproject_version, init_version = crv.read_versions(REPO_ROOT)
        self.assertEqual(pyproject_version, init_version)

    def test_real_version_tag_passes(self):
        pyproject_version, _ = crv.read_versions(REPO_ROOT)
        self.assertEqual(crv.main(["check", f"v{pyproject_version}"]), 0)


if __name__ == "__main__":
    unittest.main()
