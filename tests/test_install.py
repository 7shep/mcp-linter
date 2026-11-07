"""Install lint (I1): launch-command checks, client config loading, and the CLI paths."""

import contextlib
import io
import json
import os
import random
import shlex
import tempfile
import time
import unittest
from unittest import mock

from mcp_lint.cli import main
from mcp_lint.client import ServerInfo
from mcp_lint.install import (
    KNOWN_BAD,
    ConfigServer,
    _redact,
    lint_command,
    load_client_config,
    remote_origin,
)
from mcp_lint.models import Severity

SHA64 = "a" * 64
SHA40 = "0123456789abcdef0123456789abcdef01234567"


def kinds(argv):
    return sorted(f.kind for f in lint_command(argv))


def split(s):
    return shlex.split(s, posix=True)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue() + err.getvalue()


class ProgramDetectionTests(unittest.TestCase):
    def test_windows_path_and_suffix_are_stripped(self):
        self.assertEqual(kinds([r"C:\Program Files\nodejs\npx.cmd", "-y", "foo"]), ["unpinned"])
        self.assertEqual(kinds(["NPX.EXE", "-y", "foo"]), ["unpinned"])

    def test_empty_and_truncated_commands_have_no_findings(self):
        for argv in ([], [""], ["npx"], ["npx", "-y"], ["docker", "run", "-e"], ["uv"], ["pnpm"]):
            self.assertEqual(lint_command(argv), [], argv)

    def test_env_prefix_is_skipped(self):
        self.assertEqual(kinds(["env", "FOO=1", "BAR=2", "npx", "-y", "foo"]), ["unpinned"])


class WrapperTests(unittest.TestCase):
    def test_cmd_c_with_one_string_is_split(self):
        self.assertEqual(kinds(["cmd", "/c", "npx -y @upstash/context7-mcp"]), ["unpinned"])

    def test_cmd_k_with_separate_args(self):
        self.assertEqual(kinds(["cmd.exe", "/k", "npx", "-y", "foo"]), ["unpinned"])

    def test_shell_string_segments_are_each_linted(self):
        self.assertEqual(kinds(split("bash -c 'pip install x && npx -y y'")), ["no_hashes", "unpinned"])
        self.assertEqual(kinds(split("sh -c 'npx -y a;npx -y b'")), ["unpinned", "unpinned"])

    def test_unparseable_shell_string_is_one_info_finding(self):
        got = lint_command(split("bash -c \"npx -y 'unterminated\""))
        self.assertEqual([f.kind for f in got], ["unparsed"])
        self.assertEqual(got[0].severity, Severity.INFO)

    def test_unparseable_cmd_string_is_unparsed(self):
        self.assertEqual([f.kind for f in lint_command(["cmd", "/c", "npx 'x"])], ["unparsed"])

    def test_deep_shell_nesting_is_reported_not_raised(self):
        s = "npx -y foo"
        for _ in range(10):  # each level's quoting grows the string, so keep this small
            s = "bash -c " + shlex.quote(s)
        self.assertEqual([f.kind for f in lint_command(split(s))], ["unparsed"])


class NpmTests(unittest.TestCase):
    def test_unpinned_forms(self):
        for argv in (["npx", "-y", "@upstash/context7-mcp"], ["npx", "-y", "context7@latest"],
                     ["npx", "-y", "context7@^1.0.0"], ["npx", "-y", "context7@1"],
                     ["pnpm", "dlx", "foo"], ["bunx", "foo"], ["bun", "x", "foo"]):
            self.assertEqual(kinds(argv), ["unpinned"], argv)

    def test_pinned_forms_are_clean(self):
        for argv in (["npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"],
                     ["npx", "-y", "context7@1.0.14-beta.2"],
                     ["npx", "--yes", "-p", "chrome-devtools-mcp@0.6.0", "chrome-devtools-mcp"],
                     ["npx", "--package=chrome-devtools-mcp@0.6.0", "chrome-devtools-mcp"]):
            self.assertEqual(lint_command(argv), [], argv)

    def test_package_flag_bin_name_is_not_checked(self):
        # The first positional is the bin, so only the -p spec is checked.
        self.assertEqual(kinds(["npx", "-p", "foo", "bar"]), ["unpinned"])

    def test_local_paths_are_not_checked(self):
        for spec in ("./local-server", "../x", "/abs/x", r"\\share\x", r"C:\x", "file:../x"):
            self.assertEqual(lint_command(["npx", "-y", spec]), [], spec)

    def test_github_and_bare_repo_sources(self):
        self.assertEqual(kinds(["npx", "-y", "github:user/repo"]), ["unpinned_source"])
        self.assertEqual(kinds(["npx", "-y", "user/repo"]), ["unpinned_source"])
        self.assertEqual(lint_command(["npx", "-y", f"github:user/repo#{SHA40}"]), [])


class PythonTests(unittest.TestCase):
    def test_unpinned_forms(self):
        for argv in (["uvx", "mcp-server-fetch"], ["uvx", "mcp-server-fetch>=1.0"],
                     ["uvx", "markitdown-mcp@latest"], ["pipx", "run", "some-mcp"],
                     ["uv", "run", "--with", "mcp", "server.py"],
                     ["uv", "tool", "run", "foo~=1.0"]):
            self.assertEqual(kinds(argv), ["unpinned"], argv)

    def test_pinned_forms_are_clean(self):
        for argv in (["uvx", "markitdown-mcp==0.0.1a4"], ["uvx", "duckduckgo-mcp-server@0.1.1"],
                     ["uvx", "--from", "awslabs.aws-documentation-mcp-server==1.1.2", "x"],
                     ["uvx", "--python", "3.12", "mcp-server-git==2025.1.14"],
                     ["uvx", "--from", "litellm[proxy]===1.0.0", "litellm"],
                     ["pipx", "run", "--spec", "some-mcp==1.0.0", "some-mcp"],
                     ["uv", "run", "--with", "mcp==1.2.0", "server.py"]):
            self.assertEqual(lint_command(argv), [], argv)

    def test_with_flags_are_checked_and_script_is_not(self):
        self.assertEqual(kinds(["uv", "run", "--with", "mcp", "script-that-is-not-checked"]), ["unpinned"])
        self.assertEqual(kinds(["uvx", "--with", "extra", "pinned==1.0"]), ["unpinned"])

    def test_git_sources(self):
        self.assertEqual(kinds(["uvx", "--from", "git+https://github.com/a/b", "b"]), ["unpinned_source"])
        self.assertEqual(lint_command(["uvx", "--from", f"git+https://github.com/a/b@{SHA40}", "b"]), [])

    def test_local_path_is_not_checked(self):
        self.assertEqual(lint_command(["uvx", "./local_pkg"]), [])


class PipTests(unittest.TestCase):
    def test_no_hashes_for_pip_forms(self):
        for argv in (["pip", "install", "foo"], ["pip3", "install", "-r", "req.txt"],
                     ["python", "-m", "pip", "install", "foo==1.0"], ["py", "-m", "pip", "install", "x"],
                     ["uv", "pip", "install", "x"]):
            self.assertEqual(kinds(argv), ["no_hashes"], argv)

    def test_require_hashes_is_clean(self):
        self.assertEqual(lint_command(["pip", "install", "--require-hashes", "-r", "requirements.txt"]), [])

    def test_known_bad_pip_pin_replaces_no_hashes(self):
        got = lint_command(["pip", "install", "--require-hashes", "LiteLLM==1.82.8"])
        self.assertEqual([f.kind for f in got], ["known_bad"])
        got = lint_command(["pip", "install", "LiteLLM==1.82.8"])
        self.assertEqual([f.kind for f in got], ["known_bad"])


class ContainerTests(unittest.TestCase):
    def test_tag_or_no_tag_without_digest(self):
        for argv in (["docker", "run", "-i", "--rm", "mcp/fetch"],
                     ["docker", "run", "-i", "--rm", "-e", "X=1", "mcp/fetch:latest"],
                     ["docker", "container", "run", "mcp/fetch"],
                     ["podman", "run", "-i", "--rm", "mcp/fetch"]):
            self.assertEqual(kinds(argv), ["no_digest"], argv)

    def test_digest_is_clean(self):
        self.assertEqual(lint_command(["docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN",
                                       f"ghcr.io/github/github-mcp-server@sha256:{SHA64}"]), [])

    def test_option_values_are_not_taken_for_the_image(self):
        # "-v" takes "a:b" and "--name" takes "gh"; the image is the next positional.
        self.assertEqual(kinds(["docker", "run", "--name", "gh", "-v", "a:b", "mcp/fetch:1.0"]), ["no_digest"])
        self.assertEqual(lint_command(["docker", "run", "-dit", "-p8080:80", f"img@sha256:{SHA64}"]), [])


class KnownBadTests(unittest.TestCase):
    def test_npm_known_bad_is_the_only_finding(self):
        got = lint_command(["npx", "-y", "postmark-mcp@1.0.16"])
        self.assertEqual([f.kind for f in got], ["known_bad"])
        self.assertEqual(got[0].severity, Severity.ERROR)

    def test_pypi_name_is_normalised(self):
        self.assertEqual(kinds(["uvx", "litellm==1.82.7"]), ["known_bad"])
        self.assertEqual(kinds(["uvx", "--from", "litellm[proxy]==1.107.0", "litellm"]), ["known_bad"])
        self.assertEqual(kinds(["uvx", "LiteLLM==1.82.8"]), ["known_bad"])
        self.assertEqual(kinds(["pip", "install", "--require-hashes", "LiteLLM==1.82.8"]), ["known_bad"])

    def test_other_versions_are_not_known_bad(self):
        self.assertEqual(lint_command(["uvx", "litellm==1.82.6"]), [])
        self.assertEqual(lint_command(["npx", "-y", "postmark-mcp@1.0.15"]), [])

    def test_table_has_the_listed_releases(self):
        self.assertEqual(KNOWN_BAD["npm"]["postmark-mcp"], {"1.0.16"})
        self.assertEqual(KNOWN_BAD["pypi"]["litellm"], {"1.82.7", "1.82.8", "1.107.0"})


class RedactionTests(unittest.TestCase):
    def test_url_userinfo_is_redacted_in_messages_and_hints(self):
        got = lint_command(["uvx", "--from", "git+https://user:hunter2pw@github.com/a/b", "mcp-b"])
        self.assertEqual([f.kind for f in got], ["unpinned_source"])
        text = " ".join((f.message or "") + " " + (f.hint or "") for f in got)
        self.assertNotIn("hunter2pw", text)
        self.assertIn("https://***@github.com/a/b", got[0].message)

    def test_redact_helper(self):
        self.assertEqual(_redact("https://user:pass@host/x"), "https://***@host/x")
        self.assertEqual(_redact("plain text"), "plain text")

    def test_other_argv_tokens_are_not_quoted(self):
        got = lint_command(["uvx", "mcp-server-fetch", "--token", "tok-SECRET999"])
        text = " ".join((f.message or "") + " " + (f.hint or "") for f in got)
        self.assertNotIn("SECRET999", text)


class FuzzTests(unittest.TestCase):
    VOCAB = ["npx", "-y", "--", "-p", "--package=", "--package", "cmd", "/c", "/k", "bash", "-c", "env",
             "FOO=1", "uvx", "--from", "--with", "--spec", "uv", "run", "tool", "pip", "install",
             "docker", "podman", "run", "-e", "-v", "-it", "--rm", "&&", "|", "||", ";", "&", "'",
             '"', "@", "@scope/", "==", "===", "@sha256:", "git+", "github:", "\\", "C:", "", "x@1.0.0",
             "postmark-mcp@1.0.16", "litellm==1.82.8", "mcp/fetch", "#", "https://u:p@h", "[", "]"]

    def test_random_token_lists_never_raise(self):
        rng = random.Random(20260404)
        for _ in range(3000):
            argv = [rng.choice(self.VOCAB) for _ in range(rng.randint(0, 9))]
            for f in lint_command(argv):
                self.assertEqual(f.rule, "I1")
                self.assertIsNone(f.tool)

    def test_long_env_chain_does_not_recurse(self):
        self.assertEqual(kinds(["env"] * 5000 + ["npx", "-y", "foo"]), ["unpinned"])


class ClientConfigTests(unittest.TestCase):
    def write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        self.addCleanup(os.remove, path)
        return path

    def test_mcp_servers_map(self):
        path = self.write({"mcpServers": {
            "a": {"command": "npx", "args": ["-y", "foo"], "env": {"K": "SECRET-ENV-VALUE"}},
            "b": {"url": "https://example.com/mcp?key=q"},
        }})
        got = {s.name: s for s in load_client_config(path)}
        self.assertEqual(got["a"], ConfigServer(name="a", argv=["npx", "-y", "foo"], url=None))
        self.assertEqual(got["b"], ConfigServer(name="b", argv=None, url="https://example.com/mcp?key=q"))
        self.assertNotIn("SECRET-ENV-VALUE", repr(got))

    def test_vscode_servers_map(self):
        path = self.write({"servers": {"f": {"command": "docker", "args": ["run", "mcp/fetch"]}}})
        self.assertEqual(load_client_config(path), [ConfigServer("f", ["docker", "run", "mcp/fetch"], None)])

    def test_projects_map_is_prefixed_with_the_path(self):
        path = self.write({"projects": {"C:/proj": {"mcpServers": {"pm": {"command": "npx", "args": []}}}},
                           "numStartups": 3})
        self.assertEqual(load_client_config(path), [ConfigServer("C:/proj:pm", ["npx"], None)])

    def test_unusable_entries_have_no_argv_or_url(self):
        path = self.write({"mcpServers": {
            "bad-args": {"command": "npx", "args": ["-y", 5]},
            "no-command": {"args": ["x"]},
            "not-object": "npx",
        }})
        for server in load_client_config(path):
            self.assertIsNone(server.argv, server.name)
            self.assertIsNone(server.url, server.name)

    def test_no_server_map_raises_value_error(self):
        path = self.write({"tools": []})
        with self.assertRaises(ValueError):
            load_client_config(path)

    def test_remote_origin_keeps_only_scheme_and_host(self):
        self.assertEqual(remote_origin("https://user:pw@example.com:8443/a/b?token=x"), "https://example.com")
        self.assertEqual(remote_origin("http://[bad"), "?")


class CheckConfigCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def config(self, data, name="cfg.json"):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def test_unpinned_warns_and_default_fail_on_exits_1(self):
        path = self.config({"mcpServers": {"ctx": {"command": "npx", "args": ["-y", "context7@latest"]}}})
        code, out = run_cli("check-config", path)
        self.assertEqual(code, 1)
        self.assertIn("ctx", out)
        self.assertIn("I1", out)

    def test_fail_on_error_ignores_warnings(self):
        path = self.config({"mcpServers": {"ctx": {"command": "npx", "args": ["-y", "context7@latest"]}}})
        self.assertEqual(run_cli("check-config", path, "--fail-on", "error")[0], 0)
        self.assertEqual(run_cli("check-config", path, "--fail-on", "never")[0], 0)

    def test_json_has_no_argv_env_or_url_path(self):
        path = self.config({"mcpServers": {
            "git": {"command": "uvx", "args": ["mcp-server-git==2025.1.14", "--token", "tok-SECRET456"],
                    "env": {"API_KEY": "sk-SECRET123"}},
            "remote": {"type": "http", "url": "https://example.com/path?key=url-SECRET789"},
        }})
        jpath = os.path.join(self.dir.name, "out.json")
        code, out = run_cli("check-config", path, "--json", jpath)
        self.assertEqual(code, 0)
        with open(jpath, encoding="utf-8") as fh:
            text = fh.read()
        data = json.loads(text)
        by_name = {s["name"]: s for s in data["servers"]}
        self.assertTrue(by_name["remote"]["remote"])
        self.assertEqual(by_name["git"]["findings"], [])
        for secret in ("tok-SECRET456", "sk-SECRET123", "url-SECRET789", "/path", '"argv"', '"env"'):
            self.assertNotIn(secret, text + out)
        self.assertIn("https://example.com", out)

    def test_invalid_and_missing_files_exit_2(self):
        bad = os.path.join(self.dir.name, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(run_cli("check-config", bad)[0], 2)
        self.assertEqual(run_cli("check-config", os.path.join(self.dir.name, "missing.json"))[0], 2)

    def test_file_without_server_map_exits_2(self):
        sample = os.path.join(os.path.dirname(__file__), "fixtures", "sample_tools.json")
        code, out = run_cli("check-config", sample)
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", out)

    def test_min_severity_hides_lines_but_not_exit_code(self):
        path = self.config({"mcpServers": {"ctx": {"command": "npx", "args": ["-y", "context7@latest"]}}})
        code, out = run_cli("check-config", path, "--min-severity", "error")
        self.assertEqual(code, 1)
        self.assertNotIn("I1", out)


class RefusalTests(unittest.TestCase):
    """run, proxy and lock refuse known-bad releases before any connection."""

    BAD = ["--", "npx", "-y", "postmark-mcp@1.0.16"]

    def assert_refused(self, sub):
        with mock.patch("mcp_lint.client.fetch_tools") as fetch, \
                mock.patch("mcp_lint.client.fetch_and_probe") as probe, \
                mock.patch("mcp_lint.proxy.serve") as serve:
            code, out = run_cli(sub, *self.BAD)
        self.assertEqual(code, 1, out)
        self.assertFalse(fetch.called)
        self.assertFalse(probe.called)
        self.assertFalse(serve.called)
        self.assertIn("postmark-mcp", out)

    def test_run_refuses(self):
        self.assert_refused("run")

    def test_proxy_refuses(self):
        self.assert_refused("proxy")

    def test_lock_refuses(self):
        self.assert_refused("lock")

    def test_run_shows_unpinned_as_i1_and_still_exits_0(self):
        info = ServerInfo(name="demo", version="1", tools=[])
        with mock.patch("mcp_lint.client.fetch_tools", new=mock.AsyncMock(return_value=info)):
            code, out = run_cli("run", "--", "npx", "-y", "some-server")
        self.assertEqual(code, 0, out)
        self.assertIn("I1", out)
        self.assertIn("(server)", out)


def refused(argv):
    return any(f.kind == "known_bad" and f.severity == Severity.ERROR for f in lint_command(argv))


class BypassTests(unittest.TestCase):
    """Round 2: the known-bad refusal must not depend on the parser finding the package."""

    def test_unlisted_value_flags_do_not_hide_known_bad(self):
        for s in ("uvx --env-file .env litellm==1.82.7", "uvx --directory /c litellm==1.82.7",
                  "uvx --cache-dir /c litellm==1.82.7", "uvx --refresh-package x litellm==1.82.7",
                  "uvx -c c.txt litellm==1.82.7", "uvx --color never litellm==1.82.7",
                  "uv --directory /srv run --with litellm==1.82.7 server.py",
                  "uv --quiet tool run litellm==1.82.7", "uv run -w litellm==1.82.7 x.py",
                  "uvx --with 'litellm==1.82.7,foo' x==1.0"):
            self.assertTrue(refused(split(s)), s)

    def test_npm_global_options_and_subcommands(self):
        for s in ("npx --cache /tmp/c postmark-mcp@1.0.16", "npx --registry https://r.example postmark-mcp@1.0.16",
                  "pnpm --silent dlx postmark-mcp@1.0.16", "npm exec -- postmark-mcp@1.0.16",
                  "npm x postmark-mcp@1.0.16"):
            self.assertTrue(refused(split(s)), s)

    def test_pip_global_options_and_interpreter_spellings(self):
        for s in ("pip -q install litellm==1.82.7", "pip3.12 install litellm==1.82.7",
                  "python3.12 -m pip install litellm==1.82.7", "python -mpip install litellm==1.82.7",
                  "python -I -m pip install litellm==1.82.7", "py -3.12 -m pip install litellm==1.82.7"):
            self.assertTrue(refused(split(s)), s)

    def test_version_spellings(self):
        for s in ("uvx litellm==1.82.7.0", "uvx litellm==01.82.7", "uvx litellm==1.82.07",
                  "uvx litellm==v1.82.7", "uvx litellm===1.82.7", "uvx 'litellm==1.82.7; python_version>\"3\"'",
                  "uvx 'litellm (==1.82.7)'", "uvx 'Lite.LLM==1.82.7'", "uvx 'litellm==0!1.82.7+local'",
                  "npx -y postmark-mcp@1.0.16+build", "npx -y postmark-mcp@v1.0.16", "npx -y postmark-mcp@=1.0.16",
                  "npx -y POSTMARK-MCP@1.0.16"):
            self.assertTrue(refused(split(s)), s)

    def test_version_near_misses_are_not_refused(self):
        for s in ("uvx litellm==1.82.71", "uvx litellm==1.107.01.1", "npx -y postmark-mcp@1.0.17",
                  "npx -y postmark-mcp@11.0.16", "npx -y postmark-mcp-x@1.0.16", "uvx notlitellm==1.82.7",
                  "uvx litellm==1.82.6"):
            self.assertFalse(refused(split(s)), s)

    def test_npm_aliases(self):
        for s in ("npx -y x@npm:postmark-mcp@1.0.16", "npx -y npm:postmark-mcp@1.0.16",
                  "npx --package x@npm:postmark-mcp@1.0.16 postmark-mcp"):
            self.assertTrue(refused(split(s)), s)

    def test_shell_forms(self):
        for s in ("bash -l -c 'npx -y postmark-mcp@1.0.16'", "bash --login -c 'npx -y postmark-mcp@1.0.16'",
                  "bash -o pipefail -c 'npx -y postmark-mcp@1.0.16'", "sh -c 'FOO=1 npx -y postmark-mcp@1.0.16'",
                  "sh -c 'exec npx -y postmark-mcp@1.0.16'", "sh -c '(npx -y postmark-mcp@1.0.16)'",
                  "sh -c '{ npx -y postmark-mcp@1.0.16; }'", "sh -c 'if true; then npx -y postmark-mcp@1.0.16; fi'",
                  "pwsh -Command 'npx -y postmark-mcp@1.0.16'", "powershell -c 'npx -y postmark-mcp@1.0.16'",
                  "env -C /tmp npx -y postmark-mcp@1.0.16", "env -S 'npx -y postmark-mcp@1.0.16'",
                  "some-unknown-launcher --flag postmark-mcp@1.0.16"):
            self.assertTrue(refused(split(s)), s)

    def test_raw_argv_shapes(self):
        for argv in (["sh", "-c", "echo hi\nnpx -y postmark-mcp@1.0.16"],
                     ["cmd", "/c", "call npx -y postmark-mcp@1.0.16"],
                     ["cmd", "/v:on", "/c", "npx -y postmark-mcp@1.0.16"],
                     ["cmd", "/s", "/c", "\"npx -y postmark-mcp@1.0.16\""],
                     ["cmd", "/cnpx", "-y", "postmark-mcp@1.0.16"],
                     ["bash", "-c", "npx -y 'unterminated postmark-mcp@1.0.16"]):
            self.assertTrue(refused(argv), argv)

    def test_pieces_with_spaces_and_parentheses(self):
        # Pieces join only inside one argv string; separate arguments are separate packages.
        self.assertFalse(refused(["uvx", "litellm", "==", "1.82.7"]))
        self.assertTrue(refused(["uvx", "litellm == 1.82.7"]))
        self.assertTrue(refused(["uvx", "litellm (==1.82.7)"]))

    def test_known_bad_is_reported_once_and_alone(self):
        got = lint_command(split("npx -y postmark-mcp@1.0.16 && npx -y postmark-mcp@1.0.16"))
        self.assertEqual([f.kind for f in got], ["known_bad"])

    def test_backstop_only_adds_known_bad(self):
        # unknown launcher, unpinned: only the backstop runs, and it must not add warnings
        self.assertEqual(lint_command(["some-launcher", "foo"]), [])


class ShellTests(unittest.TestCase):
    def test_unknown_shell_shapes_give_a_finding(self):
        for s in ("bash -c 'npx -y $(cat pkg.txt)'", "bash -c 'npx -y `cat pkg.txt`'",
                  "bash -c 'while read x; do npx -y foo; done'"):
            self.assertTrue(lint_command(split(s)), s)

    def test_env_chdir_and_unset_are_skipped(self):
        self.assertEqual(kinds(["env", "-u", "X", "-i", "npx", "-y", "foo"]), ["unpinned"])

    def test_fish_is_a_shell(self):
        self.assertEqual(kinds(split("fish -c 'npx -y foo'")), ["unpinned"])


class DockerTests(unittest.TestCase):
    def test_short_cluster_with_value_consumes_next_token(self):
        got = lint_command(split("docker run --rm -ie GITHUB_TOKEN=ghp_LEAK1 ghcr.io/github/github-mcp-server"))
        text = " ".join((f.message or "") + " " + (f.hint or "") for f in got)
        self.assertNotIn("LEAK1", text)
        self.assertEqual([f.kind for f in got], ["no_digest"])
        self.assertIn("ghcr.io/github/github-mcp-server", got[0].message)

    def test_unidentifiable_image_is_not_quoted(self):
        got = lint_command(split("docker run --rm -e 'TOKEN=LEAK6' --name x not/pinned?x=LEAK7"))
        text = " ".join((f.message or "") + " " + (f.hint or "") for f in got)
        self.assertNotIn("LEAK", text)
        self.assertEqual([f.kind for f in got], ["no_digest"])

    def test_new_value_flags_are_consumed(self):
        self.assertEqual(lint_command(split(f"docker run -a stdin --dns 8.8.8.8 ghcr.io/x/y@sha256:{SHA64}")), [])


class SourceTests(unittest.TestCase):
    def test_pinned_git_with_fragments_is_clean(self):
        for s in (f"uvx --from git+https://github.com/a/b@{SHA40}#subdirectory=src/x x",
                  f"uvx --from git+https://github.com/a/b@{SHA40}#egg=b b",
                  f"uvx --from 'b @ git+https://github.com/a/b@{SHA40}' b"):
            self.assertEqual(lint_command(split(s)), [], s)

    def test_pep508_direct_reference_goes_through_the_source_check(self):
        self.assertEqual(kinds(split("uvx --from 'b @ git+https://github.com/a/b' b")), ["unpinned_source"])

    def test_query_and_fragment_are_dropped_from_quotes(self):
        got = lint_command(split("uvx --from 'git+https://h.example/a/b?token=LEAK5#frag' b"))
        text = " ".join((f.message or "") + " " + (f.hint or "") for f in got)
        self.assertNotIn("LEAK5", text)
        self.assertIn("git+https://h.example/a/b", got[0].message)
        self.assertEqual(_redact("https://h/x?k=v#f"), "https://h/x")

    def test_long_inputs_are_fast_and_capped(self):
        import time

        t0 = time.perf_counter()
        lint_command(["npx", "-y", "a" * 200_000])
        lint_command(["uvx", "--from", "git+" + "a" * 200_000, "b"])
        self.assertLess(time.perf_counter() - t0, 2.0)
        long = lint_command(["npx", "-y", "b" * 5000])
        self.assertTrue(all(len(f.message) <= 600 for f in long))


class VersionEdgeTests(unittest.TestCase):
    def test_unbalanced_quotes_still_backstopped(self):
        self.assertTrue(refused(["bash", "-c", "npx -y 'unterminated postmark-mcp@1.0.16"]))

    def test_names_with_no_exact_match_are_clean(self):
        self.assertEqual(lint_command(["uvx", "notlitellm==1.82.7"]), [])


class ConfigReadingTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write_text(self, name, text, encoding="utf-8"):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding=encoding) as fh:
            fh.write(text)
        return path

    def test_bom_is_read(self):
        path = self.write_text("c.json", '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "foo"]}}}',
                               encoding="utf-8-sig")
        self.assertEqual(run_cli("check-config", path)[0], 1)

    def test_jsonc_comments_and_trailing_commas(self):
        path = self.write_text("mcp.json", '{\n  // comment\n  "servers": {\n    /* block */ "a": {"command": "npx", '
                               '"args": ["-y", "foo", "http://x//not-a-comment"],},\n  },\n}\n')
        servers = load_client_config(path)
        self.assertEqual(servers[0].argv, ["npx", "-y", "foo", "http://x//not-a-comment"])

    def test_vscode_settings_mcp_servers(self):
        path = self.write_text("settings.json", json.dumps({"mcp": {"servers": {
            "a": {"command": "npx", "args": ["-y", "foo"]}}}}))
        self.assertEqual([s.name for s in load_client_config(path)], ["a"])

    def test_unreadable_entry_is_a_warning_that_fails_default_gate(self):
        path = self.write_text("odd.json", json.dumps({"mcpServers": {
            "a": {"command": "npx", "args": ["-y", "postmark-mcp@1.0.16", 5]}}}))
        code, out = run_cli("check-config", path)
        self.assertEqual(code, 1)
        self.assertIn("args is not a list of strings", out)

    def test_unreadable_entry_kind_and_severity(self):
        from mcp_lint.install import unreadable_finding

        f = unreadable_finding("a", "args is not a list of strings")
        self.assertEqual((f.kind, f.severity), ("unreadable_entry", Severity.WARNING))

    def test_control_characters_in_names_are_escaped(self):
        path = self.write_text(".mcp.json", json.dumps({"mcpServers": {
            "zz\x1b[3A\x1b[J": {"command": "npx", "args": ["-y", "foo"]}}}))
        code, out = run_cli("check-config", path)
        self.assertNotIn("\x1b", out)

    def test_init_fixtures_refuses_known_bad(self):
        with mock.patch("mcp_lint.client.fetch_tools") as fetch:
            code, out = run_cli("init-fixtures", os.path.join(self.dir.name, "f.json"), "--",
                                "npx", "-y", "postmark-mcp@1.0.16")
        self.assertEqual(code, 1)
        self.assertFalse(fetch.called)


class BypassCliTests(unittest.TestCase):
    """run, proxy and lock refuse the bypass shapes without connecting."""

    SHAPES = (["uvx", "--env-file", ".env", "litellm==1.82.7"],
              ["uv", "--directory", "/srv", "run", "--with", "litellm==1.82.7", "server.py"],
              ["npx", "-y", "x@npm:postmark-mcp@1.0.16"],
              ["bash", "-l", "-c", "npx -y postmark-mcp@1.0.16"])

    def test_refusal_through_every_command(self):
        for sub in ("run", "proxy", "lock"):
            for cmd in self.SHAPES:
                with mock.patch("mcp_lint.client.fetch_tools") as fetch, \
                        mock.patch("mcp_lint.client.fetch_and_probe") as probe, \
                        mock.patch("mcp_lint.proxy.serve") as serve:
                    code, out = run_cli(sub, "--", *cmd)
                self.assertEqual(code, 1, (sub, cmd, out))
                self.assertFalse(fetch.called or probe.called or serve.called, (sub, cmd))


class Round3Tests(unittest.TestCase):
    """Ranges, loose versions, artifacts, escapes, prefix wrappers and redaction."""

    def refused(self, cmd):
        if isinstance(cmd, str):
            cmd = split(cmd)
        return any(f.kind == "known_bad" and f.severity == Severity.ERROR for f in lint_command(cmd))

    def assert_refused(self, cmds):
        for cmd in cmds:
            self.assertTrue(self.refused(cmd), cmd)

    def assert_allowed(self, cmds):
        for cmd in cmds:
            self.assertFalse(self.refused(cmd), cmd)

    def test_pypi_specifier_sets_refused(self):
        self.assert_refused([
            "uvx 'litellm>=0,==1.82.7'", "uvx 'litellm!=0,==1.82.7'", "uvx 'litellm==1.82.7.*'",
            "uvx 'litellm~=1.82.7.0'", "uvx 'litellm>=1.82.7,<1.82.8'",
            "uvx 'litellm<=1.82.7,>=1.82.7'", "uvx 'litellm>=1.82.8,<1.82.9'",
            "pip install 'litellm>=0,==1.82.8'", "uvx --with 'litellm>=1.82.8,<1.82.9' x==1.0",
            "uvx 'litellm >= 1.82.7 , < 1.82.8'"])

    def test_pypi_specifier_sets_allowed(self):
        self.assert_allowed([
            "uvx 'litellm>=1.82.7'", "uvx 'litellm~=1.82.7'", "uvx 'litellm<2'",
            "uvx 'litellm!=1.82.7,!=1.82.8'", "uvx 'litellm>=1.82.7,<1.82.10'",
            "uvx 'litellm==1.82.*'", "uvx 'litellm>=1.82.7,garbage'"])

    def test_with_specifier_set_stays_one_requirement(self):
        got = lint_command(split("uvx --with 'litellm!=1.82.7,!=1.82.8' x==1.0"))
        self.assertEqual([f.kind for f in got], ["unpinned"])
        self.assertNotIn('"!=1.82.8"', " ".join(f.message for f in got))

    def test_npm_loose_versions(self):
        self.assert_refused(["npx -y postmark-mcp@1.0.016", "npx -y postmark-mcp@01.00.16",
                             "npx -y postmark-mcp@v=1.0.16", "npx -y postmark-mcp@1.0.16+b"])

    def test_npm_ranges_refused(self):
        for rng in (">=0 1.0.16", "0.0.0-x || 1.0.16", ">=1.0.16 <1.0.17", "<=1.0.16 >=1.0.16",
                    "1.0.16 - 1.0.16", "<=1.0.16", ">= 1.0.16 < 1.0.17", "1.0.16 || ^1.0.16"):
            self.assertTrue(self.refused(["npx", "-y", "postmark-mcp@" + rng]), rng)

    def test_npm_ranges_allowed(self):
        for rng in ("^1.0.16", "~1.0.16", ">=1.0.16", "1.0.x", "1.0.160", "1.x", "*", "latest",
                    "1.0.17-beta", ">1.0.15"):
            self.assertFalse(self.refused(["npx", "-y", "postmark-mcp@" + rng]), rng)

    def test_artifacts(self):
        self.assert_refused([
            "npx -y https://registry.npmjs.org/postmark-mcp/-/postmark-mcp-1.0.16.tgz",
            "uvx --from https://files.pythonhosted.org/packages/xx/litellm-1.82.8-py3-none-any.whl litellm",
            "uvx --from ./dist/litellm-1.82.7.tar.gz litellm",
            "pip install ./postmark-mcp-1.0.16.tgz", "pip install litellm-1.107.0.zip"])
        self.assertTrue(self.refused(["uvx", "--from", "C:\\dist\\litellm-1.82.7.tar.gz", "litellm"]))
        self.assert_allowed(["npx -y https://example.com/postmark-mcp-1.0.17.tgz",
                             "uvx --from ./dist/litellm-1.82.6.tar.gz litellm"])

    def test_bash_c_with_later_options(self):
        self.assert_refused(["bash -c -x 'npx postmark-mcp@1.0.16'",
                             "bash -c -- 'npx postmark-mcp@1.0.16'",
                             "bash -c -o pipefail 'npx postmark-mcp@1.0.16'"])
        self.assertEqual(kinds(["bash", "-c", "-x"]), ["unparsed"])
        self.assertEqual(kinds(["bash", "-c", "--"]), ["unparsed"])

    def test_escapes(self):
        self.assert_refused([
            ["bash", "-c", "-x", "npx postmark-mcp@1.0.1\\6"],
            ["cmd", "/c", "npx postmark-mcp@1.0.^16"],
            ["cmd", "/c", "npx", "postmark-mcp@1.0.^16"],
            ["pwsh", "-Command", "npx postmark-mcp@1.0.1`6"],
            ["sudo", "bash", "-c", "npx postmark-mcp@1.0.1\\6"],
            ["sudo", "bash", "-c", "uvx litellm==1.82.8>/dev/null"],
            ["uvx", "litellm==1.82.8>/dev/null"]])

    def test_semver_caret_is_not_an_escape(self):
        self.assert_allowed([["npx", "-y", "postmark-mcp@^1.0.16"]])

    def test_prefix_wrappers(self):
        self.assert_refused([
            "sudo uvx 'litellm[a,b,c,d]==1.82.7'", "op run -- uvx 'litellm[a,b,c,d]==1.82.7'",
            "timeout 10 npx -y postmark-mcp@1.0.16", "doppler run -- npx -y postmark-mcp@1.0.16",
            "wsl npx -y postmark-mcp@1.0.16", "cross-env A=1 npx -y postmark-mcp@1.0.16",
            "sudo -u bob timeout 5 npx -y 'postmark-mcp@>=0 1.0.16'"])

    def test_many_extras_stay_one_piece(self):
        extras = ",".join(f"x{i}" for i in range(300))
        self.assertTrue(self.refused(["uvx", f"litellm[{extras}]==1.82.7"]))
        self.assertTrue(self.refused(["sudo", "uvx", f"--from=litellm[{extras}]==1.82.7", "litellm"]))
        self.assertTrue(self.refused(["foo", f"x,litellm[{extras}]==1.82.7"]))

    def test_adjacent_pieces_join_only_within_one_argv_string(self):
        self.assert_allowed([["uvx", "litellm", "==1.82.7"], ["npx", "-y", "postmark-mcp@", "1.0.16"]])
        self.assert_refused([["foo", "litellm ==1.82.7"], ["foo", "litellm (==1.82.7)"],
                             ["foo", "postmark-mcp@ 1.0.16"]])

    def test_redaction_with_hash_or_question_mark_in_password(self):
        self.assertEqual(_redact("https://u:pw#x@host/a/b"), "https://***@host/a/b")
        self.assertEqual(_redact("https://u:pw?x@host/a?q=1#f"), "https://***@host/a")
        for url in ("git+https://usrSECRET:pwSECRET#x@host/a/b", "git+https://usrSECRET:pw?SECRET@host/a/b"):
            text = " ".join((f.message or "") + (f.hint or "")
                            for f in lint_command(["uvx", "--from", url, "b"]))
            self.assertNotIn("SECRET", text)
            self.assertIn("unpinned_source", kinds(["uvx", "--from", url, "b"]))

    def test_repeated_version_prefix_is_fast(self):
        t0 = time.perf_counter()
        lint_command(["npx", "x@" + "v" * 1_000_000])
        lint_command(["npx", "x@" + "=" * 1_000_000])
        self.assertLess(time.perf_counter() - t0, 3.0)

    def test_odd_ranges_never_raise(self):
        for rng in ("", "||", ">=", "- -", "1.0.16 -", "x.y.z", "^", "1." + "9" * 40, "<" * 50,
                    " ".join(f">={i}" for i in range(1000))):
            lint_command(["npx", "-y", "postmark-mcp@" + rng])
        for spec in ("litellm==", "litellm>=,", "litellm~=1", "litellm==1.82.7.*.*", "litellm==" + "9" * 5000,
                     "litellm" + ",=1" * 1000):
            lint_command(["uvx", spec])


class JsoncEscapeTests(unittest.TestCase):
    def test_escaped_quote_and_comment_like_strings(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "mcp.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"servers": {"a": {"command": "npx", "args": ["-y", "postmark-mcp@1.0.16", '
                         '"q\\"//still,}", "/* not */"],},},}')
            servers = load_client_config(path)
            self.assertEqual(servers[0].argv, ["npx", "-y", "postmark-mcp@1.0.16", 'q"//still,}', "/* not */"])
            code, out = run_cli("check-config", path, "--fail-on", "error")
            self.assertEqual(code, 1)
            self.assertIn("postmark-mcp", out)


if __name__ == "__main__":
    unittest.main()
